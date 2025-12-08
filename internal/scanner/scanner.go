// internal/scanner/scanner.go
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"go-arpscan/internal/oui"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/schollz/progressbar/v3"
)

type ScanResult struct {
	IP     string
	MAC    string
	RTT    time.Duration
	Vendor string
	Status string
}

type Config struct {
	Interface         *net.Interface
	IPs               []net.IP
	VendorDB          *oui.VendorDB
	ScanTimeout       time.Duration
	HostTimeout       time.Duration
	Retry             int
	Interval          time.Duration
	BackoffFactor     float64
	ArpSPA            net.IP
	ArpSPADest        bool
	ArpSHA            net.HardwareAddr
	EthSrcMAC         net.HardwareAddr
	ArpOpCode         uint16
	EthDstMAC         net.HardwareAddr
	ArpTHA            net.HardwareAddr
	EthernetPrototype uint16
	ArpHardwareType   uint16
	ArpProtocolType   uint16
	ArpHardwareLen    uint8
	ArpProtocolLen    uint8
	PaddingData       []byte
	UseLLC            bool
	Verbosity         int
	PcapSaveFile      string
	VlanID            uint16
	Snaplen           int
	ProgressBar       *progressbar.ProgressBar
}

type targetStatus int

const (
	StatusPending targetStatus = iota
	StatusSent
	StatusReplied
)

type Target struct {
	IP       net.IP
	Status   targetStatus
	LastSent time.Time
	mu       sync.Mutex
}

const (
	numSenders = 50
)

// [Fase 2] Helper para convertir IP a array [4]byte sin allocs
func ipToKey(ip net.IP) [4]byte {
	var key [4]byte
	// Si es IPv4, suele ser slice de 4 bytes o 16 bytes (mapped).
	// Usamos copy que maneja ambos casos seguramente si tomamos los últimos 4.
	if len(ip) == 4 {
		copy(key[:], ip)
	} else {
		copy(key[:], ip[len(ip)-4:])
	}
	return key
}

func StartScan(cfg *Config) (<-chan ScanResult, error) {
	handle, err := pcap.OpenLive(cfg.Interface.Name, int32(cfg.Snaplen), true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("no se pudo abrir el handle de pcap: %w", err)
	}

	bpfFilter := "arp"
	if cfg.VlanID > 0 {
		bpfFilter = fmt.Sprintf("vlan %d and arp", cfg.VlanID)
	}
	if cfg.Verbosity >= 2 {
		log.Printf("Estableciendo filtro pcap BPF: '%s'", bpfFilter)
	}
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("no se pudo establecer el filtro BPF: %w", err)
	}

	results := make(chan ScanResult)
	jobs := make(chan net.IP, numSenders)

	go func() {
		defer close(results)
		defer handle.Close()

		var pcapWriter *pcapgo.Writer
		if cfg.PcapSaveFile != "" {
			f, err := os.Create(cfg.PcapSaveFile)
			if err != nil {
				log.Printf("CRÍTICO: No se pudo crear el archivo pcap '%s': %v. El escaneo continuará sin guardar.", cfg.PcapSaveFile, err)
			} else {
				defer f.Close()
				pcapWriter = pcapgo.NewWriter(f)
				if err := pcapWriter.WriteFileHeader(uint32(cfg.Snaplen), handle.LinkType()); err != nil {
					log.Printf("CRÍTICO: No se pudo escribir la cabecera del archivo pcap: %v.", err)
					pcapWriter = nil
				}
			}
		}

		// [Fase 2] Cambio de map[string] a map[[4]byte]
		targets := make(map[[4]byte]*Target)
		targetList := make([]*Target, len(cfg.IPs))
		
		for i, ip := range cfg.IPs {
			t := &Target{
				IP:     ip,
				Status: StatusPending,
			}
			// Usamos la IP normalizada a 4 bytes como clave
			targets[ipToKey(ip)] = t
			targetList[i] = t
		}

		// [Fase 3] Contador atómico
		var pendingTargets int64 = int64(len(cfg.IPs))

		ctx, cancel := context.WithTimeout(context.Background(), cfg.ScanTimeout)
		defer cancel()

		var wgListener sync.WaitGroup
		wgListener.Add(1)
		// Pasamos el mapa con el nuevo tipo de clave
		go listener(ctx, &wgListener, handle, cfg, targets, results, pcapWriter, &pendingTargets)

		var wgSenders sync.WaitGroup
		ifaceIPNet, err := GetSrcIPNet(cfg.Interface)
		if err != nil {
			log.Printf("CRÍTICO: no se pudo obtener la IP y máscara de la interfaz para el sender: %v", err)
			cancel()
		} else {
			for i := 0; i < numSenders; i++ {
				wgSenders.Add(1)
				go sender(ctx, &wgSenders, handle, cfg, jobs, ifaceIPNet)
			}
		}

		ticker := time.NewTicker(cfg.Interval)
		defer ticker.Stop()

	main_loop:
		for pass := 0; pass < cfg.Retry; pass++ {
			if cfg.ProgressBar != nil {
				if cfg.Retry > 1 {
					cfg.ProgressBar.Describe(fmt.Sprintf("Pase %d/%d: Sondeando...", pass+1, cfg.Retry))
				} else {
					cfg.ProgressBar.Describe("Sondeando...")
				}
			}

			for _, t := range targetList {
				t.mu.Lock()
				status := t.Status
				t.mu.Unlock()

				if status == StatusReplied {
					continue
				}

				select {
				case <-ticker.C:
					t.mu.Lock()
					t.Status = StatusSent
					t.LastSent = time.Now()
					t.mu.Unlock()

					select {
					case jobs <- t.IP:
					case <-ctx.Done():
						break main_loop
					}
				case <-ctx.Done():
					break main_loop
				}
			}
			
			// [Fase 3] Lectura atómica
			remaining := atomic.LoadInt64(&pendingTargets)
			if cfg.Verbosity >= 1 {
				log.Printf("Fin de la pasada %d. Hosts restantes: %d", pass+1, remaining)
			}

			currentHostTimeout := float64(cfg.HostTimeout)
			for i := 0; i < pass; i++ {
				currentHostTimeout *= cfg.BackoffFactor
			}
			time.Sleep(time.Duration(currentHostTimeout))

			// [Fase 3] Check atómico
			if atomic.LoadInt64(&pendingTargets) <= 0 {
				break main_loop
			}
		}

		close(jobs)
		wgSenders.Wait()

		time.Sleep(cfg.HostTimeout)
		cancel()
		wgListener.Wait()
	}()

	return results, nil
}

func sender(ctx context.Context, wg *sync.WaitGroup, handle *pcap.Handle, cfg *Config, jobs <-chan net.IP, ifaceIPNet *net.IPNet) {
	defer wg.Done()

	ifaceIPv4 := ifaceIPNet.IP.To4()
	if ifaceIPv4 == nil {
		log.Printf("Error crítico en sender: la IP de la interfaz no es una IPv4 válida.")
		return
	}

	hostPart := make(net.IP, net.IPv4len)
	copy(hostPart, ifaceIPv4)

	for i := 0; i < net.IPv4len; i++ {
		hostPart[i] &^= ifaceIPNet.Mask[i]
	}

	// [Fase 1] Buffer Reuse
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	for {
		select {
		case <-ctx.Done():
			return
		case dstIP, ok := <-jobs:
			if !ok {
				return
			}

			dstIPv4 := dstIP.To4()
			if dstIPv4 == nil {
				if cfg.Verbosity > 0 {
					log.Printf("Saltando destino no IPv4: %s", dstIP)
				}
				continue
			}

			var sourceIP net.IP
			if cfg.ArpSPADest {
				sourceIP = dstIPv4
			} else if cfg.ArpSPA != nil {
				sourceIP = cfg.ArpSPA.To4()
			} else {
				dstMask := dstIPv4.DefaultMask()
				if dstMask == nil {
					dstMask = net.CIDRMask(24, 32)
				}
				networkPart := dstIPv4.Mask(dstMask)

				sourceIP = make(net.IP, net.IPv4len)
				for i := 0; i < net.IPv4len; i++ {
					sourceIP[i] = networkPart[i] | hostPart[i]
				}
			}

			if sourceIP == nil {
				log.Printf("Error: no se pudo determinar la IP de origen para el destino %s", dstIPv4)
				continue
			}

			if cfg.Verbosity >= 2 {
				log.Printf("Enviando ARP a %s desde %s", dstIPv4, sourceIP)
			}
			
			// [Fase 1] Pasamos buffer y opciones
			sendARP(handle, cfg.Interface, cfg, sourceIP, dstIPv4, buf, opts)
			// [Fase 1] Limpiamos buffer
			buf.Clear()

			if cfg.ProgressBar != nil {
				cfg.ProgressBar.Add(1)
			}
		}
	}
}

// [Fase 2] Mapa actualizado a map[[4]byte]*Target
func listener(ctx context.Context, wg *sync.WaitGroup, handle *pcap.Handle, cfg *Config, targets map[[4]byte]*Target, results chan<- ScanResult, pcapWriter *pcapgo.Writer, pendingTargets *int64) {
	defer wg.Done()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return
			}

			arpLayerCheck := packet.Layer(layers.LayerTypeARP)
			if arpLayerCheck != nil {
				if arp, ok := arpLayerCheck.(*layers.ARP); ok && arp.Operation == layers.ARPReply {
					if pcapWriter != nil {
						if err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
							log.Printf("Advertencia: no se pudo escribir el paquete en el archivo pcap: %v", err)
						}
					}
				}
			}

			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp, _ := arpLayer.(*layers.ARP)

			if arp.Operation != layers.ARPReply || bytes.Equal(cfg.Interface.HardwareAddr, arp.SourceHwAddress) {
				continue
			}

			// [Fase 2] Optimización CRÍTICA:
			// Antes: srcIPStr := net.IP(...).String() -> Malloc en heap + copia
			// Ahora: ipToKey(...) -> Stack allocation (cero basura)
			
			// Solo convertimos a String si realmente encontramos el target y necesitamos reportarlo.
			targetKey := ipToKey(arp.SourceProtAddress)
			
			target, found := targets[targetKey]
			if !found {
				if cfg.Verbosity >= 1 {
					// Solo aquí pagamos el precio de convertir a string
					log.Printf("Recibida respuesta de un host desconocido: %s", net.IP(arp.SourceProtAddress))
				}
				continue
			}
			
			// Ahora que sabemos que es un target válido, preparamos los datos para el resultado
			// Esta conversión es inevitable para el reporte, pero hemos filtrado el ruido primero.
			srcIPStr := target.IP.String() 
			srcMACStr := net.HardwareAddr(arp.SourceHwAddress).String()

			if cfg.Verbosity >= 2 {
				log.Printf("Recibido paquete ARP de %s [%s]", srcIPStr, srcMACStr)
			}

			target.mu.Lock()
			var rtt time.Duration
			if !target.LastSent.IsZero() {
				rtt = time.Since(target.LastSent)
			}

			// [Fase 3] Lógica atómica
			if target.Status != StatusReplied {
				target.Status = StatusReplied
				atomic.AddInt64(pendingTargets, -1)
				
				if cfg.Verbosity >= 2 {
					log.Printf("Primera respuesta de %s. Marcado como respondido.", srcIPStr)
				}
			}
			target.mu.Unlock()

			vendor := cfg.VendorDB.Lookup(srcMACStr)
			results <- ScanResult{
				IP:     srcIPStr,
				MAC:    srcMACStr,
				RTT:    rtt,
				Vendor: vendor,
			}
		}
	}
}

// [Fase 1] sendARP Optimizado
func sendARP(handle *pcap.Handle, iface *net.Interface, cfg *Config, srcIP, dstIP net.IP, buf gopacket.SerializeBuffer, opts gopacket.SerializeOptions) {
	var sourceEthMAC net.HardwareAddr
	if cfg.EthSrcMAC != nil {
		sourceEthMAC = cfg.EthSrcMAC
	} else {
		sourceEthMAC = iface.HardwareAddr
	}

	var destinationEthMAC net.HardwareAddr
	if cfg.EthDstMAC != nil {
		destinationEthMAC = cfg.EthDstMAC
	} else {
		destinationEthMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} // Broadcast
	}

	eth := layers.Ethernet{
		SrcMAC: sourceEthMAC,
		DstMAC: destinationEthMAC,
	}

	var sourceArpSHA net.HardwareAddr
	if cfg.ArpSHA != nil {
		sourceArpSHA = cfg.ArpSHA
	} else {
		sourceArpSHA = iface.HardwareAddr
	}

	var destinationArpTHA []byte
	if cfg.ArpTHA != nil {
		destinationArpTHA = []byte(cfg.ArpTHA)
	} else {
		destinationArpTHA = []byte{0, 0, 0, 0, 0, 0}
	}

	arp := layers.ARP{
		AddrType:          layers.LinkType(cfg.ArpHardwareType),
		Protocol:          layers.EthernetType(cfg.ArpProtocolType),
		HwAddressSize:     cfg.ArpHardwareLen,
		ProtAddressSize:   cfg.ArpProtocolLen,
		Operation:         cfg.ArpOpCode,
		SourceHwAddress:   []byte(sourceArpSHA),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      destinationArpTHA,
		DstProtAddress:    []byte(dstIP.To4()),
	}

	// [Fase 1] Pre-alloc
	layersToSerialize := make([]gopacket.SerializableLayer, 0, 5)

	if cfg.UseLLC {
		llc := layers.LLC{
			DSAP:    0xAA,
			SSAP:    0xAA,
			Control: 0x03,
		}
		snap := layers.SNAP{
			OrganizationalCode: []byte{0x00, 0x00, 0x00},
			Type:               layers.EthernetType(cfg.EthernetPrototype),
		}

		if cfg.VlanID > 0 {
			eth.EthernetType = layers.EthernetTypeDot1Q
			dot1q := layers.Dot1Q{
				VLANIdentifier: cfg.VlanID,
			}
			layersToSerialize = append(layersToSerialize, &eth, &dot1q, &llc, &snap, &arp)
		} else {
			layersToSerialize = append(layersToSerialize, &eth, &llc, &snap, &arp)
		}
	} else {
		if cfg.VlanID > 0 {
			eth.EthernetType = layers.EthernetTypeDot1Q
			dot1q := layers.Dot1Q{
				VLANIdentifier: cfg.VlanID,
				Type:           layers.EthernetType(cfg.EthernetPrototype),
			}
			layersToSerialize = append(layersToSerialize, &eth, &dot1q, &arp)
		} else {
			eth.EthernetType = layers.EthernetType(cfg.EthernetPrototype)
			layersToSerialize = append(layersToSerialize, &eth, &arp)
		}
	}

	if len(cfg.PaddingData) > 0 {
		layersToSerialize = append(layersToSerialize, gopacket.Payload(cfg.PaddingData))
	}

	// [Fase 1] Serialize
	err := gopacket.SerializeLayers(buf, opts, layersToSerialize...)

	if err != nil {
		log.Printf("Error serializando paquete para %s: %v", dstIP, err)
		return
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		log.Printf("Error enviando paquete para %s: %v", dstIP, err)
	}
}

func GetSrcIPNet(iface *net.Interface) (*net.IPNet, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet, nil
			}
		}
	}
	return nil, fmt.Errorf("no se encontró una dirección IPv4 en la interfaz %s", iface.Name)
}
