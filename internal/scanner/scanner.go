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

		targets := make(map[string]*Target)
		targetList := make([]*Target, len(cfg.IPs))
		for i, ip := range cfg.IPs {
			t := &Target{
				IP:     ip,
				Status: StatusPending,
			}
			targets[ip.String()] = t
			targetList[i] = t
		}

		ctx, cancel := context.WithTimeout(context.Background(), cfg.ScanTimeout)
		defer cancel()

		var wgListener sync.WaitGroup
		wgListener.Add(1)
		go listener(ctx, &wgListener, handle, cfg, targets, results, pcapWriter)

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
			if cfg.Verbosity >= 1 {
				log.Printf("Fin de la pasada %d. Hosts restantes: %d", pass+1, countRemainingTargets(targets))
			}

			currentHostTimeout := float64(cfg.HostTimeout)
			for i := 0; i < pass; i++ {
				currentHostTimeout *= cfg.BackoffFactor
			}
			time.Sleep(time.Duration(currentHostTimeout))

			if countRemainingTargets(targets) == 0 {
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

func countRemainingTargets(targets map[string]*Target) int {
	count := 0
	for _, t := range targets {
		t.mu.Lock()
		if t.Status != StatusReplied {
			count++
		}
		t.mu.Unlock()
	}
	return count
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
			sendARP(handle, cfg.Interface, cfg, sourceIP, dstIPv4)

			if cfg.ProgressBar != nil {
				cfg.ProgressBar.Add(1)
			}
		}
	}
}

func listener(ctx context.Context, wg *sync.WaitGroup, handle *pcap.Handle, cfg *Config, targets map[string]*Target, results chan<- ScanResult, pcapWriter *pcapgo.Writer) {
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

			srcIPStr := net.IP(arp.SourceProtAddress).String()
			srcMACStr := net.HardwareAddr(arp.SourceHwAddress).String()

			if cfg.Verbosity >= 2 {
				log.Printf("Recibido paquete ARP de %s [%s]", srcIPStr, srcMACStr)
			}

			target, found := targets[srcIPStr]
			if !found {
				if cfg.Verbosity >= 1 {
					log.Printf("Recibida respuesta de un host desconocido: %s", srcIPStr)
				}
				continue
			}

			// <<< INICIO DE LA LÓGICA CORREGIDA >>>
			target.mu.Lock()
			var rtt time.Duration
			if !target.LastSent.IsZero() {
				rtt = time.Since(target.LastSent)
			}

			// Marcamos el objetivo como respondido en la primera respuesta.
			// Esto es importante para que el bucle principal de escaneo sepa
			// que no necesita seguir enviando paquetes a este objetivo.
			if target.Status != StatusReplied {
				target.Status = StatusReplied
				if cfg.Verbosity >= 2 {
					log.Printf("Primera respuesta de %s. Marcado como respondido.", srcIPStr)
				}
			}
			target.mu.Unlock()

			// ¡LA CLAVE! Enviamos CADA resultado al canal de procesamiento,
			// permitiendo que la capa superior se encargue de la lógica de
			// conflictos y duplicados.
			vendor := cfg.VendorDB.Lookup(srcMACStr)
			results <- ScanResult{
				IP:     srcIPStr,
				MAC:    srcMACStr,
				RTT:    rtt,
				Vendor: vendor,
			}
			// <<< FIN DE LA LÓGICA CORREGIDA >>>
		}
	}
}

func sendARP(handle *pcap.Handle, iface *net.Interface, cfg *Config, srcIP, dstIP net.IP) {
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

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true} // FixLengths a true es más seguro con LLC
	var err error

	var layersToSerialize []gopacket.SerializableLayer

	if cfg.UseLLC {
		// Construir el paquete con framing IEEE 802.2 LLC/SNAP (RFC 1042)
		llc := layers.LLC{
			DSAP:    0xAA, // SNAP
			SSAP:    0xAA, // SNAP
			Control: 0x03, // Unnumbered Information
		}
		// <-- CORRECCIÓN: El nombre del campo es OrganizationalCode, no OUI. -->
		snap := layers.SNAP{
			OrganizationalCode: []byte{0x00, 0x00, 0x00}, // Encapsulated Ethernet OUI
			Type:               layers.EthernetType(cfg.EthernetPrototype),
		}

		if cfg.VlanID > 0 {
			eth.EthernetType = layers.EthernetTypeDot1Q
			dot1q := layers.Dot1Q{
				VLANIdentifier: cfg.VlanID,
				// gopacket calculará el Type como la longitud del payload LLC/SNAP/ARP
			}
			layersToSerialize = append(layersToSerialize, &eth, &dot1q, &llc, &snap, &arp)
		} else {
			// gopacket calculará el EthernetType como la longitud del payload LLC/SNAP/ARP
			layersToSerialize = append(layersToSerialize, &eth, &llc, &snap, &arp)
		}
	} else {
		// Lógica original para framing Ethernet-II
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

	err = gopacket.SerializeLayers(buf, opts, layersToSerialize...)

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
