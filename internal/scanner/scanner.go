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

// Estados atómicos
const (
	StatusPending int32 = iota
	StatusSent
	StatusReplied
)

type Target struct {
	IP       net.IP
	Status   int32 // Acceso atómico
	LastSent int64 // UnixNano, acceso atómico para RTT
}

const (
	numSenders = 50
)

// ipToKey convierte una IP a un array de 4 bytes para usar como clave de mapa sin allocs.
// Asume IPv4.
func ipToKey(ip net.IP) [4]byte {
	var key [4]byte
	if len(ip) == 4 {
		copy(key[:], ip)
	} else {
		copy(key[:], ip[len(ip)-4:])
	}
	return key
}

func StartScan(cfg *Config) (<-chan ScanResult, error) {
	// OPTIMIZACIÓN CRÍTICA (Precepto #16 y #53):
	// Usamos un timeout corto (10ms) en lugar de pcap.BlockForever.
	// Esto permite que el lector compruebe regularmente si el contexto ha sido cancelado,
	// evitando que la goroutine se quede "colgada" esperando paquetes en una red silenciosa.
	handle, err := pcap.OpenLive(cfg.Interface.Name, int32(cfg.Snaplen), true, 10*time.Millisecond)
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

	results := make(chan ScanResult, 100) // Buffer pequeño para evitar bloqueos
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

		// Optimización: Mapa con clave [4]byte para evitar allocs de string en el hot path
		targets := make(map[[4]byte]*Target, len(cfg.IPs))
		targetList := make([]*Target, len(cfg.IPs))

		for i, ip := range cfg.IPs {
			t := &Target{
				IP:     ip,
				Status: StatusPending,
			}
			targets[ipToKey(ip)] = t
			targetList[i] = t
		}

		// Contador atómico de objetivos pendientes
		var pendingTargets int64 = int64(len(cfg.IPs))

		ctx, cancel := context.WithTimeout(context.Background(), cfg.ScanTimeout)
		defer cancel()

		var wgListener sync.WaitGroup
		wgListener.Add(1)

		// Iniciar Listener optimizado
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
				msg := "Sondeando..."
				if cfg.Retry > 1 {
					msg = fmt.Sprintf("Pase %d/%d: Sondeando...", pass+1, cfg.Retry)
				}
				cfg.ProgressBar.Describe(msg)
			}

			for _, t := range targetList {
				// Lectura atómica rápida
				if atomic.LoadInt32(&t.Status) == StatusReplied {
					continue
				}

				select {
				case <-ticker.C:
					// Transición de estado segura
					atomic.CompareAndSwapInt32(&t.Status, StatusPending, StatusSent)
					atomic.StoreInt64(&t.LastSent, time.Now().UnixNano())

					select {
					case jobs <- t.IP:
					case <-ctx.Done():
						break main_loop
					}
				case <-ctx.Done():
					break main_loop
				}
			}

			remaining := atomic.LoadInt64(&pendingTargets)
			if cfg.Verbosity >= 1 {
				log.Printf("Fin de la pasada %d. Hosts restantes: %d", pass+1, remaining)
			}

			// Backoff
			currentHostTimeout := float64(cfg.HostTimeout)
			for i := 0; i < pass; i++ {
				currentHostTimeout *= cfg.BackoffFactor
			}

			// Espera antes de la siguiente pasada o fin, pero chequeando finalización temprana
			timeoutCh := time.After(time.Duration(currentHostTimeout))

			select {
			case <-timeoutCh:
				if atomic.LoadInt64(&pendingTargets) <= 0 {
					break main_loop
				}
			case <-ctx.Done():
				break main_loop
			}
		}

		close(jobs)
		wgSenders.Wait()

		// Espera final para respuestas tardías
		time.Sleep(cfg.HostTimeout)
		cancel()
		wgListener.Wait()
	}()

	return results, nil
}

// sender procesa el envío de paquetes. Optimizado para reutilizar buffers.
func sender(ctx context.Context, wg *sync.WaitGroup, handle *pcap.Handle, cfg *Config, jobs <-chan net.IP, ifaceIPNet *net.IPNet) {
	defer wg.Done()

	ifaceIPv4 := ifaceIPNet.IP.To4()
	if ifaceIPv4 == nil {
		return
	}

	// Pre-cálculo de la parte de host para IPs dinámicas
	hostPart := make(net.IP, net.IPv4len)
	copy(hostPart, ifaceIPv4)
	for i := 0; i < net.IPv4len; i++ {
		hostPart[i] &^= ifaceIPNet.Mask[i]
	}

	// Optimización: Buffer reutilizable por goroutine
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
				continue
			}

			var sourceIP net.IP
			if cfg.ArpSPADest {
				sourceIP = dstIPv4
			} else if cfg.ArpSPA != nil {
				sourceIP = cfg.ArpSPA.To4()
			} else {
				// Cálculo de IP dinámica optimizable, pero aceptable aquí
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

			if cfg.Verbosity >= 2 {
				log.Printf("Enviando ARP a %s desde %s", dstIPv4, sourceIP)
			}

			// Llamada a sendARP con buffer reutilizado
			sendARP(handle, cfg.Interface, cfg, sourceIP, dstIPv4, buf, opts)
			buf.Clear() // Importante: limpiar buffer para siguiente uso

			if cfg.ProgressBar != nil {
				cfg.ProgressBar.Add(1)
			}
		}
	}
}

// listener recibe paquetes. Optimizado con "Zero-Copy" logic y fast-path decoding.
func listener(ctx context.Context, wg *sync.WaitGroup, handle *pcap.Handle, cfg *Config, targets map[[4]byte]*Target, results chan<- ScanResult, pcapWriter *pcapgo.Writer, pendingTargets *int64) {
	defer wg.Done()

	// Objetos de capa reutilizables para el decoder
	var eth layers.Ethernet
	var arp layers.ARP
	var dot1q layers.Dot1Q

	// Parser optimizado: mucho más rápido que NewPacket
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &arp)

	// slice para almacenar qué capas se han decodificado
	decoded := make([]gopacket.LayerType, 0, 4)

	// Bucle de lectura directa del handle
	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Leer datos crudos.
			data, ci, err := handle.ReadPacketData()
			if err != nil {
				// FIX CRÍTICO: Si hay timeout, simplemente continuamos el bucle.
				// Esto permite revisar ctx.Done() y salir limpiamente.
				if err == pcap.NextErrorTimeoutExpired {
					continue
				}
				// Otros errores (ej: interfaz caída) podrían requerir salir.
				// Por robustez en hot-path, logueamos y reintentamos o salimos.
				// Para evitar bucle infinito de errores, salimos si no es timeout.
				return
			}

			// --- FIX CRÍTICO: Gestión de errores del parser ---
			// decodingLayerParser devuelve error si hay padding al final del paquete (común en ARP).
			// NO debemos descartar el paquete si hay error, sino comprobar si la capa ARP se decodificó.

			// Reseteamos el slice de capas decodificadas
			decoded = decoded[:0]

			_ = parser.DecodeLayers(data, &decoded)
			// Ignoramos el error devuelto por DecodeLayers intencionadamente aquí,
			// porque verificamos manualmente si LayerTypeARP está en 'decoded'.

			isARP := false
			for _, layerType := range decoded {
				if layerType == layers.LayerTypeARP {
					isARP = true
					break
				}
			}

			if !isARP {
				continue
			}
			// --------------------------------------------------

			// Lógica de captura pcap
			if arp.Operation == layers.ARPReply && pcapWriter != nil {
				if err := pcapWriter.WritePacket(ci, data); err != nil {
					log.Printf("Advertencia pcap: %v", err)
				}
			}

			// Filtrar paquetes propios y no-reply
			if arp.Operation != layers.ARPReply || bytes.Equal(cfg.Interface.HardwareAddr, arp.SourceHwAddress) {
				continue
			}

			// Optimización: Lookup en mapa con clave [4]byte (Stack allocation)
			key := ipToKey(arp.SourceProtAddress)
			target, found := targets[key]

			if !found {
				if cfg.Verbosity >= 1 {
					log.Printf("Recibida respuesta de desconocido: %s", net.IP(arp.SourceProtAddress))
				}
				continue
			}

			// Hemos encontrado un target válido.
			srcIPStr := target.IP.String()
			srcMACStr := net.HardwareAddr(arp.SourceHwAddress).String()

			if cfg.Verbosity >= 2 {
				log.Printf("Recibido ARP Reply de %s [%s]", srcIPStr, srcMACStr)
			}

			// Cálculo de RTT atómico
			var rtt time.Duration
			sentTime := atomic.LoadInt64(&target.LastSent)
			if sentTime != 0 {
				rtt = time.Since(time.Unix(0, sentTime))
			}

			// Actualización atómica de estado
			if atomic.CompareAndSwapInt32(&target.Status, StatusSent, StatusReplied) ||
				atomic.CompareAndSwapInt32(&target.Status, StatusPending, StatusReplied) {

				atomic.AddInt64(pendingTargets, -1)
				if cfg.Verbosity >= 2 {
					log.Printf("Target %s respondido. RTT: %v", srcIPStr, rtt)
				}
			}

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

func sendARP(handle *pcap.Handle, iface *net.Interface, cfg *Config, srcIP, dstIP net.IP, buf gopacket.SerializeBuffer, opts gopacket.SerializeOptions) {
	var sourceEthMAC, destinationEthMAC, sourceArpSHA net.HardwareAddr

	if cfg.EthSrcMAC != nil {
		sourceEthMAC = cfg.EthSrcMAC
	} else {
		sourceEthMAC = iface.HardwareAddr
	}
	if cfg.EthDstMAC != nil {
		destinationEthMAC = cfg.EthDstMAC
	} else {
		destinationEthMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}
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

	eth := layers.Ethernet{
		SrcMAC:       sourceEthMAC,
		DstMAC:       destinationEthMAC,
		EthernetType: layers.EthernetType(cfg.EthernetPrototype), // Default ARP
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

	// Construcción de capas.
	var layersToSerialize []gopacket.SerializableLayer
	layersToSerialize = make([]gopacket.SerializableLayer, 0, 5)

	if cfg.UseLLC {
		llc := layers.LLC{DSAP: 0xAA, SSAP: 0xAA, Control: 0x03}
		snap := layers.SNAP{OrganizationalCode: []byte{0x00, 0x00, 0x00}, Type: layers.EthernetType(cfg.EthernetPrototype)}

		if cfg.VlanID > 0 {
			eth.EthernetType = layers.EthernetTypeDot1Q
			dot1q := layers.Dot1Q{VLANIdentifier: cfg.VlanID}
			layersToSerialize = append(layersToSerialize, &eth, &dot1q, &llc, &snap, &arp)
		} else {
			layersToSerialize = append(layersToSerialize, &eth, &llc, &snap, &arp)
		}
	} else {
		if cfg.VlanID > 0 {
			eth.EthernetType = layers.EthernetTypeDot1Q
			dot1q := layers.Dot1Q{VLANIdentifier: cfg.VlanID, Type: layers.EthernetType(cfg.EthernetPrototype)}
			layersToSerialize = append(layersToSerialize, &eth, &dot1q, &arp)
		} else {
			layersToSerialize = append(layersToSerialize, &eth, &arp)
		}
	}

	if len(cfg.PaddingData) > 0 {
		layersToSerialize = append(layersToSerialize, gopacket.Payload(cfg.PaddingData))
	}

	if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
		return // Silent fail
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		if cfg.Verbosity >= 2 {
			log.Printf("Error sending: %v", err)
		}
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
