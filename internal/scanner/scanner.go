// internal/scanner/scanner.go
package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
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
	// Fast activa el motor zero-allocation AF_PACKET (solo Linux).
	// Si las flags avanzadas no son compatibles, FastEligible devuelve false
	// y el runner cae al motor original.
	Fast bool
	// RandomSeed siembra la permutación Feistel del motor fast. 0 = fija.
	RandomSeed int64
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
func ipToKey(ip net.IP) [4]byte {
	var key [4]byte
	if len(ip) == 4 {
		copy(key[:], ip)
	} else {
		copy(key[:], ip[len(ip)-4:])
	}
	return key
}

// parseARPPacket comprueba si los datos de la trama corresponden a alguno de los
// formatos de encapsulación soportados (Ethernet II, LLC/SNAP, VLAN, VLAN+LLC/SNAP).
// Devuelve el desplazamiento (offset) donde comienza la carga útil ARP, o -1 si no es válida.
func parseARPPacket(data []byte) int {
	if len(data) < 14 {
		return -1
	}

	proto := binary.BigEndian.Uint16(data[12:14])
	off := 14

	// 1. Manejo opcional de cabecera VLAN (802.1Q)
	if proto == 0x8100 {
		if len(data) < 18 {
			return -1
		}
		proto = binary.BigEndian.Uint16(data[16:18])
		off = 18
	}

	// 2. Formato Ethernet II Estándar
	if proto == 0x0806 {
		if len(data) >= off+28 {
			return off
		}
		return -1
	}

	// 3. Formato 802.3 LLC/SNAP (EtherType <= 1500 indica longitud)
	if proto <= 1500 {
		if len(data) < off+3+5+28 {
			return -1
		}
		// Decodificación de LLC: DSAP (0xAA), SSAP (0xAA), Control (0x03)
		if data[off] == 0xAA && data[off+1] == 0xAA && data[off+2] == 0x03 {
			// Decodificación de SNAP: OUI (3 bytes), Protocolo (2 bytes)
			snapProto := binary.BigEndian.Uint16(data[off+6 : off+8])
			if snapProto == 0x0806 { // SNAP ARP
				return off + 8
			}
		}
	}

	return -1
}

func StartScan(cfg *Config) (<-chan ScanResult, error) {
	// Timeout corto (10ms) para evitar bloqueo de goroutine al salir
	handle, err := pcap.OpenLive(cfg.Interface.Name, int32(cfg.Snaplen), true, 10*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("could not open pcap handle: %w", err)
	}

	// Filtro BPF expandido para capturar respuestas encapsuladas en LLC/SNAP y/o VLANs
	bpfFilter := "arp or (ether[12:2] <= 1500 and ether[14:2] == 0xaaaa) or (vlan and (arp or (ether[16:2] <= 1500 and ether[18:2] == 0xaaaa)))"
	if cfg.VlanID > 0 {
		bpfFilter = fmt.Sprintf("vlan %d and (arp or (ether[16:2] <= 1500 and ether[18:2] == 0xaaaa))", cfg.VlanID)
	}
	if cfg.Verbosity >= 2 {
		log.Printf("Setting pcap BPF filter: %q", bpfFilter)
	}
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("could not set BPF filter: %w", err)
	}

	results := make(chan ScanResult, 100) // Buffer pequeño
	jobs := make(chan net.IP, numSenders)

	go func() {
		defer close(results)
		defer handle.Close()

		var pcapWriter *pcapgo.Writer
		if cfg.PcapSaveFile != "" {
			f, err := os.Create(cfg.PcapSaveFile)
			if err != nil {
				log.Printf("CRITICAL: Could not create pcap file %q: %v.", cfg.PcapSaveFile, err)
			} else {
				defer f.Close()
				pcapWriter = pcapgo.NewWriter(f)
				if err := pcapWriter.WriteFileHeader(uint32(cfg.Snaplen), handle.LinkType()); err != nil {
					pcapWriter = nil
				}
			}
		}

		targets := make(map[[4]byte]*Target, len(cfg.IPs))
		targetList := make([]*Target, len(cfg.IPs))
		for i, ip := range cfg.IPs {
			t := &Target{IP: ip, Status: StatusPending}
			targets[ipToKey(ip)] = t
			targetList[i] = t
		}

		var pendingTargets int64 = int64(len(cfg.IPs))
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ScanTimeout)
		defer cancel()

		var wgListener sync.WaitGroup
		wgListener.Add(1)
		go listener(ctx, &wgListener, handle, cfg, targets, results, pcapWriter, &pendingTargets)

		var wgSenders sync.WaitGroup
		ifaceIPNet, err := GetSrcIPNet(cfg.Interface)
		if err != nil {
			log.Printf("CRITICAL: could not get interface IP: %v", err)
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
				msg := "Probing..."
				if cfg.Retry > 1 {
					msg = fmt.Sprintf("Pass %d/%d: Probing...", pass+1, cfg.Retry)
				}
				cfg.ProgressBar.Describe(msg)
			}

			for _, t := range targetList {
				if atomic.LoadInt32(&t.Status) == StatusReplied {
					continue
				}
				select {
				case <-ticker.C:
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
				log.Printf("End of pass %d. Hosts remaining: %d", pass+1, remaining)
			}

			currentHostTimeout := float64(cfg.HostTimeout)
			for i := 0; i < pass; i++ {
				currentHostTimeout *= cfg.BackoffFactor
			}

			// Esperamos el timeout del host.
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

		cancel() // Cancelamos contexto de listener explícitamente
		wgListener.Wait()
	}()

	return results, nil
}

// sender procesa el envío de paquetes.
func sender(ctx context.Context, wg *sync.WaitGroup, handle *pcap.Handle, cfg *Config, jobs <-chan net.IP, ifaceIPNet *net.IPNet) {
	defer wg.Done()

	ifaceIPv4 := ifaceIPNet.IP.To4()
	if ifaceIPv4 == nil {
		return
	}
	hostPart := make(net.IP, net.IPv4len)
	copy(hostPart, ifaceIPv4)
	for i := 0; i < net.IPv4len; i++ {
		hostPart[i] &^= ifaceIPNet.Mask[i]
	}

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
				log.Printf("Sending ARP to %s from %s", dstIPv4, sourceIP)
			}
			sendARP(handle, cfg.Interface, cfg, sourceIP, dstIPv4, buf, opts)
			buf.Clear()
			if cfg.ProgressBar != nil {
				cfg.ProgressBar.Add(1)
			}
		}
	}
}

// listener recibe paquetes utilizando el parser manual multi-formato de alto rendimiento.
func listener(ctx context.Context, wg *sync.WaitGroup, handle *pcap.Handle, cfg *Config, targets map[[4]byte]*Target, results chan<- ScanResult, pcapWriter *pcapgo.Writer, pendingTargets *int64) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			data, ci, err := handle.ReadPacketData()
			if err != nil {
				if err == pcap.NextErrorTimeoutExpired {
					continue
				}
				return
			}

			// Decodificación manual rápida de cabeceras de encapsulación
			arpOff := parseARPPacket(data)
			if arpOff == -1 {
				continue
			}

			// Extracción de campos clave del payload ARP de 28 bytes
			arpOp := binary.BigEndian.Uint16(data[arpOff+6 : arpOff+8])
			arpSHA := data[arpOff+8 : arpOff+14]
			arpSPA := data[arpOff+14 : arpOff+18]

			// Guardar respuestas ARP Reply válidas si está configurado el pcapWriter
			if arpOp == 2 && pcapWriter != nil { // 2 = ARP Reply
				if err := pcapWriter.WritePacket(ci, data); err != nil {
					log.Printf("pcap warning: %v", err)
				}
			}

			// Descartar si no es un ARP Reply o si es un reflejo de nuestra propia interfaz
			if arpOp != 2 || bytes.Equal(cfg.Interface.HardwareAddr, arpSHA) {
				continue
			}

			key := ipToKey(arpSPA)
			target, found := targets[key]
			if !found {
				if cfg.Verbosity >= 1 {
					log.Printf("Received reply from unknown target: %s", net.IP(arpSPA))
				}
				continue
			}

			srcIPStr := target.IP.String()
			srcMACStr := net.HardwareAddr(arpSHA).String()

			if cfg.Verbosity >= 2 {
				log.Printf("Received ARP Reply from %s [%s]", srcIPStr, srcMACStr)
			}

			var rtt time.Duration
			sentTime := atomic.LoadInt64(&target.LastSent)
			if sentTime != 0 {
				rtt = time.Since(time.Unix(0, sentTime))
			}

			if atomic.CompareAndSwapInt32(&target.Status, StatusSent, StatusReplied) ||
				atomic.CompareAndSwapInt32(&target.Status, StatusPending, StatusReplied) {
				atomic.AddInt64(pendingTargets, -1)
				if cfg.Verbosity >= 2 {
					log.Printf("Target %s replied. RTT: %v", srcIPStr, rtt)
				}
			}

			vendor := cfg.VendorDB.Lookup(srcMACStr)
			results <- ScanResult{IP: srcIPStr, MAC: srcMACStr, RTT: rtt, Vendor: vendor}
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
		EthernetType: layers.EthernetType(cfg.EthernetPrototype),
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
		return
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
	return nil, fmt.Errorf("no IPv4 address found on interface %s", iface.Name)
}
