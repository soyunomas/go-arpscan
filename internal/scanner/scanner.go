// internal/scanner/scanner.go
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"go-arpscan/internal/oui"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ScanResult struct {
	IP     string
	MAC    string
	RTT    time.Duration
	Vendor string
	Status string
}

type Config struct {
	Interface     *net.Interface
	IPs           []net.IP
	VendorDB      *oui.VendorDB
	ScanTimeout   time.Duration
	HostTimeout   time.Duration
	Retry         int
	Interval      time.Duration
	BackoffFactor float64
	ArpSPA        net.IP
	Verbosity     int
}

type targetStatus int

const (
	StatusPending targetStatus = iota
	StatusSent
	StatusReplied
)

type Target struct {
	IP             net.IP
	Status         targetStatus
	SentCount      int
	LastSent       time.Time
	currentTimeout time.Duration
	mu             sync.Mutex
}

const (
	numSenders = 50
)

func StartScan(cfg *Config) (<-chan ScanResult, error) {
	handle, err := pcap.OpenLive(cfg.Interface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("no se pudo abrir el handle de pcap: %w", err)
	}

	bpfFilter := "arp"
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

		targets := make(map[string]*Target)
		for _, ip := range cfg.IPs {
			targets[ip.String()] = &Target{
				IP:             ip,
				Status:         StatusPending,
				currentTimeout: cfg.HostTimeout,
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), cfg.ScanTimeout)
		defer cancel()

		var wgListener sync.WaitGroup
		wgListener.Add(1)
		go listener(ctx, &wgListener, handle, cfg, targets, results)

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

		passCounter := 0

	main_loop:
		for {
			select {
			case <-ctx.Done():
				break main_loop
			case <-ticker.C:
				now := time.Now()
				targetToSend := findNextTarget(targets, now, cfg.Retry)

				if targetToSend == nil {
					if allTargetsDone(targets, cfg.Retry) {
						break main_loop
					}
					continue
				}

				if targetToSend.SentCount == passCounter && cfg.Verbosity >= 1 {
					log.Printf("Fin de la pasada %d. Hosts restantes: %d", passCounter+1, countRemainingTargets(targets))
					passCounter++
				}

				targetToSend.mu.Lock()
				targetToSend.Status = StatusSent
				targetToSend.SentCount++
				targetToSend.LastSent = now
				targetToSend.currentTimeout = time.Duration(float64(targetToSend.currentTimeout) * cfg.BackoffFactor)
				targetToSend.mu.Unlock()

				select {
				case jobs <- targetToSend.IP:
				case <-ctx.Done():
					break main_loop
				}
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

	// <-- INICIO BLOQUE CORREGIDO: CÁLCULO DEFENSIVO -->
	ifaceIPv4 := ifaceIPNet.IP.To4()
	if ifaceIPv4 == nil {
		log.Printf("Error crítico en sender: la IP de la interfaz no es una IPv4 válida.")
		return
	}

	hostPart := make(net.IP, net.IPv4len)
	copy(hostPart, ifaceIPv4)

	// La máscara de un IPNet de una interfaz real siempre tendrá la longitud correcta (4 o 16).
	// Forzamos el cálculo a 4 bytes para estar seguros.
	for i := 0; i < net.IPv4len; i++ {
		hostPart[i] &^= ifaceIPNet.Mask[i]
	}
	// <-- FIN BLOQUE CORREGIDO -->

	for {
		select {
		case <-ctx.Done():
			return
		case dstIP, ok := <-jobs:
			if !ok {
				return
			}

			// <-- INICIO BLOQUE CORREGIDO: USO DEFENSIVO -->
			dstIPv4 := dstIP.To4()
			if dstIPv4 == nil {
				if cfg.Verbosity > 0 {
					log.Printf("Saltando destino no IPv4: %s", dstIP)
				}
				continue
			}

			var sourceIP net.IP
			if cfg.ArpSPA != nil {
				sourceIP = cfg.ArpSPA.To4() // Forzamos a 4 bytes también aquí
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
			// <-- FIN BLOQUE CORREGIDO -->

			if cfg.Verbosity >= 2 {
				log.Printf("Enviando ARP a %s desde %s", dstIPv4, sourceIP)
			}
			sendARP(handle, cfg.Interface, sourceIP, dstIPv4)
		}
	}
}

func allTargetsDone(targets map[string]*Target, maxRetries int) bool {
	// ... (sin cambios)
	for _, t := range targets {
		t.mu.Lock()
		status := t.Status
		sentCount := t.SentCount
		t.mu.Unlock()

		if status != StatusReplied && sentCount < maxRetries {
			return false
		}
	}
	return true
}

func findNextTarget(targets map[string]*Target, now time.Time, maxRetries int) *Target {
	// ... (sin cambios)
	for _, t := range targets {
		t.mu.Lock()
		status := t.Status
		t.mu.Unlock()

		if status == StatusPending {
			return t
		}
	}
	for _, t := range targets {
		t.mu.Lock()
		status := t.Status
		sentCount := t.SentCount
		lastSent := t.LastSent
		timeout := t.currentTimeout
		t.mu.Unlock()

		if status == StatusSent && sentCount < maxRetries && now.After(lastSent.Add(timeout)) {
			return t
		}
	}
	return nil
}

func listener(ctx context.Context, wg *sync.WaitGroup, handle *pcap.Handle, cfg *Config, targets map[string]*Target, results chan<- ScanResult) {
	// ... (sin cambios)
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

			target.mu.Lock()
			var rtt time.Duration
			if !target.LastSent.IsZero() {
				rtt = time.Since(target.LastSent)
			}

			if target.Status != StatusReplied {
				target.Status = StatusReplied
				if cfg.Verbosity >= 2 {
					log.Printf("Primera respuesta de %s. Eliminando de la lista de pendientes de reintento.", srcIPStr)
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

func sendARP(handle *pcap.Handle, iface *net.Interface, srcIP, dstIP net.IP) {
	// ... (sin cambios)
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP.To4()),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err != nil {
		log.Printf("Error serializando paquete para %s: %v", dstIP, err)
		return
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		log.Printf("Error enviando paquete para %s: %v", dstIP, err)
	}
}

func GetSrcIPNet(iface *net.Interface) (*net.IPNet, error) {
	// ... (sin cambios)
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
