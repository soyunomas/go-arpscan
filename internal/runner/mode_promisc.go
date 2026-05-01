// internal/runner/mode_promisc.go
package runner

import (
	"bytes"
	"context" // <<< IMPORT AÑADIDO
	"fmt"
	"log"
	"net"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// runDetectPromiscMode ejecuta la lógica de detección de modo promiscuo.
func (r *Runner) runDetectPromiscMode() error {
	iface := r.scanConfig.Interface
	targetIPStr := r.cfg.DetectPromiscTargetIP
	log.Printf("Starting promiscuous mode detection against %s on interface %s", targetIPStr, iface.Name)

	targetIP := net.ParseIP(targetIPStr)
	if targetIP == nil || targetIP.To4() == nil {
		return fmt.Errorf("target IP %q is not a valid IPv4 address", targetIPStr)
	}

	handle, err := pcap.OpenLive(iface.Name, 128, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("could not open pcap handle for operation: %w", err)
	}
	defer handle.Close()

	log.Println("Step 1: resolving the target's real MAC address to confirm it is online...")
	realTargetMAC, err := r.getMacForIPWithHandle(handle, targetIP)
	if err != nil {
		return fmt.Errorf("target %s did not reply to a standard ARP request. Cannot continue. Error: %w", targetIP, err)
	}
	log.Printf("-> Real MAC resolved: %s. Target is online.", realTargetMAC)

	log.Println("Step 2: sending ARP probe with incorrect destination MAC...")

	fakeDstMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	if bytes.Equal(fakeDstMAC, realTargetMAC) {
		fakeDstMAC, _ = net.ParseMAC("00:11:22:33:44:66")
	}

	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       fakeDstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(targetIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(targetIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return fmt.Errorf("error serializing probe packet: %w", err)
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return fmt.Errorf("error sending probe packet: %w", err)
	}
	log.Printf("Packet sent to %s (Ethernet Dst: %s).", targetIP, fakeDstMAC)

	log.Println("Step 3: listening for a possible response (timeout 5s)...")
	bpfFilter := fmt.Sprintf("arp and src host %s", targetIP.String())
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return fmt.Errorf("could not set BPF filter: %w", err)
	}

	// --- INICIO DEL BLOQUE LÓGICO CORREGIDO ---
	// Usamos un contexto para manejar el timeout de forma limpia.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	arpReplyChan := make(chan *layers.ARP)

	// Lanzamos la escucha de paquetes en una goroutine separada.
	go func() {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-ctx.Done(): // Si el contexto termina, la goroutine finaliza limpiamente.
				return
			case packet, ok := <-packetSource.Packets():
				if !ok {
					return // El canal de paquetes se cerró.
				}
				arpLayer := packet.Layer(layers.LayerTypeARP)
				if arpLayer == nil {
					continue
				}
				arp, _ := arpLayer.(*layers.ARP)
				if arp.Operation == layers.ARPReply {
					arpReplyChan <- arp // Enviamos el resultado y terminamos.
					return
				}
			}
		}
	}()

	// La función principal espera una respuesta o a que se cumpla el timeout.
	select {
	case <-arpReplyChan:
		detectedColor := color.New(color.FgHiRed, color.Bold).SprintFunc()
		log.Printf("\nVERDICT: %s - ARP reply received. Host %s (%s) is in PROMISCUOUS MODE.",
			detectedColor("DETECTED"), targetIP, realTargetMAC)
	case <-ctx.Done():
		notDetectedColor := color.New(color.FgHiGreen).SprintFunc()
		log.Printf("\nVERDICT: %s - No reply received. Host %s (%s) appears to operate in NORMAL MODE.",
			notDetectedColor("NOT DETECTED"), targetIP, realTargetMAC)
	}

	// --- FIN DEL BLOQUE LÓGICO CORREGIDO ---

	return nil
}
