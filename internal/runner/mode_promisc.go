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
	log.Printf("Iniciando detección de modo promiscuo contra %s en la interfaz %s", targetIPStr, iface.Name)

	targetIP := net.ParseIP(targetIPStr)
	if targetIP == nil || targetIP.To4() == nil {
		return fmt.Errorf("la IP objetivo '%s' no es una dirección IPv4 válida", targetIPStr)
	}

	handle, err := pcap.OpenLive(iface.Name, 128, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("no se pudo abrir el handle de pcap para la operación: %w", err)
	}
	defer handle.Close()

	log.Println("Paso 1: Obteniendo la dirección MAC real del objetivo para confirmar que está en línea...")
	realTargetMAC, err := r.getMacForIPWithHandle(handle, targetIP)
	if err != nil {
		return fmt.Errorf("el objetivo %s no respondió a un ARP request estándar. No se puede continuar. Error: %w", targetIP, err)
	}
	log.Printf("-> MAC real obtenida: %s. El objetivo está activo.", realTargetMAC)

	log.Println("Paso 2: Enviando paquete ARP de sondeo con MAC de destino incorrecta...")

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
		return fmt.Errorf("error serializando el paquete de sondeo: %w", err)
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return fmt.Errorf("error al enviar el paquete de sondeo: %w", err)
	}
	log.Printf("Paquete enviado a %s (Ethernet Dst: %s).", targetIP, fakeDstMAC)

	log.Println("Paso 3: Escuchando una posible respuesta (timeout 5s)...")
	bpfFilter := fmt.Sprintf("arp and src host %s", targetIP.String())
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return fmt.Errorf("no se pudo establecer el filtro BPF: %w", err)
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
		log.Printf("\nVEREDICTO: %s - Se recibió una respuesta ARP. El host %s (%s) está en MODO PROMISCUO.",
			detectedColor("¡DETECTADO!"), targetIP, realTargetMAC)
	case <-ctx.Done():
		notDetectedColor := color.New(color.FgHiGreen).SprintFunc()
		log.Printf("\nVEREDICTO: %s - No se recibió respuesta. El host %s (%s) parece operar en MODO NORMAL.",
			notDetectedColor("NO DETECTADO"), targetIP, realTargetMAC)
	}

	// --- FIN DEL BLOQUE LÓGICO CORREGIDO ---

	return nil
}
