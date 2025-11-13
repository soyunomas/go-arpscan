// internal/runner/mode_monitor.go
package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go-arpscan/internal/scanner"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket" // <<< IMPORT AÑADIDO
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// HostState representa el estado conocido de un host en el modo monitor.
type HostState int

const (
	HostStateActive   HostState = iota // El host ha sido visto recientemente.
	HostStateInactive                  // El host no respondió al último sondeo.
)

// monitorHostInfo almacena el estado completo de un host monitorizado.
type monitorHostInfo struct {
	MAC      string
	Vendor   string
	State    HostState
	LastSeen time.Time
}

// MonitorEvent define la estructura de un evento de red para la salida JSON.
type MonitorEvent struct {
	Timestamp string `json:"timestamp"`
	Event     string `json:"event"` // e.g., "NEW_HOST", "HOST_RETURNED", "HOST_INACTIVE", "IP_CONFLICT", "HOST_REMOVED"
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Vendor    string `json:"vendor"`
	Notes     string `json:"notes,omitempty"`
}

// dispatchEvent gestiona el envío de un evento tanto a la salida estándar como a un webhook.
func (r *Runner) dispatchEvent(event MonitorEvent) {
	// 1. Rellenar el timestamp
	event.Timestamp = time.Now().UTC().Format(time.RFC3339)

	// 2. Serializar a JSON y mostrar en la salida estándar
	jsonData, err := json.Marshal(event)
	if err != nil {
		log.Printf("Error al serializar el evento del monitor a JSON: %v", err)
		return
	}
	fmt.Println(string(jsonData))

	// 3. Enviar a webhook de forma asíncrona si está configurado
	if r.cfg.WebhookURL != "" {
		go r.sendWebhook(jsonData)
	}
}

// sendWebhook envía el payload de un evento a la URL configurada.
func (r *Runner) sendWebhook(payload []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.WebhookURL, bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("ADVERTENCIA (Webhook): Error creando la petición: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "go-arpscan-monitor")

	for _, h := range r.cfg.WebhookHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			req.Header.Set(key, value)
		} else {
			log.Printf("ADVERTENCIA (Webhook): Ignorando cabecera mal formada: %s", h)
		}
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("ADVERTENCIA (Webhook): Error enviando la petición a %s: %v", r.cfg.WebhookURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("ADVERTENCIA (Webhook): Respuesta no exitosa (código %d) de %s", resp.StatusCode, r.cfg.WebhookURL)
	}
}

// runMonitorMode es el punto de entrada para la lógica de monitorización continua.
func (r *Runner) runMonitorMode() error {
	log.Printf("Iniciando modo monitor en la interfaz %s. Presione Ctrl+C para salir.", r.scanConfig.Interface.Name)
	knownHosts := make(map[string]*monitorHostInfo) // Usamos punteros para poder modificar in-place.
	arpPackets := make(chan *layers.ARP)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Manejar Ctrl+C
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Println("\nSeñal de interrupción recibida. Finalizando el modo monitor...")
		cancel()
	}()

	// Iniciar la escucha pasiva
	go r.passiveARPListener(ctx, arpPackets)

	// Realizar un escaneo inicial para establecer la línea base
	log.Println("Realizando escaneo inicial para establecer la línea base de la red...")
	initialScan := r.runScanAndCollect()
	for _, result := range initialScan.Results {
		info := &monitorHostInfo{
			MAC:      result.MAC,
			Vendor:   result.Vendor,
			State:    HostStateActive,
			LastSeen: time.Now(),
		}
		knownHosts[result.IP] = info
		r.dispatchEvent(MonitorEvent{Event: "NEW_HOST", IP: result.IP, MAC: info.MAC, Vendor: info.Vendor})
	}
	log.Printf("Línea base establecida. %d hosts activos detectados. Iniciando monitorización continua.", len(knownHosts))

	ticker := time.NewTicker(r.cfg.MonitorInterval)
	defer ticker.Stop()

	// Bucle principal del monitor
	for {
		select {
		case <-ctx.Done():
			return nil

		case arpPacket := <-arpPackets:
			srcIP := net.IP(arpPacket.SourceProtAddress).String()
			srcMAC := net.HardwareAddr(arpPacket.SourceHwAddress).String()

			if knownInfo, ok := knownHosts[srcIP]; ok {
				// El host es conocido, actualizamos su estado.
				knownInfo.LastSeen = time.Now()
				if knownInfo.MAC != srcMAC {
					oldMAC := knownInfo.MAC
					knownInfo.MAC = srcMAC
					knownInfo.Vendor = r.scanConfig.VendorDB.Lookup(srcMAC)
					r.dispatchEvent(MonitorEvent{
						Event:  "IP_CONFLICT",
						IP:     srcIP,
						MAC:    knownInfo.MAC,
						Vendor: knownInfo.Vendor,
						Notes:  fmt.Sprintf("La MAC cambió de %s a %s (visto pasivamente).", oldMAC, srcMAC),
					})
				}
				if knownInfo.State == HostStateInactive {
					knownInfo.State = HostStateActive
					r.dispatchEvent(MonitorEvent{Event: "HOST_RETURNED", IP: srcIP, MAC: knownInfo.MAC, Vendor: knownInfo.Vendor, Notes: "Visto pasivamente."})
				}
			} else {
				// El host es completamente nuevo.
				info := &monitorHostInfo{
					MAC:      srcMAC,
					Vendor:   r.scanConfig.VendorDB.Lookup(srcMAC),
					State:    HostStateActive,
					LastSeen: time.Now(),
				}
				knownHosts[srcIP] = info
				r.dispatchEvent(MonitorEvent{Event: "NEW_HOST", IP: srcIP, MAC: info.MAC, Vendor: info.Vendor, Notes: "Detectado pasivamente."})
			}

		case <-ticker.C:
			log.Printf("Iniciando sondeo activo periódico (intervalo: %v)...", r.cfg.MonitorInterval)
			activeScan := r.runScanAndCollect()
			currentScanHosts := make(map[string]scanner.ScanResult)
			for _, result := range activeScan.Results {
				currentScanHosts[result.IP] = result
			}

			// Actualizar estado de hosts conocidos basado en el sondeo
			for ip, knownInfo := range knownHosts {
				if newInfo, responded := currentScanHosts[ip]; responded {
					knownInfo.LastSeen = time.Now()
					if knownInfo.MAC != newInfo.MAC {
						oldMAC := knownInfo.MAC
						knownInfo.MAC = newInfo.MAC
						knownInfo.Vendor = newInfo.Vendor
						r.dispatchEvent(MonitorEvent{
							Event:  "IP_CONFLICT",
							IP:     ip,
							MAC:    newInfo.MAC,
							Vendor: newInfo.Vendor,
							Notes:  fmt.Sprintf("La MAC cambió de %s a %s (detectado en sondeo activo).", oldMAC, newInfo.MAC),
						})
					}
					if knownInfo.State == HostStateInactive {
						knownInfo.State = HostStateActive
						r.dispatchEvent(MonitorEvent{Event: "HOST_RETURNED", IP: ip, MAC: knownInfo.MAC, Vendor: knownInfo.Vendor, Notes: "Respondió al sondeo activo."})
					}
				} else { // No respondió
					if knownInfo.State == HostStateActive {
						knownInfo.State = HostStateInactive
						r.dispatchEvent(MonitorEvent{Event: "HOST_INACTIVE", IP: ip, MAC: knownInfo.MAC, Vendor: knownInfo.Vendor, Notes: "No respondió al sondeo activo."})
					}
				}
			}

			// Purgar hosts que han estado inactivos demasiado tiempo
			for ip, knownInfo := range knownHosts {
				if knownInfo.State == HostStateInactive && time.Since(knownInfo.LastSeen) > r.cfg.MonitorRemovalThreshold {
					r.dispatchEvent(MonitorEvent{Event: "HOST_REMOVED", IP: ip, MAC: knownInfo.MAC, Vendor: knownInfo.Vendor, Notes: fmt.Sprintf("Inactivo durante más de %v.", r.cfg.MonitorRemovalThreshold)})
					delete(knownHosts, ip)
				}
			}

			// Añadir nuevos hosts descubiertos en el sondeo activo
			for ip, newInfo := range currentScanHosts {
				if _, isKnown := knownHosts[ip]; !isKnown {
					info := &monitorHostInfo{
						MAC:      newInfo.MAC,
						Vendor:   newInfo.Vendor,
						State:    HostStateActive,
						LastSeen: time.Now(),
					}
					knownHosts[ip] = info
					r.dispatchEvent(MonitorEvent{Event: "NEW_HOST", IP: ip, MAC: info.MAC, Vendor: info.Vendor, Notes: "Detectado en sondeo activo."})
				}
			}
			log.Println("Sondeo activo completado.")
		}
	}
}

// passiveARPListener escucha pasivamente el tráfico ARP y envía los paquetes a un canal.
func (r *Runner) passiveARPListener(ctx context.Context, arpChannel chan<- *layers.ARP) {
	handle, err := pcap.OpenLive(r.scanConfig.Interface.Name, 1, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Error crítico en listener pasivo: no se pudo abrir pcap: %v", err)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("arp"); err != nil {
		log.Printf("Error crítico en listener pasivo: no se pudo establecer filtro BPF: %v", err)
		return
	}

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

			// Ignorar paquetes ARP enviados por nuestra propia interfaz
			if bytes.Equal(arp.SourceHwAddress, r.scanConfig.Interface.HardwareAddr) {
				continue
			}

			// Enviar una copia para evitar condiciones de carrera si el buffer del paquete es reutilizado
			arpCopy := *arp
			arpChannel <- &arpCopy
		}
	}
}
