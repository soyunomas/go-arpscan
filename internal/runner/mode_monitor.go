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

	"github.com/google/gopacket"
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

// <<< INICIO: CONSTANTES Y STRUCT DE EVENTOS MEJORADAS >>>
const (
	EventNewHost             = "NEW_HOST"
	EventHostReturned        = "HOST_RETURNED"
	EventHostInactive        = "HOST_INACTIVE"
	EventIPConflict          = "IP_CONFLICT"
	EventHostRemoved         = "HOST_REMOVED"
	EventGatewaySpoofDetected = "GATEWAY_SPOOF_DETECTED"
)

// MonitorEvent define la estructura de un evento de red para la salida JSON.
type MonitorEvent struct {
	Timestamp     string `json:"timestamp"`
	Event         string `json:"event"`
	IP            string `json:"ip"`
	MAC           string `json:"mac"`
	Vendor        string `json:"vendor"`
	Notes         string `json:"notes,omitempty"`
	Severity      string `json:"severity,omitempty"`
	LegitimateMAC string `json:"legitimate_mac,omitempty"`
	AttackerMAC   string `json:"attacker_mac,omitempty"`
}

// <<< FIN: CONSTANTES Y STRUCT DE EVENTOS MEJORADAS >>>

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

	// <<< INICIO: VARIABLES PARA DETECCIÓN DE SPOOFING >>>
	var monitoredGatewayIP net.IP
	var monitoredGatewayMAC net.HardwareAddr
	// <<< FIN: VARIABLES PARA DETECCIÓN DE SPOOFING >>>

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
		r.dispatchEvent(MonitorEvent{Event: EventNewHost, IP: result.IP, MAC: info.MAC, Vendor: info.Vendor})
	}

	// <<< INICIO: LÓGICA DE LÍNEA BASE PARA EL GATEWAY >>>
	if r.cfg.DetectArpSpoofing {
		monitoredGatewayIP = net.ParseIP(r.cfg.MonitorGatewayIP)
		if gwInfo, found := knownHosts[r.cfg.MonitorGatewayIP]; found {
			var err error
			monitoredGatewayMAC, err = net.ParseMAC(gwInfo.MAC)
			if err != nil {
				log.Fatalf("Error crítico: no se pudo parsear la MAC del gateway '%s' durante la inicialización.", gwInfo.MAC)
			}
			log.Printf("Protección de suplantación ARP activada para el gateway %s -> %s", monitoredGatewayIP, monitoredGatewayMAC)
		} else {
			log.Fatalf("Error crítico: El gateway especificado %s no fue encontrado en el escaneo inicial. No se puede activar la protección.", r.cfg.MonitorGatewayIP)
		}
	}
	// <<< FIN: LÓGICA DE LÍNEA BASE PARA EL GATEWAY >>>

	log.Printf("Línea base establecida. %d hosts activos detectados. Iniciando monitorización continua.", len(knownHosts))

	ticker := time.NewTicker(r.cfg.MonitorInterval)
	defer ticker.Stop()

	// Bucle principal del monitor
	for {
		select {
		case <-ctx.Done():
			return nil

		case arpPacket := <-arpPackets:
			srcIP := net.IP(arpPacket.SourceProtAddress)
			srcIPStr := srcIP.String()
			srcMAC := net.HardwareAddr(arpPacket.SourceHwAddress)
			srcMACStr := srcMAC.String()

			// <<< INICIO: HEURÍSTICA DE DETECCIÓN PASIVA >>>
			if r.cfg.DetectArpSpoofing && monitoredGatewayIP.Equal(srcIP) && !bytes.Equal(monitoredGatewayMAC, srcMAC) {
				attackerVendor := r.scanConfig.VendorDB.Lookup(srcMACStr)
				r.dispatchEvent(MonitorEvent{
					Event:         EventGatewaySpoofDetected,
					Severity:      "CRITICAL",
					IP:            srcIPStr,
					MAC:           srcMACStr, // MAC del paquete, que es la del atacante
					Vendor:        attackerVendor,
					Notes:         "Se detectó un anuncio ARP pasivo para el gateway desde una MAC no autorizada.",
					LegitimateMAC: monitoredGatewayMAC.String(),
					AttackerMAC:   srcMACStr,
				})
				// Continuamos para que el host atacante (si es nuevo) también sea registrado.
			}
			// <<< FIN: HEURÍSTICA DE DETECCIÓN PASIVA >>>

			if knownInfo, ok := knownHosts[srcIPStr]; ok {
				// El host es conocido, actualizamos su estado.
				knownInfo.LastSeen = time.Now()
				if knownInfo.MAC != srcMACStr {
					oldMAC := knownInfo.MAC
					knownInfo.MAC = srcMACStr
					knownInfo.Vendor = r.scanConfig.VendorDB.Lookup(srcMACStr)
					r.dispatchEvent(MonitorEvent{
						Event:  EventIPConflict,
						IP:     srcIPStr,
						MAC:    knownInfo.MAC,
						Vendor: knownInfo.Vendor,
						Notes:  fmt.Sprintf("La MAC cambió de %s a %s (visto pasivamente).", oldMAC, srcMACStr),
					})
				}
				if knownInfo.State == HostStateInactive {
					knownInfo.State = HostStateActive
					r.dispatchEvent(MonitorEvent{Event: EventHostReturned, IP: srcIPStr, MAC: knownInfo.MAC, Vendor: knownInfo.Vendor, Notes: "Visto pasivamente."})
				}
			} else {
				// El host es completamente nuevo.
				info := &monitorHostInfo{
					MAC:      srcMACStr,
					Vendor:   r.scanConfig.VendorDB.Lookup(srcMACStr),
					State:    HostStateActive,
					LastSeen: time.Now(),
				}
				knownHosts[srcIPStr] = info
				r.dispatchEvent(MonitorEvent{Event: EventNewHost, IP: srcIPStr, MAC: info.MAC, Vendor: info.Vendor, Notes: "Detectado pasivamente."})
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
					// <<< INICIO: HEURÍSTICA DE DETECCIÓN ACTIVA >>>
					if r.cfg.DetectArpSpoofing && ip == monitoredGatewayIP.String() && knownInfo.MAC != newInfo.MAC {
						attackerVendor := r.scanConfig.VendorDB.Lookup(newInfo.MAC)
						r.dispatchEvent(MonitorEvent{
							Event:         EventGatewaySpoofDetected,
							Severity:      "CRITICAL",
							IP:            ip,
							MAC:           newInfo.MAC,
							Vendor:        attackerVendor,
							Notes:         "Se detectó una respuesta ARP del gateway desde una MAC no autorizada durante el sondeo activo.",
							LegitimateMAC: monitoredGatewayMAC.String(),
							AttackerMAC:   newInfo.MAC,
						})
						// No actualizamos la MAC del gateway en nuestro estado, mantenemos la legítima.
					}
					// <<< FIN: HEURÍSTICA DE DETECCIÓN ACTIVA >>>

					knownInfo.LastSeen = time.Now()
					if knownInfo.MAC != newInfo.MAC && ip != monitoredGatewayIP.String() { // Solo actualiza si no es el gateway protegido
						oldMAC := knownInfo.MAC
						knownInfo.MAC = newInfo.MAC
						knownInfo.Vendor = newInfo.Vendor
						r.dispatchEvent(MonitorEvent{
							Event:  EventIPConflict,
							IP:     ip,
							MAC:    newInfo.MAC,
							Vendor: newInfo.Vendor,
							Notes:  fmt.Sprintf("La MAC cambió de %s a %s (detectado en sondeo activo).", oldMAC, newInfo.MAC),
						})
					}
					if knownInfo.State == HostStateInactive {
						knownInfo.State = HostStateActive
						r.dispatchEvent(MonitorEvent{Event: EventHostReturned, IP: ip, MAC: knownInfo.MAC, Vendor: knownInfo.Vendor, Notes: "Respondió al sondeo activo."})
					}
				} else { // No respondió
					if knownInfo.State == HostStateActive {
						knownInfo.State = HostStateInactive
						r.dispatchEvent(MonitorEvent{Event: EventHostInactive, IP: ip, MAC: knownInfo.MAC, Vendor: knownInfo.Vendor, Notes: "No respondió al sondeo activo."})
					}
				}
			}

			// Purgar hosts que han estado inactivos demasiado tiempo
			for ip, knownInfo := range knownHosts {
				if knownInfo.State == HostStateInactive && time.Since(knownInfo.LastSeen) > r.cfg.MonitorRemovalThreshold {
					r.dispatchEvent(MonitorEvent{Event: EventHostRemoved, IP: ip, MAC: knownInfo.MAC, Vendor: knownInfo.Vendor, Notes: fmt.Sprintf("Inactivo durante más de %v.", r.cfg.MonitorRemovalThreshold)})
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
					r.dispatchEvent(MonitorEvent{Event: EventNewHost, IP: ip, MAC: info.MAC, Vendor: info.Vendor, Notes: "Detectado en sondeo activo."})
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
