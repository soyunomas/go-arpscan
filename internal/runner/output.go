// internal/runner/output.go
package runner

import (
	"encoding/json"
	"fmt"
	"go-arpscan/internal/config"
	"go-arpscan/internal/formatter"
	"go-arpscan/internal/scanner"
	"log"
	"os"
)

func (r *Runner) saveStateToFile(analyzed *AnalyzedResults, filePath string) error {
	output := formatter.JSONOutput{}
	output.Summary.Conflicts = analyzed.ConflictSummaries
	output.Summary.MultiIP = analyzed.MultiIPSummaries
	output.Results = make([]formatter.JSONResult, len(analyzed.Results))

	for i, res := range analyzed.Results {
		output.Results[i] = formatter.JSONResult{
			IP:     res.IP,
			MAC:    res.MAC,
			RTTms:  res.RTT.Milliseconds(),
			Vendor: res.Vendor,
			Status: res.Status,
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
		// Este caso es para cuando --progress está activado sin otro formato de salida.
		// El formateador por defecto se usa para imprimir la tabla final.
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
