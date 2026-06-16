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
		return fmt.Errorf("error generating JSON for state file: %w", err)
	}

	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return fmt.Errorf("error writing state file %q: %w", filePath, err)
	}

	log.Printf("Scan state saved successfully to %s", filePath)
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
	log.Printf("Starting scan on interface %s (%s)", scancfg.Interface.Name, scancfg.Interface.HardwareAddr)
	if scancfg.VlanID > 0 {
		log.Printf("Using VLAN tag: %d", scancfg.VlanID)
	}
	log.Printf("Targets to scan: %d IPs", len(scancfg.IPs))

	if scancfg.ArpSPADest {
		log.Println("Using dynamic source IP equal to target IP (--arpspa=dest).")
	} else if cfg.ArpSPA != "" {
		log.Printf("Using custom source IP (SPA) for all packets: %s", scancfg.ArpSPA)
	} else {
		log.Printf("Using interface source IP (SPA) for all packets: %s (default behavior).", scancfg.ArpSPA)
	}

	if cfg.ArpSHA != "" {
		log.Printf("Using custom source MAC (SHA) for all packets: %s", scancfg.ArpSHA)
	}
	if cfg.EthSrcMAC != "" {
		log.Printf("Using custom Ethernet frame source MAC for all packets: %s", scancfg.EthSrcMAC)
	}
	if cfg.EthPrototype != "0x0806" {
		log.Printf("Using custom Ethernet protocol type: %s", cfg.EthPrototype)
	}
	if cfg.ArpOpCode != 1 {
		opCodeName := "Request"
		if cfg.ArpOpCode == 2 {
			opCodeName = "Reply"
		}
		log.Printf("Using custom ARP operation code: %d (%s)", cfg.ArpOpCode, opCodeName)
	}
	if cfg.EthDstMAC != "" {
		log.Printf("Using custom Ethernet frame destination MAC for all packets: %s", scancfg.EthDstMAC)
	}
	if cfg.ArpTHA != "" {
		log.Printf("Using custom ARP destination MAC (THA) for all packets: %s", scancfg.ArpTHA)
	}
	if cfg.ArpHrd != 1 {
		log.Printf("Using custom ARP hardware type (ar$hrd): %d", scancfg.ArpHardwareType)
	}
	if cfg.ArpPro != "0x0800" {
		log.Printf("Using custom ARP protocol type (ar$pro): %s", cfg.ArpPro)
	}
	if cfg.ArpHln != 6 {
		log.Printf("Using custom ARP hardware address length (ar$hln): %d", scancfg.ArpHardwareLen)
	}
	if cfg.ArpPln != 4 {
		log.Printf("Using custom ARP protocol address length (ar$pln): %d", scancfg.ArpProtocolLen)
	}
	if cfg.PaddingHex != "" {
		log.Printf("Adding custom packet padding: %s", cfg.PaddingHex)
	}
	if cfg.UseLLC {
		log.Println("Using RFC 1042 LLC/SNAP framing for outgoing packets.")
	}
	if cfg.PcapSaveFile != "" {
		log.Printf("Saving ARP replies to pcap file: %s", cfg.PcapSaveFile)
	}
}

func isScriptingOutput(cfg *config.ResolvedConfig) bool {
	return cfg.JSONOutput || cfg.CSVOutput || cfg.Plain || cfg.Quiet
}
