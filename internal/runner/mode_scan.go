// internal/runner/mode_scan.go
package runner

import (
	"fmt" // <<< IMPORT AÑADIDO
	"go-arpscan/internal/formatter"
	"go-arpscan/internal/scanner"
	"log"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/schollz/progressbar/v3"
)

// AnalyzedResults contiene los resultados del escaneo junto con los resúmenes de análisis.
type AnalyzedResults struct {
	Results           []scanner.ScanResult
	ConflictSummaries []string
	MultiIPSummaries  []string
}

// analysisSummaries es una estructura interna para pasar los resúmenes.
type analysisSummaries struct {
	ConflictSummaries []string
	MultiIPSummaries  []string
}

// runScanMode es el punto de entrada para la lógica de escaneo estándar.
func (r *Runner) runScanMode() error {
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
			if err := r.saveStateToFile(allResults, r.cfg.StateFilePath); err != nil {
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

// processResults consume el canal de resultados, realiza el análisis en tiempo real
// y llama a una función de callback para cada resultado procesado.
func processResults(resultsChan <-chan scanner.ScanResult, ignoreDups bool, verboseCount int, resultCallback func(scanner.ScanResult)) analysisSummaries {
	seenIPs := make(map[string]string)
	seenMACs := make(map[string][]string)
	var conflictSummaries []string

	for result := range resultsChan {
		if previousMAC, found := seenIPs[result.IP]; found {
			if ignoreDups {
				if verboseCount >= 1 {
					log.Printf("Respuesta duplicada/conflicto para %s (%s) ignorada.", result.IP, result.MAC)
				}
				continue
			}
			if previousMAC != result.MAC {
				result.Status = "(CONFLICT)"
				summary := fmt.Sprintf("%s está en uso por %s y %s", result.IP, previousMAC, result.MAC)
				conflictSummaries = append(conflictSummaries, summary)
			} else {
				result.Status = "(DUPLICATE)"
			}
		} else {
			seenIPs[result.IP] = result.MAC
		}

		ipsForMAC := seenMACs[result.MAC]
		isNewIPForThisMAC := true
		for _, seenIP := range ipsForMAC {
			if seenIP == result.IP {
				isNewIPForThisMAC = false
				break
			}
		}
		if isNewIPForThisMAC {
			seenMACs[result.MAC] = append(ipsForMAC, result.IP)
			if len(seenMACs[result.MAC]) > 1 && result.Status == "" {
				result.Status = "(Multi-IP)"
			}
		}

		resultCallback(result)
	}

	var multiIPSummaries []string
	for mac, seenIPsForMac := range seenMACs {
		if len(seenIPsForMac) > 1 {
			summary := fmt.Sprintf("MAC %s responde para múltiples IPs: %s", mac, strings.Join(seenIPsForMac, ", "))
			multiIPSummaries = append(multiIPSummaries, summary)
		}
	}

	return analysisSummaries{
		ConflictSummaries: conflictSummaries,
		MultiIPSummaries:  multiIPSummaries,
	}
}
