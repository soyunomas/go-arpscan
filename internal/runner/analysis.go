// internal/runner/analysis.go
package runner

import (
	"fmt"
	"go-arpscan/internal/scanner"
	"log"
	"strings"
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
