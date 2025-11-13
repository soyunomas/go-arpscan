// internal/runner/mode_diff.go
package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"go-arpscan/internal/formatter"
	"log"
	"os"

	"github.com/fatih/color"
)

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

	type hostInfo struct {
		MAC    string
		Vendor string
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
