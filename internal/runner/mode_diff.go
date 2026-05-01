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
	log.Printf("DIFF mode: comparing current scan with state from %q", stateFile)

	stateContent, err := os.ReadFile(stateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("state file %q does not exist. Run a scan with --state-file first to create it", stateFile)
		}
		return fmt.Errorf("error reading state file %q: %w", stateFile, err)
	}

	var oldState formatter.JSONOutput
	if err := json.Unmarshal(stateContent, &oldState); err != nil {
		return fmt.Errorf("error parsing JSON state file %q: %w", stateFile, err)
	}

	type hostInfo struct {
		MAC    string
		Vendor string
	}

	oldStateMap := make(map[string]hostInfo)
	for _, res := range oldState.Results {
		oldStateMap[res.IP] = hostInfo{MAC: res.MAC, Vendor: res.Vendor}
	}

	log.Printf("Starting new scan for comparison...")
	allNewResults := r.runScanAndCollect()

	newStateMap := make(map[string]hostInfo)
	for _, res := range allNewResults.Results {
		newStateMap[res.IP] = hostInfo{MAC: res.MAC, Vendor: res.Vendor}
	}
	log.Println("Comparison scan completed. Analyzing differences...")

	addedColor := color.New(color.FgHiGreen).SprintFunc()
	removedColor := color.New(color.FgHiRed).SprintFunc()
	modifiedColor := color.New(color.FgHiYellow).SprintFunc()
	headerColor := color.New(color.Bold).SprintFunc()

	hasChanges := false

	for ip, newInfo := range newStateMap {
		if oldInfo, found := oldStateMap[ip]; !found {
			fmt.Printf("%s\t%s\t%s\t(%s)\n", addedColor("[+] ADDED:"), ip, newInfo.MAC, newInfo.Vendor)
			hasChanges = true
		} else {
			if newInfo.MAC != oldInfo.MAC {
				fmt.Printf("%s\t%s\n", modifiedColor("[~] MODIFIED:"), headerColor(ip))
				fmt.Printf("\t  %s %s (%s)\n", removedColor("- OLD MAC:"), oldInfo.MAC, oldInfo.Vendor)
				fmt.Printf("\t  %s %s (%s)\n", addedColor("+ NEW MAC:"), newInfo.MAC, newInfo.Vendor)
				hasChanges = true
			}
			delete(oldStateMap, ip)
		}
	}

	for ip, oldInfo := range oldStateMap {
		fmt.Printf("%s\t%s\t%s\t(%s)\n", removedColor("[-] REMOVED:"), ip, oldInfo.MAC, oldInfo.Vendor)
		hasChanges = true
	}

	if !hasChanges {
		log.Println("No network changes detected.")
	}
	return nil
}
