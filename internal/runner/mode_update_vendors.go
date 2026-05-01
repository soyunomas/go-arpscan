package runner

import (
	"fmt"
	"go-arpscan/internal/oui"
	"log"
)

func (r *Runner) runUpdateVendorsMode() error {
	if r.cfg.OUIFilePath == "" {
		return fmt.Errorf("--update-vendors requires a valid OUI path")
	}
	if r.cfg.IABFilePath == "" {
		return fmt.Errorf("--update-vendors requires a valid IAB path")
	}

	if err := oui.UpdateVendorFiles(r.cfg.OUIFilePath, r.cfg.IABFilePath, ieeeOUIURL, ieeeIABURL, r.cfg.VerboseCount); err != nil {
		return err
	}

	log.Printf("Vendors updated: OUI=%s IAB=%s OUI_BIN=%s", r.cfg.OUIFilePath, r.cfg.IABFilePath, r.cfg.OUIFilePath+".bin")
	return nil
}
