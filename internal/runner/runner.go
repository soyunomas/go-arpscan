// internal/runner/runner.go
package runner

import (
	"errors"
	"fmt"
	"go-arpscan/internal/config"
	"go-arpscan/internal/scanner"
)

// Runner encapsula la lógica de ejecución de un escaneo.
type Runner struct {
	cfg        *config.ResolvedConfig
	args       []string
	scanConfig *scanner.Config
}

// New crea una nueva instancia de Runner, validando la configuración inicial.
func New(cfg *config.ResolvedConfig, args []string) (*Runner, error) {
	if cfg.UpdateVendors {
		return &Runner{cfg: cfg, args: args}, nil
	}

	// En modos exclusivos, no necesitamos la configuración completa del scanner, pero sí la interfaz.
	// buildScannerConfig se encarga de resolver la interfaz correctamente.
	scanCfg, err := buildScannerConfig(cfg, args)
	if err != nil {
		// Ignoramos el error de "no se especificaron objetivos" si estamos en un modo exclusivo.
		isExclusiveMode := cfg.SpoofTargetIP != "" || cfg.MonitorMode || cfg.DetectPromiscTargetIP != ""
		if !isExclusiveMode || !errors.Is(err, errNoTargets) {
			return nil, fmt.Errorf("failed to build application configuration: %w", err)
		}
	}

	return &Runner{
		cfg:        cfg,
		args:       args,
		scanConfig: scanCfg,
	}, nil
}

// Run ejecuta el flujo principal de la aplicación, delegando al modo de operación correcto.
func (r *Runner) Run() error {
	switch {
	case r.cfg.UpdateVendors:
		return r.runUpdateVendorsMode()
	case r.cfg.SpoofTargetIP != "":
		return r.runSpoofMode()
	case r.cfg.DetectPromiscTargetIP != "":
		return r.runDetectPromiscMode()
	case r.cfg.DiffMode:
		return r.runDiffMode()
	case r.cfg.MonitorMode:
		return r.runMonitorMode()
	default:
		// Modo de escaneo por defecto
		return r.runScanMode()
	}
}
