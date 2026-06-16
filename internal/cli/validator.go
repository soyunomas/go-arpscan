// internal/cli/validator.go
package cli

import (
	"fmt"
	"go-arpscan/internal/config"
	"strconv"
	"strings"
)

// ValidateFlags realiza una serie de comprobaciones sobre la configuración
// resuelta para asegurar que las combinaciones de flags son válidas.
func ValidateFlags(cfg *config.ResolvedConfig, args []string) error {
	if cfg.UpdateVendors {
		if cfg.UseLocalnet || cfg.FilePath != "" || len(args) > 0 {
			return fmt.Errorf("--update-vendors cannot be combined with --localnet, --file, or command-line targets")
		}
		if cfg.SpoofTargetIP != "" || cfg.GatewayIP != "" || cfg.DetectPromiscTargetIP != "" || cfg.MonitorMode || cfg.DiffMode {
			return fmt.Errorf("--update-vendors is exclusive and cannot be combined with scan, spoofing, monitor, or diff modes")
		}
	}

	// Validar exclusividad de --localnet (alineado con arp-scan)
	if cfg.UseLocalnet {
		if cfg.FilePath != "" {
			return fmt.Errorf("--localnet cannot be combined with --file")
		}
		if len(args) > 0 {
			return fmt.Errorf("--localnet cannot be combined with command-line targets")
		}
	}

	// Validar modo de suplantación (--spoof)
	inSpoofMode := cfg.SpoofTargetIP != "" || cfg.GatewayIP != ""
	if inSpoofMode {
		if cfg.SpoofTargetIP == "" || cfg.GatewayIP == "" {
			return fmt.Errorf("--spoof and --gateway must be used together")
		}
		// El modo Spoof es exclusivo y no se puede combinar con modos de escaneo.
		if cfg.UseLocalnet || cfg.FilePath != "" || len(args) > 0 {
			return fmt.Errorf("--spoof cannot be combined with --localnet, --file, or command-line targets")
		}
		if cfg.DiffMode {
			return fmt.Errorf("--spoof cannot be combined with --diff")
		}
		if cfg.MonitorMode {
			return fmt.Errorf("--spoof cannot be combined with --monitor")
		}
	}

	// Validar modo de detección promiscuo (--detect-promisc)
	if cfg.DetectPromiscTargetIP != "" {
		if cfg.UseLocalnet || cfg.FilePath != "" || len(args) > 0 {
			return fmt.Errorf("--detect-promisc cannot be combined with --localnet, --file, or command-line targets")
		}
		if cfg.SpoofTargetIP != "" || cfg.DiffMode || cfg.MonitorMode {
			return fmt.Errorf("--detect-promisc is exclusive and cannot be combined with --spoof, --diff, or --monitor")
		}
		if isAnyFormatFlagSet(cfg) {
			return fmt.Errorf("--detect-promisc is not compatible with output format flags")
		}
	}

	// Validar modo monitor (--monitor)
	if cfg.MonitorMode {
		if !cfg.UseLocalnet {
			return fmt.Errorf("--monitor requires --localnet to define the monitoring scope")
		}
		if cfg.FilePath != "" || len(args) > 0 {
			return fmt.Errorf("--monitor cannot be combined with --file or command-line targets")
		}
		if cfg.SpoofTargetIP != "" || cfg.DiffMode || cfg.StateFilePath != "" {
			return fmt.Errorf("--monitor is exclusive and cannot be combined with --spoof, --diff, or --state-file")
		}
		// El modo monitor tiene su propia salida JSON, no es compatible con otros formatos.
		if cfg.JSONOutput || cfg.CSVOutput || cfg.Plain || cfg.Quiet {
			return fmt.Errorf("--monitor is not compatible with output format flags (--json, --csv, etc.)")
		}
	}

	// <<< INICIO DE NUEVO BLOQUE DE VALIDACIÓN PARA DETECCIÓN DE SPOOFING >>>
	// Validar dependencias de la detección de suplantación ARP
	if cfg.DetectArpSpoofing {
		if !cfg.MonitorMode {
			return fmt.Errorf("--detect-arp-spoofing is only valid in --monitor mode")
		}
		if cfg.MonitorGatewayIP == "" {
			return fmt.Errorf("--detect-arp-spoofing requires a gateway IP specified with --monitor-gateway")
		}
	}
	if cfg.MonitorGatewayIP != "" && !cfg.DetectArpSpoofing {
		return fmt.Errorf("--monitor-gateway is only valid when --detect-arp-spoofing is used")
	}
	// <<< FIN DE NUEVO BLOQUE DE VALIDACIÓN >>>

	// Validar dependencias del webhook
	if (cfg.WebhookURL != "" || len(cfg.WebhookHeaders) > 0) && !cfg.MonitorMode {
		return fmt.Errorf("--webhook-url and --webhook-header are only valid in --monitor mode")
	}

	// Validar formatos de salida mutuamente excluyentes
	if countFormatFlags(cfg) > 1 {
		return fmt.Errorf("output format flags (--json, --csv, --quiet, --plain) are mutually exclusive")
	}

	// Validar dependencias del modo --diff
	if cfg.DiffMode {
		if cfg.StateFilePath == "" {
			return fmt.Errorf("--diff requires a state file specified with --state-file")
		}
		if countFormatFlags(cfg) > 0 {
			return fmt.Errorf("--diff cannot be combined with output format flags (--json, --csv, etc.)")
		}
	}

	// Validar rango de VLAN ID. -1 desactiva 802.1Q; 0 es válido
	// (priority-tagged frame), igual que arp-scan upstream.
	if cfg.VlanID != -1 && (cfg.VlanID < 0 || cfg.VlanID > 4095) {
		return fmt.Errorf("VLAN ID must be -1 (disabled) or between 0 and 4095")
	}

	return nil
}

// isAnyFormatFlagSet comprueba si se ha activado algún flag de formato de salida.
func isAnyFormatFlagSet(cfg *config.ResolvedConfig) bool {
	return cfg.JSONOutput || cfg.CSVOutput || cfg.Quiet || cfg.Plain
}

// countFormatFlags cuenta cuántos flags de formato de salida están activos.
func countFormatFlags(cfg *config.ResolvedConfig) int {
	count := 0
	if cfg.JSONOutput {
		count++
	}
	if cfg.CSVOutput {
		count++
	}
	if cfg.Quiet {
		count++
	}
	if cfg.Plain {
		count++
	}
	return count
}

// ParseBandwidth convierte un string como "1M" o "256k" a un valor int64 de bits por segundo.
func ParseBandwidth(bwStr string) (int64, error) {
	if bwStr == "" {
		return 0, nil // No es un error, simplemente no se estableció.
	}

	lowerBwStr := strings.ToLower(bwStr)
	var multiplier float64 = 1.0
	var numPart string

	if strings.HasSuffix(lowerBwStr, "g") {
		multiplier = 1e9
		numPart = strings.TrimSuffix(lowerBwStr, "g")
	} else if strings.HasSuffix(lowerBwStr, "m") {
		multiplier = 1e6
		numPart = strings.TrimSuffix(lowerBwStr, "m")
	} else if strings.HasSuffix(lowerBwStr, "k") {
		multiplier = 1e3
		numPart = strings.TrimSuffix(lowerBwStr, "k")
	} else {
		numPart = lowerBwStr
	}

	val, err := strconv.ParseFloat(numPart, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric part %q in bandwidth: %w", numPart, err)
	}

	bitsPerSecond := int64(val * multiplier)
	if bitsPerSecond < 0 {
		return 0, fmt.Errorf("bandwidth cannot be negative")
	}

	return bitsPerSecond, nil
}
