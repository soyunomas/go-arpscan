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
	// Validar modo de suplantación (--spoof)
	inSpoofMode := cfg.SpoofTargetIP != "" || cfg.GatewayIP != ""
	if inSpoofMode {
		if cfg.SpoofTargetIP == "" || cfg.GatewayIP == "" {
			return fmt.Errorf("los flags --spoof y --gateway deben usarse juntos")
		}
		// El modo Spoof es exclusivo y no se puede combinar con modos de escaneo.
		if cfg.UseLocalnet || cfg.FilePath != "" || len(args) > 0 {
			return fmt.Errorf("el modo --spoof no se puede combinar con --localnet, --file o objetivos en la línea de comandos")
		}
		if cfg.DiffMode {
			return fmt.Errorf("el modo --spoof no se puede combinar con --diff")
		}
	}

	// Validar formatos de salida mutuamente excluyentes
	formatFlags := 0
	if cfg.JSONOutput {
		formatFlags++
	}
	if cfg.CSVOutput {
		formatFlags++
	}
	if cfg.Quiet {
		formatFlags++
	}
	if cfg.Plain {
		formatFlags++
	}
	if formatFlags > 1 {
		return fmt.Errorf("los flags de formato (--json, --csv, --quiet, --plain) son mutuamente excluyentes")
	}

	// Validar dependencias del modo --diff
	if cfg.DiffMode {
		if cfg.StateFilePath == "" {
			return fmt.Errorf("el modo --diff requiere que se especifique un fichero de estado con --state-file")
		}
		if formatFlags > 0 {
			return fmt.Errorf("el modo --diff no se puede combinar con otros flags de formato de salida (--json, --csv, etc.)")
		}
	}

	// Validar --bandwidth y --interval
	// Esta lógica es un poco más compleja porque necesitamos saber si los flags fueron
	// explícitamente seteados. Por ahora, asumimos que la lógica de carga ya ha manejado
	// la precedencia y podemos simplemente comprobar si ambos tienen valores no-default.
	// NOTA: Cobra no facilita saber si un flag se seteó desde un fichero de config vs linea de comandos.
	// La comprobación original en main.go era más precisa. La simplificaremos aquí por ahora.

	// Validar rango de VLAN ID
	if cfg.VlanID != 0 && (cfg.VlanID < 1 || cfg.VlanID > 4094) {
		return fmt.Errorf("el ID de VLAN debe estar entre 1 y 4094")
	}

	return nil
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
		return 0, fmt.Errorf("parte numérica '%s' inválida en el ancho de banda: %w", numPart, err)
	}

	bitsPerSecond := int64(val * multiplier)
	if bitsPerSecond < 0 {
		return 0, fmt.Errorf("el ancho de banda no puede ser negativo")
	}

	return bitsPerSecond, nil
}
