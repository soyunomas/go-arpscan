// internal/flagval/flagval.go
//
// Tipos pflag.Value que alinean la gramática de entrada de --host-timeout/-t
// y --interval/-i con la del arp-scan original, SIN perder la sintaxis nativa
// de Go (time.Duration) ni romper la configuración YAML (que sigue usando
// duraciones estilo Go, p.ej. "500ms").
//
// Es un paquete hoja (solo depende de pflag + stdlib) para evitar el ciclo
// internal/config → internal/cli → internal/config: lo importan tanto el
// paquete main (registro de flags) como internal/config (lectura del valor).
package flagval

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

// arpMillisDuration acepta:
//   - una duración Go válida (p.ej. "500ms", "1s")  → se usa tal cual.
//   - un entero sin signo                            → se interpreta como
//     milisegundos, igual que arp-scan (`--timeout=<i>`, Strtoul base 10, ms).
type arpMillisDuration struct {
	d time.Duration
}

// Set implementa pflag.Value.
func (v *arpMillisDuration) Set(s string) error {
	s = strings.TrimSpace(s)
	// Ruta nativa Go (mantiene compatibilidad: 500ms, 1s, 2m…).
	if d, err := time.ParseDuration(s); err == nil {
		v.d = d
		return nil
	}
	// Ruta arp-scan: entero pelado = milisegundos.
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timeout %q: use a Go duration (e.g. 500ms, 1s) or an integer of milliseconds (e.g. 500)", s)
	}
	v.d = time.Duration(n) * time.Millisecond
	return nil
}

// Type implementa pflag.Value (se muestra en la ayuda).
func (v *arpMillisDuration) Type() string { return "duration" }

// String implementa pflag.Value (renderiza el valor/por defecto).
func (v *arpMillisDuration) String() string { return v.d.String() }

// arpInterval acepta:
//   - una duración Go válida (p.ej. "1ms", "500us")  → se usa tal cual.
//   - la gramática str_to_interval() de arp-scan:
//     entero pelado = ms, sufijo 'u'/'U' = µs, sufijo 's'/'S' = s.
type arpInterval struct {
	d time.Duration
}

// Set implementa pflag.Value.
func (v *arpInterval) Set(s string) error {
	s = strings.TrimSpace(s)
	// Ruta nativa Go (mantiene compatibilidad: 1ms, 500us, 2s…).
	if d, err := time.ParseDuration(s); err == nil {
		v.d = d
		return nil
	}
	if s == "" {
		return fmt.Errorf("invalid interval %q: empty value", s)
	}
	// Ruta arp-scan (str_to_interval, utils.c).
	mult := time.Millisecond
	numStr := s
	last := s[len(s)-1]
	if last < '0' || last > '9' {
		switch last {
		case 'u', 'U':
			mult = time.Microsecond
		case 's', 'S':
			mult = time.Second
		default:
			return fmt.Errorf("invalid interval %q: unknown multiplier %q (use a Go duration, an integer of ms, or suffix u=µs / s=s)", s, string(last))
		}
		numStr = strings.TrimSpace(s[:len(s)-1])
	}
	n, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid interval %q: numeric part must be an unsigned integer", s)
	}
	v.d = time.Duration(n) * mult
	return nil
}

// Type implementa pflag.Value.
func (v *arpInterval) Type() string { return "duration" }

// String implementa pflag.Value.
func (v *arpInterval) String() string { return v.d.String() }

// NewMillis crea un pflag.Value para --host-timeout/-t con la duración por
// defecto indicada.
func NewMillis(def time.Duration) pflag.Value { return &arpMillisDuration{d: def} }

// NewInterval crea un pflag.Value para --interval/-i con la duración por
// defecto indicada.
func NewInterval(def time.Duration) pflag.Value { return &arpInterval{d: def} }

// Get lee la time.Duration de un flag registrado con NewMillis/NewInterval.
// Si el flag no existe o no es de estos tipos, cae a ParseDuration sobre su
// representación textual (defensa; no debería ocurrir en uso normal).
func Get(fs *pflag.FlagSet, name string) time.Duration {
	f := fs.Lookup(name)
	if f == nil {
		return 0
	}
	switch v := f.Value.(type) {
	case *arpMillisDuration:
		return v.d
	case *arpInterval:
		return v.d
	default:
		d, _ := time.ParseDuration(f.Value.String())
		return d
	}
}
