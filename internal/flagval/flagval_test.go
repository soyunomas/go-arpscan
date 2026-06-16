// internal/flagval/flagval_test.go
package flagval

import (
	"testing"
	"time"

	"github.com/spf13/pflag"
)

func TestMillisGrammar(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		// Gramática nativa Go (compatibilidad hacia atrás).
		{"500ms", 500 * time.Millisecond, false},
		{"1s", time.Second, false},
		{"2m", 2 * time.Minute, false},
		{"500us", 500 * time.Microsecond, false},
		// Gramática arp-scan: entero pelado = milisegundos.
		{"500", 500 * time.Millisecond, false},
		{"0", 0, false},
		{"1000", time.Second, false},
		{" 250 ", 250 * time.Millisecond, false},
		// Inválidos.
		{"abc", 0, true},
		{"500x", 0, true},
		{"-5", 0, true},
	}
	for _, c := range cases {
		v := NewMillis(0)
		err := v.Set(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Set(%q): expected error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("Set(%q): unexpected error: %v", c.in, err)
			continue
		}
		fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
		fs.Var(v, "host-timeout", "")
		if got := Get(fs, "host-timeout"); got != c.want {
			t.Errorf("Set(%q): got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIntervalGrammar(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		// Gramática nativa Go.
		{"1ms", time.Millisecond, false},
		{"500us", 500 * time.Microsecond, false},
		{"2s", 2 * time.Second, false},
		// Gramática arp-scan (str_to_interval): int=ms, u=µs, s=s.
		{"10", 10 * time.Millisecond, false},
		{"500u", 500 * time.Microsecond, false},
		{"500U", 500 * time.Microsecond, false},
		{"2S", 2 * time.Second, false},
		{"0", 0, false},
		// Inválidos: multiplicador desconocido / parte numérica inválida.
		{"10x", 0, true},
		{"abc", 0, true},
		{"u", 0, true},
	}
	for _, c := range cases {
		v := NewInterval(0)
		err := v.Set(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Set(%q): expected error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("Set(%q): unexpected error: %v", c.in, err)
			continue
		}
		fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
		fs.Var(v, "interval", "")
		if got := Get(fs, "interval"); got != c.want {
			t.Errorf("Set(%q): got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestDefaultsRendered(t *testing.T) {
	if got := NewMillis(500 * time.Millisecond).String(); got != "500ms" {
		t.Errorf("default host-timeout String() = %q, want 500ms", got)
	}
	if got := NewInterval(time.Millisecond).String(); got != "1ms" {
		t.Errorf("default interval String() = %q, want 1ms", got)
	}
}
