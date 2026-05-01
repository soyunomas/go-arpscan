//go:build !linux

// internal/scanner/fastscan_other.go
//
// Stubs para plataformas no-Linux. El motor rápido depende de AF_PACKET
// + SO_ATTACH_FILTER (Linux puro). En BSD/macOS la ruta zero-copy
// equivalente sería BPF + bpf_zerocopy (Fase futura).
package scanner

// FastEligible: en plataformas no soportadas, siempre falso → fallback.
func FastEligible(cfg *Config) bool { return false }

// StartFastScan: nunca debe ser invocado fuera de Linux; protegido por
// FastEligible. Devolvemos error explícito por seguridad.
func StartFastScan(cfg *Config) (<-chan ScanResult, error) {
	return nil, errFastUnsupported
}
