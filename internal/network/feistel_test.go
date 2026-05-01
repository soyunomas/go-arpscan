package network

import "testing"

// TestFeistelBijection verifica que para varios tamaños comunes de subred,
// recorrer Encrypt(0..size-1) produce exactamente todos los valores de
// [0, size) sin repetidos ni huecos. Esto es crítico: si el Feistel no es
// biyectivo, el escáner se saltaría IPs o duplicaría tráfico.
func TestFeistelBijection(t *testing.T) {
	for _, bits := range []uint8{1, 2, 4, 8, 12, 16, 20} {
		size := uint32(1) << bits
		f := NewFeistel(0xDEADBEEF, bits)
		seen := make([]bool, size)
		for i := uint32(0); i < size; i++ {
			out := f.Encrypt(i)
			if out >= size {
				t.Fatalf("bits=%d: Encrypt(%d)=%d out of range [0,%d)", bits, i, out, size)
			}
			if seen[out] {
				t.Fatalf("bits=%d: collision in Encrypt(%d)=%d", bits, i, out)
			}
			seen[out] = true
		}
	}
}

// TestFeistelDeterminismo: misma seed → misma permutación.
func TestFeistelDeterminismo(t *testing.T) {
	f1 := NewFeistel(42, 8)
	f2 := NewFeistel(42, 8)
	for i := uint32(0); i < 256; i++ {
		if f1.Encrypt(i) != f2.Encrypt(i) {
			t.Fatalf("non-deterministic at i=%d", i)
		}
	}
}

// TestARPFrame: el frame estático tiene los bytes correctos en los offsets
// críticos del estándar RFC 826 *[Regla 100]*.
func TestARPFrame(t *testing.T) {
	srcMAC := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	srcIP := []byte{192, 168, 1, 10}
	f, err := BuildARPFrame(nil, srcMAC, srcIP, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Eth dst = broadcast
	for i := 0; i < 6; i++ {
		if f[i] != 0xff {
			t.Fatalf("dst MAC[%d] != 0xff", i)
		}
	}
	// EtherType = 0x0806
	if f[12] != 0x08 || f[13] != 0x06 {
		t.Fatalf("incorrect ethertype: %02x%02x", f[12], f[13])
	}
	// Hardware type = 1
	if f[14] != 0x00 || f[15] != 0x01 {
		t.Fatalf("incorrect hardware type")
	}
	// Protocol type = 0x0800
	if f[16] != 0x08 || f[17] != 0x00 {
		t.Fatalf("incorrect protocol type")
	}
	if f[18] != 6 || f[19] != 4 {
		t.Fatalf("incorrect hlen/plen")
	}
	// Opcode = 1 (Request)
	if f[20] != 0 || f[21] != 1 {
		t.Fatalf("incorrect opcode")
	}
	// SHA = srcMAC
	for i := 0; i < 6; i++ {
		if f[OffArpSHA+i] != srcMAC[i] {
			t.Fatalf("incorrect SHA[%d]", i)
		}
	}
	// SPA = srcIP
	for i := 0; i < 4; i++ {
		if f[OffArpSPA+i] != srcIP[i] {
			t.Fatalf("incorrect SPA[%d]", i)
		}
	}
	// THA = 0
	for i := 0; i < 6; i++ {
		if f[OffArpTHA+i] != 0 {
			t.Fatalf("THA[%d] != 0", i)
		}
	}

	// SetTargetIP muta exactamente los 4 bytes [38..42].
	SetTargetIP(&f, 0xC0A80114) // 192.168.1.20
	if f[38] != 0xC0 || f[39] != 0xA8 || f[40] != 0x01 || f[41] != 0x14 {
		t.Fatalf("SetTargetIP did not write expected bytes: %02x %02x %02x %02x",
			f[38], f[39], f[40], f[41])
	}
	// Padding intacto
	for i := 42; i < 60; i++ {
		if f[i] != 0 {
			t.Fatalf("padding[%d] != 0", i-42)
		}
	}
}

// BenchmarkSetTargetIP debe ser 0 allocs/op y nanosegundos por op.
// *[Regla 16, 93]*: el hot-path no asigna.
func BenchmarkSetTargetIP(b *testing.B) {
	srcMAC := []byte{1, 2, 3, 4, 5, 6}
	srcIP := []byte{10, 0, 0, 1}
	frame, _ := BuildARPFrame(nil, srcMAC, srcIP, nil, 1)
	b.ReportAllocs()
	b.ResetTimer()
	var ip uint32 = 0x0A000001
	for i := 0; i < b.N; i++ {
		SetTargetIP(&frame, ip)
		ip++
	}
}

// BenchmarkFeistel: O(1) por IP, zero-alloc.
func BenchmarkFeistel(b *testing.B) {
	f := NewFeistel(0xCAFEBABE, 16)
	b.ReportAllocs()
	b.ResetTimer()
	var sink uint32
	for i := 0; i < b.N; i++ {
		sink ^= f.Encrypt(uint32(i))
	}
	_ = sink
}
