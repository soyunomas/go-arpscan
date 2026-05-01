//go:build linux && amd64

package network

import (
	"testing"
	"unsafe"
)

// TestMmsghdrLayout: verifica que nuestra struct mmsghdr replica el ABI
// que espera el kernel Linux en x86_64. Si esto cambia entre versiones,
// el test salta inmediatamente y evitamos una corrupción silenciosa.
//
// Expected size on glibc x86_64:
//
//	sizeof(struct msghdr)  = 56
//	sizeof(struct mmsghdr) = 64 (msghdr + uint32 + 4B padding)
func TestMmsghdrLayout(t *testing.T) {
	if got := unsafe.Sizeof(mmsghdr{}); got != 64 {
		t.Fatalf("mmsghdr size = %d, expected 64", got)
	}
}

// TestTXBatcherInit: el batcher deja todos los slots con el template y
// SetTargetAt solo muta los 4 bytes objetivo.
func TestTXBatcherInit(t *testing.T) {
	srcMAC := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	srcIP := []byte{10, 0, 0, 1}
	tpl, err := BuildARPFrame(nil, srcMAC, srcIP, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	const cap = 8
	b := NewTXBatcher(-1, cap, tpl) // fd=-1, no enviaremos en este test

	if b.Cap() != cap {
		t.Fatalf("Cap=%d expected %d", b.Cap(), cap)
	}
	// Cada slot debe ser idéntico al template.
	for i := 0; i < cap; i++ {
		off := i * ARPFrameLen
		for j := 0; j < ARPFrameLen; j++ {
			if b.frames[off+j] != tpl[j] {
				t.Fatalf("slot %d byte %d: %02x != %02x", i, j, b.frames[off+j], tpl[j])
			}
		}
	}

	// SetTargetAt(3, 0xC0A8010A) → solo muta offsets 38..42 del slot 3.
	b.SetTargetAt(3, 0xC0A8010A)
	off := 3 * ARPFrameLen
	if b.frames[off+OffArpTPA] != 0xC0 ||
		b.frames[off+OffArpTPA+1] != 0xA8 ||
		b.frames[off+OffArpTPA+2] != 0x01 ||
		b.frames[off+OffArpTPA+3] != 0x0A {
		t.Fatalf("SetTargetAt did not write expected bytes")
	}
	// Resto del slot 3 intacto.
	for j := 0; j < ARPFrameLen; j++ {
		if j >= OffArpTPA && j < OffArpTPA+4 {
			continue
		}
		if b.frames[off+j] != tpl[j] {
			t.Fatalf("slot 3 byte %d corrupted: %02x != %02x", j, b.frames[off+j], tpl[j])
		}
	}
	// Otros slots intactos.
	for i := 0; i < cap; i++ {
		if i == 3 {
			continue
		}
		off := i * ARPFrameLen
		for j := 0; j < ARPFrameLen; j++ {
			if b.frames[off+j] != tpl[j] {
				t.Fatalf("slot %d (untouched) byte %d corrupted", i, j)
			}
		}
	}
}

// TestTXBatcherCompact: tras un Flush parcial, Compact debe mover los slots
// no-enviados al inicio para reciclarlos en el siguiente Flush.
func TestTXBatcherCompact(t *testing.T) {
	srcMAC := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	srcIP := []byte{10, 0, 0, 1}
	tpl, err := BuildARPFrame(nil, srcMAC, srcIP, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	const cap = 8
	b := NewTXBatcher(-1, cap, tpl)

	// Cargamos 8 slots con IPs distintas (0x0A000001 .. 0x0A000008).
	for i := 0; i < cap; i++ {
		b.SetTargetAt(i, 0x0A000001+uint32(i))
	}

	// Simulamos un Flush parcial donde el kernel aceptó 3 slots → quedan
	// pendientes [3..8). Compact los mueve a [0..5).
	b.Compact(3, 8)

	for i := 0; i < 5; i++ {
		off := i*ARPFrameLen + OffArpTPA
		got := uint32(b.frames[off])<<24 |
			uint32(b.frames[off+1])<<16 |
			uint32(b.frames[off+2])<<8 |
			uint32(b.frames[off+3])
		want := uint32(0x0A000001 + 3 + i)
		if got != want {
			t.Fatalf("slot %d after Compact: got %08x, want %08x", i, got, want)
		}
	}

	// Compact con from=0 o from>=to no hace nada (no panic).
	b.Compact(0, 5)
	b.Compact(5, 5)
	b.Compact(6, 4)
}

// BenchmarkSetTargetAt: hot-path real del batcher. Debe ser 0 allocs/op.
func BenchmarkSetTargetAt(b *testing.B) {
	srcMAC := []byte{1, 2, 3, 4, 5, 6}
	srcIP := []byte{10, 0, 0, 1}
	tpl, _ := BuildARPFrame(nil, srcMAC, srcIP, nil, 1)
	bx := NewTXBatcher(-1, 32, tpl)

	b.ReportAllocs()
	b.ResetTimer()
	var ip uint32 = 0x0A000001
	for i := 0; i < b.N; i++ {
		bx.SetTargetAt(int(uint(i)&31), ip)
		ip++
	}
}
