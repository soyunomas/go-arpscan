//go:build linux && amd64

package network

import (
	"testing"
	"unsafe"
)

// Tests de layout: si una versión de kernel cambia los offsets, queremos
// fallar inmediatamente y no corromper memoria silenciosamente.
//
// Referencia x86_64 (kernel >= 3.15):
//   sizeof(tpacket_req3)        = 28
//   sizeof(tpacket_req)         = 16
//   sizeof(tpacket_bd_ts)       = 8
//   sizeof(tpacket_hdr_v1)      = 40
//   sizeof(tpacket_block_desc)  = 48
//   sizeof(tpacket3_hdr)        = 48
//   sizeof(tpacket2_hdr)        = 32

func TestTPacketReqLayout(t *testing.T) {
	if got := unsafe.Sizeof(tpacketReq{}); got != 16 {
		t.Fatalf("tpacketReq size = %d, expected 16", got)
	}
}

func TestTPacketReq3Layout(t *testing.T) {
	if got := unsafe.Sizeof(tpacketReq3{}); got != 28 {
		t.Fatalf("tpacketReq3 size = %d, expected 28", got)
	}
}

func TestTPacketBdTsLayout(t *testing.T) {
	if got := unsafe.Sizeof(tpacketBdTs{}); got != 8 {
		t.Fatalf("tpacketBdTs size = %d, expected 8", got)
	}
}

func TestTPacketHdrV1Layout(t *testing.T) {
	if got := unsafe.Sizeof(tpacketHdrV1{}); got != 40 {
		t.Fatalf("tpacketHdrV1 size = %d, expected 40", got)
	}
	// Verificar offset de SeqNum (debe ser 16, alineado a 8).
	var v tpacketHdrV1
	if off := unsafe.Offsetof(v.SeqNum); off != 16 {
		t.Fatalf("SeqNum offset = %d, expected 16", off)
	}
}

func TestTPacketBlockDescLayout(t *testing.T) {
	if got := unsafe.Sizeof(tpacketBlockDesc{}); got != 48 {
		t.Fatalf("tpacketBlockDesc size = %d, expected 48", got)
	}
	// La unión bh1 empieza tras los dos uint32 (offset 8).
	var v tpacketBlockDesc
	if off := unsafe.Offsetof(v.Hdr); off != 8 {
		t.Fatalf("Hdr offset = %d, expected 8", off)
	}
}

func TestTPacket3HdrLayout(t *testing.T) {
	if got := unsafe.Sizeof(tpacket3Hdr{}); got != 48 {
		t.Fatalf("tpacket3Hdr size = %d, expected 48", got)
	}
	var v tpacket3Hdr
	// Offsets críticos del kernel:
	if off := unsafe.Offsetof(v.NextOffset); off != 0 {
		t.Fatalf("NextOffset offset = %d, expected 0", off)
	}
	if off := unsafe.Offsetof(v.Status); off != 20 {
		t.Fatalf("Status offset = %d, expected 20", off)
	}
	if off := unsafe.Offsetof(v.Mac); off != 24 {
		t.Fatalf("Mac offset = %d, expected 24", off)
	}
}

func TestTPacket2HdrLayout(t *testing.T) {
	if got := unsafe.Sizeof(tpacket2Hdr{}); got != 32 {
		t.Fatalf("tpacket2Hdr size = %d, expected 32", got)
	}
	var v tpacket2Hdr
	if off := unsafe.Offsetof(v.Status); off != 0 {
		t.Fatalf("Status offset = %d, expected 0", off)
	}
	if off := unsafe.Offsetof(v.Mac); off != 12 {
		t.Fatalf("Mac offset = %d, expected 12", off)
	}
	if off := unsafe.Offsetof(v.VlanTci); off != 24 {
		t.Fatalf("VlanTci offset = %d, expected 24", off)
	}
	if got := tpacket2HdrLen; got != 52 {
		t.Fatalf("tpacket2HdrLen = %d, expected 52", got)
	}
}
