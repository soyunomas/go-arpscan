// internal/network/arpframe.go
//
// Constructor y mutador del frame ARP estático de 60 bytes (mínimo Ethernet
// con padding). En el hot-path **solo se mutan 4 bytes** (target IP en
// offset [38..42]) — el resto del frame es inmutable durante el escaneo.
//
// *[Reglas 9, 10, 19, 31, 89]* — Cero allocations, cero serialización.
package network

import (
	"encoding/binary"
	"errors"
	"net"
)

// Tamaño mínimo de un frame Ethernet (incluye 14 bytes header + 46 bytes payload
// para llegar al mínimo de 60 bytes en cable, sin contar FCS).
const ARPFrameLen = 60

// Offsets dentro del frame Ethernet+ARP:
//
//	[0:6]   dst MAC      (broadcast por defecto)
//	[6:12]  src MAC      (MAC de la interfaz)
//	[12:14] ethertype    = 0x0806 (ARP)
//	[14:16] htype        = 0x0001 (Ethernet)
//	[16:18] ptype        = 0x0800 (IPv4)
//	[18]    hlen         = 6
//	[19]    plen         = 4
//	[20:22] opcode       = 0x0001 (Request)
//	[22:28] sender HW    = MAC de la interfaz
//	[28:32] sender IP    = IP de la interfaz (uint32 BE)
//	[32:38] target HW    = 00:00:00:00:00:00
//	[38:42] target IP    ◀── ÚNICO CAMPO MUTABLE EN EL HOT PATH
//	[42:60] padding      = ceros
const (
	OffEthDst  = 0
	OffEthSrc  = 6
	OffEthType = 12
	OffArpHrd  = 14
	OffArpPro  = 16
	OffArpHln  = 18
	OffArpPln  = 19
	OffArpOp   = 20
	OffArpSHA  = 22
	OffArpSPA  = 28
	OffArpTHA  = 32
	OffArpTPA  = 38
	// 42..60 padding
)

// BuildARPFrame inicializa un frame ARP Request listo para enviarse a través
// de un socket AF_PACKET. Solo el offset [38..42] (target IP) deberá mutarse
// en el bucle caliente vía SetTargetIP.
//
// dstMAC: típicamente broadcast (ff:ff:ff:ff:ff:ff). Si nil, se usa broadcast.
// srcMAC: MAC de la interfaz (6 bytes obligatorios).
// srcIP:  IP de origen ARP (sender protocol address) en formato 4 bytes.
// tha:    target HW addr (6 bytes). Si nil, se usa 00:00:00:00:00:00.
// opcode: 1 = ARP Request, 2 = ARP Reply.
//
// Devuelve un [ARPFrameLen]byte por valor: el caller es libre de copiarlo a
// stack o de almacenarlo en una variable global por-worker.
func BuildARPFrame(dstMAC, srcMAC net.HardwareAddr, srcIP net.IP, tha net.HardwareAddr, opcode uint16) ([ARPFrameLen]byte, error) {
	var f [ARPFrameLen]byte

	if len(srcMAC) != 6 {
		return f, errors.New("BuildARPFrame: srcMAC must have 6 bytes")
	}
	src4 := srcIP.To4()
	if src4 == nil {
		return f, errors.New("BuildARPFrame: srcIP must be IPv4")
	}

	// Eth dst
	if len(dstMAC) == 6 {
		copy(f[OffEthDst:OffEthDst+6], dstMAC)
	} else {
		f[0], f[1], f[2], f[3], f[4], f[5] = 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	}
	// Eth src
	copy(f[OffEthSrc:OffEthSrc+6], srcMAC)
	// EtherType = ARP
	binary.BigEndian.PutUint16(f[OffEthType:], 0x0806)
	// ARP hardware type = Ethernet
	binary.BigEndian.PutUint16(f[OffArpHrd:], 0x0001)
	// ARP protocol type = IPv4
	binary.BigEndian.PutUint16(f[OffArpPro:], 0x0800)
	// ARP HLEN/PLEN
	f[OffArpHln] = 6
	f[OffArpPln] = 4
	// ARP opcode
	binary.BigEndian.PutUint16(f[OffArpOp:], opcode)
	// ARP SHA = MAC de la interfaz
	copy(f[OffArpSHA:OffArpSHA+6], srcMAC)
	// ARP SPA = IP de la interfaz
	copy(f[OffArpSPA:OffArpSPA+4], src4)
	// ARP THA
	if len(tha) == 6 {
		copy(f[OffArpTHA:OffArpTHA+6], tha)
	} // else: ya es 0:0:0:0:0:0
	// ARP TPA: se rellenará por iteración con SetTargetIP.
	// Padding [42..60]: ya está a cero por ser zero-value.
	return f, nil
}

// SetTargetIP muta los 4 bytes de target IP (offset 38..42) del frame.
// Es la ÚNICA escritura por iteración en el hot-path.
//
// El compilador convierte el binary.BigEndian.PutUint32 sobre un slice de
// longitud constante en una secuencia de MOVs sin bounds check (BCE) cuando
// el array es de tamaño fijo y el offset es constante *[Reglas 21, 31, 88]*.
//
//go:nosplit
//go:inline
func SetTargetIP(frame *[ARPFrameLen]byte, targetIPBE uint32) {
	// Hint BCE: indica al compilador que el slice tiene al menos 4 bytes
	// a partir de OffArpTPA. Es un array de tamaño fijo, así que el compilador
	// elimina el bounds check de la siguiente línea.
	_ = frame[OffArpTPA+3]
	binary.BigEndian.PutUint32(frame[OffArpTPA:OffArpTPA+4], targetIPBE)
}

// IPv4ToBE convierte una net.IP IPv4 a uint32 big-endian.
// El uint32 resultante puede pasarse directamente a SetTargetIP.
//
// *[Regla 29]* — En el motor interno trabajamos con uint32, no con net.IP.
//
//go:nosplit
func IPv4ToBE(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(v4), true
}

// BEToIPv4 reconstruye una net.IP a partir de un uint32 big-endian.
// Solo se usa en cold-path (formato de salida).
func BEToIPv4(u uint32) net.IP {
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}
