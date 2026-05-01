//go:build linux && amd64

// internal/network/txbatcher_linux.go
//
// Batcher de transmisión basado en sendmmsg(2). En lugar de hacer 1 syscall
// `sendto` por paquete (igual que arp-scan), enviamos N paquetes en una sola
// syscall. Esto es la diferencia operativa que nos permite SUPERAR a arp-scan
// en throughput puro.
//
// *[Reglas 5, 9, 10, 16, 19, 21]* — pre-asignamos N frames contiguos, mutamos
// solo los 4 bytes de target IP por slot, y hacemos UNA syscall por batch.
//
// La estructura mmsghdr no está expuesta en golang.org/x/sys/unix v0.29
// para esta plataforma; la declaramos aquí para amd64. (Si necesitamos otras
// arquitecturas en el futuro, replicaremos con build tags adicionales.)
package network

import (
	"encoding/binary"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// mmsghdr replica la struct mmsghdr de Linux (sys/socket.h):
//
//	struct mmsghdr {
//	    struct msghdr msg_hdr;
//	    unsigned int  msg_len;
//	};
//
// El padding de 4 bytes al final asegura que el array tenga el mismo stride
// que glibc espera (64 bytes por entrada en x86_64).
type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   [4]byte
}

// TXBatcher mantiene el estado de un batch de transmisión:
//   - frames:  bloque contiguo de N×ARPFrameLen bytes (cada slot = 1 frame ARP).
//   - iovs:    N entradas Iovec, cada una apuntando al frame correspondiente.
//   - mhdrs:   N entradas mmsghdr, cada una apuntando a su iovec.
//
// Toda la memoria se asigna UNA vez en NewTXBatcher. Durante el escaneo solo
// se mutan los 4 bytes de target IP en frames[i*60+38..i*60+42] y se invoca
// Flush(n) para enviar los primeros n slots.
type TXBatcher struct {
	fd      int
	cap     int
	frames  []byte
	iovs    []unix.Iovec
	mhdrs   []mmsghdr
}

// NewTXBatcher pre-asigna un batch de capacidad `cap` slots, cada uno
// inicializado con `template`. La estructura es totalmente reutilizable.
func NewTXBatcher(fd, cap int, template [ARPFrameLen]byte) *TXBatcher {
	if cap < 1 {
		cap = 1
	}
	b := &TXBatcher{
		fd:     fd,
		cap:    cap,
		frames: make([]byte, cap*ARPFrameLen),
		iovs:   make([]unix.Iovec, cap),
		mhdrs:  make([]mmsghdr, cap),
	}
	for i := 0; i < cap; i++ {
		// Copia del template en el slot i.
		copy(b.frames[i*ARPFrameLen:(i+1)*ARPFrameLen], template[:])
		// Iovec → frame[i].
		b.iovs[i].Base = &b.frames[i*ARPFrameLen]
		b.iovs[i].SetLen(ARPFrameLen)
		// Msghdr: solo configuramos Iov + Iovlen. Name/Namelen=0 hace que el
		// kernel use el binding del socket (AF_PACKET ifindex) — exactamente
		// lo que queremos para evitar pasar sockaddr_ll por paquete.
		b.mhdrs[i].Hdr.Iov = &b.iovs[i]
		b.mhdrs[i].Hdr.SetIovlen(1)
	}
	return b
}

// Cap devuelve la capacidad del batch (slots máximos por Flush).
func (b *TXBatcher) Cap() int { return b.cap }

// SetTargetAt muta el target IP del slot `i` (offset 38..42). Cero allocs.
//
//go:nosplit
func (b *TXBatcher) SetTargetAt(i int, ipBE uint32) {
	off := i*ARPFrameLen + OffArpTPA
	// Hint BCE: el slice tiene exactamente cap*ARPFrameLen bytes.
	_ = b.frames[off+3]
	binary.BigEndian.PutUint32(b.frames[off:off+4], ipBE)
}

// Compact mueve los slots [from..to) al inicio del batch [0..to-from), de
// modo que tras un Flush parcial el caller pueda reintentar los restantes
// sin volver a copiar templates ni recalcular target IPs. *[Regla 88]* —
// se traduce a `memmove` puro.
//
//go:nosplit
func (b *TXBatcher) Compact(from, to int) {
	if from <= 0 || from >= to {
		return
	}
	n := to - from
	src := b.frames[from*ARPFrameLen : to*ARPFrameLen]
	dst := b.frames[0 : n*ARPFrameLen]
	copy(dst, src)
}

// Flush envía los primeros `n` slots en una sola syscall sendmmsg(2).
// Devuelve cuántos slots aceptó el kernel y un error si fue parcial/falló.
//
// Si el kernel acepta menos de n (raro: ENOBUFS, EAGAIN), el caller debe
// reenviar los restantes. Para pacing simple, basta con un sleep breve y
// reintentar la cola.
//
//go:nosplit
func (b *TXBatcher) Flush(n int) (int, error) {
	if n <= 0 {
		return 0, nil
	}
	if n > b.cap {
		n = b.cap
	}
	sent, _, errno := syscall.Syscall6(
		unix.SYS_SENDMMSG,
		uintptr(b.fd),
		uintptr(unsafe.Pointer(&b.mhdrs[0])),
		uintptr(n),
		0, // flags: 0 (síncrono). MSG_DONTWAIT podría ayudar bajo presión
		// pero sin un fallback de retransmisión riguroso lo evitamos.
		0, 0,
	)
	if errno != 0 {
		return int(sent), errno
	}
	return int(sent), nil
}
