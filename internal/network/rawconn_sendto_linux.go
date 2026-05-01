//go:build linux

// internal/network/rawconn_sendto_linux.go
//
// sendto(2) directo sobre un sockaddr_ll, sin pasar por la conversión
// Sockaddr→RawSockaddrAny de unix.Sendto (que asigna en el heap).
//
// *[Reglas 11, 16]* — Llamada syscall cruda con punteros a memoria propia,
// cero asignaciones por paquete enviado.
package network

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sendtoLL inyecta `frame` por `fd` usando una sockaddr_ll provista por el
// caller. Devuelve un error syscall si la transmisión falla.
//
// Esta función es deliberadamente trivial para que el compilador la inlinee
// y para garantizar que `sa` viva en stack (no escape al heap) cuando es
// llamada desde el bucle de TX.
//
//go:nosplit
func sendtoLL(fd int, frame []byte, sa *unix.RawSockaddrLinklayer) error {
	var p unsafe.Pointer
	if len(frame) > 0 {
		p = unsafe.Pointer(&frame[0])
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SENDTO,
		uintptr(fd),
		uintptr(p),
		uintptr(len(frame)),
		0, // flags
		uintptr(unsafe.Pointer(sa)),
		unsafe.Sizeof(*sa),
	)
	if errno != 0 {
		return errno
	}
	return nil
}
