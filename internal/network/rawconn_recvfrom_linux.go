//go:build linux

// internal/network/rawconn_recvfrom_linux.go
//
// recvfrom(2) directo. unix.Recvfrom devuelve un Sockaddr (interfaz) que
// asigna memoria en cada llamada. En el bucle de RX no podemos permitirnos
// eso *[Reglas 16, 22]*. Usamos syscall.Syscall6 con MSG_TRUNC=0 y descartamos
// la dirección de origen (no la necesitamos: ya filtramos por interfaz al
// hacer bind y por opcode con BPF).
package network

import (
	"syscall"
	"unsafe"
)

// recvFD lee del fd al buffer p. Devuelve (n, errno).
// Cero asignaciones por llamada.
//
//go:nosplit
func recvFD(fd int, p []byte) (int, syscall.Errno) {
	if len(p) == 0 {
		return 0, 0
	}
	n, _, errno := syscall.Syscall6(
		syscall.SYS_RECVFROM,
		uintptr(fd),
		uintptr(unsafe.Pointer(&p[0])),
		uintptr(len(p)),
		0, // flags
		0, // src addr (NULL → no escribe)
		0, // src addrlen ptr (NULL)
	)
	return int(n), errno
}
