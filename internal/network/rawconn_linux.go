//go:build linux

// internal/network/rawconn_linux.go
//
// Wrapper minimalista sobre AF_PACKET + SOCK_RAW para inyección y captura
// de tramas Ethernet a Layer 2, sin pasar por la pila TCP/IP del kernel.
//
// *[Reglas 1, 2, 4, 7, 11, 12]*:
//   - AF_PACKET / SOCK_RAW puro (no net.PacketConn, no pcap, no gopacket).
//   - SO_RCVBUF / SO_SNDBUF maximizados.
//   - SO_ATTACH_FILTER con BPF pre-compilado: el kernel descarta el 99 % del
//     ruido antes de copiar a userspace.
//   - golang.org/x/sys/unix (mantenido) en lugar de syscall (deprecated).
//
// Esta abstracción es el "pre-MMAP": una API simple sobre sendto/recvfrom.
// La FASE 2 introducirá TPACKET_V2/V3 con ring buffer mmap-ado.
package network

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// RawConn representa un socket AF_PACKET vinculado a una interfaz.
type RawConn struct {
	fd      int
	ifIndex int
	mtu     int
	mac     [6]byte
}

// htons (host→network short) — compilador lo inlinea trivialmente.
//
//go:nosplit
func htons(x uint16) uint16 { return (x<<8)&0xff00 | x>>8 }

// OpenRaw abre un socket AF_PACKET ligado a iface, escuchando solo ARP
// (ETH_P_ARP = 0x0806). Maximiza buffers de RX/TX.
//
// Si attachBPF es true, instala un BPF que solo deja pasar ARP Reply (op=2),
// reduciendo drásticamente las copias kernel→user *[Regla 4]*.
func OpenRaw(iface *net.Interface, attachBPF bool) (*RawConn, error) {
	if iface == nil {
		return nil, errors.New("OpenRaw: iface nil")
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("OpenRaw: interface %s has no 6-byte MAC", iface.Name)
	}

	// SOCK_RAW: recibimos la trama Ethernet completa (incluye L2).
	// htons(ETH_P_ARP): el kernel solo nos entregará tramas ARP.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket: %w", err)
	}

	rc := &RawConn{
		fd:      fd,
		ifIndex: iface.Index,
		mtu:     iface.MTU,
	}
	copy(rc.mac[:], iface.HardwareAddr)

	// Bind al ifindex con protocolo ARP. Esto es lo que filtra por interfaz
	// (no necesitamos SO_BINDTODEVICE).
	sll := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ARP),
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, sll); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind AF_PACKET to %s: %w", iface.Name, err)
	}

	// Buffers gigantes para absorber ráfagas. *[Regla 7]*.
	// Pedimos lo máximo permitido por net.core.{r,w}mem_max; si el kernel
	// recorta, no es fatal (mejor que el default de 256 KB).
	const want = 16 * 1024 * 1024
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, want)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, want)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, want)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, want)

	if attachBPF {
		if err := attachARPReplyFilter(fd); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("SO_ATTACH_FILTER: %w", err)
		}
	}

	return rc, nil
}

// Close libera el socket.
func (r *RawConn) Close() error {
	if r == nil || r.fd < 0 {
		return nil
	}
	err := unix.Close(r.fd)
	r.fd = -1
	return err
}

// FD devuelve el descriptor de archivo subyacente (para epoll, poll, etc.).
func (r *RawConn) FD() int { return r.fd }

// HardwareAddr devuelve la MAC de la interfaz como array fijo (zero-alloc).
func (r *RawConn) HardwareAddr() [6]byte { return r.mac }

// IfIndex devuelve el índice de la interfaz.
func (r *RawConn) IfIndex() int { return r.ifIndex }

// SetReadDeadline activa un timeout de lectura usando SO_RCVTIMEO.
// timeoutUs en microsegundos. 0 = sin timeout (blocking).
func (r *RawConn) SetReadTimeoutMicro(timeoutUs int64) error {
	tv := unix.Timeval{
		Sec:  timeoutUs / 1_000_000,
		Usec: timeoutUs % 1_000_000,
	}
	return unix.SetsockoptTimeval(r.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
}

// SetNonblock pone el socket en modo no-bloqueante.
func (r *RawConn) SetNonblock(nb bool) error {
	return unix.SetNonblock(r.fd, nb)
}

// SendTo inyecta el frame al cable. La sockaddr_ll está pre-construida con
// el ifindex correcto. Esta es la única syscall del path TX (1 syscall por
// paquete; en FASE 2 lo amortizaremos con TX_RING).
//
//go:nosplit
func (r *RawConn) SendTo(frame []byte) error {
	sll := unix.RawSockaddrLinklayer{
		Family:   unix.AF_PACKET,
		Protocol: htons(unix.ETH_P_ARP),
		Ifindex:  int32(r.ifIndex),
		Halen:    6,
	}
	// Halen=6, addr=broadcast (no se usa cuando bindeamos por ifindex,
	// pero lo dejamos consistente).
	for i := 0; i < 6; i++ {
		sll.Addr[i] = 0xff
	}
	return sendtoLL(r.fd, frame, &sll)
}

// Recv lee una trama en buf y devuelve el número de bytes copiados.
// Devuelve (0, nil) si fue un timeout (cuando hay deadline configurado).
//
// Implementación zero-alloc: bypass de unix.Recvfrom (que devuelve un
// Sockaddr interface y asigna por llamada).
//
//go:nosplit
func (r *RawConn) Recv(buf []byte) (int, error) {
	n, errno := recvFD(r.fd, buf)
	if errno == 0 {
		return n, nil
	}
	if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK || errno == unix.EINTR {
		return 0, nil
	}
	return 0, os.NewSyscallError("recvfrom", errno)
}

// attachARPReplyFilter compila un BPF mínimo que solo acepta ARP Reply
// (ethertype 0x0806 + opcode 2). Todo lo demás se descarta en el kernel.
//
// Programa BPF:
//
//	(0) ldh [12]              ; ethertype
//	(1) jeq #0x0806, jt=0, jf=DROP
//	(2) ldh [20]              ; ARP opcode (offset 14 + 6 = 20)
//	(3) jeq #2, jt=ACCEPT, jf=DROP
//	(4) ret #0xffffffff       ; ACCEPT: copia hasta snaplen
//	(5) ret #0                ; DROP
func attachARPReplyFilter(fd int) error {
	prog := []unix.SockFilter{
		{Code: 0x28, Jt: 0, Jf: 0, K: 12},          // ldh [12]
		{Code: 0x15, Jt: 0, Jf: 3, K: 0x0806},      // jeq #0x0806 → next, else DROP
		{Code: 0x28, Jt: 0, Jf: 0, K: 20},          // ldh [20]
		{Code: 0x15, Jt: 0, Jf: 1, K: 0x0002},      // jeq #2 → ACCEPT, else DROP
		{Code: 0x06, Jt: 0, Jf: 0, K: 0xffff_ffff}, // ret #-1 (snaplen máx)
		{Code: 0x06, Jt: 0, Jf: 0, K: 0},           // ret #0 (drop)
	}
	fprog := unix.SockFprog{
		Len:    uint16(len(prog)),
		Filter: &prog[0],
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog)
}
