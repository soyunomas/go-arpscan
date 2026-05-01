//go:build linux && amd64

// internal/network/tpacket_linux.go
package network

import (
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tpacketV1 = 0
	tpacketV2 = 1
	tpacketV3 = 2

	packetRxRing  = 5
	packetTxRing  = 13
	packetVersion = 10

	tpStatusKernel = 0x0
	tpStatusUser   = 0x1

	tpStatusAvailable   = 0x0
	tpStatusSendRequest = 0x1
	tpStatusSending     = 0x2
	tpStatusWrongFormat = 0x4

	tpacketAlignment = 16
)

//go:nosplit
func tpacketAlign(x uintptr) uintptr {
	return (x + tpacketAlignment - 1) &^ (tpacketAlignment - 1)
}

type tpacketReq struct {
	BlockSize uint32
	BlockNr   uint32
	FrameSize uint32
	FrameNr   uint32
}

type tpacketReq3 struct {
	BlockSize      uint32
	BlockNr        uint32
	FrameSize      uint32
	FrameNr        uint32
	RetireBlkTov   uint32
	SizeofPriv     uint32
	FeatureReqWord uint32
}

type tpacketBdTs struct {
	Sec  uint32
	Nsec uint32
}

type tpacketHdrV1 struct {
	BlockStatus      uint32
	NumPkts          uint32
	OffsetToFirstPkt uint32
	BlkLen           uint32
	SeqNum           uint64
	TsFirstPkt       tpacketBdTs
	TsLastPkt        tpacketBdTs
}

type tpacketBlockDesc struct {
	Version      uint32
	OffsetToPriv uint32
	Hdr          tpacketHdrV1
}

type tpacket3Hdr struct {
	NextOffset uint32
	Sec        uint32
	Nsec       uint32
	Snaplen    uint32
	Len        uint32
	Status     uint32
	Mac        uint16
	Net        uint16
	RxHash    uint32
	VlanTci   uint32
	VlanTpid  uint16
	HvPadding uint16
	Padding   [8]byte
}

type tpacket2Hdr struct {
	Status   uint32
	Len      uint32
	Snaplen  uint32
	Mac      uint16
	Net      uint16
	Sec      uint32
	Nsec     uint32
	VlanTci  uint16
	VlanTpid uint16
	Padding  [4]byte
}

var tpacket2HdrLen = tpacketAlign(unsafe.Sizeof(tpacket2Hdr{})) + unsafe.Sizeof(unix.RawSockaddrLinklayer{})

type RXRing struct {
	fd        int
	mmap      []byte
	blockSize uint32
	blockNr   uint32
	curBlock  uint32
}

type TXRing struct {
	fd        int
	mmap      []byte
	frameSize uint32
	frameNr   uint32
	cap       int
	cur       uint32
	template  [ARPFrameLen]byte
}

func NewTXRing(fd int, frameSize, frameNr uint32, template [ARPFrameLen]byte) (*TXRing, error) {
	log.Printf("[TX_RING_DEBUG] Iniciando NewTXRing con frameSize=%d, frameNr=%d", frameSize, frameNr)
	log.Printf("[TX_RING_DEBUG] tpacket2HdrLen calculado: %d", tpacket2HdrLen)

	if fd < 0 {
		return nil, errors.New("TXRing: invalid fd")
	}
	if frameSize == 0 || frameNr == 0 {
		return nil, errors.New("TXRing: invalid dimensions")
	}
	if uintptr(frameSize) < tpacket2HdrLen+ARPFrameLen {
		return nil, fmt.Errorf("TXRing: frameSize %d smaller than header+ARP", frameSize)
	}
	page := uint32(osGetpagesize())
	blockSize := frameSize * frameNr
	if blockSize%page != 0 {
		return nil, fmt.Errorf("TXRing: frameSize*frameNr must be a multiple of page size")
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, packetVersion, tpacketV2); err != nil {
		return nil, fmt.Errorf("PACKET_VERSION V2: %w", err)
	}

	req := tpacketReq{
		BlockSize: blockSize,
		BlockNr:   1,
		FrameSize: frameSize,
		FrameNr:   frameNr,
	}
	_, _, errno := syscall.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_PACKET),
		uintptr(packetTxRing),
		uintptr(unsafe.Pointer(&req)),
		unsafe.Sizeof(req),
		0,
	)
	if errno != 0 {
		return nil, fmt.Errorf("PACKET_TX_RING: %w", errno)
	}

	size := int(blockSize)
	flags := unix.MAP_SHARED | unix.MAP_LOCKED | unix.MAP_POPULATE
	mm, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, flags)
	if err != nil {
		mm, err = unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			return nil, fmt.Errorf("mmap TX_RING: %w", err)
		}
	}

	r := &TXRing{
		fd:        fd,
		mmap:      mm,
		frameSize: frameSize,
		frameNr:   frameNr,
		cap:       int(frameNr),
		template:  template,
	}
	for i := uint32(0); i < frameNr; i++ {
		r.initFrame(i)
	}
	
	log.Printf("[TX_RING_DEBUG] TXRing mmap completado correctamente")
	return r, nil
}

func (r *TXRing) Close() error {
	if r == nil || len(r.mmap) == 0 {
		return nil
	}
	err := unix.Munmap(r.mmap)
	r.mmap = nil
	return err
}

func osGetpagesize() int {
	return unix.Getpagesize()
}

func (r *TXRing) Cap() int { return r.cap }

//go:nosplit
func (r *TXRing) frameAt(i uint32) *tpacket2Hdr {
	off := uintptr(i) * uintptr(r.frameSize)
	return (*tpacket2Hdr)(unsafe.Pointer(&r.mmap[off]))
}

//go:nosplit
func (r *TXRing) dataAt(i uint32) []byte {
	off := uintptr(i)*uintptr(r.frameSize) + tpacket2HdrLen
	return unsafe.Slice((*byte)(unsafe.Pointer(&r.mmap[off])), ARPFrameLen)
}

func (r *TXRing) initFrame(i uint32) {
	h := r.frameAt(i)
	h.Status = tpStatusAvailable
	h.Len = ARPFrameLen
	h.Snaplen = ARPFrameLen
	h.Mac = uint16(tpacket2HdrLen)
	h.Net = uint16(tpacket2HdrLen + OffArpHrd)
	copy(r.dataAt(i), r.template[:])
}

func (r *TXRing) SetTargetAt(i int, ipBE uint32) {
	slot := (r.cur + uint32(i)) % r.frameNr
	h := r.frameAt(slot)
	
	waitCount := 0
	for {
		status := atomic.LoadUint32(&h.Status)
		if status == tpStatusAvailable {
			break
		}
		if status&tpStatusWrongFormat != 0 {
			log.Printf("[TX_RING_DEBUG] SetTargetAt detectó WRONG_FORMAT en slot %d", slot)
			atomic.StoreUint32(&h.Status, tpStatusAvailable)
			break
		}
		waitCount++
		if waitCount == 1 {
			log.Printf("[TX_RING_DEBUG] SetTargetAt esperando por slot %d (status=0x%x)", slot, status)
		}
		runtime.Gosched()
	}
	
	frame := r.dataAt(slot)
	_ = frame[OffArpTPA+3]
	frame[OffArpTPA+0] = byte(ipBE >> 24)
	frame[OffArpTPA+1] = byte(ipBE >> 16)
	frame[OffArpTPA+2] = byte(ipBE >> 8)
	frame[OffArpTPA+3] = byte(ipBE)
}

//go:nosplit
func (r *TXRing) Compact(from, to int) {}

func (r *TXRing) Flush(n int) (int, error) {
	if n <= 0 {
		return 0, nil
	}
	if n > r.cap {
		n = r.cap
	}

	log.Printf("[TX_RING_DEBUG] ---------- INICIANDO FLUSH DE %d SLOTS ----------", n)

	for i := 0; i < n; i++ {
		slot := (r.cur + uint32(i)) % r.frameNr
		h := r.frameAt(slot)
		
		h.Len = ARPFrameLen
		h.Snaplen = ARPFrameLen
		h.Mac = uint16(tpacket2HdrLen)
		h.Net = uint16(tpacket2HdrLen + OffArpHrd)
		
		atomic.StoreUint32(&h.Status, tpStatusSendRequest)
	}

	// Ejecuta sendto
	_, _, errno := syscall.Syscall6(unix.SYS_SENDTO, uintptr(r.fd), 0, 0, 0, 0, 0)
	
	if errno != 0 {
		log.Printf("[TX_RING_DEBUG] Syscall SENDTO retornó errno=%d", errno)
	} else {
		log.Printf("[TX_RING_DEBUG] Syscall SENDTO completada sin errno")
	}

	processed := 0
	for i := 0; i < n; i++ {
		slot := (r.cur + uint32(i)) % r.frameNr
		h := r.frameAt(slot)
		status := atomic.LoadUint32(&h.Status)
		
		if status != tpStatusSendRequest {
			if status&tpStatusWrongFormat != 0 {
				log.Printf("[TX_RING_DEBUG] Slot %d procesado pero el kernel lo marcó WRONG_FORMAT (0x%x)!", slot, status)
				atomic.StoreUint32(&h.Status, tpStatusAvailable)
			} else {
				log.Printf("[TX_RING_DEBUG] Slot %d procesado exitosamente por el kernel (status=0x%x)", slot, status)
			}
			processed++
		} else {
			log.Printf("[TX_RING_DEBUG] Slot %d SE QUEDÓ ATASCADO en SEND_REQUEST", slot)
			break
		}
	}

	log.Printf("[TX_RING_DEBUG] Se procesaron %d de %d slots. Avanzando cursor.", processed, n)

	// Restaurar slots atascados
	for i := processed; i < n; i++ {
		slot := (r.cur + uint32(i)) % r.frameNr
		h := r.frameAt(slot)
		atomic.StoreUint32(&h.Status, tpStatusAvailable)
	}

	r.cur = (r.cur + uint32(processed)) % r.frameNr

	if errno != 0 {
		return processed, errno
	}
	return processed, nil
}

func NewRXRing(fd int, blockSize, blockNr, frameSize uint32, retireMs uint32) (*RXRing, error) {
	if fd < 0 {
		return nil, errors.New("RXRing: invalid fd")
	}
	if blockSize == 0 || blockNr == 0 || frameSize == 0 {
		return nil, errors.New("RXRing: invalid dimensions")
	}
	if blockSize%frameSize != 0 {
		return nil, fmt.Errorf("RXRing: blockSize %d is not a multiple of frameSize", blockSize)
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, packetVersion, tpacketV3); err != nil {
		return nil, fmt.Errorf("PACKET_VERSION V3: %w", err)
	}

	req := tpacketReq3{
		BlockSize:    blockSize,
		BlockNr:      blockNr,
		FrameSize:    frameSize,
		FrameNr:      (blockSize / frameSize) * blockNr,
		RetireBlkTov: retireMs,
	}
	_, _, errno := syscall.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_PACKET),
		uintptr(packetRxRing),
		uintptr(unsafe.Pointer(&req)),
		unsafe.Sizeof(req),
		0,
	)
	if errno != 0 {
		return nil, fmt.Errorf("PACKET_RX_RING: %w", errno)
	}

	size := int(blockSize) * int(blockNr)
	flags := unix.MAP_SHARED | unix.MAP_LOCKED | unix.MAP_POPULATE
	mm, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, flags)
	if err != nil {
		mm, err = unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			return nil, fmt.Errorf("mmap RX_RING: %w", err)
		}
	}

	return &RXRing{
		fd:        fd,
		mmap:      mm,
		blockSize: blockSize,
		blockNr:   blockNr,
	}, nil
}

func (r *RXRing) Close() error {
	if r == nil || len(r.mmap) == 0 {
		return nil
	}
	err := unix.Munmap(r.mmap)
	r.mmap = nil
	return err
}

//go:nosplit
func (r *RXRing) blockAt(i uint32) *tpacketBlockDesc {
	off := uintptr(i) * uintptr(r.blockSize)
	return (*tpacketBlockDesc)(unsafe.Pointer(&r.mmap[off]))
}

//go:nosplit
func (r *RXRing) PollNext(timeoutMs int, cb func(payload []byte)) (int, error) {
	bd := r.blockAt(r.curBlock)
	if atomic.LoadUint32(&bd.Hdr.BlockStatus)&tpStatusUser == 0 {
		pfd := unix.PollFd{Fd: int32(r.fd), Events: unix.POLLIN | unix.POLLERR}
		fds := [1]unix.PollFd{pfd}
		_, err := unix.Poll(fds[:], timeoutMs)
		if err != nil {
			if err == unix.EINTR {
				return 0, nil
			}
			return 0, err
		}
		if atomic.LoadUint32(&bd.Hdr.BlockStatus)&tpStatusUser == 0 {
			return 0, nil
		}
	}

	num := bd.Hdr.NumPkts
	off := bd.Hdr.OffsetToFirstPkt
	base := unsafe.Pointer(bd)
	processed := 0
	for j := uint32(0); j < num; j++ {
		hdrPtr := unsafe.Add(base, off)
		ph := (*tpacket3Hdr)(hdrPtr)
		payloadPtr := unsafe.Add(hdrPtr, uintptr(ph.Mac))
		payloadLen := int(ph.Snaplen)
		payload := unsafe.Slice((*byte)(payloadPtr), payloadLen)
		cb(payload)
		processed++

		if ph.NextOffset == 0 {
			break
		}
		off += ph.NextOffset
	}

	atomic.StoreUint32(&bd.Hdr.BlockStatus, tpStatusKernel)
	r.curBlock = (r.curBlock + 1) % r.blockNr
	return processed, nil
}
