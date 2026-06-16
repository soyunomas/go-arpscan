//go:build linux

// internal/scanner/fastscan_linux.go
//
// Motor de escaneo "FAST" zero-allocation sobre AF_PACKET puro.
//
// Comparado con el motor por defecto (gopacket+libpcap):
//   - No usa gopacket (Reglas 1, 12, 22): el frame ARP se construye una vez y
//     solo se mutan 4 bytes (target IP) por iteración.
//   - No usa pcap (Regla 11): socket AF_PACKET directo con SO_ATTACH_FILTER
//     que descarta no-ARP en el kernel.
//   - 2 goroutines pinneadas (LockOSThread) en lugar de N senders + listener
//     (Reglas 6, 46, 47): TX y RX desacoplados sobre el MISMO fd.
//   - Estado por target en un slice plano de 16 bytes (Regla 27): cero punteros
//     en el hot-path → cero presión sobre el GC.
//
// Cobertura funcional Fase 1: ARP Request estándar (op=1, EtherType 0x0806,
// HW=Ethernet, Pro=IPv4, sin VLAN, sin LLC, sin padding, sin overrides de
// SHA/THA/SPA/destaddr/srcaddr). Los modos avanzados caen al motor original
// (Regla 75: Fast-Path vs Slow-Path).
package scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"go-arpscan/internal/network"
	"log"
	"math"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// FastEligible decide si la configuración es soportada por el motor rápido.
// Si retorna false, el caller debe usar StartScan (motor original).
func FastEligible(cfg *Config) bool {
	if cfg.UseLLC || cfg.VlanID != -1 {
		return false
	}
	if len(cfg.PaddingData) != 0 {
		return false
	}
	// Solo ARP Request (op=1) soportado en fast path Fase 1.
	if cfg.ArpOpCode != 0 && cfg.ArpOpCode != 1 {
		return false
	}
	if cfg.ArpSPADest {
		return false
	}
	if cfg.ArpSPA != nil {
		ifaceIPNet, err := GetSrcIPNet(cfg.Interface)
		if err != nil {
			return false
		}
		// Es elegible si la IP configurada coincide con la IP física de la interfaz.
		if !cfg.ArpSPA.Equal(ifaceIPNet.IP.To4()) {
			return false
		}
	}
	if cfg.ArpSHA != nil || cfg.EthSrcMAC != nil || cfg.EthDstMAC != nil || cfg.ArpTHA != nil {
		return false
	}
	// Tipos no estándar → slow path
	if cfg.EthernetPrototype != 0 && cfg.EthernetPrototype != 0x0806 {
		return false
	}
	if cfg.ArpHardwareType != 0 && cfg.ArpHardwareType != 1 {
		return false
	}
	if cfg.ArpProtocolType != 0 && cfg.ArpProtocolType != 0x0800 {
		return false
	}
	if cfg.ArpHardwareLen != 0 && cfg.ArpHardwareLen != 6 {
		return false
	}
	if cfg.ArpProtocolLen != 0 && cfg.ArpProtocolLen != 4 {
		return false
	}
	// PCAP save no soportado todavía en fast path.
	if cfg.PcapSaveFile != "" {
		return false
	}
	return true
}

// fastTarget: 16 bytes exactos, alineado a 8B. Cero punteros → invisible al GC.
// *[Reglas 25, 26, 27]*.
type fastTarget struct {
	ipBE    uint32 // IP en network byte order (big-endian)
	replied uint32 // atomic 0/1
	sentNs  int64  // atomic UnixNano del último envío
}

// StartFastScan arranca el motor rápido. La firma es idéntica a StartScan
// para que el runner alterne sin fricción.
func StartFastScan(cfg *Config) (<-chan ScanResult, error) {
	iface := cfg.Interface
	if iface == nil {
		return nil, fmt.Errorf("fastscan: nil interface")
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("fastscan: interface %s has no valid MAC", iface.Name)
	}

	// IP de origen ARP: la IPv4 de la interfaz.
	ifIPNet, err := GetSrcIPNet(iface)
	if err != nil {
		return nil, fmt.Errorf("fastscan: %w", err)
	}
	srcIP := ifIPNet.IP.To4()
	if srcIP == nil {
		return nil, fmt.Errorf("fastscan: interface has no IPv4")
	}

	// Frame ARP estático. Solo offset [38..42] se mutará en el hot-path.
	frame, err := network.BuildARPFrame(nil, iface.HardwareAddr, srcIP, nil, 1)
	if err != nil {
		return nil, fmt.Errorf("fastscan: %w", err)
	}

	// Socket AF_PACKET con BPF kernel "solo ARP Reply".
	rc, err := network.OpenRaw(iface, true)
	if err != nil {
		return nil, fmt.Errorf("fastscan: open raw: %w", err)
	}

	// Construcción de targets en slice plano + índice por IP.
	// El índice solo se usa en RX (pocas escrituras tras el setup).
	targets := make([]fastTarget, 0, len(cfg.IPs))
	index := make(map[uint32]int, len(cfg.IPs))
	for _, ip := range cfg.IPs {
		u, ok := network.IPv4ToBE(ip)
		if !ok {
			continue
		}
		if _, dup := index[u]; dup {
			continue
		}
		index[u] = len(targets)
		targets = append(targets, fastTarget{ipBE: u})
	}
	if len(targets) == 0 {
		_ = rc.Close()
		return nil, fmt.Errorf("fastscan: 0 valid IPv4 targets")
	}

	results := make(chan ScanResult, 1024)
	pending := int64(len(targets))

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ScanTimeout)

	// MAC propia para descartar reflejos (Regla 82).
	var ownMAC [6]byte
	copy(ownMAC[:], iface.HardwareAddr)

	// CPU affinity: pin RX al último CPU físico, TX al penúltimo. Si solo
	// hay 1 CPU o el usuario opta-out (GOARPSCAN_NOAFFINITY=1), se omite.
	// *[Regla 72]*.
	rxCPU, txCPU := pickAffinity()

	closeTX := func() {}
	txRingEnabled := false
	var txRing *network.TXRing
	if os.Getenv("GOARPSCAN_TX_RING") == "1" {
		txRC, err := network.OpenRaw(iface, false)
		if err != nil {
			if cfg.Verbosity >= 1 {
				log.Printf("fastscan: TX_RING socket unavailable (%v); using sendmmsg", err)
			}
		} else {
			ring, err := network.NewTXRing(txRC.FD(), 2048, 64, frame)
			if err != nil {
				if cfg.Verbosity >= 1 {
					log.Printf("fastscan: TPACKET_V2 TX_RING unavailable (%v); using sendmmsg", err)
				}
				_ = txRC.Close()
			} else {
				if cfg.Verbosity >= 1 {
					log.Println("fastscan: TX engine = TPACKET_V2 TX_RING (mmap).")
				}
				txRing = ring
				txRingEnabled = true
				closeTX = func() {
					_ = ring.Close()
					_ = txRC.Close()
				}
			}
		}
	}

	// Selección de motor RX: por defecto recvfrom (probado). Opt-in al
	// PACKET_MMAP TPACKET_V3 vía GOARPSCAN_TPACKET=1. Cualquier fallo en el
	// setup del ring cae al path por defecto sin perder funcionalidad.
	rxDone := make(chan struct{})
	if os.Getenv("GOARPSCAN_TPACKET") == "1" {
		ring, err := network.NewRXRing(rc.FD(),
			1<<22, // blockSize: 4 MiB
			4,     // blockNr: 4 bloques (16 MiB total mmap)
			2048,  // frameSize: 2 KB (suficiente para ARP)
			60,    // retire timeout: 60 ms
		)
		if err != nil {
			if cfg.Verbosity >= 1 {
				log.Printf("fastscan: TPACKET RX_RING unavailable (%v); using recvfrom", err)
			}
			go runRX(ctx, rc, &ownMAC, targets, index, &pending, cfg, results, rxDone, rxCPU, cancel)
		} else {
			if cfg.Verbosity >= 1 {
				log.Println("fastscan: RX engine = TPACKET_V3 RX_RING (zero-copy mmap).")
			}
			go runRXRing(ctx, rc, ring, &ownMAC, targets, index, &pending, cfg, results, rxDone, rxCPU, cancel)
		}
	} else {
		go runRX(ctx, rc, &ownMAC, targets, index, &pending, cfg, results, rxDone, rxCPU, cancel)
	}

	// TX goroutine — pinneada, dirige las pasadas y backoff. Por defecto usa
	// sendmmsg; TX_RING es opt-in y cae a sendmmsg si el setup falla.
	if txRingEnabled {
		go runTX(ctx, rc, txRing, targets, &pending, cfg, results, rxDone, cancel, closeTX, txCPU)
	} else {
		batcher := network.NewTXBatcher(rc.FD(), 32, frame)
		go runTX(ctx, rc, batcher, targets, &pending, cfg, results, rxDone, cancel, closeTX, txCPU)
	}

	return results, nil
}

// pickAffinity devuelve los CPUs sugeridos para RX y TX. -1 = sin pin.
// Política: si #CPUs >= 2 y la opción no está desactivada, RX→último CPU,
// TX→penúltimo. Esto reduce migraciones de scheduler y mantiene la cache
// L1/L2 caliente en cada hilo. *[Regla 72]*.
func pickAffinity() (rxCPU, txCPU int) {
	if os.Getenv("GOARPSCAN_NOAFFINITY") != "" {
		return -1, -1
	}
	n := runtime.NumCPU()
	if n < 2 {
		return -1, -1
	}
	return n - 1, n - 2
}

// pinCurrentThreadTo intenta fijar el thread OS actual al CPU `cpu`.
// Si falla (permisos, núcleo offline) registra a verbosity≥2 y sigue.
// Cero allocs en hot path: solo se llama una vez por goroutine.
func pinCurrentThreadTo(cpu int, verbosity int) {
	if cpu < 0 {
		return
	}
	var set unix.CPUSet
	set.Zero()
	set.Set(cpu)
	if err := unix.SchedSetaffinity(0, &set); err != nil && verbosity >= 2 {
		log.Printf("fastscan: SchedSetaffinity(cpu=%d): %v", cpu, err)
	}
}

// runRX bucle reactivo de recepción. Lee tramas ARP Reply, filtra reflejos,
// muta el bitmap atómico y emite ScanResult.
//
// *[Reglas 31, 39, 81, 84]*: branch predictability, "happy path" sin
// indentación, descarte temprano (2 bytes opcode), zero-alloc en hot path.
func runRX(
	ctx context.Context,
	rc *network.RawConn,
	ownMAC *[6]byte,
	targets []fastTarget,
	index map[uint32]int,
	pending *int64,
	cfg *Config,
	results chan<- ScanResult,
	done chan<- struct{},
	cpu int,
	cancel context.CancelFunc,
) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(done)
	pinCurrentThreadTo(cpu, cfg.Verbosity)

	// Timeout corto para que el bucle compruebe ctx periódicamente.
	_ = rc.SetReadTimeoutMicro(50_000) // 50ms

	var buf [128]byte // stack-allocated. Frame ARP + Eth = 60 bytes max.

	for {
		// Comprobación liviana de cancelación (no en hot inner) — Regla 55.
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := rc.Recv(buf[:])
		if err != nil {
			if cfg.Verbosity >= 2 {
				log.Printf("fastscan RX: %v", err)
			}
			return
		}
		if n == 0 {
			continue // timeout
		}
		processARPReply(buf[:n], ownMAC, targets, index, pending, cfg, results, cancel)
	}
}

// runRXRing es la variante de recepción basada en TPACKET_V3 RX_RING. La
// semántica de procesamiento es idéntica (delegada en processARPReply); la
// diferencia está en que las tramas viven en la mmap del kernel — cero copia
// kernel→user *[Regla 13]*.
func runRXRing(
	ctx context.Context,
	rc *network.RawConn,
	ring *network.RXRing,
	ownMAC *[6]byte,
	targets []fastTarget,
	index map[uint32]int,
	pending *int64,
	cfg *Config,
	results chan<- ScanResult,
	done chan<- struct{},
	cpu int,
	cancel context.CancelFunc,
) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(done)
	defer ring.Close()
	pinCurrentThreadTo(cpu, cfg.Verbosity)

	cb := func(payload []byte) {
		processARPReply(payload, ownMAC, targets, index, pending, cfg, results, cancel)
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Poll con timeout corto para revisar ctx periódicamente.
		if _, err := ring.PollNext(50, cb); err != nil {
			if cfg.Verbosity >= 2 {
				log.Printf("fastscan RXRing: %v", err)
			}
			return
		}
	}
}

// processARPReply valida un buffer Ethernet+ARP, descarta reflejos y
// duplicados, calcula RTT y emite ScanResult. *[Reglas 16, 31, 39, 81, 82]*.
//
// `pkt` puede apuntar a un buffer en stack (recvfrom) o a la mmap del
// PACKET_MMAP (zero-copy). En ambos casos NO debe escribirse.
func processARPReply(
	pkt []byte,
	ownMAC *[6]byte,
	targets []fastTarget,
	index map[uint32]int,
	pending *int64,
	cfg *Config,
	results chan<- ScanResult,
	cancel context.CancelFunc,
) {
	if len(pkt) < 42 {
		return // trama demasiado corta para Eth+ARP
	}
	// El BPF kernel ya filtra ethertype=ARP + opcode=Reply, pero
	// verificamos por defensa (coste: 4 cmps).
	if pkt[12] != 0x08 || pkt[13] != 0x06 {
		return
	}
	if pkt[20] != 0 || pkt[21] != 2 {
		return
	}
	// Descartar reflejos del propio host *[Regla 82]*.
	if pkt[22] == ownMAC[0] && pkt[23] == ownMAC[1] && pkt[24] == ownMAC[2] &&
		pkt[25] == ownMAC[3] && pkt[26] == ownMAC[4] && pkt[27] == ownMAC[5] {
		return
	}
	// Sender Protocol Address (offset 28..32) — IP del que respondió.
	senderIPBE := binary.BigEndian.Uint32(pkt[28:32])
	idx, ok := index[senderIPBE]
	if !ok {
		if cfg.Verbosity >= 1 {
			log.Printf("fastscan: reply from unsolicited IP: %s", network.BEToIPv4(senderIPBE))
		}
		return
	}
	t := &targets[idx]
	// CAS para garantizar emit-once.
	if !atomic.CompareAndSwapUint32(&t.replied, 0, 1) {
		if cfg.Verbosity >= 2 {
			log.Printf("fastscan: duplicate reply for %s ignored", network.BEToIPv4(senderIPBE))
		}
		return
	}
	if atomic.AddInt64(pending, -1) == 0 {
		cancel()
	}

	var rtt time.Duration
	if sentNs := atomic.LoadInt64(&t.sentNs); sentNs != 0 {
		rtt = time.Since(time.Unix(0, sentNs))
	}
	// Cold path: formatear strings y consultar OUI.
	ipStr := network.BEToIPv4(senderIPBE).String()
	macStr := net.HardwareAddr(pkt[22:28]).String()
	var vendor string
	if cfg.VendorDB != nil {
		vendor = cfg.VendorDB.Lookup(macStr)
	}
	results <- ScanResult{IP: ipStr, MAC: macStr, RTT: rtt, Vendor: vendor}
}

// runTX bucle de transmisión con sendmmsg batching.
//
// Cada pasada itera sobre los targets en orden Feistel (Regla 79), llena
// el batcher, y descarga con UNA syscall por batch. El pacing se aplica
// entre batches usando deadlines acumulativos (Regla 44).
//
// *[Reglas 5, 9, 10, 16, 19, 21, 79]*: cero allocs en hot path, syscalls
// amortizadas por factor `cap`.
type fastTXBackend interface {
	Cap() int
	SetTargetAt(i int, ipBE uint32)
	Flush(n int) (int, error)
	Compact(from, to int)
}

func runTX[T fastTXBackend](
	ctx context.Context,
	rc *network.RawConn,
	tx T,
	targets []fastTarget,
	pending *int64,
	cfg *Config,
	results chan<- ScanResult,
	rxDone <-chan struct{},
	cancel context.CancelFunc,
	closeTX func(),
	cpu int,
) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pinCurrentThreadTo(cpu, cfg.Verbosity)

	// Cleanup ordenado al salir: cancelamos ctx → RX termina → cerramos
	// results y socket.
	defer func() {
		cancel()
		<-rxDone
		close(results)
		closeTX()
		_ = rc.Close()
	}()

	interval := cfg.Interval
	if interval <= 0 {
		interval = 100 * time.Microsecond
	}
	retry := cfg.Retry
	if retry < 1 {
		retry = 1
	}
	hostTO := cfg.HostTimeout
	if hostTO <= 0 {
		hostTO = 500 * time.Millisecond
	}
	backoff := cfg.BackoffFactor
	if backoff <= 0 {
		backoff = 1.0
	}

	// Feistel determinista para orden pseudoaleatorio sin allocs.
	// Calculamos los bits mínimos para cubrir len(targets) y aplicamos
	// cycle-walking si len no es potencia de 2.
	n := uint32(len(targets))
	bits := uint8(1)
	for (uint32(1) << bits) < n {
		bits++
		if bits == 32 {
			break
		}
	}
	seed := uint32(cfg.RandomSeed)
	if seed == 0 {
		seed = 0x9E3779B1
	}
	fei := network.NewFeistel(seed, bits)
	domSize := uint32(1) << bits

	batchCap := tx.Cap()
	// Pacing por batch: si interval es por paquete, el delay entre batches es
	// interval × batchCap (mantenemos el bandwidth solicitado).
	batchInterval := interval * time.Duration(batchCap)

	// AIMD adaptativo *[Regla 80]*: ante ENOBUFS aumentamos `extraSleep`
	// aditivamente; en éxito decae multiplicativamente. Mantenemos el
	// pacing dentro de un rango razonable para no inflar el tiempo total.
	const (
		aimdMin     = 0
		aimdMax     = 5 * time.Millisecond
		aimdAdd     = 100 * time.Microsecond
		aimdDecay   = 0.95 // 5% de decay por flush exitoso
		aimdRetries = 4    // reintentos máximos por slot tras backpressure
	)
	var extraSleep time.Duration

	for pass := 0; pass < retry; pass++ {
		if cfg.ProgressBar != nil {
			msg := "Probing..."
			if retry > 1 {
				msg = fmt.Sprintf("Pass %d/%d: Probing...", pass+1, retry)
			}
			cfg.ProgressBar.Describe(msg)
		}

		nextDeadline := time.Now()
		pos := 0

		// flush envía los `pos` slots cargados. Si el kernel acepta menos
		// (sendmmsg parcial / ENOBUFS), compactamos los restantes al inicio
		// del batch y reintentamos hasta `aimdRetries` veces. Cada reintento
		// aplica AIMD sobre `extraSleep`.
		flush := func() {
			if pos == 0 {
				return
			}
			now := time.Now()
			if now.Before(nextDeadline) {
				sleepUntil(nextDeadline, ctx)
			}
			if extraSleep > 0 {
				time.Sleep(extraSleep)
			}

			for try := 0; try < aimdRetries && pos > 0; try++ {
				sent, err := tx.Flush(pos)
				if cfg.ProgressBar != nil && sent > 0 {
					cfg.ProgressBar.Add(sent)
				}
				if err == nil && sent == pos {
					// Éxito total → decaer extraSleep.
					if extraSleep > 0 {
						extraSleep = time.Duration(float64(extraSleep) * aimdDecay)
						if extraSleep < aimdMin {
							extraSleep = aimdMin
						}
					}
					pos = 0
					break
				}
				// Parcial o error → tratar ENOBUFS/EAGAIN como backpressure.
				if isBackpressure(err) {
					extraSleep += aimdAdd
					if extraSleep > aimdMax {
						extraSleep = aimdMax
					}
					if cfg.Verbosity >= 2 {
						log.Printf("fastscan TX backpressure (try=%d sent=%d/%d): %v → extraSleep=%v",
							try, sent, pos, err, extraSleep)
					}
				} else if err != nil {
					if cfg.Verbosity >= 1 {
						log.Printf("fastscan TX flush: %v", err)
					}
					// Error no recuperable: descartamos los pendientes
					// para evitar bucle infinito.
					pos = 0
					return
				}
				// Compactar slots no enviados a [0..pos-sent) y reintentar.
				if sent > 0 && sent < pos {
					tx.Compact(sent, pos)
				}
				pos -= sent
				if pos > 0 {
					time.Sleep(extraSleep)
				}
			}
			// Si tras los reintentos quedan slots, los descartamos: el RX
			// aún recibirá las respuestas si el batch anterior llegó, y la
			// próxima pasada (retry) los reintentará.
			if pos > 0 && cfg.Verbosity >= 1 {
				log.Printf("fastscan TX: dropped %d slots after %d retries", pos, aimdRetries)
			}
			pos = 0
			nextDeadline = time.Now().Add(batchInterval)
		}

		for i := uint32(0); i < domSize; i++ {
			// Comprobación liviana de cancelación cada slot (Regla 55:
			// la check pasiva es barata aquí porque el batch ya amortiza
			// las syscalls).
			if pos == 0 {
				select {
				case <-ctx.Done():
					return
				default:
				}
			}

			idx := fei.Encrypt(i)
			if idx >= n {
				continue // cycle-walking para n no-potencia-de-2
			}
			t := &targets[idx]
			if atomic.LoadUint32(&t.replied) == 1 {
				continue
			}

			// Cargar slot del batch.
			tx.SetTargetAt(pos, t.ipBE)
			atomic.StoreInt64(&t.sentNs, time.Now().UnixNano())
			pos++

			if pos == batchCap {
				flush()
			}
		}
		// Cola residual.
		flush()

		// Espera para esta pasada con backoff acumulativo.
		wait := time.Duration(float64(hostTO) * math.Pow(backoff, float64(pass)))
		if !sleepCtx(wait, ctx) {
			return
		}
		if atomic.LoadInt64(pending) <= 0 {
			return
		}
	}
}

// isBackpressure devuelve true si el errno indica saturación temporal del
// kernel (cola TX llena, sin buffers). En esos casos AIMD aumenta el delay.
func isBackpressure(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ENOBUFS || errno == syscall.EAGAIN || errno == syscall.EINTR
	}
	return false
}

// sleepCtx duerme `d` o sale antes si ctx se cancela. Devuelve false si
// fue cancelado.
func sleepCtx(d time.Duration, ctx context.Context) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}


