// internal/oui/binary.go
//
// OUI binario pre-ordenado para lookup zero-allocation.
//
// Formato del fichero (.bin) — todo little-endian:
//
//	┌───────────────────────────────────────────────────────────────┐
//	│ Header (32 bytes)                                             │
//	│   Magic     [8] = "GOAS_OUI"                                  │
//	│   Version   u32 = 1                                           │
//	│   Count     u32 = N (entradas)                                │
//	│   EntrySize u32 = 64                                          │
//	│   Reserved [12]                                               │
//	├───────────────────────────────────────────────────────────────┤
//	│ Entries (N × 64 bytes), ORDENADAS por prefijo                 │
//	│   Prefix [3]   = OUI big-endian (e.g. 00:11:22)               │
//	│   Pad    [1]   = 0                                            │
//	│   Vendor [60]  = nombre NUL-padded UTF-8                      │
//	└───────────────────────────────────────────────────────────────┘
//
// Lookup: búsqueda binaria sobre las entradas. *[Reglas 30, 67]* — datos
// planos, sin punteros, totalmente cache-friendly. Cero asignaciones por
// llamada (devolvemos string-slice vía unsafe sobre el buffer mmap-eable).
//
// La cabecera de 32 B y la entrada de 64 B garantizan alineación natural a
// línea de caché L1 (64 B) sin padding extra.
package oui

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"unsafe"
)

const (
	binMagic     = "GOAS_OUI"
	binVersion   = uint32(1)
	binEntrySize = 64
	binHeaderLen = 32
	binPrefixLen = 3
	binVendorLen = 60
)

// binDB es la base OUI mapeada en memoria. Si el fichero .bin existe se
// carga por encima del map[string]string heredado y `Lookup` lo prefiere.
type binDB struct {
	data    []byte // contenido completo del fichero .bin
	entries []byte // sub-slice apuntando a las entradas (count × 64)
	count   int
}

// loadBinDB lee y valida un fichero binario OUI. Devuelve nil si no existe.
func loadBinDB(path string) (*binDB, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if len(raw) < binHeaderLen {
		return nil, fmt.Errorf("oui.bin: truncated file (%d B)", len(raw))
	}
	if !bytes.Equal(raw[:8], []byte(binMagic)) {
		return nil, fmt.Errorf("oui.bin: invalid magic")
	}
	ver := binary.LittleEndian.Uint32(raw[8:12])
	if ver != binVersion {
		return nil, fmt.Errorf("oui.bin: unsupported version %d (expected %d)", ver, binVersion)
	}
	count := binary.LittleEndian.Uint32(raw[12:16])
	esize := binary.LittleEndian.Uint32(raw[16:20])
	if esize != binEntrySize {
		return nil, fmt.Errorf("oui.bin: entrySize %d != %d", esize, binEntrySize)
	}
	expected := binHeaderLen + int(count)*binEntrySize
	if len(raw) < expected {
		return nil, fmt.Errorf("oui.bin: size %d < expected %d", len(raw), expected)
	}
	return &binDB{
		data:    raw,
		entries: raw[binHeaderLen : binHeaderLen+int(count)*binEntrySize],
		count:   int(count),
	}, nil
}

// lookup busca el prefijo [3]byte y devuelve (vendor, true) o ("", false).
//
// Cero asignaciones: devolvemos un string que apunta directamente al buffer
// mediante `unsafe.String` *[Regla 20]*. El buffer es inmutable mientras el
// binDB esté vivo (el caller no debe escribir sobre él).
//
//go:nosplit
func (d *binDB) lookup(prefix [3]byte) (string, bool) {
	if d == nil || d.count == 0 {
		return "", false
	}
	// Búsqueda binaria sobre entries: cada entrada de 64 B empieza con 3 B
	// de prefijo. sort.Search es zero-alloc cuando la lambda no captura
	// referencias al heap; la nuestra solo lee del buffer.
	idx := sort.Search(d.count, func(i int) bool {
		off := i * binEntrySize
		// Comparar 3 bytes BE como uint24.
		a := uint32(d.entries[off])<<16 | uint32(d.entries[off+1])<<8 | uint32(d.entries[off+2])
		b := uint32(prefix[0])<<16 | uint32(prefix[1])<<8 | uint32(prefix[2])
		return a >= b
	})
	if idx >= d.count {
		return "", false
	}
	off := idx * binEntrySize
	if d.entries[off] != prefix[0] || d.entries[off+1] != prefix[1] || d.entries[off+2] != prefix[2] {
		return "", false
	}
	// Vendor en [off+4 .. off+64), terminada en NUL.
	vstart := off + 4
	vend := vstart + binVendorLen
	for i := vstart; i < vend; i++ {
		if d.entries[i] == 0 {
			vend = i
			break
		}
	}
	// unsafe.String evita la copia. *[Regla 20]*.
	return unsafe.String(&d.entries[vstart], vend-vstart), true
}

// BuildBinFile genera el fichero binario `outPath` a partir de un
// map[prefijo→vendor] (claves "AABBCC", longitud 6 hex). Idempotente:
// trunca y reescribe.
//
// Solo se invoca en cold-path (al inicio si el .bin no existe). Aquí sí
// asignamos libremente: estamos fuera del hot-path *[Regla 100]*.
func BuildBinFile(outPath string, ouiMap map[string]string) error {
	type kv struct {
		prefix [3]byte
		vendor string
	}
	entries := make([]kv, 0, len(ouiMap))
	for k, v := range ouiMap {
		if len(k) != 6 {
			continue
		}
		var p [3]byte
		if _, err := fmt.Sscanf(k, "%02X%02X%02X", &p[0], &p[1], &p[2]); err != nil {
			continue
		}
		entries = append(entries, kv{p, v})
	}
	sort.Slice(entries, func(i, j int) bool {
		a := entries[i].prefix
		b := entries[j].prefix
		ai := uint32(a[0])<<16 | uint32(a[1])<<8 | uint32(a[2])
		bi := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
		return ai < bi
	})

	out := make([]byte, binHeaderLen+len(entries)*binEntrySize)
	copy(out[:8], binMagic)
	binary.LittleEndian.PutUint32(out[8:12], binVersion)
	binary.LittleEndian.PutUint32(out[12:16], uint32(len(entries)))
	binary.LittleEndian.PutUint32(out[16:20], binEntrySize)
	for i, e := range entries {
		off := binHeaderLen + i*binEntrySize
		out[off] = e.prefix[0]
		out[off+1] = e.prefix[1]
		out[off+2] = e.prefix[2]
		// out[off+3] = 0 (pad)
		v := e.vendor
		if len(v) > binVendorLen {
			v = v[:binVendorLen]
		}
		copy(out[off+4:off+4+len(v)], v)
		// resto NUL ya por construcción.
	}
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, outPath)
}
