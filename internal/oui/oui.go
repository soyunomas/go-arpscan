// internal/oui/oui.go
package oui

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath" // <--- NUEVO IMPORT
	"strings"
	"time"
)

// VendorDB contiene todos los mapas de vendedores y la lógica para buscarlos.
type VendorDB struct {
	customVendors map[string]string
	iabVendors    map[string]string
	ouiVendors    map[string]string
	// ouiBin es la copia binaria pre-ordenada del fichero OUI. Si está
	// presente se prefiere para el lookup *[Regla 67]*: búsqueda binaria
	// sobre datos planos cache-friendly, cero asignaciones por llamada.
	ouiBin *binDB
}

// NewVendorDB crea e inicializa una nueva base de datos de vendedores a partir de los ficheros.
func NewVendorDB(ouiPath, iabPath, macPath string, verbosity int) (*VendorDB, error) {
	db := &VendorDB{
		customVendors: make(map[string]string),
		iabVendors:    make(map[string]string),
		ouiVendors:    make(map[string]string),
	}

	var err error

	if macPath != "" {
		db.customVendors, err = loadCustomMACMap(macPath, verbosity)
		if err != nil {
			log.Printf("Warning: could not load custom MAC file %s: %v", macPath, err)
		}
	}

	db.iabVendors, err = loadIABMap(iabPath, verbosity)
	if err != nil {
		log.Printf("Warning: could not load IAB file %s: %v", iabPath, err)
	}

	db.ouiVendors, err = loadOUIMap(ouiPath, verbosity)
	if err != nil {
		log.Printf("Warning: could not load OUI file %s: %v", ouiPath, err)
	}

	// Pre-ordenar OUI en formato binario para búsqueda binaria sin allocs
	// *[Reglas 30, 67]*. El .bin se genera lazy si no existe (cold-path).
	if ouiPath != "" && len(db.ouiVendors) > 0 {
		binPath := ouiPath + ".bin"
		bdb, berr := loadBinDB(binPath)
		if berr != nil {
			if verbosity >= 1 {
				log.Printf("Invalid OUI bin (%v); regenerating", berr)
			}
			bdb = nil
		}
		if bdb == nil {
			if verbosity >= 1 {
				log.Printf("Generating pre-sorted binary OUI index at %s...", binPath)
			}
			if werr := BuildBinFile(binPath, db.ouiVendors); werr != nil {
				if verbosity >= 1 {
					log.Printf("Warning: could not write %s: %v", binPath, werr)
				}
			} else {
				bdb, _ = loadBinDB(binPath)
			}
		}
		if bdb != nil {
			db.ouiBin = bdb
			if verbosity >= 2 {
				log.Printf("Binary OUI index loaded: %d entries (binary search active)", bdb.count)
			}
		}
	}

	return db, nil
}

// normaliza una MAC: la convierte a mayúsculas y quita los separadores.
func normalizeMAC(mac string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(mac, ":", ""), "-", ""))
}

// hex2 convierte dos caracteres hex (en mayúsculas o minúsculas) a un byte.
// Sin asignaciones, branchless-ish *[Regla 62]*.
//
//go:nosplit
func hex2(hi, lo byte) (byte, bool) {
	a, ok1 := hexNibble(hi)
	b, ok2 := hexNibble(lo)
	if !ok1 || !ok2 {
		return 0, false
	}
	return (a << 4) | b, true
}

//go:nosplit
func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

// Lookup busca el vendedor de una MAC siguiendo el orden de precedencia.
func (db *VendorDB) Lookup(mac string) string {
	normMAC := normalizeMAC(mac)
	if len(normMAC) != 12 {
		return "Unknown" // MAC inválida
	}

	// 1. Mapa MAC Personalizado (coincidencia de prefijo más largo)
	if len(db.customVendors) > 0 {
		longestMatch := ""
		vendor := ""
		for prefix, v := range db.customVendors {
			if strings.HasPrefix(normMAC, prefix) {
				if len(prefix) > len(longestMatch) {
					longestMatch = prefix
					vendor = v
				}
			}
		}
		if vendor != "" {
			return vendor
		}
	}

	// 2. Mapa IAB (36 bits / 9 caracteres)
	if len(db.iabVendors) > 0 {
		prefix := normMAC[:9]
		if vendor, ok := db.iabVendors[prefix]; ok {
			return vendor
		}
	}

	// 3. OUI: preferir índice binario pre-ordenado *[Regla 67]*.
	if db.ouiBin != nil {
		var p [3]byte
		// Parseo manual hex → byte (sin asignaciones, sin strconv).
		// *[Regla 62]*.
		if b, ok := hex2(normMAC[0], normMAC[1]); ok {
			p[0] = b
		} else {
			goto fallback
		}
		if b, ok := hex2(normMAC[2], normMAC[3]); ok {
			p[1] = b
		} else {
			goto fallback
		}
		if b, ok := hex2(normMAC[4], normMAC[5]); ok {
			p[2] = b
		} else {
			goto fallback
		}
		if vendor, ok := db.ouiBin.lookup(p); ok {
			return vendor
		}
	}
fallback:
	// Fallback al mapa (compatibilidad si el .bin no se pudo generar).
	if len(db.ouiVendors) > 0 {
		prefix := normMAC[:6]
		if vendor, ok := db.ouiVendors[prefix]; ok {
			return vendor
		}
	}

	// 4. Chequeo de Locally Administered Address (LAA)
	// Si el segundo bit menos significativo del primer byte es 1, es local.
	if len(normMAC) >= 2 {
		var firstByte byte
		// Usamos Sscanf para parsear el hex del primer byte
		fmt.Sscanf(normMAC[:2], "%02X", &firstByte)
		if (firstByte & 0x02) != 0 {
			return "Unknown (Locally Administered)"
		}
	}

	return "Unknown"
}

// loadOUIMap carga el fichero OUI.
func loadOUIMap(path string, verbosity int) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening: %w", err)
	}
	defer file.Close()

	vendors := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "(hex)") {
			parts := strings.SplitN(line, "(hex)", 2)
			if len(parts) != 2 {
				continue
			}
			ouiRaw := strings.TrimSpace(parts[0])
			vendor := strings.TrimSpace(parts[1])
			// La clave es el prefijo de 6 caracteres normalizado.
			key := normalizeMAC(ouiRaw)
			if len(key) == 6 {
				vendors[key] = vendor
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading: %w", err)
	}
	if verbosity >= 2 && len(vendors) > 0 {
		log.Printf("Loaded %d OUI vendors from %s", len(vendors), path)
	}
	return vendors, nil
}

// loadIABMap carga el fichero IAB.
func loadIABMap(path string, verbosity int) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening: %w", err)
	}
	defer file.Close()

	vendors := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "(hex)") {
			parts := strings.SplitN(line, "(hex)", 2)
			if len(parts) != 2 {
				continue
			}
			iabRaw := strings.TrimSpace(parts[0])
			vendor := strings.TrimSpace(parts[1])
			// La clave es el prefijo de 9 caracteres normalizado.
			key := normalizeMAC(iabRaw)
			if len(key) == 9 {
				vendors[key] = vendor
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading: %w", err)
	}
	if verbosity >= 2 && len(vendors) > 0 {
		log.Printf("Loaded %d IAB vendors from %s", len(vendors), path)
	}
	return vendors, nil
}

// loadCustomMACMap carga el fichero MAC personalizado.
func loadCustomMACMap(path string, verbosity int) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening: %w", err)
	}
	defer file.Close()

	vendors := make(map[string]string)
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			log.Printf("Warning: invalid format in %s line %d: %s", path, lineNum, line)
			continue
		}

		key := normalizeMAC(parts[0])
		vendor := strings.Join(parts[1:], " ")
		vendors[key] = vendor
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading: %w", err)
	}
	if verbosity >= 2 && len(vendors) > 0 {
		log.Printf("Loaded %d custom vendors from %s", len(vendors), path)
	}
	return vendors, nil
}

// UpdateVendorFiles fuerza la actualización de OUI/IAB y regenera el índice
// binario OUI. Es cold-path explícito: no participa en el escaneo.
func UpdateVendorFiles(ouiPath, iabPath, ouiURL, iabURL string, verbosity int) error {
	if err := downloadFileAtomic(iabPath, iabURL, "IAB"); err != nil {
		return err
	}
	if err := downloadFileAtomic(ouiPath, ouiURL, "OUI"); err != nil {
		return err
	}

	binPath := ouiPath + ".bin"
	if err := os.Remove(binPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to invalidate %s: %w", binPath, err)
	}

	ouiMap, err := loadOUIMap(ouiPath, verbosity)
	if err != nil {
		return fmt.Errorf("error loading updated OUI to generate binary index: %w", err)
	}
	if len(ouiMap) == 0 {
		return fmt.Errorf("updated OUI contains no valid entries")
	}
	if verbosity >= 1 {
		log.Printf("Regenerating pre-sorted binary OUI index at %s...", binPath)
	}
	if err := BuildBinFile(binPath, ouiMap); err != nil {
		return fmt.Errorf("failed to regenerate %s: %w", binPath, err)
	}
	return nil
}

// EnsureFile comprueba si un fichero existe y lo descarga si es necesario.
func EnsureFile(path, url, fileType string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("error checking %s file: %w", fileType, err)
	}

	return downloadFileAtomic(path, url, fileType)
}

func downloadFileAtomic(path, url, fileType string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for %s at %s: %w", fileType, dir, err)
	}

	log.Printf("Downloading %s file from %s to %s...", fileType, url, path)

	if strings.HasPrefix(url, "file://") {
		srcPath := strings.TrimPrefix(url, "file://")
		src, err := os.Open(srcPath)
		if err != nil {
			return fmt.Errorf("failed to open local source for %s: %w", fileType, err)
		}
		defer src.Close()
		if err := writeFileAtomic(path, src, fileType); err != nil {
			return err
		}
		log.Printf("%s file downloaded and saved successfully to %s", fileType, path)
		return nil
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request for %s: %w", fileType, err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download %s file: %w", fileType, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download %s file: received status code %d", fileType, resp.StatusCode)
	}

	if err := writeFileAtomic(path, resp.Body, fileType); err != nil {
		return err
	}

	log.Printf("%s file downloaded and saved successfully to %s", fileType, path)
	return nil
}

func writeFileAtomic(path string, r io.Reader, fileType string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary file for %s: %w", fileType, err)
	}
	tmpName := tmp.Name()
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = io.Copy(tmp, r); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to save %s file: %w", fileType, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temporary %s file: %w", fileType, err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("failed to set permissions for %s: %w", fileType, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to publish local %s file: %w", fileType, err)
	}
	removeTmp = false
	return nil
}
