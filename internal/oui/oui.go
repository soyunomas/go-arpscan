// internal/oui/oui.go
package oui

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// VendorDB contiene todos los mapas de vendedores y la lógica para buscarlos.
type VendorDB struct {
	customVendors map[string]string
	iabVendors    map[string]string
	ouiVendors    map[string]string
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
			log.Printf("Advertencia: no se pudo cargar el archivo MAC personalizado %s: %v", macPath, err)
		}
	}

	db.iabVendors, err = loadIABMap(iabPath, verbosity)
	if err != nil {
		log.Printf("Advertencia: no se pudo cargar el archivo IAB %s: %v", iabPath, err)
	}

	db.ouiVendors, err = loadOUIMap(ouiPath, verbosity)
	if err != nil {
		log.Printf("Advertencia: no se pudo cargar el archivo OUI %s: %v", ouiPath, err)
	}

	return db, nil
}

// normaliza una MAC: la convierte a mayúsculas y quita los separadores.
func normalizeMAC(mac string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(mac, ":", ""), "-", ""))
}

// Lookup busca el vendedor de una MAC siguiendo el orden de precedencia.
func (db *VendorDB) Lookup(mac string) string {
	normMAC := normalizeMAC(mac)
	if len(normMAC) != 12 {
		return "Desconocido" // MAC inválida
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

	// 3. Mapa OUI (24 bits / 6 caracteres)
	if len(db.ouiVendors) > 0 {
		prefix := normMAC[:6]
		if vendor, ok := db.ouiVendors[prefix]; ok {
			return vendor
		}
	}

	return "Desconocido"
}

// loadOUIMap carga el fichero OUI.
func loadOUIMap(path string, verbosity int) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error al abrir: %w", err)
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
		return nil, fmt.Errorf("error al leer: %w", err)
	}
	if verbosity >= 2 && len(vendors) > 0 {
		log.Printf("Se cargaron %d vendedores OUI desde %s", len(vendors), path)
	}
	return vendors, nil
}

// loadIABMap carga el fichero IAB.
func loadIABMap(path string, verbosity int) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error al abrir: %w", err)
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
		return nil, fmt.Errorf("error al leer: %w", err)
	}
	if verbosity >= 2 && len(vendors) > 0 {
		log.Printf("Se cargaron %d vendedores IAB desde %s", len(vendors), path)
	}
	return vendors, nil
}

// loadCustomMACMap carga el fichero MAC personalizado.
func loadCustomMACMap(path string, verbosity int) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error al abrir: %w", err)
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
			log.Printf("Advertencia: formato inválido en %s línea %d: %s", path, lineNum, line)
			continue
		}

		key := normalizeMAC(parts[0])
		vendor := strings.Join(parts[1:], " ")
		vendors[key] = vendor
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error al leer: %w", err)
	}
	if verbosity >= 2 && len(vendors) > 0 {
		log.Printf("Se cargaron %d vendedores personalizados desde %s", len(vendors), path)
	}
	return vendors, nil
}

// EnsureFile comprueba si un fichero existe y lo descarga si es necesario.
func EnsureFile(path, url, fileType string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("error al verificar el archivo %s: %w", fileType, err)
	}

	log.Printf("Archivo %s no encontrado. Descargando desde %s...", fileType, url)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("fallo al crear la solicitud HTTP para %s: %w", fileType, err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fallo al descargar el archivo %s: %w", fileType, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fallo al descargar el archivo %s: se recibió el código de estado %d", fileType, resp.StatusCode)
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("fallo al crear el archivo %s local: %w", fileType, err)
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("fallo al guardar el archivo %s: %w", fileType, err)
	}

	log.Printf("Archivo %s descargado y guardado exitosamente en %s", fileType, path)
	return nil
}
