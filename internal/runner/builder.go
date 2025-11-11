// internal/runner/builder.go
package runner

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"go-arpscan/internal/cli"
	"go-arpscan/internal/config"
	"go-arpscan/internal/network"
	"go-arpscan/internal/oui"
	"go-arpscan/internal/scanner"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const effectivePacketBits = 672

var errNoTargets = errors.New("no se especificaron objetivos de escaneo")

// buildScannerConfig construye el objeto scanner.Config a partir de la configuración resuelta.
// Este es el puente entre la configuración del usuario y lo que el motor de escaneo necesita.
func buildScannerConfig(cfg *config.ResolvedConfig, args []string) (*scanner.Config, error) {
	// --- Interfaz de Red ---
	var iface *net.Interface
	var localnetCIDR *net.IPNet
	var err error

	if cfg.IfaceName != "" {
		iface, localnetCIDR, err = network.GetInterfaceByName(cfg.IfaceName)
		if err != nil {
			return nil, fmt.Errorf("error al obtener la interfaz especificada: %w", err)
		}
	} else {
		iface, localnetCIDR, err = network.GetDefaultInterface()
		if err != nil {
			return nil, fmt.Errorf("no se pudo auto-detectar la interfaz, por favor especifique una con -i: %w", err)
		}
		if cfg.VerboseCount > 0 {
			log.Printf("Interfaz no especificada. Usando interfaz auto-detectada: %s", iface.Name)
		}
	}

	// --- Resolución de Objetivos ---
	var targets []string
	if cfg.UseLocalnet {
		if localnetCIDR == nil {
			return nil, fmt.Errorf("no se pudo determinar la red local de %s para usar con --localnet", iface.Name)
		}
		if cfg.VerboseCount >= 1 {
			log.Printf("Añadiendo red local de la interfaz %s a los objetivos: %s", iface.Name, localnetCIDR.String())
		}
		targets = append(targets, localnetCIDR.String())
	}
	if cfg.FilePath != "" {
		var f *os.File
		if cfg.FilePath == "-" {
			f = os.Stdin
		} else {
			f, err = os.Open(cfg.FilePath)
			if err != nil {
				return nil, fmt.Errorf("error abriendo el archivo de targets: %w", err)
			}
			defer f.Close()
		}
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	}
	targets = append(targets, args...)

	ips, err := network.ResolveTargets(targets, cfg.Numeric)
	if err != nil {
		// Si el usuario proporcionó objetivos pero no se pudieron resolver, es un error.
		if len(targets) > 0 {
			return nil, fmt.Errorf("error resolviendo targets: %w", err)
		}
		// Si no se proporcionaron objetivos, `ips` será un slice vacío, lo cual es manejado más adelante.
	}

	// --- Aplicación de Exclusiones ---
	if len(cfg.ExcludeTargets) > 0 || cfg.ExcludeFilePath != "" {
		var exclusionStrings []string
		exclusionStrings = append(exclusionStrings, cfg.ExcludeTargets...)

		if cfg.ExcludeFilePath != "" {
			file, err := os.Open(cfg.ExcludeFilePath)
			if err != nil {
				return nil, fmt.Errorf("error abriendo el archivo de exclusión '%s': %w", cfg.ExcludeFilePath, err)
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					exclusionStrings = append(exclusionStrings, line)
				}
			}
			if err := scanner.Err(); err != nil {
				return nil, fmt.Errorf("error leyendo el archivo de exclusión '%s': %w", cfg.ExcludeFilePath, err)
			}
		}

		if len(exclusionStrings) > 0 {
			excludedIPs := make(map[string]struct{})
			var excludedNets []*net.IPNet

			for _, exclusion := range exclusionStrings {
				if _, ipNet, err := net.ParseCIDR(exclusion); err == nil {
					excludedNets = append(excludedNets, ipNet)
					continue
				}
				if ip := net.ParseIP(exclusion); ip != nil {
					excludedIPs[ip.String()] = struct{}{}
					continue
				}
				log.Printf("Advertencia: formato de exclusión no válido, ignorando: '%s'", exclusion)
			}

			if len(excludedIPs) > 0 || len(excludedNets) > 0 {
				initialCount := len(ips)
				var filteredIPs []net.IP

				for _, ip := range ips {
					isExcluded := false
					if _, found := excludedIPs[ip.String()]; found {
						isExcluded = true
					} else {
						for _, net := range excludedNets {
							if net.Contains(ip) {
								isExcluded = true
								break
							}
						}
					}

					if !isExcluded {
						filteredIPs = append(filteredIPs, ip)
					}
				}

				if cfg.VerboseCount > 0 && initialCount != len(filteredIPs) {
					log.Printf("Se aplicaron exclusiones. %d hosts eliminados de la lista de objetivos. %d hosts restantes.", initialCount-len(filteredIPs), len(filteredIPs))
				}
				ips = filteredIPs
			}
		}
	}

	// Ahora, después de filtrar, comprobamos si nos hemos quedado sin objetivos.
	if len(ips) == 0 && cfg.SpoofTargetIP == "" {
		return &scanner.Config{Interface: iface}, errNoTargets
	}

	// --- Aleatorización ---
	if cfg.Random {
		seed := cfg.RandomSeed
		if seed == 0 {
			seed = time.Now().UnixNano()
		}
		r := rand.New(rand.NewSource(seed))
		r.Shuffle(len(ips), func(i, j int) { ips[i], ips[j] = ips[j], ips[i] })
		if cfg.VerboseCount >= 1 {
			log.Printf("Aleatorizando el orden de %d hosts...", len(ips))
		}
	}

	// --- Base de Datos de Vendors ---
	if err := oui.EnsureFile(cfg.OUIFilePath, "https://standards-oui.ieee.org/oui/oui.txt", "OUI"); err != nil {
		log.Printf("Advertencia: Falló la gestión del archivo OUI: %v.", err)
	}
	if err := oui.EnsureFile(cfg.IABFilePath, "https://standards-oui.ieee.org/iab/iab.txt", "IAB"); err != nil {
		log.Printf("Advertencia: Falló la gestión del archivo IAB: %v.", err)
	}
	vendorDB, err := oui.NewVendorDB(cfg.OUIFilePath, cfg.IABFilePath, cfg.MACFilePath, cfg.VerboseCount)
	if err != nil {
		return nil, fmt.Errorf("error cargando la base de datos de vendedores: %w", err)
	}

	// --- Configuración de Tiempos y Ancho de Banda ---
	interval := cfg.Interval
	if cfg.Bandwidth != "" {
		bitsPerSecond, err := cli.ParseBandwidth(cfg.Bandwidth)
		if err != nil {
			return nil, fmt.Errorf("ancho de banda inválido: %w", err)
		}
		if bitsPerSecond > 0 {
			interval = time.Duration(float64(effectivePacketBits) / float64(bitsPerSecond) * float64(time.Second))
		}
	}

	scanTimeout := cfg.ScanTimeout
	if scanTimeout == 20*time.Second { // El valor por defecto no fue sobreescrito
		numHosts := len(ips)
		baseSendTime := time.Duration(numHosts) * interval * time.Duration(cfg.Retry)
		finalHostTimeout := float64(cfg.HostTimeout) * math.Pow(cfg.BackoffFactor, float64(cfg.Retry-1))
		finalBuffer := time.Duration(finalHostTimeout) + 2*time.Second
		calculatedTimeout := baseSendTime + finalBuffer
		if calculatedTimeout < 5*time.Second {
			calculatedTimeout = 5 * time.Second
		}
		scanTimeout = calculatedTimeout
		if cfg.VerboseCount > 0 && len(ips) > 0 {
			log.Printf("Timeout de escaneo no especificado. Calculado automáticamente a: %v", scanTimeout)
		}
	}

	// --- Parsing de Parámetros de Paquetes ---
	var finalArpSPA net.IP
	var useArpSPADest bool
	if cfg.ArpSPA != "" {
		if strings.ToLower(cfg.ArpSPA) == "dest" {
			useArpSPADest = true
		} else {
			finalArpSPA = net.ParseIP(cfg.ArpSPA)
			if finalArpSPA == nil || finalArpSPA.To4() == nil {
				return nil, fmt.Errorf("IP de origen --arpspa inválida: %s", cfg.ArpSPA)
			}
		}
	}

	var finalArpSHA, finalEthSrcMAC, finalEthDstMAC, finalArpTHA net.HardwareAddr
	if cfg.ArpSHA != "" {
		finalArpSHA, err = net.ParseMAC(cfg.ArpSHA)
		if err != nil {
			return nil, fmt.Errorf("MAC de origen --arpsha inválida: %w", err)
		}
	}
	// ... (repetir para las otras MACs)
	if cfg.EthSrcMAC != "" {
		finalEthSrcMAC, err = net.ParseMAC(cfg.EthSrcMAC)
		if err != nil {
			return nil, fmt.Errorf("MAC de origen Ethernet --srcaddr inválida: %w", err)
		}
	}
	if cfg.EthDstMAC != "" {
		finalEthDstMAC, err = net.ParseMAC(cfg.EthDstMAC)
		if err != nil {
			return nil, fmt.Errorf("MAC de destino Ethernet --destaddr inválida: %w", err)
		}
	}
	if cfg.ArpTHA != "" {
		finalArpTHA, err = net.ParseMAC(cfg.ArpTHA)
		if err != nil {
			return nil, fmt.Errorf("MAC de destino ARP --arptha inválida: %w", err)
		}
	}

	parseHex16 := func(hexStr, flagName string) (uint16, error) {
		val, err := strconv.ParseUint(strings.TrimPrefix(hexStr, "0x"), 16, 16)
		if err != nil {
			return 0, fmt.Errorf("valor de --%s inválido: %s. Debe ser un número de 16-bit: %w", flagName, hexStr, err)
		}
		return uint16(val), nil
	}

	finalEthPrototype, err := parseHex16(cfg.EthPrototype, "prototype")
	if err != nil {
		return nil, err
	}
	finalArpPro, err := parseHex16(cfg.ArpPro, "arppro")
	if err != nil {
		return nil, err
	}

	var finalPaddingData []byte
	if cfg.PaddingHex != "" {
		finalPaddingData, err = hex.DecodeString(cfg.PaddingHex)
		if err != nil {
			return nil, fmt.Errorf("valor de --padding inválido, debe ser hexadecimal: %w", err)
		}
	}

	// --- Ensamblaje Final del scanner.Config ---
	scannerConfig := &scanner.Config{
		Interface:         iface,
		IPs:               ips,
		VendorDB:          vendorDB,
		ScanTimeout:       scanTimeout,
		HostTimeout:       cfg.HostTimeout,
		Retry:             cfg.Retry,
		Interval:          interval,
		BackoffFactor:     cfg.BackoffFactor,
		ArpSPA:            finalArpSPA,
		ArpSPADest:        useArpSPADest,
		ArpSHA:            finalArpSHA,
		EthSrcMAC:         finalEthSrcMAC,
		ArpOpCode:         uint16(cfg.ArpOpCode),
		EthDstMAC:         finalEthDstMAC,
		ArpTHA:            finalArpTHA,
		EthernetPrototype: finalEthPrototype,
		ArpHardwareType:   uint16(cfg.ArpHrd),
		ArpProtocolType:   finalArpPro,
		ArpHardwareLen:    uint8(cfg.ArpHln),
		ArpProtocolLen:    uint8(cfg.ArpPln),
		PaddingData:       finalPaddingData,
		UseLLC:            cfg.UseLLC,
		Verbosity:         cfg.VerboseCount,
		PcapSaveFile:      cfg.PcapSaveFile,
		VlanID:            uint16(cfg.VlanID),
		Snaplen:           cfg.Snaplen,
	}

	return scannerConfig, nil
}
