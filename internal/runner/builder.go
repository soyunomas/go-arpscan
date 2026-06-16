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
const ieeeOUIURL = "https://standards-oui.ieee.org/oui/oui.txt"
const ieeeIABURL = "https://standards-oui.ieee.org/iab/iab.txt"

var errNoTargets = errors.New("no scan targets specified")

// buildScannerConfig construye el objeto scanner.Config a partir de la configuración resuelta.
func buildScannerConfig(cfg *config.ResolvedConfig, args []string) (*scanner.Config, error) {
	// --- Interfaz de Red ---
	var iface *net.Interface
	var localnetCIDR *net.IPNet
	var err error

	if cfg.IfaceName != "" {
		iface, localnetCIDR, err = network.GetInterfaceByName(cfg.IfaceName)
		if err != nil {
			return nil, fmt.Errorf("error getting specified interface: %w", err)
		}
	} else {
		iface, localnetCIDR, err = network.GetDefaultInterface()
		if err != nil {
			return nil, fmt.Errorf("could not auto-detect interface, please specify one with -I: %w", err)
		}
		if cfg.VerboseCount > 0 {
			log.Printf("No interface specified. Using auto-detected interface: %s", iface.Name)
		}
	}

	// --- Resolución de Objetivos ---
	var targets []string
	if cfg.UseLocalnet {
		if localnetCIDR == nil {
			return nil, fmt.Errorf("could not determine local network for %s to use with --localnet", iface.Name)
		}
		if cfg.VerboseCount >= 1 {
			log.Printf("Adding local network for interface %s to targets: %s", iface.Name, localnetCIDR.String())
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
				return nil, fmt.Errorf("error opening targets file: %w", err)
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
		if len(targets) > 0 {
			return nil, fmt.Errorf("error resolving targets: %w", err)
		}
	}

	// --- Aplicación de Exclusiones ---
	if len(cfg.ExcludeTargets) > 0 || cfg.ExcludeFilePath != "" {
		var exclusionStrings []string
		exclusionStrings = append(exclusionStrings, cfg.ExcludeTargets...)

		if cfg.ExcludeFilePath != "" {
			file, err := os.Open(cfg.ExcludeFilePath)
			if err != nil {
				return nil, fmt.Errorf("error opening exclusion file %q: %w", cfg.ExcludeFilePath, err)
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
				return nil, fmt.Errorf("error reading exclusion file %q: %w", cfg.ExcludeFilePath, err)
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
				log.Printf("Warning: invalid exclusion format, ignoring: %q", exclusion)
			}

			if len(excludedIPs) > 0 || len(excludedNets) > 0 {
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
				ips = filteredIPs
			}
		}
	}

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
	}

	// --- Vendors ---
	var vendorDB *oui.VendorDB
	if !cfg.Quiet {
		if err := oui.EnsureFile(cfg.OUIFilePath, ieeeOUIURL, "OUI"); err != nil {
			log.Printf("Warning: OUI file management failed: %v.", err)
		}
		if err := oui.EnsureFile(cfg.IABFilePath, ieeeIABURL, "IAB"); err != nil {
			log.Printf("Warning: IAB file management failed: %v.", err)
		}
		vendorDB, err = oui.NewVendorDB(cfg.OUIFilePath, cfg.IABFilePath, cfg.MACFilePath, cfg.VerboseCount)
		if err != nil {
			return nil, fmt.Errorf("error loading vendor database: %w", err)
		}
	} else {
		// En modo silencioso (--quiet/-q) se evita por completo la descarga, verificación o carga de
		// los archivos de vendors (OUI/IAB) para reducir drásticamente el consumo de memoria,
		// evitar retrasos de red y permitir ejecuciones seguras offline sin advertencias.
		// Inicializamos un VendorDB vacío para evitar pánicos por puntero nulo en otros paths.
		vendorDB, _ = oui.NewVendorDB("", "", "", 0)
	}

	// --- Configuración de Tiempos y Ancho de Banda ---
	interval := cfg.Interval

	// Se respeta estrictamente el intervalo local o de configuración por defecto (ej. 1ms).
	// Si se define un ancho de banda explícito, este tiene prioridad para calcular el intervalo.
	if cfg.Bandwidth != "" {
		bitsPerSecond, err := cli.ParseBandwidth(cfg.Bandwidth)
		if err != nil {
			return nil, fmt.Errorf("invalid bandwidth: %w", err)
		}
		if bitsPerSecond > 0 {
			interval = time.Duration(float64(effectivePacketBits) / float64(bitsPerSecond) * float64(time.Second))
		}
	}

	scanTimeout := cfg.ScanTimeout
	// Cálculo ajustado del timeout global
	if scanTimeout == 20*time.Second {
		numHosts := len(ips)
		// Tiempo total de transmisión (nº hosts * intervalo * intentos)
		txTime := time.Duration(numHosts) * interval * time.Duration(cfg.Retry)

		// Tiempo de espera para el ÚLTIMO paquete (Backoff acumulado)
		lastPacketWait := time.Duration(float64(cfg.HostTimeout) * math.Pow(cfg.BackoffFactor, float64(cfg.Retry-1)))

		// Buffer de seguridad mínimo (Deadlines ajustados)
		safetyBuffer := 100 * time.Millisecond

		calculatedTimeout := txTime + lastPacketWait + safetyBuffer

		// Mínimo absoluto para redes muy pequeñas
		if calculatedTimeout < 1*time.Second {
			calculatedTimeout = 1 * time.Second
		}
		scanTimeout = calculatedTimeout

		if cfg.VerboseCount > 0 && len(ips) > 0 {
			log.Printf("Calculated global timeout: %v", scanTimeout)
		}
	}

	// --- Parsing de Paquetes ---
	var finalArpSPA net.IP
	var useArpSPADest bool
	if cfg.ArpSPA != "" {
		if strings.ToLower(cfg.ArpSPA) == "dest" {
			useArpSPADest = true
		} else {
			finalArpSPA = net.ParseIP(cfg.ArpSPA)
			if finalArpSPA == nil || finalArpSPA.To4() == nil {
				return nil, fmt.Errorf("invalid --arpspa source IP: %s", cfg.ArpSPA)
			}
		}
	} else {
		// Comportamiento por defecto (idéntico a arp-scan): usar la IP real de la interfaz.
		ifaceIPNet, err := scanner.GetSrcIPNet(iface)
		if err != nil {
			return nil, fmt.Errorf("could not get interface source IP: %w", err)
		}
		finalArpSPA = ifaceIPNet.IP.To4()
	}

	var finalArpSHA, finalEthSrcMAC, finalEthDstMAC, finalArpTHA net.HardwareAddr
	if cfg.ArpSHA != "" {
		finalArpSHA, err = net.ParseMAC(cfg.ArpSHA)
		if err != nil {
			return nil, fmt.Errorf("invalid --arpsha source MAC: %w", err)
		}
	}
	if cfg.EthSrcMAC != "" {
		finalEthSrcMAC, err = net.ParseMAC(cfg.EthSrcMAC)
		if err != nil {
			return nil, fmt.Errorf("invalid --srcaddr Ethernet source MAC: %w", err)
		}
	}
	if cfg.EthDstMAC != "" {
		finalEthDstMAC, err = net.ParseMAC(cfg.EthDstMAC)
		if err != nil {
			return nil, fmt.Errorf("invalid --destaddr Ethernet destination MAC: %w", err)
		}
	}
	if cfg.ArpTHA != "" {
		finalArpTHA, err = net.ParseMAC(cfg.ArpTHA)
		if err != nil {
			return nil, fmt.Errorf("invalid --arptha ARP destination MAC: %w", err)
		}
	}

	parseHex16 := func(hexStr, flagName string) (uint16, error) {
		val, err := strconv.ParseUint(strings.TrimPrefix(hexStr, "0x"), 16, 16)
		if err != nil {
			return 0, fmt.Errorf("invalid --%s value: %s. Must be a 16-bit number: %w", flagName, hexStr, err)
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
			return nil, fmt.Errorf("invalid --padding value, must be hexadecimal: %w", err)
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
		Fast:              cfg.Fast,
		RandomSeed:        cfg.RandomSeed,
	}

	return scannerConfig, nil
}
