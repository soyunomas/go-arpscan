// cmd/go-arpscan/main.go
package main

import (
	"bufio"
	"fmt"
	"go-arpscan/internal/formatter"
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

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const (
	ouiFileDefaultName  = "oui.txt"
	iabFileDefaultName  = "iab.txt"
	macFileDefaultName  = ""
	ouiURL              = "https://standards-oui.ieee.org/oui/oui.txt"
	iabURL              = "https://standards-oui.ieee.org/iab/iab.txt"
	effectivePacketBits = 672
)

var (
	version = "dev"

	// Flags
	ifaceName     string
	filePath      string
	scanTimeout   time.Duration
	hostTimeout   time.Duration
	retry         int
	interval      time.Duration
	backoffFactor float64
	arpSPA        string
	quiet         bool
	plain         bool
	jsonOutput    bool
	csvOutput     bool
	showRTT       bool
	random        bool
	randomSeed    int64
	bandwidth     string
	verboseCount  int
	versionFlag   bool
	ouiFilePath   string
	iabFilePath   string
	macFilePath   string
	numeric       bool
	useLocalnet   bool
	ignoreDups    bool
	colorMode     string
	pcapSaveFile  string
)

var rootCmd = &cobra.Command{
	Use:   "go-arpscan [options] [hosts...]",
	Short: "go-arpscan es un escáner de red ARP rápido y moderno escrito en Go.",
	Long: `Envía paquetes ARP a los hosts de la red local y muestra las respuestas recibidas.

Los hosts de destino deben especificarse en la línea de comandos a menos que se use la opción --file,
en cuyo caso los destinos se leen desde el archivo especificado, o si se usa la opción --localnet,
en cuyo caso los destinos se generan a partir de la dirección IP y la máscara de red de la interfaz.

Si no se especifica una interfaz con -i, go-arpscan intentará seleccionar una automáticamente.

Es necesario ejecutar go-arpscan como root, ya que las funciones que utiliza para leer y escribir
paquetes de red requieren privilegios elevados.

Los hosts de destino se pueden especificar como direcciones IP, nombres de host, o rangos. También puede especificar
el destino como IPnetwork/bits (p. ej., 192.168.1.0/24) para especificar todos los hosts en la red
dada, o IPstart-IPend (p. ej., 192.168.1.3-192.168.1.27) para especificar todos los hosts en
el rango inclusivo.

Reporta bugs o envía sugerencias a tu mentor Gopher.`,
	Example: `  sudo ./go-arpscan --localnet
  sudo ./go-arpscan -i eth0 192.168.1.0/24
  sudo ./go-arpscan -i eth0 192.168.1.1-192.168.1.254
  sudo ./go-arpscan --file=hostlist.txt --json
  sudo ./go-arpscan -i wlan0 --localnet --pcapsavefile=capture.pcap`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if versionFlag {
			fmt.Printf("go-arpscan version %s\n", version)
			os.Exit(0)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		if os.Geteuid() != 0 {
			log.Fatal("Este programa debe ser ejecutado como root.")
		}

		formatFlags := 0
		if jsonOutput {
			formatFlags++
		}
		if csvOutput {
			formatFlags++
		}
		if quiet {
			formatFlags++
		}
		if plain {
			formatFlags++
		}
		if formatFlags > 1 {
			log.Fatal("Error: los flags de formato (--json, --csv, --quiet, --plain) son mutuamente excluyentes.")
		}

		switch strings.ToLower(colorMode) {
		case "off":
			color.NoColor = true
		case "on":
			color.NoColor = false
		case "auto":
		default:
			log.Fatalf("Valor inválido para --color: %s. Use 'auto', 'on', o 'off'.", colorMode)
		}

		bandwidthFlagChanged := cmd.Flags().Changed("bandwidth")
		intervalFlagChanged := cmd.Flags().Changed("interval")

		if bandwidthFlagChanged && intervalFlagChanged {
			log.Fatal("Error: los flags --bandwidth (-B) y --interval son mutuamente excluyentes.")
		}

		if bandwidthFlagChanged {
			bitsPerSecond, err := parseBandwidth(bandwidth)
			if err != nil {
				log.Fatalf("Ancho de banda inválido: %v", err)
			}
			if bitsPerSecond == 0 {
				log.Fatalf("El ancho de banda no puede ser cero.")
			}
			interval = time.Duration(float64(effectivePacketBits) / float64(bitsPerSecond) * float64(time.Second))
			log.Printf("Ancho de banda establecido en %s. Intervalo entre paquetes calculado: %v", bandwidth, interval)
		}

		var iface *net.Interface
		var localnetCIDR *net.IPNet
		var err error

		if ifaceName != "" {
			iface, localnetCIDR, err = network.GetInterfaceByName(ifaceName)
			if err != nil {
				log.Fatalf("Error al obtener la interfaz especificada: %v.", err)
			}
		} else {
			iface, localnetCIDR, err = network.GetDefaultInterface()
			if err != nil {
				log.Fatalf("No se pudo auto-detectar la interfaz. Por favor, especifique una con -i. Error: %v", err)
			}
			if verboseCount > 0 {
				log.Printf("Interfaz no especificada. Usando interfaz auto-detectada: %s", iface.Name)
			}
		}

		var finalArpSPA net.IP
		if arpSPA != "" {
			finalArpSPA = net.ParseIP(arpSPA)
			if finalArpSPA == nil || finalArpSPA.To4() == nil {
				log.Fatalf("IP de origen --arpspa inválida: %s", arpSPA)
			}
		}

		var targets []string
		if useLocalnet {
			if localnetCIDR == nil {
				log.Fatalf("No se pudo determinar la red local de la interfaz %s para usar con --localnet", iface.Name)
			}
			if verboseCount >= 1 {
				log.Printf("Añadiendo red local de la interfaz %s a los objetivos: %s", iface.Name, localnetCIDR.String())
			}
			targets = append(targets, localnetCIDR.String())
		}

		if filePath != "" {
			file, err := os.Open(filePath)
			if err != nil {
				log.Fatalf("Error abriendo el archivo de targets: %v", err)
			}
			defer file.Close()
			s := bufio.NewScanner(file)
			for s.Scan() {
				line := strings.TrimSpace(s.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					targets = append(targets, line)
				}
			}
		}
		targets = append(targets, args...)

		if len(targets) == 0 {
			log.Fatalf("No se especificaron objetivos. Use --localnet, --file, o proporcione hosts en la línea de comandos.")
		}

		ips, err := network.ResolveTargets(targets, numeric)
		if err != nil {
			log.Fatalf("Error resolviendo targets: %v", err)
		}

		if !cmd.Flags().Changed("scan-timeout") {
			numHosts := len(ips)
			baseSendTime := time.Duration(numHosts) * interval * time.Duration(retry)
			finalHostTimeout := float64(hostTimeout) * math.Pow(backoffFactor, float64(retry-1))
			finalBuffer := time.Duration(finalHostTimeout) + 2*time.Second
			calculatedTimeout := baseSendTime + finalBuffer
			minTimeout := 5 * time.Second
			if calculatedTimeout < minTimeout {
				calculatedTimeout = minTimeout
			}
			scanTimeout = calculatedTimeout
			if verboseCount > 0 {
				log.Printf("Timeout de escaneo no especificado. Calculado automáticamente a: %v", scanTimeout)
			}
		}

		if random {
			var seed int64
			if randomSeed != 0 {
				seed = randomSeed
				if verboseCount >= 1 {
					log.Printf("Usando semilla de aleatorización proporcionada: %d", seed)
				}
			} else {
				seed = time.Now().UnixNano()
				if verboseCount >= 1 {
					log.Println("Usando semilla de aleatorización basada en el tiempo actual")
				}
			}
			r := rand.New(rand.NewSource(seed))
			if verboseCount >= 1 {
				log.Printf("Aleatorizando el orden de %d hosts...", len(ips))
			}
			r.Shuffle(len(ips), func(i, j int) {
				ips[i], ips[j] = ips[j], ips[i]
			})
		}
		if verboseCount >= 3 {
			log.Println("Lista de hosts a escanear:")
			for _, ip := range ips {
				fmt.Printf("- %s\n", ip.String())
			}
		}

		finalOUIPath := ouiFileDefaultName
		if cmd.Flags().Changed("ouifile") {
			finalOUIPath = ouiFilePath
		}
		if err := oui.EnsureFile(finalOUIPath, ouiURL, "OUI"); err != nil {
			log.Printf("Advertencia: Falló la gestión del archivo OUI: %v.", err)
		}

		finalIABPath := iabFileDefaultName
		if cmd.Flags().Changed("iabfile") {
			finalIABPath = iabFilePath
		}
		if err := oui.EnsureFile(finalIABPath, iabURL, "IAB"); err != nil {
			log.Printf("Advertencia: Falló la gestión del archivo IAB: %v.", err)
		}

		vendorDB, err := oui.NewVendorDB(finalOUIPath, finalIABPath, macFilePath, verboseCount)
		if err != nil {
			log.Fatalf("Error cargando la base de datos de vendedores: %v", err)
		}

		config := &scanner.Config{
			Interface:     iface,
			IPs:           ips,
			VendorDB:      vendorDB,
			ScanTimeout:   scanTimeout,
			HostTimeout:   hostTimeout,
			Retry:         retry,
			Interval:      interval,
			BackoffFactor: backoffFactor,
			ArpSPA:        finalArpSPA,
			Verbosity:     verboseCount,
			PcapSaveFile:  pcapSaveFile,
		}

		var f formatter.Formatter
		if jsonOutput {
			f = formatter.NewJSONFormatter()
		} else if csvOutput {
			f = formatter.NewCSVFormatter()
		} else if quiet {
			f = formatter.NewQuietFormatter()
		} else if plain {
			f = formatter.NewPlainFormatter(showRTT)
		} else {
			f = formatter.NewDefaultFormatter(showRTT)
		}

		// <-- INICIO BLOQUE MODIFICADO: LÓGICA DE LOGS CORREGIDA -->
		// Solo mostrar logs si la salida NO es para scripts (json, csv, plain, quiet)
		isScriptingOutput := jsonOutput || csvOutput || plain || quiet
		if !isScriptingOutput {
			log.Printf("Iniciando escaneo en la interfaz %s (%s)", config.Interface.Name, config.Interface.HardwareAddr)
			log.Printf("Objetivos a escanear: %d IPs", len(config.IPs))
			if arpSPA != "" {
				log.Printf("Usando IP de origen personalizada (SPA) para todos los paquetes: %s", finalArpSPA)
			} else {
				log.Println("Usando IP de origen dinámica para cada paquete (comportamiento por defecto).")
			}
			if pcapSaveFile != "" {
				log.Printf("Guardando respuestas ARP en el fichero pcap: %s", pcapSaveFile)
			}
		}
		// <-- FIN BLOQUE MODIFICADO -->

		resultsChan, err := scanner.StartScan(config)
		if err != nil {
			log.Fatalf("Error iniciando el escaneo: %v", err)
		}

		f.PrintHeader()

		seenIPs := make(map[string]string)
		seenMACs := make(map[string][]string)
		var conflictSummaries []string

		for result := range resultsChan {
			if previousMAC, found := seenIPs[result.IP]; found {
				if ignoreDups {
					// En modo no-script, loguear si la verbosidad es alta
					if !isScriptingOutput && verboseCount >= 1 {
						log.Printf("Respuesta duplicada/conflicto para %s (%s) ignorada.", result.IP, result.MAC)
					}
					continue
				}
				if previousMAC != result.MAC {
					result.Status = "(CONFLICT)"
					summary := fmt.Sprintf("%s está en uso por %s y %s", result.IP, previousMAC, result.MAC)
					conflictSummaries = append(conflictSummaries, summary)
				} else {
					result.Status = "(DUPLICATE)"
				}
			} else {
				seenIPs[result.IP] = result.MAC
			}

			ipsForMAC := seenMACs[result.MAC]
			isNewIPForThisMAC := true
			for _, seenIP := range ipsForMAC {
				if seenIP == result.IP {
					isNewIPForThisMAC = false
					break
				}
			}
			if isNewIPForThisMAC {
				seenMACs[result.MAC] = append(ipsForMAC, result.IP)
				if len(seenMACs[result.MAC]) > 1 && result.Status == "" {
					result.Status = "(Multi-IP)"
				}
			}

			f.PrintResult(result)
		}

		var multiIPSummaries []string
		for mac, seenIPsForMac := range seenMACs {
			if len(seenIPsForMac) > 1 {
				summary := fmt.Sprintf("MAC %s responde para múltiples IPs: %s", mac, strings.Join(seenIPsForMac, ", "))
				multiIPSummaries = append(multiIPSummaries, summary)
			}
		}

		f.PrintFooter(conflictSummaries, multiIPSummaries)

		// <-- INICIO BLOQUE MODIFICADO: LÓGICA DE LOGS CORREGIDA -->
		if !isScriptingOutput {
			log.Println("Escaneo completado.")
		}
		// <-- FIN BLOQUE MODIFICADO -->
	},
}

func init() {
	cobra.EnableCommandSorting = false
	rootCmd.PersistentFlags().SortFlags = false
	rootCmd.Flags().SortFlags = false

	rootCmd.PersistentFlags().StringVarP(&ifaceName, "interface", "i", "", "Usa la interfaz de red <s>. Si no se especifica, se auto-detecta.")
	rootCmd.PersistentFlags().DurationVar(&scanTimeout, "scan-timeout", 20*time.Second, "Establece un timeout global de <d> para el escaneo completo.\n(calculado automáticamente si no se especifica)")

	rootCmd.Flags().BoolVar(&useLocalnet, "localnet", false, "Escanea la red local de la interfaz especificada.")
	rootCmd.Flags().StringVarP(&filePath, "file", "f", "", "Lee los nombres de host o direcciones desde el archivo especificado s>.\nUn nombre o dirección IP por línea. Usa \"-\" para la entrada estándar.")
	rootCmd.Flags().BoolVarP(&numeric, "numeric", "N", false, "No realizar resolución de nombres de host (DNS).")

	rootCmd.Flags().DurationVarP(&hostTimeout, "host-timeout", "t", 500*time.Millisecond, "Establece el timeout inicial por host a <d> (e.g., 500ms, 1s).\nEste timeout es para el primer paquete enviado a cada host. Los timeouts\nsubsiguientes se multiplican por el factor de backoff.")
	rootCmd.Flags().IntVarP(&retry, "retry", "r", 2, "Establece el número total de intentos por host a <i>.\nUn valor de 1 significa que solo se envía un paquete (sin reintentos).")

	rootCmd.Flags().DurationVar(&interval, "interval", 1*time.Millisecond, "Establece el intervalo mínimo entre el envío de paquetes a <d>.\nEsto controla el ancho de banda de salida. Para un control más intuitivo,\nconsidere usar --bandwidth.")
	rootCmd.Flags().StringVarP(&bandwidth, "bandwidth", "B", "", "Establece el ancho de banda de salida deseado a <x> (e.g., 1M, 256k).\nEl valor es en bits/segundo. Soporta sufijos K, M, G (decimales).\nNo se puede usar junto con --interval.")
	rootCmd.Flags().Float64VarP(&backoffFactor, "backoff", "b", 1.5, "Establece el factor de backoff del timeout a <f>.\nEl timeout por host se multiplica por este factor después de cada reintento.")

	rootCmd.Flags().StringVar(&arpSPA, "arpspa", "", "Usa <a> como la dirección IP de origen en los paquetes ARP.\nPor defecto, se utiliza la dirección IP de la interfaz de salida.\nAlgunos sistemas operativos solo responden si la IP de origen\npertenece a su misma subred.")

	rootCmd.Flags().StringVarP(&ouiFilePath, "ouifile", "O", "", "Usa el fichero de mapeo OUI de IEEE a vendor s>.\nPor defecto, se busca 'oui.txt' y se descarga si no existe.")
	rootCmd.Flags().StringVar(&iabFilePath, "iabfile", "", "Usa el fichero de mapeo IAB de IEEE a vendor <a>.\nPor defecto, se busca 'iab.txt' y se descarga si no existe.")
	rootCmd.Flags().StringVar(&macFilePath, "macfile", "", "Usa el fichero personalizado de mapeo MAC/prefijo a vendor s>.")

	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Muestra solo salida mínima (IP y MAC).\nNo se realiza decodificación de protocolos y no se usan los ficheros de mapeo OUI.")
	rootCmd.Flags().BoolVarP(&plain, "plain", "x", false, "Muestra una salida simple que solo contiene los hosts que responden.\nSuprime la cabecera y el pie de página, útil para scripts.")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Muestra la salida completa en formato JSON.")
	rootCmd.Flags().BoolVar(&csvOutput, "csv", false, "Muestra la salida en formato CSV (Comma-Separated Values).")

	rootCmd.Flags().BoolVarP(&showRTT, "rtt", "D", false, "Muestra el tiempo de ida y vuelta (Round-Trip Time) del paquete.")
	rootCmd.Flags().StringVarP(&pcapSaveFile, "pcapsavefile", "W", "", "Guarda las respuestas ARP en un fichero pcap <s>.")
	rootCmd.Flags().BoolVarP(&ignoreDups, "ignoredups", "g", false, "No mostrar respuestas duplicadas.")
	rootCmd.Flags().StringVar(&colorMode, "color", "auto", "Controla el uso de color en la salida (auto, on, off).")

	rootCmd.Flags().BoolVarP(&random, "random", "R", false, "Aleatoriza el orden de los hosts en la lista de objetivos.\nEsto hace que los paquetes ARP se envíen en un orden aleatorio.")
	rootCmd.Flags().Int64Var(&randomSeed, "randomseed", 0, "Usa <i> como semilla para el generador de números pseudoaleatorios.\nÚtil para obtener un orden aleatorio reproducible. Solo efectivo con --random.")

	rootCmd.Flags().CountVarP(&verboseCount, "verbose", "v", "Muestra mensajes de progreso detallados.\nÚsalo más de una vez para mayor efecto (-v, -vv, -vvv):\n1: Muestra finalización de pasadas y hosts desconocidos.\n2: Muestra cada paquete enviado/recibido y el filtro pcap.\n3. Muestra la lista de hosts antes de iniciar el escaneo.")
	rootCmd.Flags().BoolVarP(&versionFlag, "version", "V", false, "Muestra la versión del programa y sale.")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func parseBandwidth(bwStr string) (int64, error) {
	if bwStr == "" {
		return 0, fmt.Errorf("el string de ancho de banda está vacío")
	}

	lowerBwStr := strings.ToLower(bwStr)
	var multiplier float64 = 1.0
	var numPart string

	if strings.HasSuffix(lowerBwStr, "g") {
		multiplier = 1e9
		numPart = strings.TrimSuffix(lowerBwStr, "g")
	} else if strings.HasSuffix(lowerBwStr, "m") {
		multiplier = 1e6
		numPart = strings.TrimSuffix(lowerBwStr, "m")
	} else if strings.HasSuffix(lowerBwStr, "k") {
		multiplier = 1e3
		numPart = strings.TrimSuffix(lowerBwStr, "k")
	} else {
		numPart = lowerBwStr
	}

	val, err := strconv.ParseFloat(numPart, 64)
	if err != nil {
		return 0, fmt.Errorf("parte numérica '%s' inválida: %w", numPart, err)
	}

	return int64(val * multiplier), nil
}
