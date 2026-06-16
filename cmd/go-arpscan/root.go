// cmd/go-arpscan/root.go
package main

import (
	"fmt"
	"go-arpscan/internal/cli"
	"go-arpscan/internal/config"
	"go-arpscan/internal/flagval"
	"go-arpscan/internal/runner"
	"log"
	"os"
	"path/filepath" // <--- NUEVO IMPORT
	"runtime/pprof"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// arpScanFlagAliases mapea nombres de flags largos del arp-scan original
// a los nombres canónicos usados en go-arpscan, para que un usuario
// de arp-scan pueda invocar el binario con su sintaxis habitual.
var arpScanFlagAliases = map[string]string{
	"timeout": "host-timeout",
}

// systemVendorCacheDir es la ubicación canónica para los ficheros OUI/IAB.
// Vive bajo /var/lib porque es persistente, escribible por root (el binario
// corre siempre como root) y compartida entre invocaciones con o sin
// `sudo -E` — el path no depende de $HOME, así que no se redescarga al
// alternar entre user y root.
const systemVendorCacheDir = "/var/lib/go-arpscan"

// resolveVendorPath devuelve la ruta del fichero OUI/IAB a usar. Recorre
// una jerarquía de candidatos y devuelve el primer existente; si ninguno
// existe, devuelve la ruta canónica donde EnsureFile descargará el fichero.
//
// Orden de búsqueda:
//  1. /var/lib/go-arpscan/<file>     ← cache propia, compartida sudo/no-sudo
//  2. ~/.config/go-arpscan/<file>    ← fallback usuario (sin root)
func resolveVendorPath(name string) string {
	canonical := filepath.Join(systemVendorCacheDir, name)

	candidates := []string{canonical}
	if cfgDir, err := os.UserConfigDir(); err == nil {
		candidates = append(candidates, filepath.Join(cfgDir, "go-arpscan", name))
	}

	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	// Ningún candidato existe: devolvemos la ruta canónica para que
	// EnsureFile cree el directorio y descargue ahí.
	return canonical
}

// normalizeFlagAliases permite aceptar nombres de flags alternativos
// (alias del arp-scan original) sin duplicar la definición.
func normalizeFlagAliases(_ *pflag.FlagSet, name string) pflag.NormalizedName {
	if alias, ok := arpScanFlagAliases[name]; ok {
		return pflag.NormalizedName(alias)
	}
	return pflag.NormalizedName(name)
}

var (
	version = "dev"

	// cfg es la configuración final, cargada y fusionada desde ficheros y flags.
	// Se rellena en el PersistentPreRun.
	// --- CORRECCIÓN CLAVE AQUÍ ---
	// Se inicializa la struct para evitar un pánico de puntero nulo en la función init().
	cfg = &config.ResolvedConfig{}

	// versionFlag se usa para comprobar si se ha solicitado la versión.
	versionFlag bool

	// cpuProfilePath activa pprof solo bajo demanda. Es cold path: no toca
	// las rutinas TX/RX ni introduce checks en el bucle caliente.
	cpuProfilePath string
)

var rootCmd = &cobra.Command{
	Use:   "go-arpscan [options] [hosts...]",
	Short: "go-arpscan is a fast, modern ARP network scanner written in Go.",
	Long: `Sends ARP packets to hosts on the local network and displays the replies.

Target hosts must be specified on the command line unless --file is used,
in which case targets are read from the specified file, or --localnet is used,
in which case targets are generated from the interface IP address and netmask.

Options can be defined in configuration files and profiles.
Priority is: Flags > Profile > Configuration > Defaults.

go-arpscan must be run as root.`,
	Example: `  sudo ./go-arpscan --localnet --progress
  sudo ./go-arpscan -I eth0 192.168.1.0/24
  sudo ./go-arpscan -I eth0 192.168.1.1-192.168.1.254
  sudo ./go-arpscan --file=hostlist.txt --json
  sudo ./go-arpscan --config=my_profile.yaml --localnet
  sudo ./go-arpscan --profile=stealth-scan-generic --localnet
  sudo ./go-arpscan -I eth0 --spoof 192.168.1.10 --gateway 192.168.1.1
  sudo ./go-arpscan --localnet --monitor --monitor-interval 5m
  sudo ./go-arpscan --detect-promisc 192.168.1.50
  sudo ./go-arpscan --localnet --monitor --detect-arp-spoofing --monitor-gateway 192.168.1.1`,

	// PersistentPreRun se ejecuta después de parsear los flags pero antes de Run.
	// Es el lugar ideal para cargar y validar la configuración.
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if versionFlag {
			fmt.Printf("go-arpscan version %s\n", version)
			os.Exit(0)
		}

		var err error
		// La variable global 'cfg' será reemplazada por la configuración completamente cargada.
		cfg, err = config.Load(cmd)
		if err != nil {
			log.Fatal(err)
		}

		if err := cli.ValidateFlags(cfg, args); err != nil {
			log.Fatal(err)
		}

		// Configurar el modo de color según la configuración resuelta
		switch cfg.ColorMode {
		case "off":
			color.NoColor = true
		case "on":
			color.NoColor = false
		case "auto":
			// El comportamiento por defecto de la librería es auto.
		default:
			log.Fatalf("Invalid value for --color: %s. Use 'auto', 'on', or 'off'.", cfg.ColorMode)
		}
	},

	// Run contiene la lógica principal de la aplicación.
	Run: func(cmd *cobra.Command, args []string) {
		if !cfg.UpdateVendors && os.Geteuid() != 0 {
			log.Fatal("This program must be run as root.")
		}

		if cpuProfilePath != "" {
			f, err := os.Create(cpuProfilePath)
			if err != nil {
				log.Fatalf("Could not create --cpuprofile %s: %v", cpuProfilePath, err)
			}
			if err := pprof.StartCPUProfile(f); err != nil {
				_ = f.Close()
				log.Fatalf("Could not start CPU profile: %v", err)
			}
			defer func() {
				pprof.StopCPUProfile()
				if err := f.Close(); err != nil {
					log.Printf("closing CPU profile: %v", err)
				}
			}()
		}

		// Creamos una instancia del Runner, el orquestador principal.
		appRunner, err := runner.New(cfg, args)
		if err != nil {
			log.Fatalf("Error initializing application: %v", err)
		}

		// Ejecutamos la lógica principal.
		if err := appRunner.Run(); err != nil {
			log.Fatalf("Runtime error: %v", err)
		}
	},
}

// Execute añade todos los comandos hijos al comando raíz y establece los flags apropiadamente.
// Esta función es llamada por main.main(). Solo debe ocurrir una vez.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Desactivamos el ordenamiento automático para mantener el orden lógico de los flags en la ayuda.
	cobra.EnableCommandSorting = false
	rootCmd.PersistentFlags().SortFlags = false
	rootCmd.Flags().SortFlags = false

	// Aceptamos alias de los flags largos del arp-scan original (e.g. --timeout -> --host-timeout)
	// para que un usuario veterano pueda usar la misma sintaxis sin sobresaltos.
	rootCmd.PersistentFlags().SetNormalizeFunc(normalizeFlagAliases)
	rootCmd.Flags().SetNormalizeFunc(normalizeFlagAliases)

	// --- LÓGICA DE DETECCIÓN DE DIRECTORIO DE CONFIGURACIÓN ---
	// El fichero OUI/IAB se resuelve buscando en una jerarquía de candidatos
	// (primer hit gana). Esto evita re-descargas cuando el binario se ejecuta
	// con/sin sudo (que cambia $HOME entre /home/<user> y /root).
	//
	// Orden de búsqueda:
	//   1. /var/lib/go-arpscan/<file>     ← cache propia (escribible como root, compartida)
	//   2. ~/.config/go-arpscan/<file>    ← fallback usuario
	//
	// Si nada existe, el default apunta a (1) y EnsureFile lo descargará allí.
	defaultOUI := resolveVendorPath("oui.txt")
	defaultIAB := resolveVendorPath("iab.txt")
	// ---------------------------------------------------------

	// --- Gestión de Configuración y Perfiles ---
	rootCmd.PersistentFlags().String("config", "", "Path to the YAML configuration file (defaults to ~/.config/go-arpscan/config.yaml).")
	rootCmd.PersistentFlags().String("profiles", "", "Path to the YAML profiles file (searches ./ and ~/.config/go-arpscan/).")
	rootCmd.PersistentFlags().String("profile", "", "Enable a tactical profile from the profiles file (e.g., 'stealth-scan-generic').")

	// --- Selección de Interfaz y Objetivos ---
	rootCmd.PersistentFlags().StringP("interface", "I", "", "Use network interface <s>. If omitted, it is auto-detected.")
	rootCmd.PersistentFlags().Duration("scan-timeout", 20*time.Second, "Set a global timeout <d> for the full scan.\n(computed automatically if omitted)")
	rootCmd.Flags().BoolP("localnet", "l", false, "Scan the local network of the selected interface.")
	rootCmd.Flags().StringP("file", "f", "", "Read hostnames or addresses from file <s>.\nOne hostname or IP address per line. Use \"-\" for standard input.")
	rootCmd.Flags().StringSlice("exclude", nil, "Exclude IPs or CIDR ranges from the scan (e.g., --exclude 1.1.1.1,1.1.2.0/24).")
	rootCmd.Flags().String("exclude-file", "", "Exclude targets listed in file <s>.")
	rootCmd.Flags().Bool("exclude-broadcast", false, "Exclude network and broadcast addresses from CIDR, network:mask, and --localnet targets.")
	rootCmd.Flags().BoolP("numeric", "N", false, "Do not perform hostname resolution (DNS).")

	// --- Control del Escaneo ---
	rootCmd.Flags().VarP(flagval.NewMillis(500*time.Millisecond), "host-timeout", "t", "Set the initial per-host timeout to <d>.\nAccepts a Go duration (e.g. 500ms, 1s) or a plain integer of milliseconds\n(e.g. 500, arp-scan style). This timeout applies to the first packet sent to\neach host. Later timeouts are multiplied by the backoff factor.")
	rootCmd.Flags().IntP("retry", "r", 2, "Set the total number of attempts per host to <i>.\nA value of 1 means only one packet is sent (no retries).")
	rootCmd.Flags().VarP(flagval.NewInterval(1*time.Millisecond), "interval", "i", "Set the minimum interval between sent packets to <d>.\nAccepts a Go duration (e.g. 1ms, 500us) or arp-scan style (10=ms, 500u=µs, 2s=s).\nThis controls outbound bandwidth. For a more intuitive control,\nconsider using --bandwidth.")
	rootCmd.Flags().StringP("bandwidth", "B", "", "Set the desired outbound bandwidth to <x> (e.g., 1M, 256k).\nThe value is in bits/second. Supports decimal K, M, G suffixes.\nCannot be used together with --interval.")
	rootCmd.Flags().Float64P("backoff", "b", 1.5, "Set the timeout backoff factor to <f>.\nThe per-host timeout is multiplied by this factor after each retry.")
	rootCmd.Flags().BoolP("random", "R", false, "Randomize target host order.\nThis sends ARP packets in random order.")
	rootCmd.Flags().Int64("randomseed", 0, "Use <i> as the pseudo-random generator seed.\nUseful for reproducible random order. Only effective with --random.")

	// --- Explotación Activa ---
	rootCmd.Flags().String("spoof", "", "Enable ARP spoofing mode against a target IP.")
	rootCmd.Flags().String("gateway", "", "Set the gateway IP for the spoofing attack (--spoof).")
	rootCmd.Flags().String("detect-promisc", "", "Detect whether a host is in promiscuous mode by sending an ARP packet with an incorrect destination MAC.")
	rootCmd.Flags().Duration("spoof-interval", 2*time.Second, "Interval between packets in spoofing mode.")
	rootCmd.Flags().Duration("spoof-mac-timeout", 3*time.Second, "Timeout for resolving MAC addresses in spoofing mode.")
	rootCmd.Flags().Duration("spoof-restore-duration", 1*time.Second, "Duration of the ARP cache restoration phase.")
	rootCmd.Flags().Duration("spoof-restore-interval", 100*time.Millisecond, "Packet interval during ARP cache restoration.")

	// --- Manipulación de Paquetes (Avanzado) ---
	rootCmd.Flags().StringP("arpspa", "s", "", "Use <a> as the source IP address in ARP packets.\nBy default, the outgoing interface IP address is used.\nSome operating systems only reply if the source IP belongs\nto their subnet. Special value: \"dest\" uses the target IP.")
	rootCmd.Flags().StringP("arpsha", "u", "", "Use <m> as the source MAC address in ARP packets (SHA).\nBy default, the outgoing interface MAC address is used.")
	rootCmd.Flags().StringP("srcaddr", "S", "", "Use <m> as the source MAC address in the Ethernet frame.\nBy default, the outgoing interface MAC address is used.")
	rootCmd.Flags().IntP("arpop", "o", 1, "Set the ARP operation code to <i>.\n1=Request (default), 2=Reply.")
	rootCmd.Flags().StringP("destaddr", "T", "", "Use <m> as the destination MAC address in the Ethernet frame.\nBy default, the broadcast address is used (ff:ff:ff:ff:ff:ff).")
	rootCmd.Flags().StringP("arptha", "w", "", "Use <m> as the destination MAC address in the ARP packet (THA).\nBy default, a zero MAC is used (00:00:00:00:00:00).")
	rootCmd.Flags().StringP("prototype", "y", "0x0806", "Set the Ethernet protocol type to <i> (e.g., 0x0806).\nDefault is 0x0806 (ARP).")
	rootCmd.Flags().IntP("arphrd", "H", 1, "Use <i> as the ARP hardware type (ar$hrd).\nThe normal value is 1 (Ethernet).")
	rootCmd.Flags().StringP("arppro", "p", "0x0800", "Use <i> as the ARP protocol type (ar$pro) (e.g., 0x0800).\nDefault is 0x0800 (IPv4).")
	rootCmd.Flags().IntP("arphln", "a", 6, "Set the hardware address length to <i> (ar$hln).\nDefault is 6 for Ethernet.")
	rootCmd.Flags().IntP("arppln", "P", 4, "Set the protocol address length to <i> (ar$pln).\nDefault is 4 for IPv4.")
	rootCmd.Flags().StringP("padding", "A", "", "Append padding data in hexadecimal format <h> to the end of the packet.")
	rootCmd.Flags().BoolP("llc", "L", false, "Use RFC 1042 LLC framing with SNAP.")
	rootCmd.Flags().IntP("vlan", "Q", -1, "Set the 802.1Q VLAN ID <i> (0-4095). Default -1 disables VLAN tagging.")
	rootCmd.Flags().IntP("snap", "n", 65536, "Set the pcap capture length to <i> bytes.")

	// --- Monitorización Continua ---
	rootCmd.Flags().Bool("monitor", false, "Enable monitor mode to detect network changes in real time.")
	rootCmd.Flags().Duration("monitor-interval", 5*time.Minute, "Interval for active probes in monitor mode (e.g., '10m', '1h').")
	rootCmd.Flags().Duration("monitor-removal-threshold", 15*time.Minute, "Inactivity duration before a host is considered removed in monitor mode.")
	// <<< INICIO DE NUEVOS FLAGS PARA DETECCIÓN DE SPOOFING >>>
	rootCmd.Flags().Bool("detect-arp-spoofing", false, "Enable ARP spoofing detection in monitor mode. Requires --monitor-gateway.")
	rootCmd.Flags().String("monitor-gateway", "", "Gateway IP to protect with --detect-arp-spoofing.")
	// <<< FIN DE NUEVOS FLAGS PARA DETECCIÓN DE SPOOFING >>>
	rootCmd.Flags().String("webhook-url", "", "Webhook URL for sending monitor-mode events.")
	rootCmd.Flags().StringSlice("webhook-header", nil, "HTTP header for the webhook request (e.g., 'Auth: Bearer ...'). Can be repeated.")

	// --- Ficheros de Datos y Vendors ---
	// MODIFICACIÓN: Usamos las rutas por defecto calculadas al inicio de init()
	rootCmd.Flags().StringP("ouifile", "O", defaultOUI, "Use the IEEE OUI-to-vendor mapping file <s>.\nBy default, "+defaultOUI+" is searched and downloaded if missing.")
	rootCmd.Flags().String("iabfile", defaultIAB, "Use the IEEE IAB-to-vendor mapping file <s>.\nBy default, "+defaultIAB+" is searched and downloaded if missing.")
	rootCmd.Flags().String("macfile", "", "Use a custom MAC/prefix-to-vendor mapping file <s>.")
	rootCmd.Flags().Bool("update-vendors", false, "Update OUI/IAB from IEEE, regenerate the binary OUI index, and exit.")

	// --- Formato de Salida y UI ---
	rootCmd.Flags().BoolP("quiet", "q", false, "Show minimal output only (IP and MAC).\nProtocol decoding is skipped and OUI mapping files are not used.")
	rootCmd.Flags().BoolP("plain", "x", false, "Show simple output containing only responding hosts.\nSuppresses header and footer, useful for scripts.")
	rootCmd.Flags().Bool("json", false, "Show full output in JSON format.")
	rootCmd.Flags().Bool("csv", false, "Show output in CSV (Comma-Separated Values) format.")
	rootCmd.Flags().String("state-file", "", "Save scan results to JSON state file <s>.\nWhen used without --diff, standard output is suppressed.")
	rootCmd.Flags().Bool("diff", false, "Compare a new scan with the state file specified by --state-file\nand show differences (added, removed, or modified hosts).")
	rootCmd.Flags().Bool("progress", false, "Show a progress bar during the scan.")
	rootCmd.Flags().BoolP("rtt", "D", false, "Show packet round-trip time (RTT).")
	rootCmd.Flags().StringP("pcapsavefile", "W", "", "Save ARP replies to pcap file <s>.")
	rootCmd.Flags().BoolP("ignoredups", "g", false, "Do not show duplicate replies.")
	rootCmd.Flags().String("color", "auto", "Control color output (auto, on, off).")

	// --- Varios ---
	rootCmd.Flags().CountVarP(&cfg.VerboseCount, "verbose", "v", "Show detailed progress messages.\nUse more than once for more detail (-v, -vv, -vvv):\n1: Show pass completion and unknown hosts.\n2: Show each sent/received packet and the pcap filter.\n3: Show the host list before starting the scan.")
	rootCmd.Flags().Bool("fast", false, "Use the zero-allocation AF_PACKET engine (Linux only, scan/diff modes).\nFaster and lower-overhead than the default pcap/gopacket engine.\nIncompatible with --vlan, --llc, --padding, --pcapsavefile and advanced ARP overrides;\nin those cases it automatically falls back to the standard engine.")
	rootCmd.Flags().StringVar(&cpuProfilePath, "cpuprofile", "", "Write a CPU pprof profile to <file> during execution.\nCold diagnostic path; use with --fast to decide whether TX_RING is worthwhile.")
	rootCmd.Flags().BoolVarP(&versionFlag, "version", "V", false, "Show program version and exit.")
}
