// cmd/go-arpscan/root.go
package main

import (
	"fmt"
	"go-arpscan/internal/cli"
	"go-arpscan/internal/config"
	"go-arpscan/internal/runner"
	"log"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	version = "dev"

	// cfg es la configuración final, cargada y fusionada desde ficheros y flags.
	// Se rellena en el PersistentPreRun.
	// --- CORRECCIÓN CLAVE AQUÍ ---
	// Se inicializa la struct para evitar un pánico de puntero nulo en la función init().
	cfg = &config.ResolvedConfig{}

	// versionFlag se usa para comprobar si se ha solicitado la versión.
	versionFlag bool
)

var rootCmd = &cobra.Command{
	Use:   "go-arpscan [options] [hosts...]",
	Short: "go-arpscan es un escáner de red ARP rápido y moderno escrito en Go.",
	Long: `Envía paquetes ARP a los hosts de la red local y muestra las respuestas recibidas.

Los hosts de destino deben especificarse en la línea de comandos a menos que se use la opción --file,
en cuyo caso los destinos se leen desde el archivo especificado, o si se usa la opción --localnet,
en cuyo caso los destinos se generan a partir de la dirección IP y la máscara de red de la interfaz.

Las opciones se pueden definir en ficheros de configuración y perfiles.
La prioridad es: Flags > Perfil > Configuración > Defaults.

Es necesario ejecutar go-arpscan como root.`,
	Example: `  sudo ./go-arpscan --localnet --progress
  sudo ./go-arpscan -i eth0 192.168.1.0/24
  sudo ./go-arpscan -i eth0 192.168.1.1-192.168.1.254
  sudo ./go-arpscan --file=hostlist.txt --json
  sudo ./go-arpscan --config=mi_perfil.yaml --localnet
  sudo ./go-arpscan --profile=stealth-scan-generic --localnet
  sudo ./go-arpscan -i eth0 --spoof 192.168.1.10 --gateway 192.168.1.1
  sudo ./go-arpscan --localnet --monitor --monitor-interval 5m
  sudo ./go-arpscan --detect-promisc 192.168.1.50`,

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
			log.Fatalf("Valor inválido para --color: %s. Use 'auto', 'on', o 'off'.", cfg.ColorMode)
		}
	},

	// Run contiene la lógica principal de la aplicación.
	Run: func(cmd *cobra.Command, args []string) {
		if os.Geteuid() != 0 {
			log.Fatal("Este programa debe ser ejecutado como root.")
		}

		// Creamos una instancia del Runner, el orquestador principal.
		appRunner, err := runner.New(cfg, args)
		if err != nil {
			log.Fatalf("Error inicializando la aplicación: %v", err)
		}

		// Ejecutamos la lógica principal.
		if err := appRunner.Run(); err != nil {
			log.Fatalf("Error durante la ejecución: %v", err)
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

	// --- Gestión de Configuración y Perfiles ---
	rootCmd.PersistentFlags().String("config", "", "Ruta al fichero de configuración YAML (por defecto ~/.config/go-arpscan/config.yaml).")
	rootCmd.PersistentFlags().String("profiles", "", "Ruta al fichero de perfiles YAML (busca en ./ y ~/.config/go-arpscan/).")
	rootCmd.PersistentFlags().String("profile", "", "Activa un perfil táctico desde el fichero de perfiles (e.g., 'stealth-scan-generic').")

	// --- Selección de Interfaz y Objetivos ---
	rootCmd.PersistentFlags().StringP("interface", "i", "", "Usa la interfaz de red <s>. Si no se especifica, se auto-detecta.")
	rootCmd.PersistentFlags().Duration("scan-timeout", 20*time.Second, "Establece un timeout global de <d> para el escaneo completo.\n(calculado automáticamente si no se especifica)")
	rootCmd.Flags().Bool("localnet", false, "Escanea la red local de la interfaz especificada.")
	rootCmd.Flags().StringP("file", "f", "", "Lee los nombres de host o direcciones desde el archivo especificado s>.\nUn nombre o dirección IP por línea. Usa \"-\" para la entrada estándar.")
	rootCmd.Flags().StringSlice("exclude", nil, "Excluye IPs o rangos CIDR del escaneo (e.g., --exclude 1.1.1.1,1.1.2.0/24).")
	rootCmd.Flags().String("exclude-file", "", "Excluye los objetivos listados en el fichero especificado <s>.")
	rootCmd.Flags().BoolP("numeric", "N", false, "No realizar resolución de nombres de host (DNS).")

	// --- Control del Escaneo ---
	rootCmd.Flags().DurationP("host-timeout", "t", 500*time.Millisecond, "Establece el timeout inicial por host a <d> (e.g., 500ms, 1s).\nEste timeout es para el primer paquete enviado a cada host. Los timeouts\nsubsiguientes se multiplican por el factor de backoff.")
	rootCmd.Flags().IntP("retry", "r", 2, "Establece el número total de intentos por host a <i> .\nUn valor de 1 significa que solo se envía un paquete (sin reintentos).")
	rootCmd.Flags().Duration("interval", 1*time.Millisecond, "Establece el intervalo mínimo entre el envío de paquetes a <d>.\nEsto controla el ancho de banda de salida. Para un control más intuitivo,\nconsidere usar --bandwidth.")
	rootCmd.Flags().StringP("bandwidth", "B", "", "Establece el ancho de banda de salida deseado a <x> (e.g., 1M, 256k).\nEl valor es en bits/segundo. Soporta sufijos K, M, G (decimales).\nNo se puede usar junto con --interval.")
	rootCmd.Flags().Float64P("backoff", "b", 1.5, "Establece el factor de backoff del timeout a <f>.\nEl timeout por host se multiplica por este factor después de cada reintento.")
	rootCmd.Flags().BoolP("random", "R", false, "Aleatoriza el orden de los hosts en la lista de objetivos.\nEsto hace que los paquetes ARP se envíen en un orden aleatorio.")
	rootCmd.Flags().Int64("randomseed", 0, "Usa <i> como semilla para el generador de números pseudoaleatorios.\nÚtil para obtener un orden aleatorio reproducible. Solo efectivo con --random.")

	// --- Explotación Activa ---
	rootCmd.Flags().String("spoof", "", "Activa el modo de suplantación ARP contra una IP objetivo.")
	rootCmd.Flags().String("gateway", "", "Especifica la IP del gateway para el ataque de suplantación (--spoof).")
	rootCmd.Flags().String("detect-promisc", "", "Detecta si un host está en modo promiscuo enviando un paquete ARP con MAC de destino incorrecta.")
	// <<< INICIO DE NUEVOS FLAGS PARA SPOOFING >>>
	rootCmd.Flags().Duration("spoof-interval", 2*time.Second, "Intervalo entre paquetes en el modo de suplantación.")
	rootCmd.Flags().Duration("spoof-mac-timeout", 3*time.Second, "Timeout para obtener las MACs en el modo de suplantación.")
	rootCmd.Flags().Duration("spoof-restore-duration", 1*time.Second, "Duración de la fase de restauración de caché ARP.")
	rootCmd.Flags().Duration("spoof-restore-interval", 100*time.Millisecond, "Intervalo de los paquetes de restauración de caché ARP.")
	// <<< FIN DE NUEVOS FLAGS PARA SPOOFING >>>

	// --- Manipulación de Paquetes (Avanzado) ---
	rootCmd.Flags().StringP("arpspa", "s", "", "Usa <a> como la dirección IP de origen en los paquetes ARP.\nPor defecto, se utiliza la dirección IP de la interfaz de salida.\nAlgunos sistemas operativos solo responden si la IP de origen\npertenece a su misma subred. Valor especial: \"dest\" para usar la IP de destino.")
	rootCmd.Flags().StringP("arpsha", "u", "", "Usa <m> como la dirección MAC de origen en los paquetes ARP (SHA).\nPor defecto, se utiliza la MAC de la interfaz de salida.")
	rootCmd.Flags().StringP("srcaddr", "S", "", "Usa <m> como la dirección MAC de origen de la trama Ethernet.\nPor defecto, se utiliza la MAC de la interfaz de salida.")
	rootCmd.Flags().IntP("arpop", "o", 1, "Especifica el código de operación ARP <i> .\n1=Request (por defecto), 2=Reply.")
	rootCmd.Flags().StringP("destaddr", "T", "", "Usa <m> como la dirección MAC de destino de la trama Ethernet.\nPor defecto, se usa la dirección de broadcast (ff:ff:ff:ff:ff:ff).")
	rootCmd.Flags().StringP("arptha", "w", "", "Usa <m> como la dirección MAC de destino en el paquete ARP (THA).\nPor defecto, se usa una dirección cero (00:00:00:00:00:00).")
	rootCmd.Flags().StringP("prototype", "y", "0x0806", "Establece el tipo de protocolo Ethernet a <i> (e.g., 0x0806).\nPor defecto es 0x0806 (ARP).")
	rootCmd.Flags().IntP("arphrd", "H", 1, "Usa <i> para el tipo de hardware ARP (ar$hrd).\nEl valor normal es 1 (Ethernet).")
	rootCmd.Flags().StringP("arppro", "p", "0x0800", "Usa <i> para el tipo de protocolo ARP (ar$pro) (e.g., 0x0800).\nPor defecto es 0x0800 (IPv4).")
	rootCmd.Flags().IntP("arphln", "a", 6, "Establece la longitud de la dirección de hardware a <i> (ar$hln).\nPor defecto es 6 para Ethernet.")
	rootCmd.Flags().IntP("arppln", "P", 4, "Establece la longitud de la dirección de protocolo a <i> (ar$pln).\nPor defecto es 4 para IPv4.")
	rootCmd.Flags().StringP("padding", "A", "", "Añade datos de relleno (padding) en formato hexadecimal <h> al final del paquete.")
	rootCmd.Flags().BoolP("llc", "L", false, "Usa framing RFC 1042 LLC con SNAP.")
	rootCmd.Flags().IntP("vlan", "Q", 0, "Especifica el ID de VLAN 802.1Q <i> (1-4094).")
	rootCmd.Flags().IntP("snap", "n", 65536, "Establece la longitud de captura pcap a <i> bytes.")

	// --- Monitorización Continua ---
	rootCmd.Flags().Bool("monitor", false, "Activa el modo monitor para detectar cambios en la red en tiempo real.")
	rootCmd.Flags().Duration("monitor-interval", 5*time.Minute, "Intervalo para los sondeos activos en modo monitor (e.g., '10m', '1h').")
	rootCmd.Flags().Duration("monitor-removal-threshold", 15*time.Minute, "Tiempo de inactividad antes de que un host sea considerado 'eliminado' en modo monitor.")
	rootCmd.Flags().String("webhook-url", "", "URL del webhook para enviar eventos en modo monitor.")
	rootCmd.Flags().StringSlice("webhook-header", nil, "Cabecera HTTP para la petición webhook (e.g., 'Auth: Bearer ...'). Se puede repetir.")

	// --- Ficheros de Datos y Vendors ---
	rootCmd.Flags().StringP("ouifile", "O", "oui.txt", "Usa el fichero de mapeo OUI de IEEE a vendor s>.\nPor defecto, se busca 'oui.txt' y se descarga si no existe.")
	rootCmd.Flags().String("iabfile", "iab.txt", "Usa el fichero de mapeo IAB de IEEE a vendor a>.\nPor defecto, se busca 'iab.txt' y se descarga si no existe.")
	rootCmd.Flags().String("macfile", "", "Usa el fichero personalizado de mapeo MAC/prefijo a vendor s>.")

	// --- Formato de Salida y UI ---
	rootCmd.Flags().BoolP("quiet", "q", false, "Muestra solo salida mínima (IP y MAC).\nNo se realiza decodificación de protocolos y no se usan los ficheros de mapeo OUI.")
	rootCmd.Flags().BoolP("plain", "x", false, "Muestra una salida simple que solo contiene los hosts que responden.\nSuprime la cabecera y el pie de página, útil para scripts.")
	rootCmd.Flags().Bool("json", false, "Muestra la salida completa en formato JSON.")
	rootCmd.Flags().Bool("csv", false, "Muestra la salida en formato CSV (Comma-Separated Values).")
	rootCmd.Flags().String("state-file", "", "Guarda los resultados del escaneo en un fichero de estado JSON s>.\nSi se usa sin --diff, suprime la salida estándar.")
	rootCmd.Flags().Bool("diff", false, "Compara un nuevo escaneo con el fichero de estado especificado en --state-file\ny muestra las diferencias (hosts añadidos, eliminados o modificados).")
	rootCmd.Flags().Bool("progress", false, "Muestra una barra de progreso durante el escaneo.")
	rootCmd.Flags().BoolP("rtt", "D", false, "Muestra el tiempo de ida y vuelta (Round-Trip Time) del paquete.")
	rootCmd.Flags().StringP("pcapsavefile", "W", "", "Guarda las respuestas ARP en un fichero pcap <s>.")
	rootCmd.Flags().BoolP("ignoredups", "g", false, "No mostrar respuestas duplicadas.")
	rootCmd.Flags().String("color", "auto", "Controla el uso de color en la salida (auto, on, off).")

	// --- Varios ---
	rootCmd.Flags().CountVarP(&cfg.VerboseCount, "verbose", "v", "Muestra mensajes de progreso detallados.\nÚsalo más de una vez para mayor efecto (-v, -vv, -vvv):\n1: Muestra finalización de pasadas y hosts desconocidos.\n2: Muestra cada paquete enviado/recibido y el filtro pcap.\n3. Muestra la lista de hosts antes de iniciar el escaneo.")
	rootCmd.Flags().BoolVarP(&versionFlag, "version", "V", false, "Muestra la versión del programa y sale.")
}
