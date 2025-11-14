# go-arpscan

Un escáner de red ARP rápido, moderno y concurrente escrito en Go, inspirado en el clásico `arp-scan` pero con mejoras de usabilidad, diagnóstico y capacidades de seguridad ofensiva.

## Descripción

`go-arpscan` envía paquetes ARP a los hosts de la red local para descubrir dispositivos activos, recopilar sus direcciones IP y MAC, e incluso realizar ataques de suplantación para auditorías de seguridad. Aprovecha la concurrencia de Go para escanear redes de forma extremadamente rápida, incluso con un gran número de hosts.

## Características Principales

*   🚀 **Escaneo Concurrente de Alto Rendimiento**: Utiliza goroutines para enviar y recibir paquetes ARP a gran velocidad.
*   📡 **Monitorización Continua de Red (`--monitor`)**: Opera como un sensor de red persistente, combinando escucha pasiva y sondeos activos para detectar nuevos dispositivos, conflictos de IP y hosts desconectados en tiempo real, generando una salida de eventos en formato JSON.
*   🛡️ **Detección de Suplantación ARP (`--detect-arp-spoofing`)**: En modo monitor, vigila activamente la MAC del gateway y genera alertas de alta severidad si detecta un intento de suplantación.
*   ⚔️ **Módulo de Ataque Man-in-the-Middle**: Realiza ataques de suplantación ARP (`--spoof`) para interceptar tráfico entre dos objetivos, con gestión automática del reenvío de paquetes y limpieza segura.
*   ✨ **Auto-Detección Inteligente**: Detecta automáticamente la interfaz de red a utilizar si no se especifica una.
*   ⚙️ **Gestión Centralizada con Ficheros de Configuración**:
    *   **Preferencias Personales (`config.yaml`)**: Define tus opciones por defecto (interfaz, timeouts, etc.) para simplificar la ejecución de comandos recurrentes.
    *   **Perfiles Tácticos (`profiles.yaml`)**: Activa conjuntos complejos de parámetros para mimetismo, evasión o pruebas de seguridad con un solo flag (`--profile <nombre>`).
*   📊 **Auditoría de Red**: Guarda instantáneas del estado de la red y compara escaneos para detectar dispositivos nuevos, eliminados o modificados (`--diff`).
*   🎯 **Precisión Quirúrgica con Listas de Exclusión**: Evita el escaneo de sistemas críticos (`--exclude`, `--exclude-file`) para operar siempre dentro de las Reglas del Enfrentamiento.
*   🔔 **Integración con Ecosistemas de SecOps (`--webhook-url`)**: Notifica eventos del modo monitor en tiempo real a Slack, plataformas SOAR o cualquier endpoint HTTP, con soporte para cabeceras de autenticación (`--webhook-header`).
*   🎨 **Salida Coloreada y Alineada**: Formato de salida moderno y legible, con control total sobre los colores (`--color=auto|on|off`).
*   📜 **Salida Estructurada**: Soporte nativo para `--json` y `--csv`, facilitando la integración con scripts y herramientas de análisis.
*   🌐 **Gestión Automática de Vendors**: Descarga automáticamente los ficheros OUI e IAB de la IEEE si no se encuentran localmente.
*   🔍 **Diagnóstico de Red Avanzado**:
    *   Detecta y reporta **Conflictos de IP** (una misma IP usada por varias MACs).
    *   Detecta y reporta dispositivos **Multi-IP** (una misma MAC respondiendo para varias IPs).
    *   Diferencia claramente las respuestas **Duplicadas**.
*   **Análisis Forense**: Guarda las respuestas de red en ficheros `pcap` para su análisis detallado en herramientas como Wireshark.
*   🎯 **Flexibilidad en los Objetivos**: Soporta IPs individuales, rangos (`192.168.1.1-192.168.1.254`) y notación CIDR (`192.168.1.0/24`).
*   ⚙️ **Control Total del Escaneo**: Parámetros configurables para timeouts, reintentos, ancho de banda, aleatorización y más.

## Instalación

### Opción 1: Binarios Pre-compilados (Recomendado)

Descarga el binario para tu sistema operativo y arquitectura desde la [página de Releases](https://github.com/soyunomas/go-arpscan/releases).

### Opción 2: Desde Fuente

Necesitas tener [Go](https://golang.org/doc/install) (versión 1.18 o superior) instalado.

```bash
# 1. Clona el repositorio
git clone https://github.com/soyunomas/go-arpscan.git
cd go-arpscan

# 2. Compila el binario
# (El flag -ldflags inyecta el número de versión)
go build -ldflags "-X main.version=1.1.0" -o go-arpscan ./cmd/go-arpscan

# 3. (Opcional) Mueve el binario a tu PATH para un acceso global
sudo mv go-arpscan /usr/local/bin/
```

**Nota**: `go-arpscan` necesita privilegios de `root` para funcionar, ya que accede a funcionalidades de red a bajo nivel. Utilízalo siempre con `sudo`.

## Uso Básico y Ejemplos

### Descubrimiento y Escaneo

```bash
# Escanear la red local automáticamente detectada con una barra de progreso
sudo ./go-arpscan --localnet --progress

# Escanear una subred completa usando notación CIDR y especificando la interfaz
sudo ./go-arpscan -i eno1 192.168.24.0/24

# Escanear una subred excluyendo el servidor de backups
sudo ./go-arpscan 192.168.24.0/24 --exclude 192.168.24.10

# Escanear un rango, mostrar RTT y guardar las respuestas para análisis en Wireshark
sudo ./go-arpscan -i eno1 -D -W scan_results.pcap 192.168.24.1-192.168.24.100

# Usar un perfil táctico para un escaneo sigiloso, evadiendo la detección
sudo ./go-arpscan --profile stealth-scan-generic --localnet

# Obtener los resultados en formato JSON y procesarlos con jq
sudo ./go-arpscan --localnet --json | jq '.results[] | {ip, mac, vendor}'

# Guardar los resultados en un fichero CSV para analizarlos en una hoja de cálculo
sudo ./go-arpscan --localnet --csv > network_scan.csv
```

### Auditoría y Detección de Cambios

`go-arpscan` puede guardar una instantánea de la red y compararla con escaneos futuros para auditar cambios.

```bash
# Paso 1: Realizar un escaneo inicial y guardarlo como la "línea base"
sudo ./go-arpscan --localnet --state-file network_baseline.json

# Paso 2: Días después, ejecutar un nuevo escaneo en modo 'diff' para ver qué ha cambiado.
# Se mostrarán los hosts añadidos, eliminados o cuya MAC ha cambiado.
sudo ./go-arpscan --localnet --diff --state-file network_baseline.json --progress
```

### Monitorización Continua e Integración con Webhooks

Activa el modo `--monitor` para convertir `go-arpscan` en un sensor de red. La herramienta realizará un escaneo inicial y luego monitorizará el tráfico ARP y realizará sondeos periódicos para detectar cambios. La salida es una secuencia de eventos en formato JSON, ideal para ser procesada por otras herramientas.

```bash
# Monitorizar la red local con sondeos activos cada 10 minutos y enviar alertas a un webhook
sudo ./go-arpscan --localnet --monitor --monitor-interval 10m \
  --webhook-url "https://hooks.slack.com/services/T000/B000/XXXX" \
  --webhook-header "Content-Type: application/json"

# Monitorizar la red y activar la detección de suplantación para el gateway 192.168.1.1
sudo ./go-arpscan --localnet --monitor --detect-arp-spoofing --monitor-gateway 192.168.1.1

# Ejemplo de procesamiento de eventos en tiempo real con jq
sudo ./go-arpscan --localnet --monitor | jq -r \
  'select(.event == "NEW_HOST") | "NUEVO HOST ==> IP: \(.ip), MAC: \(.mac), Vendor: \(.vendor)"'
```

### Explotación Activa (Ataque Man-in-the-Middle)

**ADVERTENCIA:** Usa esta funcionalidad de forma ética y solo en redes para las que tengas permiso explícito.

```bash
# Ataque estándar: Interceptar el tráfico entre el host 192.168.1.100 y el gateway 192.168.1.1
# La herramienta gestiona el reenvío de paquetes para que la víctima no pierda la conexión.
sudo ./go-arpscan -i eno1 --spoof 192.168.1.100 --gateway 192.168.1.1

# Ataque sigiloso: Interceptar el tráfico con menos frecuencia para evitar la detección
# Los paquetes de envenenamiento se envían cada 30 segundos en lugar de cada 2.
sudo ./go-arpscan -i eno1 --spoof 192.168.1.100 --gateway 192.168.1.1 --spoof-interval 30s
```
*En otra terminal, puedes usar `wireshark` o `tcpdump` para ver el tráfico interceptado en la interfaz `eno1`.*

### Una Nota Importante sobre las Pruebas de Seguridad

Al probar funcionalidades de ataque (`--spoof`) y defensa (`--detect-arp-spoofing`), es crucial utilizar un **entorno de red realista con al menos dos máquinas distintas** (un atacante y una víctima/sensor).

Realizar una prueba donde el atacante y la víctima son la misma máquina puede llevar a resultados inesperados. El kernel del sistema operativo, en un esfuerzo por ser eficiente, puede procesar los paquetes de red destinados a sí mismo internamente (vía loopback), evitando que salgan a la tarjeta de red física. Como resultado, un sensor que escucha en la tarjeta física (como `go-arpscan`) nunca verá el tráfico del ataque.

Para una prueba fiable, siempre use una máquina separada (o una máquina virtual con su propia identidad de red) para lanzar el ataque contra la máquina donde se ejecuta el sensor.

## Ficheros de Configuración

`go-arpscan` soporta el uso de ficheros de configuración en formato YAML para establecer valores por defecto, simplificando la ejecución de escaneos recurrentes.

**Prioridad de Configuración (de menor a mayor):**
1.  Valores por defecto del programa.
2.  Valores en `config.yaml`.
3.  Valores del perfil activado con `--profile` (desde `profiles.yaml`).
4.  Flags especificados en la línea de comandos (siempre tienen la última palabra).

### 1. Fichero de Preferencias (`config.yaml`)

Este fichero es para tus **preferencias personales y por defecto**.

**Ubicación por defecto**: `~/.config/go-arpscan/config.yaml`.
Se puede especificar una ruta personalizada con `--config <ruta>`.

**Ejemplo de `config.yaml`**:
```yaml
# Establecer 'eno1' como mi interfaz de red por defecto
interface: "eno1"

# Siempre mostrar la barra de progreso y el RTT
ui:
  progress: true
output:
  rtt: true
```

### 2. Fichero de Perfiles Tácticos (`profiles.yaml`)

Este fichero define **conjuntos de parámetros reutilizables** para escenarios específicos (mimetismo, evasión, pruebas, etc.), que se activan con el flag `--profile <nombre>`.

**Ubicación y Búsqueda (se usará el primero que se encuentre):**
1.  La ruta especificada con el flag `--profiles <ruta>`.
2.  `profiles.yaml` en el directorio de trabajo actual.
3.  `profiles.yaml` en el mismo directorio que el fichero de configuración (`--config`).
4.  La ruta por defecto: `~/.config/go-arpscan/profiles.yaml`.

Puedes usar los ficheros `config.complete.yaml` y `profiles.yaml` del repositorio como plantillas.

### Ejemplo de Salida
```
# Salida de un escaneo normal con varios escenarios de diagnóstico
$ sudo ./go-arpscan -i eno1 192.168.24.0/24
2025/11/08 01:15:10 Iniciando escaneo en la interfaz eno1 (aa:bb:cc:00:11:22)
2025/11/08 01:15:10 Objetivos a escanear: 254 IPs
2025/11/08 01:15:10 Usando IP de origen dinámica para cada paquete (comportamiento por defecto).
IP Address         MAC Address          Status          Vendor
---------------    -----------------    ------------    ------------------------------
192.168.24.1       aa:bb:cc:dd:ee:01                    Router Manufacturer Inc.
192.168.24.10      aa:bb:cc:dd:ee:f0    (Multi-IP)      Virtualization Corp.
192.168.24.11      aa:bb:cc:dd:ee:f0    (Multi-IP)      Virtualization Corp.
192.168.24.50      aa:bb:cc:dd:ee:a1                    Brother Industries, LTD.
192.168.24.50      aa:bb:cc:dd:ee:b2    (CONFLICT)      Generic NIC Company
192.168.24.100     aa:bb:cc:dd:ee:c3                    HP Inc.
192.168.24.100     aa:bb:cc:dd:ee:c3    (DUPLICATE)     HP Inc.

# Salida del modo --diff
$ sudo ./go-arpscan -i eno1 --diff --state-file network_baseline.json
2025/11/09 10:30:00 Modo DIFF: Comparando el escaneo actual con el estado de 'network_baseline.json'
...
[+] AÑADIDO:     192.168.24.112  aa:bb:cc:11:22:33  (Apple, Inc.)
[-] ELIMINADO:   192.168.24.50   aa:bb:cc:44:55:66  (Brother Industries, LTD.)
[~] MODIFICADO:  192.168.24.10
	  - MAC ANTERIOR: aa:bb:cc:00:00:01 (Dell Inc.)
	  + MAC NUEVA:    aa:bb:cc:00:00:02 (Raspberry Pi Foundation)

# Salida del modo --monitor
$ sudo ./go-arpscan --localnet --monitor
2025/11/10 12:00:00 Iniciando modo monitor en la interfaz eno1. Presione Ctrl+C para salir.
2025/11/10 12:00:00 Realizando escaneo inicial para establecer la línea base de la red...
{"timestamp":"2025-11-10T12:00:02Z","event":"NEW_HOST","ip":"192.168.1.1","mac":"aa:bb:cc:00:01:01","vendor":"RouterCo"}
{"timestamp":"2025-11-10T12:00:03Z","event":"NEW_HOST","ip":"192.168.1.10","mac":"aa:bb:cc:00:02:02","vendor":"Apple, Inc."}
...
2025/11/10 12:00:05 Línea base establecida. 2 hosts activos detectados. Iniciando monitorización continua.
{"timestamp":"2025-11-10T12:03:15Z","event":"NEW_HOST","ip":"192.168.1.15","mac":"aa:bb:cc:00:03:03","vendor":"Samsung Electronics"}
{"timestamp":"2025-11-10T12:05:22Z","event":"IP_CONFLICT","ip":"192.168.1.10","mac":"aa:bb:cc:00:04:04","vendor":"Dell Inc.","notes":"La MAC cambió de aa:bb:cc:00:02:02 a aa:bb:cc:00:04:04."}
{"timestamp":"2025-11-10T14:30:15Z","event":"GATEWAY_SPOOF_DETECTED","ip":"192.168.1.1","mac":"de:ad:be:ef:00:11","vendor":"VMware, Inc.","notes":"Se detectó un anuncio ARP para el gateway desde una MAC no autorizada.","severity":"CRITICAL","legitimate_mac":"aa:bb:cc:00:01:01","attacker_mac":"de:ad:be:ef:00:11"}
```

### Lista Completa de Parámetros

| Flag Corto | Flag Largo | Tipo | Descripción | Por Defecto |
| :---: | :--- | :--- | :--- | :--- |
| `-h` | `--help` | `bool` | Muestra el mensaje de ayuda y sale. | `false` |
| | `--config` | `string` | Ruta al fichero de configuración YAML (`config.yaml`). | `~/.config/...` |
| | `--profiles` | `string` | Ruta al fichero de perfiles YAML (`profiles.yaml`). | Búsqueda automática |
| | `--profile` | `string` | Activa un perfil táctico desde el fichero de perfiles. | `""` |
| `-i` | `--interface` | `string` | Interfaz de red a utilizar. | Auto-detectada |
| | `--scan-timeout`| `duration` | Timeout global para todo el escaneo. | Calculado |
| | `--localnet` | `bool` | Escanear la red local de la interfaz. | `false` |
| `-f` | `--file` | `string` | Leer objetivos desde un fichero (usar `-` para stdin). | `""` |
| | `--exclude` | `stringSlice` | Excluye IPs o rangos CIDR del escaneo. | `nil` |
| | `--exclude-file` | `string` | Excluye los objetivos listados en un fichero. | `""` |
| `-N` | `--numeric` | `bool` | No realizar resolución de nombres de host (DNS). | `false` |
| `-t` | `--host-timeout` | `duration` | Timeout inicial para el primer paquete enviado a un host. | `500ms` |
| `-r` | `--retry` | `int` | Número total de intentos por host (1 = un paquete, sin reintentos). | `2` |
| | `--interval` | `duration` | Intervalo mínimo entre el envío de paquetes. | `1ms` |
| `-B` | `--bandwidth` | `string` | Ancho de banda de salida deseado (e.g., `1M`, `256k`). | `""` |
| `-b` | `--backoff` | `float` | Factor por el que se multiplica el timeout en cada reintento. | `1.5` |
| | **--- Explotación Activa ---** | | | |
| | `--spoof` | `string` | Activa el modo de suplantación ARP contra una IP objetivo. | `""` |
| | `--gateway` | `string` | Especifica la IP del gateway para el ataque de suplantación (`--spoof`). | `""` |
| | `--spoof-interval` | `duration` | Intervalo entre paquetes en el modo de suplantación. | `2s` |
| | `--spoof-mac-timeout` | `duration` | Timeout para obtener las MACs en el modo de suplantación. | `3s` |
| | `--spoof-restore-duration` | `duration` | Duración de la fase de restauración de caché ARP. | `1s` |
| | `--spoof-restore-interval` | `duration` | Intervalo de los paquetes de restauración de caché ARP. | `100ms` |
| | `--detect-promisc` | `string` | Detecta si un host está en modo promiscuo. | `""` |
| | **--- Monitorización Continua ---** | | | |
| | `--monitor` | `bool` | Activa el modo monitor para detectar cambios en la red en tiempo real. | `false` |
| | `--monitor-interval` | `duration` | Intervalo para los sondeos activos en modo monitor (e.g., '10m', '1h'). | `5m` |
| | `--detect-arp-spoofing` | `bool` | Activa la detección de suplantación ARP en modo monitor. | `false` |
| | `--monitor-gateway` | `string` | IP del gateway a proteger con --detect-arp-spoofing. | `""` |
| | `--webhook-url` | `string` | URL del webhook para enviar eventos del modo monitor. | `""` |
| | `--webhook-header`| `stringSlice`| Cabecera HTTP para la petición webhook (e.g., 'Auth: Bearer...'). | `nil` |
| | **--- Manipulación de Paquetes ---** | | | |
| `-s` | `--arpspa` | `string` | Dirección IP de origen a usar en los paquetes ARP. | IP de la interfaz |
| `-u` | `--arpsha` | `string` | Dirección MAC de origen a usar en el paquete ARP (SHA). | MAC de la interfaz |
| `-S` | `--srcaddr` | `string` | Dirección MAC de origen a usar en la trama Ethernet. | MAC de la interfaz |
| `-T` | `--destaddr` | `string` | Dirección MAC de destino a usar en la trama Ethernet. | Broadcast |
| `-w` | `--arptha` | `string` | Dirección MAC de destino a usar en el paquete ARP (THA). | Cero (`00:..:00`) |
| `-o` | `--arpop` | `int` | Código de operación ARP (1=Request, 2=Reply). | `1` |
| `-y` | `--prototype` | `string` | Establece el tipo de protocolo Ethernet (e.g., `0x0806`). | `0x0806` (ARP) |
| `-H` | `--arphrd` | `int` | Establece el tipo de hardware ARP (ar$hrd). | `1` (Ethernet) |
| `-p` | `--arppro` | `string` | Establece el tipo de protocolo ARP (ar$pro) (e.g., `0x0800`). | `0x0800` (IPv4) |
| `-a` | `--arphln` | `int` | Establece la longitud de la dirección de hardware (ar$hln). | `6` |
| `-P` | `--arppln` | `int` | Establece la longitud de la dirección de protocolo (ar$pln). | `4` |
| `-A` | `--padding` | `string` | Añade datos de relleno (padding) en formato hexadecimal `<h>`. | `""` |
| `-L` | `--llc` | `bool` | Usa framing RFC 1042 LLC con SNAP. | `false` |
| | **--- Ficheros y Formato ---** | | | |
| `-O` | `--ouifile` | `string` | Fichero de mapeo OUI personalizado. | `oui.txt` |
| | `--iabfile` | `string` | Fichero de mapeo IAB personalizado. | `iab.txt` |
| | `--macfile` | `string` | Fichero de mapeo MAC personalizado. | `""` |
| `-q` | `--quiet` | `bool` | Salida mínima (solo IP y MAC). | `false` |
| `-x` | `--plain` | `bool` | Salida simple sin cabeceras/pies, para scripts. | `false` |
| | `--json` | `bool` | Muestra la salida completa en formato JSON. | `false` |
| | `--csv` | `bool` | Muestra la salida en formato CSV (Comma-Separated Values). | `false` |
| | `--state-file` | `string` | Guardar/Leer el estado del escaneo en un fichero JSON. | `""` |
| | `--diff` | `bool` | Compara el escaneo actual con un `--state-file` y muestra las diferencias. | `false` |
| | `--progress` | `bool` | Muestra una barra de progreso durante el escaneo. | `false` |
| `-D` | `--rtt` | `bool` | Mostrar el tiempo de ida y vuelta (Round-Trip Time). | `false` |
| `-W` | `--pcapsavefile`| `string` | Guardar respuestas ARP (ARP Reply) en un fichero pcap `<s>` para análisis en Wireshark. | `""` |
| `-g` | `--ignoredups` | `bool` | No mostrar respuestas duplicadas. | `false` |
| | `--color` | `string` | Controlar el uso de color en la salida (`auto`, `on`, `off`). | `auto` |
| | **--- Varios ---** | | | |
| `-R` | `--random` | `bool` | Aleatorizar el orden de los hosts a escanear. | `false` |
| | `--randomseed` | `int64` | Semilla para el generador de números aleatorios. | Basada en el tiempo |
| `-Q` | `--vlan` | `int` | Especifica el ID de VLAN 802.1Q `<i>` (1-4094). | `0` |
| `-n` | `--snap` | `int` | Establece la longitud de captura pcap a `<i>` bytes. | `65536` |
| `-v` | `--verbose` | `count` | Aumenta la verbosidad (-v, -vv, -vvv). | `0` |
| `-V` | `--version` | `bool` | Muestra la versión del programa y sale. | `false` |

---

## Comparación con arp-scan

`go-arpscan` está fuertemente inspirado en la funcionalidad del clásico `arp-scan`, pero busca modernizar la experiencia del usuario y añadir características para la integración en flujos de trabajo actuales. La siguiente tabla muestra la correspondencia de los parámetros entre ambas herramientas.

| Funcionalidad | `arp-scan` (original) | `go-arpscan` (nuestro) | Estado / Comentarios |
| :--- | :--- | :--- | :--- |
| **Gestión de Objetivos** | | | |
| Escanear Red Local | `--localnet`, `-l` | `--localnet` | ✅ **Implementado**. En `go-arpscan` se puede combinar con otros objetivos. |
| Leer Objetivos de Fichero | `--file=<s>`, `-f <s>` | `--file=<s>`, `-f <s>` | ✅ **Implementado**. |
| No usar DNS | `--numeric`, `-N` | `--numeric`, `-N` | ✅ **Implementado**. |
| **Control del Escaneo** | | | |
| Especificar Interfaz | `--interface=<s>`, `-I <s>` | `--interface=<s>`, `-i <s>` | ✅ **Implementado**. ¡Ojo! El flag corto es diferente. Al igual que `arp-scan`, `go-arpscan` también auto-detecta la mejor interfaz si no se especifica. |
| Timeouts por Host | `--timeout=<i>`, `-t <i>` | `--host-timeout=<d>`, `-t <d>` | ✅ **Implementado**. `go-arpscan` acepta unidades de tiempo (e.g., `750ms`). |
| Nº de Reintentos | `--retry=<i>`, `-r <i>` | `--retry=<i>`, `-r <i>` | ✅ **Implementado**. |
| Intervalo entre Paquetes | `--interval=<x>`, `-i <x>` | `--interval=<d>` | ✅ **Implementado**. ¡Ojo! En `arp-scan`, `-i` es alias de `--interval`. En `go-arpscan`, `-i` es alias de `--interface`. |
| Limitar Ancho de Banda | `--bandwidth=<x>`, `-B <x>` | `--bandwidth=<x>`, `-B <x>` | ✅ **Implementado**. |
| Factor de Backoff | `--backoff=<f>`, `-b <f>` | `--backoff=<f>`, `-b <f>` | ✅ **Implementado**. |
| Aleatorizar Objetivos | `--random`, `-R` | `--random`, `-R` | ✅ **Implementado**. |
| Semilla Aleatoria | `--randomseed=<i>` | `--randomseed=<i>` | ✅ **Implementado**. |
| **Capacidades Ofensivas** | | | |
| Suplantación ARP (MitM) | *(No disponible)* | `--spoof`, `--gateway` | 💡 **Nuevo**. Permite realizar ataques de Man-in-the-Middle. |
| Detección Modo Promiscuo | *(No disponible)* | `--detect-promisc` | 💡 **Nuevo**. Permite detectar sniffers en la red. |
| **Formato de Salida** | | | |
| Salida Mínima | `--quiet`, `-q` | `--quiet`, `-q` | ✅ **Implementado**. |
| Salida Simple para Scripts | `--plain`, `-x` | `--plain`, `-x` | ✅ **Implementado**. |
| Ignorar Duplicados | `--ignoredups`, `-g` | `--ignoredups`, `-g` | ✅ **Implementado**. |
| Mostrar RTT | `--rtt`, `-D` | `--rtt`, `-D` | ✅ **Implementado**. |
| Guardar Captura pcap | `--pcapsavefile=<s>`, `-W <s>` | `--pcapsavefile=<s>`, `-W <s>` | ✅ **Implementado**. Guarda solo las respuestas (ARP Reply). |
| Salida JSON | *(No disponible)* | `--json` | 💡 **Nuevo**. Característica clave para la integración moderna. |
| Salida CSV | *(No disponible)* | `--csv` | 💡 **Nuevo**. Facilita el análisis de datos en hojas de cálculo. |
| Salida Coloreada | *(No disponible)* | `--color=<auto\|on\|off>` | 💡 **Nuevo**. Mejora la legibilidad de la salida por defecto. |
| **Integración y Usabilidad** | | | |
| Fichero de Configuración | *(No disponible)* | `--config=<s>` | 💡 **Nuevo**. Permite definir opciones por defecto en un fichero YAML. |
| Perfiles Tácticos | *(No disponible)* | `--profile=<s>` | 💡 **Nuevo**. Activa conjuntos de parámetros predefinidos para mimetismo, evasión, etc. |
| Barra de Progreso | *(No disponible)* | `--progress` | 💡 **Nuevo**. Feedback visual inmediato en escaneos largos. |
| Auditoría de Red | *(No disponible)* | `--state-file`, `--diff` | 💡 **Nuevo**. Permite guardar y comparar escaneos para detectar cambios en la red. |
| Monitorización Continua | *(No disponible)* | `--monitor` | 💡 **Nuevo**. Opera como un sensor de red para la detección de cambios en tiempo real. |
| Detección de Spoofing | *(No disponible)* | `--detect-arp-spoofing` | 💡 **Nuevo**. Activa la detección de suplantación ARP en el modo monitor. |
| Webhooks de Alerta | *(No disponible)* | `--webhook-url` | 💡 **Nuevo**. Conecta el modo monitor con sistemas de alerta y SOARs. |
| Listas de Exclusión | *(No disponible)* | `--exclude`, `--exclude-file` | 💡 **Nuevo**. Permite un escaneo quirúrgico, evitando sistemas críticos. |
| **Manipulación de Paquetes** | | | |
| Fichero OUI | `--ouifile=<s>`, `-O <s>` | `--ouifile=<s>`, `-O <s>` | ✨ **Mejorado**. `go-arpscan` descarga el fichero automáticamente si no existe. |
| Fichero IAB | `--iabfile=<s>` | `--iabfile=<s>` | ✨ **Mejorado**. `go-arpscan` descarga el fichero automáticamente. |
| Fichero MAC Personalizado | `--macfile=<s>` | `--macfile=<s>` | ✅ **Implementado**. |
| IP de Origen ARP (SPA) | `--arpspa=<a>`, `-s <a>` | `--arpspa=<a>`, `-s <a>` | ✅ **Implementado**. |
| Longitud de Captura (snap) | `--snap=<i>`, `-n <i>` | `--snap=<i>`, `-n <i>` | ✅ **Implementado**. |
| VLAN Tagging | `--vlan=<i>`, `-Q <i>` | `--vlan=<i>`, `-Q <i>` | ✅ **Implementado**. |
| MAC Origen Ethernet | `--srcaddr=<m>`, `-S <m>` | `--srcaddr=<m>`, `-S <m>` | ✅ **Implementado**. |
| MAC Destino Ethernet | `--destaddr=<m>`, `-T <m>` | `--destaddr=<m>`, `-T <m>` | ✅ **Implementado**. |
| MAC Origen ARP (SHA) | `--arpsha=<m>`, `-u <m>` | `--arpsha=<m>`, `-u <m>` | ✅ **Implementado**. |
| MAC Destino ARP (THA) | `--arptha=<m>`, `-w <m>` | `--arptha=<m>`, `-w <m>` | ✅ **Implementado**. |
| Operación ARP (Opcode) | `--arpop=<i>`, `-o <i>` | `--arpop=<i>`, `-o <i>` | ✅ **Implementado**. |
| Tipo de Protocolo Ethernet | `--prototype=<i>`, `-y <i>` | `--prototype=<i>`, `-y <i>` | ✅ **Implementado**. |
| Tipo Hardware ARP | `--arphrd=<i>`, `-H <i>` | `--arphrd=<i>`, `-H <i>` | ✅ **Implementado**. |
| Tipo Protocolo ARP | `--arppro=<i>`, `-p <i>` | `--arppro=<i>`, `-p <i>` | ✅ **Implementado**. |
| Longitud HW/Proto ARP | `--arphln=<i>, -a<i>`, `--arppln=<i>, -P<i>` | `--arphln=<i>, -a<i>`, `--arppln=<i>, -P<i>` | ✅ **Implementado**. |
| Relleno (Padding) | `--padding=<h>`, `-A <h>` | `--padding=<h>`, `-A <h>` | ✅ **Implementado**. |
| Framing LLC | `--llc`, `-L` | `--llc`, `-L` | ✅ **Implementado**. |

## Hoja de Ruta

A continuación se detalla el estado actual y las funcionalidades futuras planificadas para `go-arpscan`.

### ✅ Fases 1 a 4: Fundación, Usabilidad, Diagnósticos y Paridad (COMPLETADO)

*Objetivo: Construir una base sólida, añadir las características de usabilidad e integración que hacen a la herramienta moderna y alcanzar la paridad completa de manipulación de paquetes con `arp-scan`.*

**Paso 1: Fundamentos de la CLI y Gestión de Objetivos**
*   [✅] **Ayuda y Versión**: `--help (-h)` y `--version (-V)`.
*   [✅] **Niveles de Verbosidad**: `--verbose (-v)`.
*   [✅] **Especificación de Objetivos**: Soporte para IPs, rangos (`1.2.3.4-5.6.7.8`) y notación CIDR (`1.2.3.0/24`).
*   [✅] **Objetivos desde Fichero**: `--file (-f)`.
*   [✅] **Escaneo de Red Local**: `--localnet`.

**Paso 2: Control del Escaneo y Paquetes**
*   [✅] **Auto-detección de Interfaz**: Selección automática de la mejor interfaz de red.
*   [✅] **Selección Manual de Interfaz**: `--interface (-i)`.
*   [✅] **Control de Reintentos**: `--retry (-r)`.
*   [✅] **Control de Timeouts**: `--host-timeout (-t)` y `--scan-timeout` (con auto-cálculo).
*   [✅] **Control de Ancho de Banda**: `--interval` y `--bandwidth (-B)`.
*   [✅] **Backoff Exponencial**: `--backoff (-b)`.
*   [✅] **Aleatorización de Objetivos**: `--random (-R)` y `--randomseed`.
*   [✅] **IP de Origen Personalizada**: `--arpspa`.

**Paso 3: Formato de Salida y Diagnósticos**
*   [✅] **Gestión de Vendors**: Descarga y uso automático de ficheros OUI/IAB.
*   [✅] **Ficheros de Vendor Personalizados**: `--ouifile (-O)`, `--iabfile` y `--macfile`.
*   [✅] **Salida Coloreada y Legible**: Formato por defecto con control vía `--color`.
*   [✅] **Mostrar Tiempo de Respuesta (RTT)**: `--rtt (-D)`.
*   [✅] **Detección de Conflictos de IP**: Muestra `(CONFLICT)`.
*   [✅] **Detección de Dispositivos Multi-IP**: Muestra `(Multi-IP)`.
*   [✅] **Ignorar Duplicados**: `--ignoredups (-g)`.
*   [✅] **Modos de Salida para Scripting**: `--quiet (-q)` para IP/MAC y `--plain (-x)` para salida sin cabeceras/pies.
*   [✅] **Salida Estructurada**: `--json`, `--csv`.
*   [✅] **Guardado de Captura PCAP**: `--pcapsavefile (-W)`.

**Paso 4: Paridad Completa de Manipulación de Paquetes ("Power-User")**
*   [✅] **VLAN Tagging**: `--vlan (-Q)`.
*   [✅] **Control de `snaplen`**: `--snap (-n)`.
*   [✅] **Spoofing de Trama Ethernet**: `--srcaddr (-S)`, `--destaddr (-T)`, `--prototype (-y)`.
*   [✅] **Spoofing de Paquete ARP**: `--arpsha (-u)`, `--arptha (-w)`, `--arpop (-o)`.
*   [✅] **Manipulación de Campos ARP**: `--arphrd (-H)`, `--arppro (-p)`, `--arphln (-a)`, `--arppln (-P)`.
*   [✅] **Framing y Datos Adicionales**: `--padding (-A)`, `--llc (-L)`.

### ✅ Fase 5: Gestión de Red y Calidad de Vida (COMPLETADO)

*Objetivo: Evolucionar `go-arpscan` de una herramienta de descubrimiento a una utilidad de monitorización y gestión de red, diseñada para administradores de sistemas.*

**Paso 5.1: Gestión de Estado y Control de Cambios**
*   [✅] **Guardado de Estado (`--state-file`)**: Guardar los resultados de un escaneo en un fichero de estado (JSON) para su posterior análisis.
*   [✅] **Comparación de Red (`--diff`)**: Realizar un nuevo escaneo y compararlo con un fichero de estado previo para reportar cambios: hosts añadidos, eliminados o modificados.

**Paso 5.2: Calidad de Vida y Usabilidad Avanzada**
*   [✅] **Barra de Progreso (`--progress`)**: Muestra una barra de progreso informativa durante los escaneos para mejorar la experiencia de usuario.
*   [✅] **Fichero de Configuración (`--config`)**: Soportar un fichero de configuración (e.g., `~/.go-arpscan.yaml`) para establecer opciones por defecto y simplificar la ejecución de comandos recurrentes.

### ✅ Fase 6: Capacidades Avanzadas de Seguridad Ofensiva y Evasión (COMPLETADO)

*Objetivo: Evolucionar `go-arpscan` a una herramienta de élite para pentesters de redes internas, añadiendo inteligencia pasiva, capacidades de evasión y un arsenal de tácticas de ataque y mimetismo en Capa 2.*

*   [✅] **Ataque de Suplantación ARP (`--spoof`)**: Realiza ataques de Man-in-the-Middle para la interceptación de tráfico.
*   [✅] **Implementación de Perfiles (`--profile`)**: Activa conjuntos de parámetros predefinidos para mimetismo, evasión y pruebas de seguridad.
*   [✅] **Detección de Modos Promiscuos (`--detect-promisc`)**: Identifica sniffers en la red mediante el envío de paquetes ARP con MAC de destino incorrecta.
  
### ✅ Fase 7: Flujos de Trabajo Profesionales y Seguridad Operacional (COMPLETADO)

*Objetivo: Solidificar `go-arpscan` como una herramienta profesional indispensable, añadiendo características centradas en la precisión quirúrgica y la eficiencia del flujo de trabajo del pentester.*

*   [✅] **Listas de Exclusión (`--exclude`, `--exclude-file`)**: Asegura que la herramienta opere con precisión, cumpliendo con las Reglas del Enfrentamiento al evitar sistemas críticos.

### ✅ Fase 8: Monitorización Continua e Integración como Sensor de Red (COMPLETADO)

*Objetivo: Evolucionar `go-arpscan` a una herramienta de defensa activa (Blue Team) de Capa 2, capaz de operar como un sensor de red distribuido y de integrarse con ecosistemas de seguridad (SIEM, SOAR).*

*   [✅] **Modo Monitor (`--monitor`)**: Opera como un sensor persistente para la detección de cambios en la red en tiempo real.
*   [✅] **Integración Nativa con Webhooks (`--webhook-url`)**: Conecta con ecosistemas de SecOps (Slack, SOARs) enviando eventos a endpoints HTTP con cabeceras de autenticación.
*   [✅] **Detección Avanzada de Anomalías ARP (`--detect-arp-spoofing`)**: Amplía el modo monitor para clasificar cambios como potencialmente maliciosos (e.g., MAC flapping del gateway).

## Aviso Legal y de Responsabilidad

**Lea atentamente antes de usar este software.**

Este programa, `go-arpscan`, ha sido creado con fines educativos, para la investigación en seguridad y para la auditoría de redes por parte de administradores de sistemas y profesionales de la ciberseguridad. Es una herramienta potente que puede ser utilizada para diagnosticar problemas de red, pero también para realizar pruebas de seguridad ofensivas.

1.  **Uso Autorizado Únicamente**: El uso de `go-arpscan` en cualquier red o sistema para el cual no tengas **permiso explícito y por escrito** es ilegal en la mayoría de las jurisdicciones. Realizar escaneos, pruebas de evasión o ataques de suplantación sin autorización puede acarrear graves consecuencias legales.

2.  **Responsabilidad Total del Usuario**: Eres el único responsable de tus acciones. Los autores y colaboradores de este proyecto no se hacen responsables de ningún daño, interrupción del servicio, pérdida de datos o consecuencia legal derivada del uso (o mal uso) de este software.

3.  **Riesgo de Interrupción**: Algunas funcionalidades y perfiles tácticos de `go-arpscan` (como `ids-stress-test` o los ataques de suplantación) son intrínsecamente disruptivos y pueden causar inestabilidad en la red, denegación de servicio (DoS) o activar sistemas de alerta. **Utiliza estas funciones únicamente en entornos de laboratorio controlados o durante auditorías autorizadas y planificadas.**

Al descargar, compilar o utilizar este software, aceptas que actúas bajo tu propio riesgo y que comprendes las implicaciones de tus acciones.

**Úsalo de forma ética y responsable.**


## Agradecimientos

Este proyecto está fuertemente inspirado por la funcionalidad y robustez de la herramienta original [arp-scan](http://www.royhills.co.uk/projects/arp-scan/) de Roy Hills.

## Licencia

Este proyecto está bajo la Licencia MIT. Ver el fichero `LICENSE` para más detalles.
