# go-arpscan

Un escáner de red ARP rápido, moderno y concurrente escrito en Go, inspirado en el clásico `arp-scan` pero con mejoras de usabilidad y diagnóstico.

## Descripción

`go-arpscan` envía paquetes ARP a los hosts de la red local para descubrir dispositivos activos y recopilar sus direcciones IP y MAC. Aprovecha la concurrencia de Go para escanear redes de forma extremadamente rápida, incluso con un gran número de hosts.

## Características Principales

*   🚀 **Escaneo Concurrente de Alto Rendimiento**: Utiliza goroutines para enviar y recibir paquetes ARP a gran velocidad.
*   ✨ **Auto-Detección Inteligente**: Detecta automáticamente la interfaz de red a utilizar si no se especifica una.
*   ⚙️ **Gestión Centralizada con Ficheros de Configuración**:
    *   **Preferencias Personales (`config.yaml`)**: Define tus opciones por defecto (interfaz, timeouts, etc.) para simplificar la ejecución de comandos recurrentes.
    *   **Perfiles Tácticos (`profiles.yaml`)**: Activa conjuntos complejos de parámetros para mimetismo, evasión o pruebas de seguridad con un solo flag (`--profile <nombre>`).
*   📊 **Auditoría de Red**: Guarda instantáneas del estado de la red y compara escaneos para detectar dispositivos nuevos, eliminados o modificados (`--diff`).
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
go build -ldflags "-X main.version=1.0.0" -o go-arpscan ./cmd/go-arpscan

# 3. (Opcional) Mueve el binario a tu PATH para un acceso global
sudo mv go-arpscan /usr/local/bin/
```

**Nota**: `go-arpscan` necesita privilegios de `root` para funcionar, ya que accede a funcionalidades de red a bajo nivel. Utilízalo siempre con `sudo`.

## Uso Básico y Ejemplos

```bash
# Escanear la red local automáticamente detectada con una barra de progreso
sudo ./go-arpscan --localnet --progress

# Escanear una subred completa usando notación CIDR y especificando la interfaz
sudo ./go-arpscan -i eno1 192.168.24.0/24

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
| `-N` | `--numeric` | `bool` | No realizar resolución de nombres de host (DNS). | `false` |
| `-t` | `--host-timeout` | `duration` | Timeout inicial para el primer paquete enviado a un host. | `500ms` |
| `-r` | `--retry` | `int` | Número total de intentos por host (1 = un paquete, sin reintentos). | `2` |
| | `--interval` | `duration` | Intervalo mínimo entre el envío de paquetes. | `1ms` |
| `-B` | `--bandwidth` | `string` | Ancho de banda de salida deseado (e.g., `1M`, `256k`). | `""` |
| `-b` | `--backoff` | `float` | Factor por el que se multiplica el timeout en cada reintento. | `1.5` |
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

### [🔲] Fase 6: Capacidades Avanzadas de Seguridad Ofensiva y Evasión

*Objetivo: Evolucionar `go-arpscan` a una herramienta de élite para pentesters y equipos de seguridad, añadiendo inteligencia activa, capacidades de evasión y un arsenal de tácticas de ataque y mimetismo reutilizables.*

**Paso 6.1: Perfilado de Objetivos (Intelligence Gathering)**
*   [🔲] **Huella Digital del Sistema Operativo (`--fingerprint`)**: Implementar un sondeo ICMP ligero para analizar el TTL de la respuesta del host. Este método permite inferir la familia del sistema operativo (Windows, Linux/Unix, Cisco) de forma rápida y sigilosa, un dato clave para seleccionar el vector de ataque adecuado.
*   [🔲] **Sondeo de Puertos Ligero**: Añadir la capacidad de realizar un sondeo TCP SYN rápido para identificar la superficie de ataque de cada host descubierto, permitiendo al analista priorizar objetivos de alto valor de forma instantánea.
    *   `--probe-ports <puertos>`: Escanea una lista específica de puertos (ej. `22,80,443,3389`).
    *   `--top-ports <N>`: Escanea los `N` puertos TCP más comunes.
    *   `--probe-iot-ports`: Un alias para escanear puertos estándar de protocolos IoT/OT (ej. `1883/MQTT`, `5683/CoAP`, `502/Modbus`), crucial para identificar infraestructura de control.

**Paso 6.2: Explotación Activa (Controlled Attack Module)**
*   [🔲] **Ataque de Suplantación ARP (`--spoof`)**: Implementar un módulo de ataque para realizar envenenamiento de caché ARP (ARP poisoning) y facilitar ataques de intermediario (Man-in-the-Middle).
    *   **Sintaxis de la Operación**: `go-arpscan --spoof <IP_objetivo> --gateway <IP_gateway>`.
    *   **Funcionamiento Profesional**: La herramienta gestionará la activación de `ip_forwarding` para asegurar que el ataque no sea destructivo (un MitM funcional en lugar de un DoS), demostrando un control preciso del entorno.
    *   **Impacto de Seguridad**: Permite demostrar riesgos críticos como el robo de credenciales en texto plano (HTTP, FTP), secuestro de cookies de sesión y la interceptación de datos sensibles.

**Paso 6.3: Evasión y Mimetismo Táctico: Perfiles de Fingerprint**
*   [✅] **Implementación de Perfiles (`--profile <nombre>`)**: Añadir la capacidad de cargar conjuntos de parámetros predefinidos desde un fichero de configuración (`profiles.yaml`). Esta característica encapsula tácticas complejas en un solo flag, permitiendo automatizar el engaño y la evasión. A continuación se detallan los perfiles iniciales que se implementarían:
    *   **Perfil: `windows11-workstation` (Mimetismo)**
    *   **Perfil: `macos-ventura` (Mimetismo)**
    *   **Perfil: `hp-officejet-printer` (Engaño)**
    *   **Perfil: `stealth-scan-generic` (Táctica)**
    *   **Perfil: `ids-stress-test` (Prueba de Defensas)**

### [🔲] Fase 7: Flujos de Trabajo Profesionales y Seguridad Operacional

*Objetivo: Solidificar `go-arpscan` como una herramienta profesional indispensable, añadiendo características centradas en la seguridad, la precisión y la eficiencia del flujo de trabajo del pentester.*

**Paso 7.1: Gestión de Alcance y Exclusiones (Safety & Precision)**
*   [🔲] **Implementación de Listas de Exclusión**: Asegura que la herramienta opere con la precisión de un cirujano, cumpliendo estrictamente con las Reglas del Enfrentamiento (Rules of Engagement).
    *   `--exclude <IP,CIDR>`: Permite especificar en la línea de comandos objetivos que deben ser ignorados por el escáner.
    *   `--exclude-file <fichero.txt>`: Carga una lista de exclusiones desde un fichero, esencial para evitar el escaneo de sistemas críticos (OT, ICS, equipamiento médico).

**Paso 7.2: Generación de Artefactos y Entregables (Efficiency)**
*   [🔲] **Módulo de Generación de Informes**: Agiliza drásticamente la fase de reporte, convirtiendo los datos brutos del escaneo en entregables claros y profesionales.
    *   `--report-html <fichero.html>`: Genera un informe HTML con un resumen, tablas de resultados y hallazgos clave.
    *   `--report-md <fichero.md>`: Genera un informe en formato Markdown para una fácil integración en wikis y documentación.

### [🔲] Fase 8: Monitorización Continua e Integración como Sensor de Red

*Objetivo: Evolucionar `go-arpscan` a una herramienta de defensa activa (Blue Team), capaz de operar como un sensor de red distribuido y de integrarse con ecosistemas de seguridad más amplios (SIEM, SOAR).*

**Paso 8.1: Detección de Amenazas en Tiempo Real**
*   [🔲] **Modo Monitor (`--monitor`)**: Implementar un modo de ejecución persistente que combine escucha pasiva de tráfico ARP (ej. Gratuitous ARP) con sondeos activos periódicos para mantener un estado actualizado de la red.
    *   **Salida de Eventos en JSON**: Generará logs estructurados para cada evento significativo, facilitando su ingesta por sistemas automatizados: `{"event": "NEW_HOST", "data": {...}}`, `{"event": "IP_CONFLICT", "data": {...}}`.
    *   **Detección de ARP Spoofing**: Añadir heurísticas avanzadas para detectar ataques de suplantación en tiempo real. Esto incluye la detección de "MAC Flapping" (cambios rápidos de la MAC asociada a una IP clave como el gateway).

**Paso 8.2: Integración con Ecosistemas de Orquestación**
*   [🔲] **Publicación de Eventos vía MQTT (`--publish-mqtt`)**: En el modo `--monitor`, añadir la capacidad de publicar eventos directamente a un broker MQTT, convirtiendo cada instancia de `go-arpscan` en un sensor de bajo coste para sistemas internos, IoT u OT.
    *   `--publish-mqtt "tcp://user:pass@broker.local:1883"`
    *   `--mqtt-topic-prefix "net-sensors/segment-finance"`
*   [🔲] **Integración Nativa con Webhooks (`--webhook-url`)**: Conecta directamente con el ecosistema de SecOps y DevOps. Cuando se detecta un evento, `go-arpscan` enviará una petición `POST` con el payload JSON del evento a la URL especificada.
    *   `--webhook-header 'Auth: Bearer ...'`: Soportará cabeceras personalizadas para la autenticación con servicios protegidos.
    *   **Caso de Uso**: Permite la integración directa con **Slack**, **PagerDuty**, o plataformas **SOAR** para desencadenar flujos de trabajo de respuesta automatizados.

## Agradecimientos

Este proyecto está fuertemente inspirado por la funcionalidad y robustez de la herramienta original [arp-scan](http://www.royhills.co.uk/projects/arp-scan/) de Roy Hills.

## Licencia

Este proyecto está bajo la Licencia MIT. Ver el fichero `LICENSE` para más detalles.
