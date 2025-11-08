# go-arpscan

Un escáner de red ARP rápido, moderno y concurrente escrito en Go, inspirado en el clásico `arp-scan` pero con mejoras de usabilidad y diagnóstico.

## Descripción

`go-arpscan` envía paquetes ARP a los hosts de la red local para descubrir dispositivos activos y recopilar sus direcciones IP y MAC. Aprovecha la concurrencia de Go para escanear redes de forma extremadamente rápida, incluso con un gran número de hosts.

## Características Principales

*   🚀 **Escaneo Concurrente de Alto Rendimiento**: Utiliza goroutines para enviar y recibir paquetes ARP a gran velocidad.
*   ✨ **Auto-Detección Inteligente**: Detecta automáticamente la interfaz de red a utilizar si no se especifica una.
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
# Escanear la red local automáticamente detectada
sudo ./go-arpscan --localnet

# Escanear una subred completa usando notación CIDR y especificando la interfaz
sudo ./go-arpscan -i eno1 192.168.24.0/24

# Escanear un rango, mostrar RTT y guardar las respuestas para análisis en Wireshark
sudo ./go-arpscan -i eno1 -D -W scan_results.pcap 192.168.24.1-192.168.24.100

# Leer objetivos desde un fichero, con salida simple para procesar con otros scripts
sudo ./go-arpscan -f hosts.txt -x

# Obtener los resultados en formato JSON y procesarlos con jq
sudo ./go-arpscan --localnet --json | jq '.results[] | {ip, mac, vendor}'

# Guardar los resultados en un fichero CSV para analizarlos en una hoja de cálculo
sudo ./go-arpscan --localnet --csv > network_scan.csv
```

### Ejemplo de Salida
```
$ sudo ./go-arpscan -i eno1 192.168.24.0/24
2025/11/08 01:15:10 Iniciando escaneo en la interfaz eno1 (98:90:96:ab:c0:20)
2025/11/08 01:15:10 Objetivos a escanear: 254 IPs
2025/11/08 01:15:10 Usando IP de origen dinámica para cada paquete (comportamiento por defecto).
IP Address         MAC Address          Status          Vendor
---------------    -----------------    ------------    ------------------------------
192.168.24.1       40:31:3c:0a:14:a7                    XIAOMI Electronics,CO.,LTD
192.168.24.12      28:d1:27:1b:da:91    (Multi-IP)      Beijing Xiaomi Mobile Software Co., Ltd
192.168.24.50      3c:21:f4:1a:c4:ef    (CONFLICT)      Brother Industries, LTD.
192.168.24.70      61:16:f0:5f:bf:bb                    HUAWEI TECHNOLOGIES CO.,LTD
192.168.24.101     ec:11:db:a2:e4:11                    Reolink Innovation Limited
```

### Lista Completa de Parámetros

| Flag Corto | Flag Largo | Tipo | Descripción | Por Defecto |
| :---: | :--- | :--- | :--- | :--- |
| `-i` | `--interface` | `string` | Interfaz de red a utilizar. | Auto-detectada |
| | `--scan-timeout`| `duration` | Timeout global para todo el escaneo. | Calculado automáticamente |
| | `--localnet` | `bool` | Escanear la red local de la interfaz. | `false` |
| `-f` | `--file` | `string` | Leer objetivos desde un fichero (usar `-` para stdin). | `""` |
| `-N` | `--numeric` | `bool` | No realizar resolución de nombres de host (DNS). | `false` |
| `-t` | `--host-timeout` | `duration` | Timeout inicial para el primer paquete enviado a un host. | `500ms` |
| `-r` | `--retry` | `int` | Número total de intentos por host (1 = un paquete, sin reintentos). | `2` |
| | `--interval` | `duration` | Intervalo mínimo entre el envío de paquetes. | `1ms` |
| `-B` | `--bandwidth` | `string` | Ancho de banda de salida deseado (e.g., `1M`, `256k`). | `""` |
| `-b` | `--backoff` | `float` | Factor por el que se multiplica el timeout en cada reintento. | `1.5` |
| | `--arpspa` | `string` | Dirección IP de origen a usar en los paquetes ARP. | IP de la interfaz |
| `-O` | `--ouifile` | `string` | Fichero de mapeo OUI personalizado. | `oui.txt` |
| | `--iabfile` | `string` | Fichero de mapeo IAB personalizado. | `iab.txt` |
| | `--macfile` | `string` | Fichero de mapeo MAC personalizado. | `""` |
| `-q` | `--quiet` | `bool` | Salida mínima (solo IP y MAC). | `false` |
| `-x` | `--plain` | `bool` | Salida simple sin cabeceras/pies, para scripts. | `false` |
| | `--json` | `bool` | Muestra la salida completa en formato JSON. | `false` |
| | `--csv` | `bool` | Muestra la salida en formato CSV (Comma-Separated Values). | `false` |
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
| `-h` | `--help` | `bool` | Muestra el mensaje de ayuda y sale. | `false` |

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
| Especificar Interfaz | `--interface=<s>`, `-I <s>` | `--interface=<s>`, `-i <s>` | ✨ **Mejorado**. ¡Ojo! El flag corto es diferente. `go-arpscan` auto-detecta la mejor interfaz si no se especifica. |
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
| **Manipulación de Paquetes** | | | |
| Fichero OUI | `--ouifile=<s>`, `-O <s>` | `--ouifile=<s>`, `-O <s>` | ✨ **Mejorado**. `go-arpscan` descarga el fichero automáticamente si no existe. |
| Fichero IAB | `--iabfile=<s>` | `--iabfile=<s>` | ✨ **Mejorado**. `go-arpscan` descarga el fichero automáticamente. |
| Fichero MAC Personalizado | `--macfile=<s>` | `--macfile=<s>` | ✅ **Implementado**. |
| IP de Origen ARP (SPA) | `--arpspa=<a>`, `-s <a>` | `--arpspa=<a>` | ✅ **Implementado**. |
| Longitud de Captura (snap) | `--snap=<i>`, `-n <i>` | `--snap=<i>`, `-n <i>` | ✅ **Implementado**. |
| VLAN Tagging | `--vlan=<i>`, `-Q <i>` | `--vlan=<i>`, `-Q <i>` | ✅ **Implementado**. |
| MAC Origen Ethernet | `--srcaddr=<m>`, `-S <m>` | *(Aún no disponible)* | 🔲 No Implementado. |
| MAC Destino Ethernet | `--destaddr=<m>`, `-T <m>` | *(Aún no disponible)* | 🔲 No Implementado. |
| MAC Origen ARP (SHA) | `--arpsha=<m>`, `-u <m>` | *(Aún no disponible)* | 🔲 No Implementado. |
| MAC Destino ARP (THA) | `--arptha=<m>`, `-w <m>` | *(Aún no disponible)* | 🔲 No Implementado. |
| Tipo de Protocolo Ethernet | `--prototype=<i>`, `-y <i>` | *(Aún no disponible)* | 🔲 No Implementado. |
| Tipo Hardware ARP | `--arphrd=<i>`, `-H <i>` | *(Aún no disponible)* | 🔲 No Implementado. |
| Tipo Protocolo ARP | `--arppro=<i>`, `-p <i>` | *(Aún no disponible)* | 🔲 No Implementado. |
| Longitud HW/Proto ARP | `--arphln`, `--arppln` | *(Aún no disponible)* | 🔲 No Implementado. |
| Operación ARP (Opcode) | `--arpop=<i>`, `-o <i>` | *(Aún no disponible)* | 🔲 No Implementado. |
| Relleno (Padding) | `--padding=<h>`, `-A <h>` | *(Aún no disponible)* | 🔲 No Implementado. |
| Framing LLC | `--llc`, `-L` | *(Aún no disponible)* | 🔲 No Implementado. |



## Hoja de Ruta

A continuación se detalla el estado actual y las funcionalidades futuras planificadas para `go-arpscan`.

### ✅ Fases 1 a 4 (COMPLETADAS)

*   [✅] **Fundación y Usabilidad**: Implementación de todos los flags básicos para la gestión de objetivos, control del escaneo, y formatos de salida, incluyendo JSON, CSV y Pcap.
*   [✅] **Diagnósticos Avanzados**: Detección automática de conflictos de IP, dispositivos Multi-IP y gestión de duplicados.
*   [✅] **Paridad Esencial de Red**: Soporte para manipulación de paquetes clave como VLAN tagging (`--vlan`) y control de longitud de captura (`--snap`).

### [🔲] Fase 5: Funcionalidades Visionarias y de Gestión de Red

*Objetivo: Evolucionar `go-arpscan` de una herramienta de descubrimiento a una utilidad de monitorización y gestión de red, diseñada para administradores de sistemas.*

**Paso 5.1: Monitorización Continua y Detección de Amenazas**
*   [🔲] **Modo Monitor (`--monitor`)**: Implementar un modo de ejecución persistente que combine escucha pasiva (Gratuitous ARP) con sondeos activos periódicos.
    *   **Salida de Eventos**: Generar logs estructurados en JSON en tiempo real para eventos como `NEW_HOST`, `IP_CONFLICT` y `HOST_DISAPPEARED`.
    *   **Detección de ARP Spoofing**: Añadir heurísticas para detectar "MAC Flapping" (cambios rápidos de MAC para una misma IP) y alertar sobre posibles ataques.

**Paso 5.2: Gestión de Estado y Control de Cambios**
*   [🔲] **Guardado de Estado (`--state-file`)**: Guardar los resultados de un escaneo en un fichero de estado (JSON) para su posterior análisis.
*   [🔲] **Comparación de Red (`--diff`)**: Realizar un nuevo escaneo y compararlo con un fichero de estado previo para reportar cambios: hosts añadidos, eliminados o modificados.

**Paso 5.3: Calidad de Vida y Usabilidad Avanzada**
*   [🔲] **Fichero de Configuración (`--config`)**: Soportar un fichero de configuración (e.g., `~/.go-arpscan.yaml`) para establecer opciones por defecto y simplificar la ejecución de comandos recurrentes.
*   [🔲] **Enriquecimiento de Datos**: Añadir flags opcionales para realizar acciones adicionales sobre los hosts descubiertos:
    *   `--resolve-names`: Realizar una búsqueda de DNS inversa (PTR) para obtener los nombres de host.
    *   `--probe-ports <ports>`: Realizar un sondeo TCP rápido en puertos comunes (e.g., 80, 443, 22) para inferir el tipo de servicio.

**Paso 5.4: Paridad Completa con `arp-scan` (Power-User)**
*   [🔲] **Spoofing y Manipulación ARP**: Implementar el resto de opciones de manipulación de paquetes como `--srcaddr`, `--arpsha`, `--arpop`, etc., para usuarios avanzados y pentesters.

## Agradecimientos

Este proyecto está fuertemente inspirado por la funcionalidad y robustez de la herramienta original [arp-scan](http://www.royhills.co.uk/projects/arp-scan/) de Roy Hills.

## Licencia

Este proyecto está bajo la Licencia MIT. Ver el fichero `LICENSE` para más detalles.
