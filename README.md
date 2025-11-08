# go-arpscan

Un escáner de red ARP rápido, moderno y concurrente escrito en Go, inspirado en el clásico `arp-scan` pero con mejoras de usabilidad y diagnóstico.

## Descripción

`go-arpscan` envía paquetes ARP a los hosts de la red local para descubrir dispositivos activos y recopilar sus direcciones IP y MAC. Aprovecha la concurrencia de Go para escanear redes de forma extremadamente rápida, incluso con un gran número de hosts.

El objetivo de este proyecto es ofrecer una alternativa moderna a `arp-scan` que sea:
*   **Más Fácil de Usar**: Con auto-detección de interfaz y descarga automática de ficheros de vendors.
*   **Más Informativa**: Con una salida coloreada y diagnósticos claros para conflictos de IP y dispositivos Multi-IP.
*   **Nativa y Portable**: Compilada en un único binario sin dependencias externas.

## Características Principales

*   🚀 **Escaneo Concurrente de Alto Rendimiento**: Utiliza goroutines para enviar y recibir paquetes ARP a gran velocidad.
*   ✨ **Auto-Detección Inteligente**: Detecta automáticamente la interfaz de red a utilizar si no se especifica una.
*   🎨 **Salida Coloreada y Alineada**: Formato de salida moderno y legible, con control total sobre los colores (`--color=auto|on|off`).
*   🌐 **Gestión Automática de Vendors**: Descarga automáticamente los ficheros OUI e IAB de la IEEE si no se encuentran localmente.
*   🔍 **Diagnóstico de Red Avanzado**:
    *   Detecta y reporta **Conflictos de IP** (una misma IP usada por varias MACs).
    *   Detecta y reporta dispositivos **Multi-IP** (una misma MAC respondiendo para varias IPs).
    *   Diferencia claramente las respuestas **Duplicadas**.
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

# Escanear un rango de IPs y mostrar el tiempo de respuesta (RTT)
sudo ./go-arpscan -i eno1 -D 192.168.24.1-192.168.24.100

# Leer objetivos desde un fichero, con salida simple para procesar con otros scripts
sudo ./go-arpscan -f hosts.txt -x
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
| `-D` | `--rtt` | `bool` | Mostrar el tiempo de ida y vuelta (Round-Trip Time). | `false` |
| `-g` | `--ignoredups` | `bool` | No mostrar respuestas duplicadas. | `false` |
| | `--color` | `string` | Controlar el uso de color en la salida (`auto`, `on`, `off`). | `auto` |
| `-R` | `--random` | `bool` | Aleatorizar el orden de los hosts a escanear. | `false` |
| | `--randomseed` | `int64` | Semilla para el generador de números aleatorios. | Basada en el tiempo |
| `-v` | `--verbose` | `count` | Aumenta la verbosidad (-v, -vv, -vvv). | `0` |
| `-V` | `--version` | `bool` | Muestra la versión del programa y sale. | `false` |
| `-h` | `--help` | `bool` | Muestra el mensaje de ayuda y sale. | `false` |


## Hoja de Ruta

A continuación se detalla el estado actual y las funcionalidades futuras planificadas para `go-arpscan`.

### ✅ Fase 1 y 2: Fundación y Usabilidad Esencial (COMPLETADO)

Esta fase se centró en replicar las funcionalidades más comunes de `arp-scan` y añadir mejoras significativas de usabilidad.

*   **Fundamentos de CLI**: `--help`, `--version`, `--verbose`.
*   **Gestión de Objetivos**: `--file`, `--localnet`, rangos IP y CIDR.
*   **Control del Escaneo**: `--retry`, `--host-timeout`, `--scan-timeout` (con auto-cálculo), `--interval`, `--bandwidth`, `--backoff`, `--random`, `--randomseed`.
*   **Control de la Salida**: `--quiet`, `--plain`, `--rtt`, y el nuevo `--color`.
*   **Configuración Básica de Paquetes**: `--arpspa`.
*   **Motor y Usabilidad**:
    *   [✅] **Auto-detección de Interfaz Inteligente**: No es necesario especificar `-i` en la mayoría de los casos.
    *   [✅] **Gestión Automática de Ficheros de Vendor**: Descarga y parseo de `oui.txt` e `iab.txt`.
    *   [✅] **Diagnósticos Mejorados**: Detección de `(CONFLICT)` y `(Multi-IP)`.
    *   [✅] **Ficheros de Vendor Personalizados**: Soporte para `--ouifile`, `--iabfile` y `--macfile`.
    *   [✅] **Soporte para Hostnames**: Resolución de nombres de host en los objetivos (desactivable con `--numeric`).
    *   [✅] **Ignorar Duplicados**: Opción `--ignoredups` para una salida más limpia.

### [🔲] Fase 3: Manipulación Avanzada de Paquetes (Paridad de "Power-User")

*   **Control de la Trama Ethernet**: `--vlan`, `--srcaddr`, `--destaddr`, `--prototype`.
*   **Control del Paquete ARP**: `--arpsha`, `--arpop`, `--arptha`, `--arphrd`, `--arppro`, etc.
*   **Framing y Datos Adicionales**: `--padding`, `--llc`.

### [🔲] Fase 4: Integración con el Ecosistema Moderno

*   **Salida Estructurada**: `--json` y `--csv` para una integración sencilla con scripts y herramientas de análisis.
*   **Interoperabilidad**: `--pcapsavefile` para guardar respuestas y analizarlas con Wireshark/tcpdump, y `--snap`.

### [🔲] Fase 5: Funcionalidades Visionarias

*   **Modos Avanzados**:
    *   `--monitor`: Modo de escucha continua para detectar nuevos dispositivos, cambios de MAC y conflictos en tiempo real.
    *   `--config`: Soporte para un fichero de configuración (e.g., `~/.go-arpscan.yaml`).
*   **Inteligencia de Red**: Detección heurística de múltiples gateways o posibles ataques de ARP spoofing en modo monitor.

## Agradecimientos

Este proyecto está fuertemente inspirado por la funcionalidad y robustez de la herramienta original [arp-scan](http://www.royhills.co.uk/projects/arp-scan/) de Roy Hills.

## Licencia

Este proyecto está bajo la Licencia MIT. Ver el fichero `LICENSE` para más detalles.
