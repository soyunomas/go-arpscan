#!/bin/bash

# ==============================================================================
# SCRIPT DE PRUEBA PARA LA DETECCIÓN DE SUPLANTACIÓN ARP DE go-arpscan (v2 - Corregido)
#
# Propósito: Simular un ataque de ARP Spoofing y verificar que go-arpscan
#            lo detecta correctamente en modo monitor.
#
# ADVERTENCIA: Este script realiza un ataque ARP real en tu red local.
#              ÚSALO ÚNICAMENTE en una red que controles y para la que tengas
#              permiso. La máquina que ejecuta el script será la "víctima"
#              del ataque para esta demostración.
# ==============================================================================

# --- Colores para la Salida ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # Sin Color

## 1. CONFIGURACIÓN Y VERIFICACIONES

# Asegurarse de que el script se ejecuta como root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: Este script debe ser ejecutado como root. Por favor, usa sudo.${NC}"
   exit 1
fi

# Verificar dependencias
for cmd in arpspoof jq ip; do
  if ! command -v $cmd &> /dev/null; then
    echo -e "${RED}Error: El comando '$cmd' no se encuentra. Por favor, instálalo.${NC}"
    echo -e "${YELLOW}En sistemas Debian/Ubuntu, prueba con: sudo apt-get update && sudo apt-get install -y dsniff jq${NC}"
    exit 1
  fi
done

# Verificar que el binario de go-arpscan está en el directorio actual
if [[ ! -f "./go-arpscan" ]]; then
    echo -e "${RED}Error: No se encontró el binario './go-arpscan'.${NC}"
    echo -e "${YELLOW}Asegúrate de haber compilado el programa y de que este script se encuentra en el mismo directorio.${NC}"
    exit 1
fi

## 2. DESCUBRIMIENTO DE RED (Automático)

echo -e "${BLUE}[*] Detectando automáticamente la configuración de red...${NC}"

# Obtener la ruta por defecto para encontrar el gateway y la interfaz
DEFAULT_ROUTE=$(ip route | grep default)
if [[ -z "$DEFAULT_ROUTE" ]]; then
    echo -e "${RED}Error: No se pudo encontrar una ruta por defecto. ¿Estás conectado a una red?${NC}"
    exit 1
fi

# Extraer el Gateway y la Interfaz
GATEWAY_IP=$(echo "$DEFAULT_ROUTE" | awk '{print $3}')
INTERFACE=$(echo "$DEFAULT_ROUTE" | awk '{print $5}')

# Obtener la IP de la máquina actual (nuestra "víctima")
VICTIM_IP=$(ip -4 addr show "$INTERFACE" | grep -oP 'inet \K[\d.]+')

if [[ -z "$GATEWAY_IP" || -z "$INTERFACE" || -z "$VICTIM_IP" ]]; then
    echo -e "${RED}Error: No se pudieron determinar todos los parámetros de red (Gateway, Interfaz, IP local).${NC}"
    exit 1
fi

if [[ "$GATEWAY_IP" == "$VICTIM_IP" ]]; then
    echo -e "${RED}Error: La IP del gateway y la IP local son la misma. No se puede realizar la prueba.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Configuración de red detectada:${NC}"
echo -e "    - Interfaz:      ${YELLOW}${INTERFACE}${NC}"
echo -e "    - Gateway (a proteger): ${YELLOW}${GATEWAY_IP}${NC}"
echo -e "    - Víctima (esta máquina): ${YELLOW}${VICTIM_IP}${NC}"
echo ""


## 3. EJECUCIÓN DE LA SIMULACIÓN

# Función de limpieza para detener los procesos en segundo plano
cleanup() {
    echo -e "\n${BLUE}[*] Limpiando... Deteniendo todos los procesos en segundo plano.${NC}"
    # Desactivar el reenvío de IP
    echo 0 > /proc/sys/net/ipv4/ip_forward
    echo -e "${GREEN}[+] Reenvío de IP desactivado.${NC}"

    if [[ ! -z "$ATTACKER_PID" ]]; then
        kill "$ATTACKER_PID" 2>/dev/null
        echo -e "${GREEN}[+] Proceso de ataque (arpspoof) detenido.${NC}"
    fi
    if [[ ! -z "$DEFENDER_PID" ]]; then
        kill "$DEFENDER_PID" 2>/dev/null
        echo -e "${GREEN}[+] Proceso defensor (go-arpscan) detenido.${NC}"
    fi
    echo -e "${GREEN}[+] Limpieza completada.${NC}"
}
trap cleanup EXIT

# --- Lanzar el Defensor (go-arpscan) ---
echo -e "${BLUE}[*] Lanzando el DEFENSOR (go-arpscan) en modo monitor...${NC}"
echo -e "${YELLOW}    Verás el escaneo inicial. Espera el mensaje 'Protección activada'.${NC}"

# Usamos 'jq' para formatear la salida y resaltar la alerta de ataque
./go-arpscan \
    --localnet \
    --monitor \
    --detect-arp-spoofing \
    --monitor-gateway "$GATEWAY_IP" \
    -i "$INTERFACE" | jq -r --unbuffered '
    if .event == "GATEWAY_SPOOF_DETECTED" then
        "\(.timestamp) | \u001b[31;1m¡¡¡ALERTA!!! \(.event)\u001b[0m | Gateway: \(.ip) | Atacante: \(.attacker_mac) (\(.vendor)) | MAC Legítima: \(.legitimate_mac)"
    elif .event == "NEW_HOST" then
        "\(.timestamp) | \u001b[32m\(.event)\u001b[0m | IP: \(.ip) | MAC: \(.mac) (\(.vendor))"
    else
        "\(.timestamp) | \u001b[33m\(.event)\u001b[0m | IP: \(.ip) | MAC: \(.mac)"
    end
' &
DEFENDER_PID=$!

# Dar tiempo a go-arpscan para que complete su escaneo inicial y establezca la línea base
echo -e "${BLUE}[*] Esperando 10 segundos para que el defensor establezca la línea base...${NC}"
sleep 10

# --- Lanzar el Atacante (arpspoof) ---
echo -e "\n${RED}[*] Lanzando el ATACANTE (arpspoof)...${NC}"
echo -e "${YELLOW}    El ataque comenzará ahora. Deberías ver una alerta del defensor en breve.${NC}"

# Activar el reenvío de IP para que la víctima no pierda la conexión (ataque MitM real)
echo 1 > /proc/sys/net/ipv4/ip_forward
echo -e "${GREEN}[+] Reenvío de IP activado temporalmente.${NC}"

# Iniciar el envenenamiento ARP
# ##########################################################################
# ## LÍNEA CORREGIDA: Apuntamos a la VÍCTIMA para suplantar al GATEWAY     ##
# ##########################################################################
arpspoof -i "$INTERFACE" -t "$VICTIM_IP" "$GATEWAY_IP" &> /dev/null &
ATTACKER_PID=$!

echo -e "\n${GREEN}[***] Simulación en curso. El defensor está monitorizando y el atacante está activo.${NC}"
echo -e "${YELLOW}Presiona [Ctrl+C] para detener la simulación y limpiar.${NC}\n"

# Esperar a que el proceso del defensor termine (lo cual ocurrirá cuando el usuario pulse Ctrl+C)
wait $DEFENDER_PID
