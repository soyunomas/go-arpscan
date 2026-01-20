#!/bin/bash

# Configuración de rutas
GO_BIN="./bin/go-arpscan"
C_BIN="arp-scan"

# Detección automática de la interfaz principal (la que tiene salida a internet)
# Esto evita que arp-scan se pierda en interfaces virtuales o Docker.
IFACE=$(ip route get 1.1.1.1 | grep -oP 'dev \K\S+')

if [ -z "$IFACE" ]; then
    echo "❌ No se pudo detectar la interfaz de red. Edita el script y define IFACE manualmente."
    exit 1
fi

echo "📡 Interfaz detectada: $IFACE"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then echo -e "${RED}Ejecuta como root.${NC}"; exit 1; fi

limpiar_red() {
    ip neigh flush all > /dev/null 2>&1
    sleep 2 # Reducido a 2s para no esperar tanto, es suficiente
}

run_test_case() {
    local TITULO=$1
    local GO_INT=$2    # Intervalo Go (ej: 800us)
    local C_INT=$3     # Intervalo C (us) (ej: 800)
    local RETRY=$4
    local TIMEOUT_GO=$5 # String con unidad (ej: 500ms)
    local TIMEOUT_C=$6  # Entero ms (ej: 500)

    echo ""
    echo -e "${BLUE}=== TEST: $TITULO ===${NC}"
    echo -e "${BLUE}Params: Int=$GO_INT, Re=$RETRY, T/O=$TIMEOUT_GO${NC}"

    # --- GO-ARPSCAN ---
    limpiar_red
    echo -e "${GREEN}▶ GO-ARPSCAN...${NC}"
    
    start_go=$(date +%s%N)
    # Pasamos explícitamente la interfaz con -i
    OUTPUT_GO=$(sudo $GO_BIN -i $IFACE --localnet --interval $GO_INT --retry $RETRY --host-timeout $TIMEOUT_GO --plain)
    end_go=$(date +%s%N)
    
    COUNT_GO=$(echo "$OUTPUT_GO" | wc -l)
    DUR_GO=$(( ($end_go - $start_go) / 1000000 ))
    echo "   Hosts: $COUNT_GO | Tiempo: ${DUR_GO} ms"

    # --- ARP-SCAN (C) ---
    limpiar_red
    echo -e "${RED}▶ ARP-SCAN (C)...${NC}"
    
    start_c=$(date +%s%N)
    # Usamos flags cortos: -I (interfaz), -i (intervalo us), -t (timeout ms), -r (retry)
    # Forzamos la interfaz con -I para evitar el cuelgue
    OUTPUT_C=$(sudo $C_BIN -I $IFACE --localnet -i $C_INT -r $RETRY -t $TIMEOUT_C --plain --quiet --ignoredups)
    end_c=$(date +%s%N)
    
    COUNT_C=$(echo "$OUTPUT_C" | wc -l)
    DUR_C=$(( ($end_c - $start_c) / 1000000 ))
    echo "   Hosts: $COUNT_C | Tiempo: ${DUR_C} ms"

    # --- VEREDICTO ---
    echo -n "📊 GANADOR: "
    if [ "$DUR_GO" -lt "$DUR_C" ]; then
        DIFF=$(( $DUR_C - $DUR_GO ))
        echo -e "${GREEN}GO (-$DIFF ms)${NC}"
    else
        DIFF=$(( $DUR_GO - $DUR_C ))
        echo -e "${RED}C (-$DIFF ms)${NC}"
    fi
}

# 1. ESCENARIO EQUILIBRADO (Lo justo para ambos)
# Intervalo 800us (0.8ms), 2 reintentos, 400ms timeout
run_test_case "BALANCEADO" "800us" "800" 2 "400ms" 400

# 2. ESCENARIO ESTRÉS (Puro throughput)
# Intervalo 300us, 3 reintentos, 200ms timeout
run_test_case "TURBO/ESTRÉS" "300us" "300" 3 "200ms" 200
