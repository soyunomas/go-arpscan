#!/bin/bash

# ==============================================================================
#           SUITE DE PRUEBAS DE INTEGRACIÓN COMPLETA PARA go-arpscan
# ==============================================================================
# Este script prueba sistemáticamente CADA PARÁMETRO de la aplicación para
# asegurar que no causa un pánico y que las combinaciones lógicas funcionan.
#
# CÓMO USAR:
# 1. Asegúrate de que el binario 'go-arpscan' esté en el mismo directorio.
# 2. Dale permisos de ejecución: chmod +x run_all_tests.sh
# 3. Ejecútalo con sudo: sudo ./run_all_tests.sh
# ==============================================================================

# --- Configuración del Entorno de Pruebas ---
set -e # El script terminará inmediatamente si un comando falla.

# Variables de Red (ajústalas si es necesario)
IFACE="eno1"
NETWORK="192.168.24.0/24"
GATEWAY="192.168.24.1"
TARGET_SINGLE="192.168.24.50"
TARGET_RANGE="192.168.24.10-192.168.24.15"

# Ficheros
BINARY_PATH="./go-arpscan"
LOG_FILE="test_suite_results.log"

# --- Función Helper para Ejecutar y Registrar Pruebas ---
run_test() {
    local description="$1"
    local command_args="$2"
    
    echo "======================================================================" | tee -a "$LOG_FILE"
    echo "--> TEST: $description" | tee -a "$LOG_FILE"
    echo "--> CMD:  sudo $BINARY_PATH $command_args" | tee -a "$LOG_FILE"
    echo "----------------------------------------------------------------------" | tee -a "$LOG_FILE"
    
    # Usamos 'timeout' para prevenir que algún comando se quede colgado.
    # Redirigimos stdout y stderr al fichero de log. tee muestra stdout en la consola.
    if sudo timeout 60s "$BINARY_PATH" $command_args >> "$LOG_FILE" 2>&1; then
        echo "--> RESULT: SUCCESS" | tee -a "$LOG_FILE"
    else
        echo "--> RESULT: FAILED (Exit Code: $?)" | tee -a "$LOG_FILE"
    fi
    echo "" | tee -a "$LOG_FILE"
    sleep 1 # Pequeña pausa para no saturar la red.
}

# --- Preparación de Ficheros Temporales ---
setup_files() {
    echo "## Preparando ficheros de prueba..."

    # Fichero de objetivos
    cat << EOF > hostlist.txt
# Lista de hosts para pruebas
192.168.24.11
192.168.24.70
EOF

    # Fichero de exclusión
    cat << EOF > excludelist.txt
# Excluir el router y la cámara
192.168.24.1
192.168.24.101
EOF

    # Fichero de configuración principal
    cat << EOF > test_config.yaml
interface: "$IFACE"
verbose: 1
ui:
  progress: true
scan:
  retry: 1
  host-timeout: "200ms"
spoofing:
  interval: "5s" # Probamos que se lee la configuración de spoofing
EOF

    # Fichero de perfiles
    cat << EOF > test_profiles.yaml
profiles:
  stealthy_test:
    description: "Un perfil de prueba sigiloso"
    arpsha: "DE:AD:BE:EF:XX:XX"
    retry: 1
    host-timeout: "1s"
    random: true
EOF
    
    # Fichero de MACs personalizadas
    cat << EOF > custom_macs.txt
# Mapeo personalizado para el laboratorio
40:31:3c:0c:54:ef    MI_ROUTER_XIAOMI_PRINCIPAL
ec:71:db:8a:e4:81    CAMARA_SEGURIDAD_REOLINK
EOF

    echo "## Ficheros creados."
}

# --- Limpieza de Ficheros ---
cleanup() {
    echo "## Limpiando ficheros de prueba..."
    rm -f hostlist.txt excludelist.txt test_config.yaml test_profiles.yaml custom_macs.txt
    rm -f baseline.json scan.pcap
    echo "## Limpieza completada."
}
trap cleanup EXIT # Asegura que la limpieza se ejecute al final

# ==============================================================================
#                           INICIO DE LA SUITE DE PRUEBAS
# ==============================================================================

# Preparamos los ficheros necesarios
setup_files

# Limpiamos el log anterior
> "$LOG_FILE"
echo "Suite de pruebas para go-arpscan iniciada el $(date)" | tee -a "$LOG_FILE"

# --- Pruebas Básicas y de Ayuda ---
run_test "Mostrar versión (-V)" "-V"
run_test "Mostrar ayuda (-h)" "-h"

# --- Pruebas de Configuración y Perfiles ---
run_test "Usar fichero de configuración personalizado (--config)" "--config=test_config.yaml --localnet"
run_test "Usar perfil táctico (--profile)" "--profile=stealthy_test --profiles=test_profiles.yaml --localnet"

# --- Pruebas de Especificación de Objetivos ---
run_test "Escanear red local (--localnet)" "--localnet"
run_test "Escanear subred CIDR" "-i $IFACE $NETWORK"
run_test "Escanear rango de IPs" "-i $IFACE $TARGET_RANGE"
run_test "Leer objetivos desde fichero (--file)" "-f hostlist.txt"
run_test "Excluir IP individual (--exclude)" "--localnet --exclude $TARGET_SINGLE"
run_test "Excluir desde fichero (--exclude-file)" "--localnet --exclude-file excludelist.txt"
run_test "No realizar resolución DNS (--numeric)" "-N --localnet"

# --- Pruebas de Control del Escaneo ---
run_test "Timeout de host corto (-t)" "-t 100ms --localnet"
run_test "Número de reintentos bajo (-r)" "-r 1 --localnet"
run_test "Limitar ancho de banda (-B)" "-B 512k --localnet"
run_test "Factor de backoff alto (-b)" "-b 3.0 --localnet"
run_test "Aleatorizar hosts (-R) con semilla (--randomseed)" "-R --randomseed 12345 --localnet -vvv" # -vvv para ver el orden

# --- Pruebas de Formato de Salida y UI ---
run_test "Salida Quieta (-q)" "-q --localnet"
run_test "Salida Plana (-x)" "-x --localnet"
run_test "Salida JSON (--json)" "--json --localnet"
run_test "Salida CSV (--csv)" "--csv --localnet"
run_test "Mostrar RTT (-D)" "-D --localnet"
run_test "Ignorar duplicados (-g)" "-g --localnet"
run_test "Control de color (--color)" "--color=on --localnet"
run_test "Mostrar barra de progreso (--progress)" "--progress --localnet"

# --- Pruebas de Ficheros de Datos y Vendors ---
run_test "Usar fichero de MACs personalizado (--macfile)" "--macfile=custom_macs.txt --localnet"
run_test "Guardar captura en pcap (-W)" "-W scan.pcap --localnet"

# --- Pruebas de Gestión de Estado (Diff) ---
run_test "PASO 1: Crear fichero de estado base (--state-file)" "--state-file baseline.json --localnet"
run_test "PASO 2: Comparar con la base para ver diferencias (--diff)" "--diff --state-file baseline.json --localnet"

# --- Pruebas de Manipulación de Paquetes (Avanzado) ---
run_test "Especificar IP de origen ARP (-s)" "-s $GATEWAY $TARGET_SINGLE"
run_test "Especificar IP de origen ARP como 'dest'" "-s dest $TARGET_SINGLE"
run_test "Especificar MAC de origen Ethernet (-S)" "-S de:ad:be:ef:00:01 $TARGET_SINGLE"
run_test "Especificar MAC de destino Ethernet (-T)" "-T $GATEWAY_MAC $TARGET_SINGLE"
run_test "Especificar MAC de origen ARP (-u)" "-u de:ad:be:ef:00:02 $TARGET_SINGLE"
run_test "Especificar MAC de destino ARP (-w)" "-w de:ad:be:ef:00:03 $TARGET_SINGLE"
run_test "Usar operación ARP Reply (-o 2)" "-o 2 --localnet"
run_test "Usar framing LLC (-L)" "-L --localnet"
run_test "Usar VLAN Tagging (-Q)" "-Q 100 --localnet"
run_test "Añadir padding hexadecimal (-A)" "-A deadbeefcafe --localnet"
run_test "Cambiar EtherType (-y)" "-y 0x8899 --localnet"
run_test "Cambiar tipo de hardware ARP (-H)" "-H 2 --localnet"
run_test "Cambiar tipo de protocolo ARP (-p)" "-p 0x88a0 --localnet"
run_test "Cambiar longitud de hardware ARP (-a)" "-a 7 --localnet"
run_test "Cambiar longitud de protocolo ARP (-P)" "-P 5 --localnet"
run_test "Cambiar longitud de captura pcap (-n)" "-n 128 --localnet"

# --- Pruebas de Explotación Activa (que terminan) ---
run_test "Detectar modo promiscuo (--detect-promisc)" "--detect-promisc $TARGET_SINGLE"

# --- Pruebas de Verbosidad ---
run_test "Verbosidad Nivel 1 (-v)" "-v --localnet"
run_test "Verbosidad Nivel 2 (-vv)" "-vv --localnet"
run_test "Verbosidad Nivel 3 (-vvv)" "-vvv --localnet"


# ==============================================================================
#            PRUEBAS EXCLUIDAS (NO SE PUEDEN AUTOMATIZAR)
# ==============================================================================
# Los siguientes comandos inician modos de ejecución persistentes que no
# terminan por sí solos, por lo que se excluyen de esta suite automática.
#
# --- MODO MONITOR ---
# MOTIVO: Se ejecuta indefinidamente hasta que se presiona Ctrl+C.
# EJEMPLO: sudo ./go-arpscan --localnet --monitor
#
# --- MODO SPOOFING (MitM) ---
# MOTIVO: Se ejecuta indefinidamente hasta que se presiona Ctrl+C.
# EJEMPLO: sudo ./go-arpscan --spoof <VICTIMA_IP> --gateway <GATEWAY_IP>
# ==============================================================================


echo ""
echo "======================================================================"
echo "          SUITE DE PRUEBAS COMPLETADA"
echo "Todos los resultados han sido guardados en: $LOG_FILE"
echo "======================================================================"
