# ==============================================================================
#  Makefile para go-arpscan (VERSIÓN FORZADA)
# ==============================================================================

# --- Variables del Proyecto ---
APP_NAME      := go-arpscan
CMD_PATH      := ./cmd/go-arpscan
BUILD_DIR     := bin
DIST_DIR      := dist
CONFIG_DIR    := /etc/$(APP_NAME)
BIN_DIR       := /usr/local/bin

# --- CONFIGURACIÓN FORZADA (Hardcoded) ---
# Aquí definimos manualmente la versión y arquitectura que quieres
VERSION       := v1.2.0
DEB_VERSION   := 1.2.0
ARCH          := amd64

# Datos adicionales para el binario (opcional, dejamos la fecha)
COMMIT_HASH   := manual-build
BUILD_DATE    := $(shell date +%Y-%m-%dT%H:%M:%S%z)
GOARCH        := amd64
GOOS          := linux

# --- Flags de Compilación (Linker) ---
# Inyectamos la versión forzada dentro del ejecutable también
LDFLAGS       := -s -w \
                 -X 'main.version=$(VERSION)' \
                 -X 'main.commit=$(COMMIT_HASH)' \
                 -X 'main.date=$(BUILD_DATE)'

# --- Colores ---
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
CYAN   := $(shell tput -Txterm setaf 6)
RESET  := $(shell tput -Txterm sgr0)

.PHONY: all build clean test deps deb install uninstall help run

# ==============================================================================
#  TARGETS PRINCIPALES
# ==============================================================================

## Construye todo y genera el paquete .deb (Versión 1.2.0 forzada)
all: clean deps build deb

## Compila el binario
build:
	@echo "${CYAN}==> Compilando $(APP_NAME) (FORZADO A: $(VERSION))...${RESET}"
	@mkdir -p $(BUILD_DIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME) $(CMD_PATH)
	@echo "${GREEN}==> Binario generado en: $(BUILD_DIR)/$(APP_NAME)${RESET}"

## Ejecuta la aplicación
run: build
	@echo "${YELLOW}==> Ejecutando con sudo...${RESET}"
	sudo ./$(BUILD_DIR)/$(APP_NAME) --localnet --progress

## Descarga dependencias
deps:
	@echo "${CYAN}==> Gestionando dependencias...${RESET}"
	go mod download
	go mod tidy

## Limpia los directorios
clean:
	@echo "${YELLOW}==> Limpiando artefactos...${RESET}"
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)
	go clean

# ==============================================================================
#  PAQUETERÍA DEBIAN (.deb)
# ==============================================================================

## Genera el paquete .deb con versión 1.2.0 limpia
deb: build
	@echo "${CYAN}==> Creando paquete .deb versión $(DEB_VERSION) para $(ARCH)...${RESET}"
	# Definimos el nombre exacto de la carpeta sin "dirty" ni hashes
	$(eval DEB_BUILD_DIR := $(DIST_DIR)/$(APP_NAME)_$(DEB_VERSION)_$(ARCH))
	
	# 1. Crear estructura
	@mkdir -p $(DEB_BUILD_DIR)/DEBIAN
	@mkdir -p $(DEB_BUILD_DIR)$(BIN_DIR)
	@mkdir -p $(DEB_BUILD_DIR)$(CONFIG_DIR)
	@mkdir -p $(DEB_BUILD_DIR)/usr/share/doc/$(APP_NAME)
	
	# 2. Copiar binario
	@cp $(BUILD_DIR)/$(APP_NAME) $(DEB_BUILD_DIR)$(BIN_DIR)/
	@chmod 755 $(DEB_BUILD_DIR)$(BIN_DIR)/$(APP_NAME)
	
	# 3. Copiar configuración
	@cp profiles.yaml $(DEB_BUILD_DIR)$(CONFIG_DIR)/profiles.yaml
	@cp config.complete.yaml $(DEB_BUILD_DIR)$(CONFIG_DIR)/config.yaml
	@chmod 644 $(DEB_BUILD_DIR)$(CONFIG_DIR)/*
	
	# 4. Copiar documentación
	@cp README.md $(DEB_BUILD_DIR)/usr/share/doc/$(APP_NAME)/
	@cp LICENSE $(DEB_BUILD_DIR)/usr/share/doc/$(APP_NAME)/
	
	# 5. Generar fichero CONTROL con la versión forzada
	@echo "Package: $(APP_NAME)" > $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Version: $(DEB_VERSION)" >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Section: net" >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Priority: optional" >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Architecture: $(ARCH)" >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Maintainer: soyunomas <soyunomas@example.com>" >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Description: Escáner de red ARP rápido y concurrente en Go." >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo " Herramienta moderna inspirada en arp-scan." >> $(DEB_BUILD_DIR)/DEBIAN/control
	
	# 6. Script post-instalación
	@echo "#!/bin/sh" > $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "set -e" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "if [ \"\$$1\" = \"configure\" ]; then" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "    if command -v setcap > /dev/null; then" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "        echo 'Configurando capabilities...'" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "        setcap cap_net_raw,cap_net_admin+eip $(BIN_DIR)/$(APP_NAME) || true" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "    fi" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "fi" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@chmod 755 $(DEB_BUILD_DIR)/DEBIAN/postinst
	
	# 7. Construir
	@dpkg-deb --build $(DEB_BUILD_DIR)
	@echo "${GREEN}==> Paquete creado: $(DEB_BUILD_DIR).deb${RESET}"

# ==============================================================================
#  AYUDA
# ==============================================================================

help:
	@echo ""
	@echo "${GREEN}Makefile (Modo Forzado v1.2.0)${RESET}"
	@echo "Targets: make all, make deb, make clean"
	@echo ""
