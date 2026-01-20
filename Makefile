# ==============================================================================
#  Makefile Profesional (Cross-Compile Docker + Paquete .deb Corregido)
# ==============================================================================

# --- Metadatos ---
APP_NAME      := go-arpscan
CMD_PATH      := ./cmd/go-arpscan
BIN_DIR       := bin
DIST_DIR      := dist

# Rutas de instalación para el paquete .deb
INSTALL_BIN_DIR := /usr/local/bin
INSTALL_CFG_DIR := /etc/$(APP_NAME)

# --- Versiones ---
# VERSION: Usada para el binario de Go (ej: v1.2.0)
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "v1.2.0")
# DEB_VERSION: Usada para el paquete Debian (ej: 1.2.0, sin la 'v' inicial)
DEB_VERSION   := $(shell echo $(VERSION) | sed 's/^v//')

COMMIT_HASH   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE    := $(shell date +%Y-%m-%dT%H:%M:%S%z)

# --- Docker Image para Cross-Compilation ---
DOCKER_IMG    := ghcr.io/gythialy/golang-cross:v1.23.0
# Usamos --entrypoint /bin/bash para evitar el error 'flag -c'
DOCKER_RUN    := docker run --rm -v $(PWD):/app -w /app --entrypoint /bin/bash $(DOCKER_IMG) -c

# --- Flags ---
LDFLAGS       := -s -w -X 'main.version=$(VERSION)' -X 'main.commit=$(COMMIT_HASH)' -X 'main.date=$(BUILD_DATE)'

# --- Colores ---
CYAN   := \033[36m
GREEN  := \033[32m
YELLOW := \033[33m
RESET  := \033[0m

.PHONY: all help build clean deps release deb pack

##@ General

all: deps build ## Prepara dependencias y compila nativamente para Linux

help: ## Muestra esta ayuda
	@awk 'BEGIN {FS = ":.*##"; printf "\nUso:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

deps: ## Descarga dependencias
	@echo "$(CYAN)==> Gestionando dependencias...$(RESET)"
	go mod download
	go mod tidy

clean: ## Limpia binarios y distribuciones
	@echo "$(YELLOW)==> Limpiando...$(RESET)"
	rm -rf $(BIN_DIR)
	rm -rf $(DIST_DIR)

##@ Compilación Nativa (Linux)

build: ## Compila para tu Linux actual (Nativo)
	@echo "$(CYAN)==> Compilando nativamente (Linux)...$(RESET)"
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME) $(CMD_PATH)

##@ Cross-Compilation (Dockerizada)

build-windows: ## Compila para Windows (usa Docker)
	@echo "$(CYAN)==> Compilando para Windows AMD64 (vía Docker)...$(RESET)"
	@mkdir -p $(BIN_DIR)/windows_amd64
	$(DOCKER_RUN) "CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
		go build -ldflags \"$(LDFLAGS)\" -o $(BIN_DIR)/windows_amd64/$(APP_NAME).exe $(CMD_PATH)"

build-macos: ## Compila para macOS Intel y Silicon (usa Docker)
	@echo "$(CYAN)==> Compilando para macOS AMD64 (Intel) (vía Docker)...$(RESET)"
	@mkdir -p $(BIN_DIR)/darwin_amd64
	$(DOCKER_RUN) "CC=o64-clang CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
		go build -ldflags \"$(LDFLAGS)\" -o $(BIN_DIR)/darwin_amd64/$(APP_NAME) $(CMD_PATH)"
	
	@echo "$(CYAN)==> Compilando para macOS ARM64 (Silicon) (vía Docker)...$(RESET)"
	@mkdir -p $(BIN_DIR)/darwin_arm64
	$(DOCKER_RUN) "CC=oa64-clang CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
		go build -ldflags \"$(LDFLAGS)\" -o $(BIN_DIR)/darwin_arm64/$(APP_NAME) $(CMD_PATH)"

build-linux-arm64: ## Compila para Linux ARM64 (Raspberry Pi) (vía Docker)
	@echo "$(CYAN)==> Compilando para Linux ARM64 (vía Docker)...$(RESET)"
	@mkdir -p $(BIN_DIR)/linux_arm64
	$(DOCKER_RUN) "CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
		go build -ldflags \"$(LDFLAGS)\" -o $(BIN_DIR)/linux_arm64/$(APP_NAME) $(CMD_PATH)"

##@ Paquetería (.deb y Releases)

deb: build ## Genera paquete .deb (Nativo Linux AMD64)
	@echo "$(CYAN)==> Creando paquete .deb versión $(DEB_VERSION) (Clean)...$(RESET)"
	# Usamos DEB_VERSION (sin 'v') para el nombre del directorio y el fichero control
	$(eval DEB_BUILD_DIR := $(DIST_DIR)/deb_package/$(APP_NAME)_$(DEB_VERSION)_amd64)
	
	# 1. Crear estructura
	@mkdir -p $(DEB_BUILD_DIR)/DEBIAN
	@mkdir -p $(DEB_BUILD_DIR)$(INSTALL_BIN_DIR)
	@mkdir -p $(DEB_BUILD_DIR)$(INSTALL_CFG_DIR)
	@mkdir -p $(DEB_BUILD_DIR)/usr/share/doc/$(APP_NAME)
	
	# 2. Copiar binario y dar permisos
	@cp $(BIN_DIR)/$(APP_NAME) $(DEB_BUILD_DIR)$(INSTALL_BIN_DIR)/
	@chmod 755 $(DEB_BUILD_DIR)$(INSTALL_BIN_DIR)/$(APP_NAME)
	
	# 3. Copiar configuración
	@cp profiles.yaml $(DEB_BUILD_DIR)$(INSTALL_CFG_DIR)/profiles.yaml
	@cp config.complete.yaml $(DEB_BUILD_DIR)$(INSTALL_CFG_DIR)/config.yaml
	@chmod 644 $(DEB_BUILD_DIR)$(INSTALL_CFG_DIR)/*
	
	# 4. Copiar documentación
	@cp README.md LICENSE $(DEB_BUILD_DIR)/usr/share/doc/$(APP_NAME)/
	
	# 5. Generar CONTROL (Usando DEB_VERSION sin la 'v')
	@echo "Package: $(APP_NAME)" > $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Version: $(DEB_VERSION)" >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Section: net" >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Priority: optional" >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Architecture: amd64" >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Maintainer: soyunomas <https://github.com/soyunomas/go-arpscan>" >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Description: Escáner de red ARP rápido y concurrente en Go." >> $(DEB_BUILD_DIR)/DEBIAN/control
	
	# 6. Script post-instalación (Capabilities para no usar sudo siempre)
	@echo "#!/bin/sh" > $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "set -e" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "if [ \"\$$1\" = \"configure\" ]; then" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "    if command -v setcap > /dev/null; then" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "        echo 'Configurando capabilities...'" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "        setcap cap_net_raw,cap_net_admin+eip $(INSTALL_BIN_DIR)/$(APP_NAME) || true" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "    fi" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "fi" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@chmod 755 $(DEB_BUILD_DIR)/DEBIAN/postinst
	
	# 7. Construir paquete
	@dpkg-deb --build $(DEB_BUILD_DIR) $(DIST_DIR)/$(APP_NAME)_$(DEB_VERSION)_amd64.deb
	@echo "$(GREEN)==> Paquete .deb generado en $(DIST_DIR)$(RESET)"

release: clean build build-windows build-macos build-linux-arm64 deb pack ## Genera TODO y empaqueta

pack: ## Empaqueta los binarios en .zip y .tar.gz
	@echo "$(CYAN)==> Empaquetando releases...$(RESET)"
	@mkdir -p $(DIST_DIR)
	
	# Linux AMD64 (Nativo)
	@tar -czf $(DIST_DIR)/$(APP_NAME)_$(VERSION)_linux_amd64.tar.gz -C $(BIN_DIR) $(APP_NAME) \
		-C ../.. README.md LICENSE profiles.yaml config.complete.yaml || true
	
	# Linux ARM64
	@tar -czf $(DIST_DIR)/$(APP_NAME)_$(VERSION)_linux_arm64.tar.gz -C $(BIN_DIR)/linux_arm64 $(APP_NAME) \
		-C ../.. README.md LICENSE profiles.yaml config.complete.yaml || true

	# Windows
	@zip -j -q $(DIST_DIR)/$(APP_NAME)_$(VERSION)_windows_amd64.zip $(BIN_DIR)/windows_amd64/$(APP_NAME).exe \
		README.md LICENSE profiles.yaml config.complete.yaml || true

	# macOS
	@tar -czf $(DIST_DIR)/$(APP_NAME)_$(VERSION)_darwin_amd64.tar.gz -C $(BIN_DIR)/darwin_amd64 $(APP_NAME) \
		-C ../.. README.md LICENSE profiles.yaml config.complete.yaml || true
	@tar -czf $(DIST_DIR)/$(APP_NAME)_$(VERSION)_darwin_arm64.tar.gz -C $(BIN_DIR)/darwin_arm64 $(APP_NAME) \
		-C ../.. README.md LICENSE profiles.yaml config.complete.yaml || true

	@echo "$(GREEN)==> ¡Todo listo en $(DIST_DIR)!$(RESET)"
	@ls -lh $(DIST_DIR)
