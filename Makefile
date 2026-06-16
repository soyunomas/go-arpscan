# ==============================================================================
#  Makefile Profesional (Cross-Compile Docker + Paquete .deb Limpio)
# ==============================================================================

# --- Metadatos ---
APP_NAME      := go-arpscan
CMD_PATH      := ./cmd/go-arpscan
BIN_DIR       := bin
DIST_DIR      := dist

INSTALL_BIN_DIR := /usr/local/bin
INSTALL_CFG_DIR := /etc/$(APP_NAME)

# --- Versionado limpio ---
# --- Version fija ---
VERSION     := v1.4.0
DEB_VERSION := 1.4.0

# Metadata separada (NO contamina la versión)
COMMIT_HASH   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE    := $(shell date +%Y-%m-%dT%H:%M:%S%z)

# --- Docker ---
DOCKER_IMG    := ghcr.io/gythialy/golang-cross:v1.23.0
DOCKER_RUN    := docker run --rm -v $(PWD):/app -w /app --entrypoint /bin/bash $(DOCKER_IMG) -c

# --- Flags ---
LDFLAGS := -s -w \
	-X 'main.version=$(VERSION)' \
	-X 'main.commit=$(COMMIT_HASH)' \
	-X 'main.date=$(BUILD_DATE)'

# --- Colores ---
CYAN   := \033[36m
GREEN  := \033[32m
YELLOW := \033[33m
RESET  := \033[0m

.PHONY: all help build clean deps deb release pack

# ==============================================================================
# GENERAL
# ==============================================================================

all: deps build

help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUso:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

deps:
	@echo "$(CYAN)==> Dependencias...$(RESET)"
	go mod download
	go mod tidy

clean:
	@echo "$(YELLOW)==> Limpiando...$(RESET)"
	rm -rf $(BIN_DIR) $(DIST_DIR)

# ==============================================================================
# BUILD NATIVO
# ==============================================================================

build:
	@echo "$(CYAN)==> Build Linux nativo...$(RESET)"
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME) $(CMD_PATH)

# ==============================================================================
# CROSS-COMPILE (Docker)
# ==============================================================================

build-windows:
	@mkdir -p $(BIN_DIR)/windows_amd64
	$(DOCKER_RUN) "CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
	go build -ldflags \"$(LDFLAGS)\" -o $(BIN_DIR)/windows_amd64/$(APP_NAME).exe $(CMD_PATH)"

build-macos:
	@mkdir -p $(BIN_DIR)/darwin_amd64
	$(DOCKER_RUN) "CC=o64-clang CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
	go build -ldflags \"$(LDFLAGS)\" -o $(BIN_DIR)/darwin_amd64/$(APP_NAME) $(CMD_PATH)"

	@mkdir -p $(BIN_DIR)/darwin_arm64
	$(DOCKER_RUN) "CC=oa64-clang CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
	go build -ldflags \"$(LDFLAGS)\" -o $(BIN_DIR)/darwin_arm64/$(APP_NAME) $(CMD_PATH)"

build-linux-arm64:
	@mkdir -p $(BIN_DIR)/linux_arm64
	$(DOCKER_RUN) "CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	go build -ldflags \"$(LDFLAGS)\" -o $(BIN_DIR)/linux_arm64/$(APP_NAME) $(CMD_PATH)"

# ==============================================================================
# DEB PACKAGE (LIMPIO)
# ==============================================================================

deb: build
	@echo "$(CYAN)==> Creando .deb $(DEB_VERSION) limpio...$(RESET)"

	$(eval DEB_BUILD_DIR := $(DIST_DIR)/deb/$(APP_NAME)_$(DEB_VERSION)_amd64)

	# Estructura
	@mkdir -p $(DEB_BUILD_DIR)/DEBIAN
	@mkdir -p $(DEB_BUILD_DIR)$(INSTALL_BIN_DIR)
	@mkdir -p $(DEB_BUILD_DIR)$(INSTALL_CFG_DIR)
	@mkdir -p $(DEB_BUILD_DIR)/usr/share/doc/$(APP_NAME)

	# Binario
	@cp $(BIN_DIR)/$(APP_NAME) $(DEB_BUILD_DIR)$(INSTALL_BIN_DIR)/
	@chmod 755 $(DEB_BUILD_DIR)$(INSTALL_BIN_DIR)/$(APP_NAME)

	# Config
	@cp profiles.yaml $(DEB_BUILD_DIR)$(INSTALL_CFG_DIR)/
	@cp config.complete.yaml $(DEB_BUILD_DIR)$(INSTALL_CFG_DIR)/config.yaml
	@chmod 644 $(DEB_BUILD_DIR)$(INSTALL_CFG_DIR)/*

	# Docs
	@cp README.md LICENSE $(DEB_BUILD_DIR)/usr/share/doc/$(APP_NAME)/

	# CONTROL
	@echo "Package: $(APP_NAME)" > $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Version: $(DEB_VERSION)" >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Section: net" >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Priority: optional" >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Architecture: amd64" >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Maintainer: soyunomas <https://github.com/soyunomas/go-arpscan>" >> $(DEB_BUILD_DIR)/DEBIAN/control
	@echo "Description: Escáner ARP rápido en Go." >> $(DEB_BUILD_DIR)/DEBIAN/control

	# postinst (capabilities)
	@echo "#!/bin/sh" > $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "set -e" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "if [ \"\$$1\" = \"configure\" ]; then" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "  command -v setcap >/dev/null && setcap cap_net_raw,cap_net_admin+eip $(INSTALL_BIN_DIR)/$(APP_NAME) || true" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@echo "fi" >> $(DEB_BUILD_DIR)/DEBIAN/postinst
	@chmod 755 $(DEB_BUILD_DIR)/DEBIAN/postinst

	# Build
	@dpkg-deb --build $(DEB_BUILD_DIR) $(DIST_DIR)/$(APP_NAME)_$(DEB_VERSION)_amd64.deb

	@echo "$(GREEN)==> .deb generado correctamente$(RESET)"

# ==============================================================================
# RELEASE
# ==============================================================================

release: clean build build-windows build-macos build-linux-arm64 deb pack

pack:
	@mkdir -p $(DIST_DIR)

	@tar -czf $(DIST_DIR)/$(APP_NAME)_$(VERSION)_linux_amd64.tar.gz -C $(BIN_DIR) $(APP_NAME)
	@tar -czf $(DIST_DIR)/$(APP_NAME)_$(VERSION)_linux_arm64.tar.gz -C $(BIN_DIR)/linux_arm64 $(APP_NAME)
	@zip -j -q $(DIST_DIR)/$(APP_NAME)_$(VERSION)_windows_amd64.zip $(BIN_DIR)/windows_amd64/$(APP_NAME).exe
	@tar -czf $(DIST_DIR)/$(APP_NAME)_$(VERSION)_darwin_amd64.tar.gz -C $(BIN_DIR)/darwin_amd64 $(APP_NAME)
	@tar -czf $(DIST_DIR)/$(APP_NAME)_$(VERSION)_darwin_arm64.tar.gz -C $(BIN_DIR)/darwin_arm64 $(APP_NAME)

	@echo "$(GREEN)==> Release lista en dist/$(RESET)"
