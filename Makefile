APP := rift
TARGET ?= x86_64-unknown-linux-musl
DIST_DIR := dist
RELEASE_BIN := target/$(TARGET)/release/$(APP)
DIST_BIN := $(DIST_DIR)/$(APP)
VERSION := $(shell sed -nE 's/^version *= *"([^"]+)"/\1/p' Cargo.toml | head -n1)
TARGET_ARCH := $(word 1,$(subst -, ,$(TARGET)))
TARGET_LIBC := $(word 4,$(subst -, ,$(TARGET)))
PKG_BASENAME := $(APP)-v$(VERSION)-linux-$(TARGET_ARCH)-$(TARGET_LIBC)
PKG_TAR := $(PKG_BASENAME).tar.gz
PKG_SHA256 := $(PKG_TAR).sha256
RUSTUP_INIT_URL := https://sh.rustup.rs
APT_BOOTSTRAP_PACKAGES := git curl ca-certificates build-essential musl-tools
CARGO_BIN := $(shell if command -v cargo >/dev/null 2>&1; then command -v cargo; elif [ -x "$(HOME)/.cargo/bin/cargo" ]; then printf '%s\n' "$(HOME)/.cargo/bin/cargo"; fi)
RUSTUP_BIN := $(shell if command -v rustup >/dev/null 2>&1; then command -v rustup; elif [ -x "$(HOME)/.cargo/bin/rustup" ]; then printf '%s\n' "$(HOME)/.cargo/bin/rustup"; fi)

.PHONY: help print-bootstrap-apt bootstrap-apt static-build static-package check-tools clean-dist

help:
	@echo "Available targets:"
	@echo "  make print-bootstrap-apt    Print Debian/Ubuntu bootstrap steps for static musl builds."
	@echo "  make bootstrap-apt          Install Debian/Ubuntu toolchain for static musl builds."
	@echo "  make static-build           Build static binary for Linux (musl)."
	@echo "  make static-package         Build static binary, strip, package, and write sha256."
	@echo "  make clean-dist             Remove dist artifacts."
	@echo ""
	@echo "Optional variables:"
	@echo "  TARGET=<rust-target> (default: x86_64-unknown-linux-musl)"

print-bootstrap-apt:
	@echo "Debian/Ubuntu bootstrap steps for static musl build:"
	@echo "  sudo apt update"
	@echo "  sudo apt install -y $(APT_BOOTSTRAP_PACKAGES)"
	@echo "  curl $(RUSTUP_INIT_URL) -sSf | sh -s -- -y"
	@echo "  . \"$$HOME/.cargo/env\""
	@echo "  rustup target add $(TARGET)"
	@echo "  make static-package TARGET=$(TARGET)"

bootstrap-apt:
	@set -e; \
	if ! command -v apt-get >/dev/null 2>&1; then \
		echo "bootstrap-apt: apt-get not found. This target is for Debian/Ubuntu."; \
		exit 1; \
	fi; \
	if [ "$$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi; \
	$$SUDO apt update; \
	$$SUDO apt install -y $(APT_BOOTSTRAP_PACKAGES); \
	if ! command -v rustup >/dev/null 2>&1 && [ ! -x "$(HOME)/.cargo/bin/rustup" ]; then \
		curl $(RUSTUP_INIT_URL) -sSf | sh -s -- -y; \
	fi; \
	RUSTUP_BIN="$$(if command -v rustup >/dev/null 2>&1; then command -v rustup; else printf '%s\n' "$(HOME)/.cargo/bin/rustup"; fi)"; \
	"$$RUSTUP_BIN" target add $(TARGET); \
	echo "bootstrap-apt: toolchain is ready."; \
	echo "If cargo is not in PATH yet, run: . \"$$HOME/.cargo/env\""; \
	echo "Next: make static-package TARGET=$(TARGET)"

check-tools:
	@missing=0; \
	if [ -z "$(CARGO_BIN)" ]; then \
		echo "cargo is required."; \
		echo "Hint: install Rust toolchain first."; \
		if command -v apt-get >/dev/null 2>&1; then \
			echo "Hint (Debian/Ubuntu): make print-bootstrap-apt"; \
		fi; \
		missing=1; \
	fi; \
	if [ -z "$(RUSTUP_BIN)" ]; then \
		echo "rustup is required."; \
		echo "Hint: install Rust toolchain first."; \
		if command -v apt-get >/dev/null 2>&1; then \
			echo "Hint (Debian/Ubuntu): make print-bootstrap-apt"; \
		fi; \
		missing=1; \
	fi; \
	if [ -n "$(RUSTUP_BIN)" ] && ! "$(RUSTUP_BIN)" target list --installed | grep -q "^$(TARGET)$$"; then \
		echo "Missing Rust target: $(TARGET)"; \
		echo "Hint: rustup target add $(TARGET)"; \
		missing=1; \
	fi; \
	if ! command -v musl-gcc >/dev/null; then \
		echo "Missing musl-gcc (required for static musl linking)."; \
		os_name=$$(uname -s); \
		if [ "$$os_name" = "Linux" ]; then \
			echo "Hint (Debian/Ubuntu): make print-bootstrap-apt"; \
			echo "Hint (Fedora): sudo dnf install -y musl-gcc"; \
		else \
			echo "Hint: install musl toolchain for your system."; \
		fi; \
		missing=1; \
	fi; \
	if [ "$$missing" -ne 0 ]; then \
		echo "check-tools: missing dependencies detected."; \
		exit 1; \
	fi; \
	echo "check-tools: all required tools are available."

static-build: check-tools
	@mkdir -p $(DIST_DIR)
	"$(CARGO_BIN)" build --release --target $(TARGET)
	cp $(RELEASE_BIN) $(DIST_BIN)
	@echo "Built: $(DIST_BIN)"
	@file $(DIST_BIN) || true
	@ldd $(DIST_BIN) || true

static-package: static-build
	strip $(DIST_BIN)
	tar -czf $(PKG_TAR) -C $(DIST_DIR) $(APP)
	sha256sum $(PKG_TAR) > $(PKG_SHA256)
	@echo "Packaged: $(PKG_TAR)"
	@echo "Checksum: $(PKG_SHA256)"

clean-dist:
	rm -rf $(DIST_DIR)
