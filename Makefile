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

.PHONY: help static-build static-package check-tools clean-dist ubuntu-static ubuntu-static-package check-ubuntu-tools

help:
	@echo "Available targets:"
	@echo "  make static-build           Build static binary for Linux (musl)."
	@echo "  make static-package         Build static binary, strip, package, and write sha256."
	@echo "  make clean-dist             Remove dist artifacts."
	@echo ""
	@echo "Optional variables:"
	@echo "  TARGET=<rust-target> (default: x86_64-unknown-linux-musl)"

check-tools:
	@missing=0; \
	if ! command -v cargo >/dev/null; then \
		echo "cargo is required."; \
		echo "Hint: install Rust toolchain first."; \
		missing=1; \
	fi; \
	if ! command -v rustup >/dev/null; then \
		echo "rustup is required."; \
		echo "Hint: install Rust toolchain first."; \
		missing=1; \
	fi; \
	if command -v rustup >/dev/null && ! rustup target list --installed | grep -q "^$(TARGET)$$"; then \
		echo "Missing Rust target: $(TARGET)"; \
		echo "Hint: rustup target add $(TARGET)"; \
		missing=1; \
	fi; \
	if ! command -v musl-gcc >/dev/null; then \
		echo "Missing musl-gcc (required for static musl linking)."; \
		os_name=$$(uname -s); \
		if [ "$$os_name" = "Linux" ]; then \
			echo "Hint (Debian/Ubuntu): sudo apt update && sudo apt install -y musl-tools"; \
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
	cargo build --release --target $(TARGET)
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
