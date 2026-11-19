.PHONY: fmt verify module-check vet compile build test test-release release release-all verify-repro clean docs

BINARY ?= nginx-ioc-scan
PKG ?= ./cmd/$(BINARY)
DOCS_DIR ?= $(CURDIR)/docs

.DEFAULT_GOAL := build

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)

export GOCACHE := $(CURDIR)/.gocache
export GOMODCACHE := $(CURDIR)/.gomodcache
export GOTOOLCHAIN := local
export CGO_ENABLED := 0
TARGET_OS ?= $(shell go env GOOS)
TARGET_ARCH ?= $(shell go env GOARCH)
EXE := $(if $(filter windows,$(TARGET_OS)),.exe,)
OUT ?= bin/$(BINARY)$(EXE)
BUILD_FLAGS ?= -trimpath -buildvcs=false
MOD_FLAG ?= -mod=readonly
LDFLAGS ?= -s -w -buildid= -X github.com/sfewer-r7/nginx2root-ioc-scan/internal/build.Version=$(VERSION) -X github.com/sfewer-r7/nginx2root-ioc-scan/internal/build.Commit=$(COMMIT)
RELEASE_TARGETS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64
RELEASE_ARCHIVES := \
	dist/$(BINARY)_darwin_amd64.tar.gz \
	dist/$(BINARY)_darwin_arm64.tar.gz \
	dist/$(BINARY)_linux_amd64.tar.gz \
	dist/$(BINARY)_linux_arm64.tar.gz \
	dist/$(BINARY)_windows_amd64.zip \
	dist/$(BINARY)_windows_arm64.zip

fmt:
	go fmt ./...

verify:
	go mod verify

module-check: verify
	go mod tidy -diff

vet: fmt verify
	go vet $(MOD_FLAG) ./...

compile: export GOOS = $(TARGET_OS)
compile: export GOARCH = $(TARGET_ARCH)
compile: verify
	@mkdir -p $(dir $(OUT))
	go build $(BUILD_FLAGS) $(MOD_FLAG) -ldflags "$(LDFLAGS)" -o $(OUT) $(PKG)

build: vet compile

test: vet
	go test $(MOD_FLAG) $(TESTFLAGS) ./...

test-release:
	python3 -B -m unittest discover -s .github/scripts -p 'test_*.py'

release: build
	@bash .github/scripts/package.sh "$(OUT)" "$(TARGET_OS)" "$(TARGET_ARCH)" "$(SOURCE_DATE_EPOCH)" dist

release-all: vet
	@set -eu; \
	for target in $(RELEASE_TARGETS); do \
		target_os=$${target%/*}; \
		target_arch=$${target#*/}; \
		ext=; if [ "$$target_os" = windows ]; then ext=.exe; fi; \
		$(MAKE) --no-print-directory compile \
			TARGET_OS="$$target_os" TARGET_ARCH="$$target_arch" \
			OUT="bin/$(BINARY)_$${target_os}_$${target_arch}$${ext}" \
			VERSION="$(VERSION)" COMMIT="$(COMMIT)"; \
		bash .github/scripts/package.sh \
			"bin/$(BINARY)_$${target_os}_$${target_arch}$${ext}" \
			"$$target_os" "$$target_arch" "$(SOURCE_DATE_EPOCH)" dist; \
	done
	@cd dist && sha256sum $(notdir $(RELEASE_ARCHIVES)) > SHA256SUMS

verify-repro:
	@mkdir -p bin
	@$(MAKE) --no-print-directory compile OUT=bin/$(BINARY).first
	@$(MAKE) --no-print-directory compile OUT=bin/$(BINARY).second
	@sha256sum bin/$(BINARY).first bin/$(BINARY).second
	@cmp bin/$(BINARY).first bin/$(BINARY).second

docs:
	@mkdir -p $(DOCS_DIR)
	@go doc -all ./internal/analyzer > $(DOCS_DIR)/analyzer.txt

clean:
	rm -rf bin dist
