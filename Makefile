.PHONY: proto build run test clean tools lint-no-disk release-ci release-local release-multiarch build-all build-amd64 build-arm64

# ----------------------------------------------------------------------
# Defaults — override on the command line: `make run TENANT_ID=foo ...`
# ----------------------------------------------------------------------
TENANT_ID    ?= ispwatch
COLLECTOR_ID ?= coll-dev-01
SERVER       ?= localhost:8443
PKI_DIR      ?= ../pki
TENANT_DIR   := $(PKI_DIR)/tenants/$(TENANT_ID)/$(COLLECTOR_ID)

CLIENT_CERT  ?= $(TENANT_DIR)/client.fullchain.pem
CLIENT_KEY   ?= $(TENANT_DIR)/client.key.pem
TRUST_BUNDLE ?= $(PKI_DIR)/intermediate/chain.pem

GOFLAGS ?=

# ----------------------------------------------------------------------
# tools — installs codegen plugins (one-time, into $(go env GOPATH)/bin)
# ----------------------------------------------------------------------
tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# ----------------------------------------------------------------------
# proto — regenerate Go stubs from the .proto file
# Output: proto/v1/collector.pb.go + collector_grpc.pb.go
# ----------------------------------------------------------------------
proto:
	protoc --proto_path=proto/v1 \
	       --go_out=proto/v1 --go_opt=paths=source_relative \
	       --go-grpc_out=proto/v1 --go-grpc_opt=paths=source_relative \
	       proto/v1/collector.proto

build:
	go build $(GOFLAGS) -o collector ./cmd/collector

run: build
	./collector \
	  -tenant-id="$(TENANT_ID)" \
	  -collector-id="$(COLLECTOR_ID)" \
	  -server="$(SERVER)" \
	  -client-cert="$(CLIENT_CERT)" \
	  -client-key="$(CLIENT_KEY)" \
	  -trust-bundle="$(TRUST_BUNDLE)"

test: lint-no-disk
	go test ./...

# ----------------------------------------------------------------------
# lint-no-disk — enforces D-15: no executor in internal/tools/ may write
# credentials (or anything else) to disk. CI fails if this finds a hit.
# ----------------------------------------------------------------------
lint-no-disk:
	@! grep -rn 'os\.WriteFile\|os\.Create\|ioutil\.WriteFile\|os\.OpenFile' internal/tools/ \
	  || (echo "FAIL: disk-write API used in internal/tools/ — see D-15"; exit 1)
	@echo "lint-no-disk: OK"

clean:
	rm -f collector collector.exe ispwatch-agent
	rm -f proto/v1/*.pb.go
	rm -rf dist

# ----------------------------------------------------------------------
# release-ci / release-local — produzem tarball reproducible + sha256
# sidecar para distribuição via GitHub Releases (Plan 03-09).
#
# CI usa: make release-ci VERSION=${GITHUB_REF_NAME} GOOS=linux GOARCH=amd64
# Local (ops debug): make release-local                       (defaults)
#                    make release-local VERSION=v0.3.0 GOARCH=arm64
#
# Layout do tarball:
#   ispwatch-agent-<version>-<goos>-<goarch>/
#     ispwatch-agent              (binário Go, static via CGO_ENABLED=0)
#     ispwatch-agent.service      (systemd unit, copiado de packaging/)
#     config-template.yaml        (idem)
#     LICENSE-NOTICE.md           (idem)
# ----------------------------------------------------------------------
VERSION ?= dev-$(shell date +%s)
GOOS    ?= linux
GOARCH  ?= amd64
DIST_NAME = ispwatch-agent-$(VERSION)-$(GOOS)-$(GOARCH)
DIST_DIR  = dist/$(DIST_NAME)

release-ci:
	@echo "==> Building release tarball: $(DIST_NAME)"
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
	  go build -trimpath -ldflags="-s -w -X main.Version=$(VERSION)" \
	  -o $(DIST_DIR)/ispwatch-agent ./cmd/collector
	cp packaging/ispwatch-agent.service $(DIST_DIR)/
	cp packaging/config-template.yaml   $(DIST_DIR)/
	cp packaging/LICENSE-NOTICE.md      $(DIST_DIR)/
	cd dist && tar -czf $(DIST_NAME).tar.gz $(DIST_NAME)
	cd dist && sha256sum $(DIST_NAME).tar.gz > $(DIST_NAME).tar.gz.sha256
	@echo "==> Built: dist/$(DIST_NAME).tar.gz"
	@cat dist/$(DIST_NAME).tar.gz.sha256

release-local: release-ci
	@echo "==> Local release artifacts in dist/"
	@ls -la dist/

# ----------------------------------------------------------------------
# release-multiarch — build amd64 + arm64 tarballs in one shot.
# Iterates release-ci with GOARCH override. ARM64 covers AWS Graviton,
# Raspberry Pi 4+, Ampere Altra, Oracle Ampere A1.
#
# Note: GOARCH=arm (armv7, Pi 3 and older) is NOT included — the embedded
# eBPF object map (internal/ebpf/ebpf.go) currently ships only "amd64"
# and "arm64" variants. Adding armv7 requires regenerating ebpf.go via
# the dockerized build in internal/ebpf/Makefile *and* fixing a
# Utsname.Release type-mismatch in cmd/collector/main.go (32-bit ARM
# uses []uint8 vs []int8 on 64-bit). Tracked in HARDENING-NOTES.md.
# ----------------------------------------------------------------------
release-multiarch:
	@echo "==> Multi-arch release build (amd64 + arm64)"
	$(MAKE) release-ci GOOS=linux GOARCH=amd64
	$(MAKE) release-ci GOOS=linux GOARCH=arm64
	@echo "==> Multi-arch artifacts:"
	@ls -la dist/*.tar.gz

# ----------------------------------------------------------------------
# build-all / build-amd64 / build-arm64 — cross-compile sanity checks
# without producing tarballs. Faster iteration during dev hardening.
# Output: dist/collector-<arch>
# ----------------------------------------------------------------------
build-amd64:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	  go build -trimpath -ldflags="-s -w" \
	  -o dist/collector-amd64 ./cmd/collector
	@file dist/collector-amd64

build-arm64:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
	  go build -trimpath -ldflags="-s -w" \
	  -o dist/collector-arm64 ./cmd/collector
	@file dist/collector-arm64

build-all: build-amd64 build-arm64
	@echo "==> All architectures built:"
	@ls -la dist/collector-*
