# Production Dockerfile for the IspWatch Collector.
# Multi-stage: build a static binary in a Go toolchain image, then ship it
# in a minimal distroless image. Image is published as
# ghcr.io/ispwatch/collector by the publish-collector GitHub Actions
# workflow on every release tag.

# ---------- Stage 1: protoc + go build ----------
FROM golang:1.25-alpine AS build

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache git protoc protobuf-dev make ca-certificates

# Pre-install protoc Go plugin (messages only — certless, sem serviço gRPC).
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

WORKDIR /src

# Cache deps separately from source to keep rebuilds fast.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Regenerate proto stubs (cheap if up to date) — keeps the image
# self-contained even if the committed *.pb.go drift from the .proto.
ENV PATH="/go/bin:${PATH}"
RUN protoc --proto_path=proto/v1 \
           --go_out=proto/v1 --go_opt=paths=source_relative \
           proto/v1/collector.proto proto/v1/apm_stats.proto

# Static build (CGO_ENABLED=0) so we can run on distroless/scratch.
# -trimpath strips local paths from the binary; -s -w shrinks size; -X stamps
# the Version variable consumed by main.go for the startup log.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath \
      -ldflags "-s -w -X main.Version=${VERSION}" \
      -o /out/collector \
      ./cmd/collector

# ---------- Stage 2: runtime ----------
# Alpine (not distroless) so the entrypoint shell can expand env vars into
# CLI flags — keeps the Go binary simple (flag-only, no env-aware config)
# and the env-var contract documented in install-collector.sh's compose file.
FROM alpine:3.20

LABEL org.opencontainers.image.title="IspWatch Collector"
LABEL org.opencontainers.image.description="On-prem agent that connects via mTLS to the IspWatch central server."
LABEL org.opencontainers.image.source="https://github.com/ispwatch/collector"
LABEL org.opencontainers.image.licenses="proprietary"

RUN apk add --no-cache ca-certificates tini \
 && addgroup -S ispwatch \
 && adduser -S -G ispwatch -u 10001 ispwatch

# OpenTelemetry Java auto-instrumentation jar — embarcado na imagem do agent
# pra ser servido pra pods Java instrumentados (via initContainer injetado
# pelo nosso webhook). Versão fixa pra reprodutibilidade. Apache-2.0.
ARG OTEL_JAVAAGENT_VERSION=2.10.0
RUN apk add --no-cache --virtual .otel-build wget \
 && mkdir -p /opt/otel \
 && wget -q -O /opt/otel/javaagent.jar \
      "https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/download/v${OTEL_JAVAAGENT_VERSION}/opentelemetry-javaagent.jar" \
 && apk del .otel-build

# Trivy — scanner de SBOM (vulnerabilidade de aplicação, camada 2/3). Embarcado
# ao lado do binário do agent (decisão: binário leve, só GERAÇÃO de SBOM, SEM
# banco de CVE — o casamento com o catálogo roda no backend). Apache-2.0. Só é
# usado quando o toggle sbomScan está ligado. Versão fixa pra reprodutibilidade.
ARG TRIVY_VERSION=0.71.2
ARG TARGETARCH
RUN apk add --no-cache --virtual .trivy-build wget tar \
 && case "${TARGETARCH:-amd64}" in \
      arm64) TRIVY_ARCH="Linux-ARM64" ;; \
      *)     TRIVY_ARCH="Linux-64bit" ;; \
    esac \
 && wget -q -O /tmp/trivy.tar.gz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz" \
 && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
 && chmod 755 /usr/local/bin/trivy \
 && rm -f /tmp/trivy.tar.gz \
 && apk del .trivy-build

COPY --from=build /out/collector /usr/local/bin/collector
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/entrypoint.sh

USER ispwatch:ispwatch

# install-collector.sh mounts certs read-only at this path.
VOLUME ["/etc/ispwatch/certs"]

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
