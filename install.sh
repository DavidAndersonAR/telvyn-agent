#!/usr/bin/env bash
# IspWatch Collector installer.
#
# Consumes a single-use enrollment token from the IspWatch UI, retrieves a
# tenant-scoped mTLS cert, writes config to disk, and runs the agent as a
# Docker container. Idempotent — re-running with a fresh token replaces the
# cert and restarts the container.
#
# Usage (typical, copied from the UI's wizard step "Token de instalação"):
#
#   curl -fsSL https://api.ispwatch.io/install/collector | \
#     INSTALL_TOKEN=<token> \
#     INSTALL_ENROLL_URL=https://api.ispwatch.io/api/noc/collectors/enroll/ \
#     bash
#
# Env vars (all optional unless noted):
#   INSTALL_TOKEN          (REQUIRED) single-use enrollment token
#   INSTALL_ENROLL_URL     (REQUIRED) full URL of the /enroll endpoint
#   INSTALL_DIR            base dir for certs+config         [default: /etc/ispwatch]
#   COLLECTOR_IMAGE        Docker image                      [default: ghcr.io/davidandersonar/telvyn-agent:latest]
#   COLLECTOR_LOG_LEVEL    debug|info|warn|error             [default: info]
#   COLLECTOR_NAME         container name                    [default: ispwatch-collector]
#   INSTALL_NO_START       if set, write files but don't 'docker compose up'
#
# Exit codes:
#   0  OK
#   1  missing required env / unsupported OS
#   2  enroll API returned an error
#   3  Docker missing / not running
#   4  failed to write files (permissions)

set -euo pipefail

# -------- styling ----------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_DIM=$'\033[2m'
else
  C_RESET=''; C_BOLD=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_DIM=''
fi

step() { printf '%s==>%s %s%s%s\n' "$C_BLUE" "$C_RESET" "$C_BOLD" "$*" "$C_RESET"; }
ok()   { printf '%s ✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s ⚠%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '%s ✗%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit "${2:-1}"; }

# -------- preconditions ----------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "Rode como root (sudo bash) — escreve em /etc e mexe em Docker." 1

: "${INSTALL_TOKEN:?Defina INSTALL_TOKEN=<token-da-UI>}"
: "${INSTALL_ENROLL_URL:?Defina INSTALL_ENROLL_URL=https://.../api/noc/collectors/enroll/}"

INSTALL_DIR="${INSTALL_DIR:-/etc/ispwatch}"
COLLECTOR_IMAGE="${COLLECTOR_IMAGE:-ghcr.io/davidandersonar/telvyn-agent:latest}"
COLLECTOR_LOG_LEVEL="${COLLECTOR_LOG_LEVEL:-info}"
COLLECTOR_NAME="${COLLECTOR_NAME:-ispwatch-collector}"

step "IspWatch Collector installer"
echo "${C_DIM}install_dir=${INSTALL_DIR}  image=${COLLECTOR_IMAGE}  log=${COLLECTOR_LOG_LEVEL}${C_RESET}"

# -------- tooling ----------------------------------------------------------
need_bin() { command -v "$1" >/dev/null 2>&1 || die "ferramenta '$1' não encontrada — instale antes de prosseguir."; }
need_bin curl
need_bin jq

if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    ok "Docker presente e acessível."
  else
    die "Docker instalado mas o daemon não responde. Verifique 'systemctl status docker'." 3
  fi
else
  die "Docker não encontrado. Instale Docker Engine antes (https://docs.docker.com/engine/install/)." 3
fi

# Detect compose v2 (preferred) or v1.
COMPOSE_BIN=""
if docker compose version >/dev/null 2>&1; then
  COMPOSE_BIN="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_BIN="docker-compose"
else
  die "Docker Compose v2 (docker compose) ou v1 (docker-compose) não encontrado." 3
fi
ok "Compose: ${COMPOSE_BIN}"

# -------- enroll -----------------------------------------------------------
step "Solicitando certificado ao IspWatch (${INSTALL_ENROLL_URL})"

ENROLL_TMP="$(mktemp)"
trap 'rm -f "$ENROLL_TMP"' EXIT

http_code=$(curl --silent --show-error --output "$ENROLL_TMP" --write-out '%{http_code}' \
  -H 'Content-Type: application/json' \
  -X POST "$INSTALL_ENROLL_URL" \
  -d "$(jq -n --arg t "$INSTALL_TOKEN" '{token:$t}')") || {
    die "Falha de rede chamando $INSTALL_ENROLL_URL (curl exit=$?)." 2
  }

if [ "$http_code" != "201" ] && [ "$http_code" != "200" ]; then
  detail=$(jq -r '.detail // .[]? // "(sem detalhe)"' "$ENROLL_TMP" 2>/dev/null || cat "$ENROLL_TMP")
  die "Enroll falhou (HTTP $http_code): $detail" 2
fi
ok "Token aceito — certificado emitido."

TENANT_ID=$(jq -r '.tenant_id' "$ENROLL_TMP")
COLLECTOR_ID=$(jq -r '.collector_id' "$ENROLL_TMP")
GRPC_ENDPOINT=$(jq -r '.server.grpc_endpoint' "$ENROLL_TMP")
NOT_AFTER=$(jq -r '.pki.not_after' "$ENROLL_TMP")

[ -n "$TENANT_ID" ] && [ "$TENANT_ID" != "null" ]     || die "Resposta inválida (tenant_id ausente)." 2
[ -n "$COLLECTOR_ID" ] && [ "$COLLECTOR_ID" != "null" ] || die "Resposta inválida (collector_id ausente)." 2
[ -n "$GRPC_ENDPOINT" ] && [ "$GRPC_ENDPOINT" != "null" ] || die "Resposta inválida (server.grpc_endpoint ausente)." 2

echo "${C_DIM}tenant=${TENANT_ID} collector=${COLLECTOR_ID}${C_RESET}"
echo "${C_DIM}server=${GRPC_ENDPOINT} cert válido até ${NOT_AFTER}${C_RESET}"

# -------- write files ------------------------------------------------------
step "Escrevendo cert/config em ${INSTALL_DIR}"

CERT_DIR="${INSTALL_DIR}/certs/${COLLECTOR_ID}"
COMPOSE_DIR="${INSTALL_DIR}/compose"
LOG_DIR="${INSTALL_DIR}/logs"

mkdir -p "$CERT_DIR" "$COMPOSE_DIR" "$LOG_DIR" || die "Sem permissão para criar ${INSTALL_DIR}." 4
chmod 750 "$INSTALL_DIR" "$CERT_DIR"

# Concatenate intermediate after the leaf cert so the server sees the full
# chain on the mTLS handshake (Quarkus PeerCertInterceptor walks it down to
# the OU=collector_id leaf).
jq -r '.pki.cert_pem' "$ENROLL_TMP"          > "${CERT_DIR}/client.cert.pem"
jq -r '.pki.intermediate_pem' "$ENROLL_TMP" >> "${CERT_DIR}/client.cert.pem"
jq -r '.pki.key_pem' "$ENROLL_TMP"           > "${CERT_DIR}/client.key.pem"

# Trust bundle for the agent: validates the server cert (signed by the same
# intermediate or root in dev/SaaS).
{ jq -r '.pki.intermediate_pem' "$ENROLL_TMP"; jq -r '.pki.root_pem' "$ENROLL_TMP"; } \
  > "${CERT_DIR}/trust-bundle.pem"

chmod 600 "${CERT_DIR}/client.key.pem"
chmod 644 "${CERT_DIR}/client.cert.pem" "${CERT_DIR}/trust-bundle.pem"
ok "Certs gravados em ${CERT_DIR} (key 0600)."

COMPOSE_FILE="${COMPOSE_DIR}/${COLLECTOR_NAME}.yml"
cat > "$COMPOSE_FILE" <<EOF
# Generated by install-collector.sh on $(date -u +%FT%TZ).
# Re-run the installer with a new token to refresh the cert.
services:
  ${COLLECTOR_NAME}:
    image: ${COLLECTOR_IMAGE}
    container_name: ${COLLECTOR_NAME}
    restart: unless-stopped
    network_mode: host
    environment:
      COLLECTOR_TENANT_ID: "${TENANT_ID}"
      COLLECTOR_ID: "${COLLECTOR_ID}"
      COLLECTOR_SERVER: "${GRPC_ENDPOINT}"
      COLLECTOR_CLIENT_CERT: "/etc/ispwatch/certs/client.cert.pem"
      COLLECTOR_CLIENT_KEY: "/etc/ispwatch/certs/client.key.pem"
      COLLECTOR_TRUST_BUNDLE: "/etc/ispwatch/certs/trust-bundle.pem"
      COLLECTOR_LOG_LEVEL: "${COLLECTOR_LOG_LEVEL}"
    volumes:
      - ${CERT_DIR}:/etc/ispwatch/certs:ro
      - ${LOG_DIR}:/var/log/ispwatch
EOF
ok "docker-compose escrito em ${COMPOSE_FILE}."

# -------- start ------------------------------------------------------------
if [ -n "${INSTALL_NO_START:-}" ]; then
  warn "INSTALL_NO_START setado — pulando 'compose up'."
  echo "Para subir manualmente:  ${COMPOSE_BIN} -f ${COMPOSE_FILE} up -d"
  exit 0
fi

step "Subindo Collector via Docker Compose"
$COMPOSE_BIN -f "$COMPOSE_FILE" pull
$COMPOSE_BIN -f "$COMPOSE_FILE" up -d --remove-orphans

# Quick health: wait up to 20s for the container to be running.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  state=$(docker inspect -f '{{.State.Status}}' "$COLLECTOR_NAME" 2>/dev/null || echo "")
  if [ "$state" = "running" ]; then
    ok "Container '${COLLECTOR_NAME}' rodando."
    break
  fi
  sleep 2
done
[ "$state" = "running" ] || warn "Container não chegou a 'running' em 20s — confira: docker logs ${COLLECTOR_NAME}"

step "Concluído."
cat <<EOF

  ${C_BOLD}Próximos passos${C_RESET}
    • Logs em tempo real:   docker logs -f ${COLLECTOR_NAME}
    • Status na UI:         abra Settings → Collectors no IspWatch
    • Re-enroll (cert novo): rode este script de novo com um INSTALL_TOKEN fresh

  ${C_DIM}cert expira em: ${NOT_AFTER}${C_RESET}

EOF
