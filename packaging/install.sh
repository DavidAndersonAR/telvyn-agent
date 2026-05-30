#!/usr/bin/env bash
# IspWatch Agent — script canônico de instalação Linux.
# Inspirado em DataDog/agent-linux-install-script (Apache-2.0).
# Atribuição: ver LICENSE-NOTICE.md neste diretório.

set -euo pipefail

# === Config ============================================================
ISPWATCH_AGENT_VERSION="${ISPWATCH_AGENT_VERSION:-latest}"
ISPWATCH_SITE="${ISPWATCH_SITE:-api.ispwatch.com}"
GITHUB_REPO="${ISPWATCH_GITHUB_REPO:-ispwatch/agent}"
# ISPWATCH_DOWNLOAD_BASE permite redirecionar para mirror/dev local sem
# editar o script (usado pelos smoke tests e pela VM dev no checkpoint).
ISPWATCH_DOWNLOAD_BASE="${ISPWATCH_DOWNLOAD_BASE:-https://github.com/${GITHUB_REPO}/releases/download}"

INSTALL_DIR="/usr/local/bin"
ETC_DIR="/etc/ispwatch"
LIB_DIR="/var/lib/ispwatch"
LOG_DIR="/var/log/ispwatch"
UNIT_PATH="/etc/systemd/system/ispwatch-agent.service"

# === Validação =========================================================
# ISPWATCH_ENROLL_TOKEN é obrigatório. Sem ele a enrollment exchange
# (Plan 09) não pode trocar token por cert mTLS.
if [[ -z "${ISPWATCH_ENROLL_TOKEN:-}" ]]; then
    echo "ERROR: ISPWATCH_ENROLL_TOKEN environment variable is required." >&2
    echo "" >&2
    # Pitfall 6: sem -E, sudo limpa o environment e perde o token mesmo
    # que o operador tenha exportado a variável.
    echo "Hint: did you forget 'sudo -E'? Without -E, sudo strips environment vars." >&2
    echo "" >&2
    echo "  curl -L <URL> | ISPWATCH_ENROLL_TOKEN=xxx sudo -E bash" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (use 'sudo -E')." >&2
    exit 1
fi

# === Traps =============================================================
on_error() {
    local lineno=$1
    echo "FATAL: install failed at line ${lineno}" >&2
    # Sem cleanup parcial — deixa o estado pra operador inspecionar.
    exit 1
}
on_exit() {
    rm -f /tmp/ispwatch-install-*.tar.gz /tmp/ispwatch-install-*.sha256 2>/dev/null || true
}
trap 'on_error $LINENO' ERR
trap on_exit EXIT

# === Detecção de distro (cascade DD-style) =============================
detect_distro() {
    if command -v lsb_release >/dev/null 2>&1; then
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    elif [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release && echo "$ID"
    else
        uname -s | tr '[:upper:]' '[:lower:]'
    fi
}
DISTRO=$(detect_distro)
echo "Detected distro: $DISTRO"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)         GO_ARCH=amd64 ;;
    aarch64|arm64)  GO_ARCH=arm64 ;;
    *)              echo "ERROR: unsupported arch $ARCH" >&2; exit 1 ;;
esac
echo "Detected arch: $GO_ARCH"

# === Sanidade systemd ==================================================
# systemd < 247 não suporta algumas directives modernas (ProcSubset=pid,
# RestrictNamespaces granular). Não falha o install — apenas avisa, o
# kernel ignora directives desconhecidas com warning.
if command -v systemctl >/dev/null 2>&1; then
    SD_VER=$(systemctl --version | head -1 | awk '{print $2}')
    if [[ "$SD_VER" =~ ^[0-9]+$ ]] && [[ "$SD_VER" -lt 247 ]]; then
        echo "WARN: systemd $SD_VER detected; some hardening directives require >= 247." >&2
        echo "      Agent will still install and run, but with reduced sandbox." >&2
    fi
else
    echo "ERROR: systemctl not found — IspWatch agent requires systemd." >&2
    exit 1
fi

# === Idempotência ======================================================
# Detecta install existente e aborta com hint claro (reinstall manual
# até ter modo --upgrade — deferido para fase futura).
if [[ -f "$INSTALL_DIR/ispwatch-agent" ]] || [[ -f "$UNIT_PATH" ]]; then
    echo "WARN: existing IspWatch agent detected." >&2
    echo "      To reinstall, first remove:" >&2
    echo "        sudo systemctl disable --now ispwatch-agent || true" >&2
    echo "        sudo rm -f $INSTALL_DIR/ispwatch-agent $UNIT_PATH" >&2
    echo "        sudo systemctl daemon-reload" >&2
    echo "      Then re-run this installer." >&2
    exit 1
fi

# === Resolução de versão ===============================================
if [[ "$ISPWATCH_AGENT_VERSION" == "latest" ]]; then
    VERSION=$(curl --proto '=https' --retry 5 --retry-delay 5 -sSL \
        "https://api.github.com/repos/$GITHUB_REPO/releases/latest" \
        | grep '"tag_name"' | head -1 | cut -d'"' -f4)
    if [[ -z "$VERSION" ]]; then
        echo "ERROR: could not resolve latest version from GitHub Releases." >&2
        exit 1
    fi
else
    VERSION="$ISPWATCH_AGENT_VERSION"
fi
echo "Installing IspWatch Agent ${VERSION} for linux-${GO_ARCH}"

TARBALL="ispwatch-agent-${VERSION}-linux-${GO_ARCH}.tar.gz"
URL="${ISPWATCH_DOWNLOAD_BASE}/${VERSION}/${TARBALL}"

# === Download + verify =================================================
TMP_TARBALL="/tmp/ispwatch-install-${VERSION}-${GO_ARCH}.tar.gz"
TMP_SHA="/tmp/ispwatch-install-${VERSION}-${GO_ARCH}.sha256"

curl --proto '=https' --retry 5 --retry-delay 5 -fsSL -o "$TMP_TARBALL" "$URL"
curl --proto '=https' --retry 5 --retry-delay 5 -fsSL -o "$TMP_SHA" "${URL}.sha256"

# sha256sum -c espera o arquivo no diretório corrente. Mover o sidecar
# pra um working dir temporário evita conflito com nomes absolutos.
WORK_DIR=$(mktemp -d /tmp/ispwatch-install-XXXXXX)
cp "$TMP_TARBALL" "${WORK_DIR}/${TARBALL}"
# O .sha256 publicado pelo release pipeline contém apenas o basename do
# tarball. Copiamos o sidecar e validamos dentro do WORK_DIR.
cp "$TMP_SHA" "${WORK_DIR}/${TARBALL}.sha256"
(cd "$WORK_DIR" && sha256sum -c "${TARBALL}.sha256")

# === User + dirs =======================================================
# user de sistema sem shell e sem home — superfície de ataque mínima.
if ! id -u ispwatch >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin ispwatch
fi
mkdir -p "$ETC_DIR" "$LIB_DIR" "$LOG_DIR"

# === Extract + install =================================================
tar -xzf "${WORK_DIR}/${TARBALL}" -C "$WORK_DIR"
EXTRACTED_DIR=$(find "$WORK_DIR" -maxdepth 1 -type d -name "ispwatch-agent-${VERSION}-*" | head -1)
if [[ -z "$EXTRACTED_DIR" ]]; then
    echo "ERROR: extracted dir not found in $WORK_DIR." >&2
    exit 1
fi

install -m 0755 -o root -g root "$EXTRACTED_DIR/ispwatch-agent" "$INSTALL_DIR/ispwatch-agent"
install -m 0640 -o root -g ispwatch "$EXTRACTED_DIR/config-template.yaml" "$ETC_DIR/agent.yaml"
install -m 0644 "$EXTRACTED_DIR/ispwatch-agent.service" "$UNIT_PATH"

# Permissões finais — exatamente o que CONTEXT.md trava.
chown -R ispwatch:ispwatch "$LIB_DIR" "$LOG_DIR"
chmod 0700 "$LIB_DIR"
chmod 0750 "$LOG_DIR"
chown root:ispwatch "$ETC_DIR"
chmod 0750 "$ETC_DIR"

# Cleanup do work dir (o trap on_exit cobre os /tmp/ispwatch-install-*.*).
rm -rf "$WORK_DIR"

# === Substituição de placeholders no config ============================
HOSTNAME_VALUE="${ISPWATCH_HOSTNAME:-$(hostname -f 2>/dev/null || hostname)}"
# Usar pipe como separador no sed evita conflito com / em paths/URLs.
sed -i \
    -e "s|__ENROLL_TOKEN__|${ISPWATCH_ENROLL_TOKEN}|g" \
    -e "s|__SITE__|${ISPWATCH_SITE}|g" \
    -e "s|__HOSTNAME__|${HOSTNAME_VALUE}|g" \
    "$ETC_DIR/agent.yaml"

# === Docker integration (opt-in) =======================================
# Phase 4 Plan 07 — `docker.host` check exige que o usuário `ispwatch` seja
# membro do grupo `docker` (acesso a /var/run/docker.sock). Esse grupo é
# root-equivalente no host (membros podem montar / como root via container);
# por isso é opt-in via env var explícita. Default OFF.
#
# Operacional: após habilitar, o agent service precisa ser reiniciado pra
# herdar a nova membership de grupo (`systemctl restart ispwatch-agent`).
if [[ "${ISPWATCH_DOCKER_INTEGRATION:-false}" == "true" ]]; then
    # groupadd -f cria o grupo se ainda não existir (em hosts sem Docker
    # instalado). Quando o operador instalar Docker depois, o grupo é o
    # mesmo (gid pode mudar, mas pertinência permanece pelo nome).
    groupadd -f docker >/dev/null 2>&1 || true
    usermod -aG docker ispwatch
    echo "Docker integration habilitada: usuário 'ispwatch' adicionado ao grupo 'docker'."
    echo "AVISO de segurança: membros do grupo 'docker' têm acesso root-equivalente"
    echo "                    ao daemon Docker (T-04-07-02). Audite quem mais está no grupo."
    echo "Após reiniciar o serviço o check docker.host poderá conectar ao socket:"
    echo "  sudo systemctl restart ispwatch-agent"
fi

# === Start =============================================================
systemctl daemon-reload
if [[ "${ISPWATCH_INSTALL_ONLY:-}" != "true" ]]; then
    systemctl enable --now ispwatch-agent.service
    echo ""
    echo "OK — ispwatch-agent installed and started."
    echo "Check status: systemctl status ispwatch-agent"
    echo "Logs:         journalctl -u ispwatch-agent -f"
else
    echo ""
    echo "OK — ispwatch-agent installed (ISPWATCH_INSTALL_ONLY=true; not started)."
    echo "Start manually: sudo systemctl enable --now ispwatch-agent"
fi
