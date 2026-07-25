#!/usr/bin/env bash
# Telvyn / IspWatch Agent — script canônico de instalação Linux (systemd).
# Inspirado em DataDog/agent-linux-install-script (Apache-2.0).
# Atribuição: ver LICENSE-NOTICE.md neste diretório.
#
# Modelo CERTLESS/INGEST (Datadog-style): o agent autentica no gateway
# /api/ingest/v1 com Bearer token (iwI_) sobre HTTPS — sem enrollment, sem
# mTLS, sem cert por máquina. O antigo caminho mTLS ("Plan 09") foi removido.
#
# Uso (o portal gera o comando pronto na tela "Instalar agent"):
#   curl -fsSL <este script> | \
#     ISPWATCH_INGEST_URL='https://telvyn.suaempresa.com' \
#     ISPWATCH_INGEST_TOKEN='iwI_...' \
#     ISPWATCH_AGENT_KIND=linux \
#     sudo -E bash

set -euo pipefail

# === Config ============================================================
# Obrigatórios (Bearer certless):
#   ISPWATCH_INGEST_URL    base do portal (https://...); o agent normaliza o
#                          sufixo /api/ingest/v1 sozinho.
#   ISPWATCH_INGEST_TOKEN  token iwI_ (Bearer).
# Opcionais:
#   ISPWATCH_AGENT_KIND    linux (default) — registra a máquina como host de app.
#   ISPWATCH_HOSTNAME      nome reportado (default: FQDN da máquina).
#   qualquer ISPWATCH_*/COLLECTOR_LOG_LEVEL extra é repassado ao agente (toggles).
ISPWATCH_AGENT_VERSION="${ISPWATCH_AGENT_VERSION:-latest}"
ISPWATCH_AGENT_KIND="${ISPWATCH_AGENT_KIND:-linux}"
# ISPWATCH_UPGRADE=true → modo ATUALIZAÇÃO (F2a): troca o binário + a unit de uma
# instalação existente e reinicia, SEM reescrever o agent.env (preserva token,
# config e toggles do operador). Não exige INGEST_URL/TOKEN (já estão no env file).
# Comando pronto: curl -fsSL <URL> | ISPWATCH_UPGRADE=true sudo -E bash
ISPWATCH_UPGRADE="${ISPWATCH_UPGRADE:-false}"
GITHUB_REPO="${ISPWATCH_GITHUB_REPO:-DavidAndersonAR/telvyn-agent}"
# ISPWATCH_DOWNLOAD_BASE permite redirecionar para mirror/dev local sem
# editar o script (usado pelos smoke tests e por VMs de dev).
ISPWATCH_DOWNLOAD_BASE="${ISPWATCH_DOWNLOAD_BASE:-https://github.com/${GITHUB_REPO}/releases/download}"

INSTALL_DIR="/usr/local/bin"
ETC_DIR="/etc/ispwatch"
LIB_DIR="/var/lib/ispwatch"
LOG_DIR="/var/log/ispwatch"
ENV_FILE="${ETC_DIR}/agent.env"
UNIT_PATH="/etc/systemd/system/ispwatch-agent.service"

# === Validação =========================================================
# No modelo certless, INGEST_URL + INGEST_TOKEN são obrigatórios (substituem
# o antigo ISPWATCH_ENROLL_TOKEN do fluxo mTLS).
# No modo upgrade, INGEST_URL/TOKEN vêm do agent.env existente — não exigir.
if [[ "$ISPWATCH_UPGRADE" != "true" ]]; then
    missing=""
    [[ -z "${ISPWATCH_INGEST_URL:-}" ]]   && missing="${missing} ISPWATCH_INGEST_URL"
    [[ -z "${ISPWATCH_INGEST_TOKEN:-}" ]] && missing="${missing} ISPWATCH_INGEST_TOKEN"
    if [[ -n "$missing" ]]; then
        echo "ERROR: variável(is) de ambiente obrigatória(s) ausente(s):${missing}" >&2
        echo "" >&2
        # Sem -E, sudo limpa o environment e perde as vars mesmo que o operador
        # as tenha exportado.
        echo "Dica: esqueceu o 'sudo -E'? Sem -E, o sudo descarta as env vars." >&2
        echo "" >&2
        echo "  curl -fsSL <URL> | \\" >&2
        echo "    ISPWATCH_INGEST_URL='https://telvyn.suaempresa.com' \\" >&2
        echo "    ISPWATCH_INGEST_TOKEN='iwI_...' \\" >&2
        echo "    sudo -E bash" >&2
        exit 1
    fi
fi

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: precisa rodar como root (use 'sudo -E')." >&2
    exit 1
fi

# === Traps =============================================================
on_error() {
    local lineno=$1
    echo "FATAL: install falhou na linha ${lineno}" >&2
    # Sem cleanup parcial — deixa o estado pro operador inspecionar.
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
echo "Distro detectada: $DISTRO"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)         GO_ARCH=amd64 ;;
    aarch64|arm64)  GO_ARCH=arm64 ;;
    *)              echo "ERROR: arquitetura não suportada: $ARCH (só amd64/arm64)" >&2; exit 1 ;;
esac
echo "Arquitetura detectada: $GO_ARCH"

# === Sanidade systemd ==================================================
# systemd < 247 não suporta algumas directives modernas (ProcSubset=pid,
# RestrictNamespaces granular). Não falha o install — apenas avisa; o kernel
# ignora directives desconhecidas com warning.
if command -v systemctl >/dev/null 2>&1; then
    SD_VER=$(systemctl --version | head -1 | awk '{print $2}')
    if [[ "$SD_VER" =~ ^[0-9]+$ ]] && [[ "$SD_VER" -lt 247 ]]; then
        echo "WARN: systemd $SD_VER detectado; algumas directives de hardening exigem >= 247." >&2
        echo "      O agent instala e roda mesmo assim, com sandbox reduzido." >&2
    fi
else
    echo "ERROR: systemctl não encontrado — o agent IspWatch requer systemd." >&2
    exit 1
fi

# === Idempotência / upgrade ============================================
# Instalação nova aborta se já existe (evita sobrescrever config). O modo
# ISPWATCH_UPGRADE=true (F2a) inverte isso: EXIGE uma instalação pra atualizar.
INSTALLED=false
if [[ -f "$INSTALL_DIR/ispwatch-agent" ]] || [[ -f "$UNIT_PATH" ]]; then
    INSTALLED=true
fi
if [[ "$ISPWATCH_UPGRADE" == "true" ]]; then
    if [[ "$INSTALLED" != "true" ]]; then
        echo "ERROR: ISPWATCH_UPGRADE=true, mas não há instalação do agent aqui pra atualizar." >&2
        echo "       Rode o instalador normal (sem ISPWATCH_UPGRADE) primeiro." >&2
        exit 1
    fi
    echo "Modo upgrade: instalação existente detectada — troco o binário e reinicio (config preservada)."
elif [[ "$INSTALLED" == "true" ]]; then
    echo "WARN: instalação existente do agent IspWatch detectada." >&2
    echo "      Para ATUALIZAR no lugar (preserva token/config), rode com ISPWATCH_UPGRADE=true:" >&2
    echo "        curl -fsSL <URL> | ISPWATCH_UPGRADE=true sudo -E bash" >&2
    echo "      Ou, para reinstalar do zero, remova antes:" >&2
    echo "        sudo systemctl disable --now ispwatch-agent || true" >&2
    echo "        sudo rm -f $INSTALL_DIR/ispwatch-agent $UNIT_PATH && sudo systemctl daemon-reload" >&2
    exit 1
fi

# === Resolução de versão ===============================================
if [[ "$ISPWATCH_AGENT_VERSION" == "latest" ]]; then
    VERSION=$(curl --proto '=https' --retry 5 --retry-delay 5 -sSL \
        "https://api.github.com/repos/$GITHUB_REPO/releases/latest" \
        | grep '"tag_name"' | head -1 | cut -d'"' -f4)
    if [[ -z "$VERSION" ]]; then
        echo "ERROR: não consegui resolver a última versão via GitHub Releases." >&2
        exit 1
    fi
else
    VERSION="$ISPWATCH_AGENT_VERSION"
fi
echo "Instalando o agent IspWatch ${VERSION} para linux-${GO_ARCH}"

TARBALL="ispwatch-agent-${VERSION}-linux-${GO_ARCH}.tar.gz"
URL="${ISPWATCH_DOWNLOAD_BASE}/${VERSION}/${TARBALL}"

# === Download + verify =================================================
TMP_TARBALL="/tmp/ispwatch-install-${VERSION}-${GO_ARCH}.tar.gz"
TMP_SHA="/tmp/ispwatch-install-${VERSION}-${GO_ARCH}.sha256"

curl --proto '=https' --retry 5 --retry-delay 5 -fsSL -o "$TMP_TARBALL" "$URL"
curl --proto '=https' --retry 5 --retry-delay 5 -fsSL -o "$TMP_SHA" "${URL}.sha256"

# sha256sum -c espera o arquivo no diretório corrente. Mover o sidecar pra um
# working dir temporário evita conflito com nomes absolutos.
WORK_DIR=$(mktemp -d /tmp/ispwatch-install-XXXXXX)
cp "$TMP_TARBALL" "${WORK_DIR}/${TARBALL}"
# O .sha256 publicado pelo release pipeline contém apenas o basename do tarball.
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
    echo "ERROR: diretório extraído não encontrado em $WORK_DIR." >&2
    exit 1
fi

install -m 0755 -o root -g root "$EXTRACTED_DIR/ispwatch-agent" "$INSTALL_DIR/ispwatch-agent"
install -m 0644 "$EXTRACTED_DIR/ispwatch-agent.service" "$UNIT_PATH"

# === F2b: helper de atualização remota (privilegiado) ==================
# O agente roda SEM privilégio (User=ispwatch) e não pode trocar o próprio
# binário nem se reiniciar. Igual ao Datadog (que delega ao package manager),
# quem APLICA o upgrade é um componente ROOT à parte — este helper. Fluxo:
#   config-pull manda should_update → agente escreve /var/lib/ispwatch/update-requested
#   → o .path (root) observa → dispara o .service (root) → roda o upgrade oficial.
# O marcador NÃO carrega payload (sem versão/URL vindo do servidor): um agente
# comprometido não faz o root rodar comando arbitrário — o helper roda SEMPRE o
# mesmo install.sh pinado, com o binário SHA256-verificado. Instalado/atualizado
# tanto no install novo quanto no upgrade (idempotente).
UPGRADE_SCRIPT_URL="${ISPWATCH_INSTALL_SCRIPT_URL:-https://raw.githubusercontent.com/${GITHUB_REPO}/main/packaging/install.sh}"
cat > "$INSTALL_DIR/ispwatch-agent-upgrade" <<EOF
#!/usr/bin/env bash
# Gerado por install.sh (F2b). Roda como ROOT via ispwatch-agent-update.service.
set -euo pipefail
logger -t ispwatch-agent-upgrade "atualização disparada — rodando upgrade oficial"
curl --proto '=https' --retry 5 --retry-delay 5 -fsSL "${UPGRADE_SCRIPT_URL}" | ISPWATCH_UPGRADE=true bash
logger -t ispwatch-agent-upgrade "upgrade concluído"
EOF
chmod 0755 "$INSTALL_DIR/ispwatch-agent-upgrade"
chown root:root "$INSTALL_DIR/ispwatch-agent-upgrade"

cat > /etc/systemd/system/ispwatch-agent-update.service <<'EOF'
[Unit]
Description=IspWatch Agent — helper de atualização (root, F2b)
Documentation=https://docs.ispwatch.com/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ispwatch-agent-upgrade
# Remove o marcador ao fim (sucesso OU falha) pra rearmar o .path e não repetir.
ExecStopPost=-/bin/rm -f /var/lib/ispwatch/update-requested
TimeoutStartSec=300
EOF

cat > /etc/systemd/system/ispwatch-agent-update.path <<'EOF'
[Unit]
Description=IspWatch Agent — observa pedido de atualização remota (F2b)

[Path]
# O agente (sem privilégio) escreve este arquivo quando o config-pull manda
# should_update. A EXISTÊNCIA dispara o .service root (o gatilho não tem payload).
PathExists=/var/lib/ispwatch/update-requested
Unit=ispwatch-agent-update.service

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ispwatch-agent-update.path

# === Upgrade: binário+unit trocados → reinicia e sai ===================
# Preserva o agent.env (token/config/toggles) — não passa pela reescrita abaixo.
# Espelha o que o Datadog faz: trocar o binário nunca mexe na config do operador.
if [[ "$ISPWATCH_UPGRADE" == "true" ]]; then
    rm -rf "$WORK_DIR"
    systemctl daemon-reload
    systemctl restart ispwatch-agent.service
    echo ""
    echo "OK — ispwatch-agent atualizado para ${VERSION} e reiniciado (config preservada)."
    echo "Status: systemctl status ispwatch-agent"
    exit 0
fi

# Permissões finais dos diretórios.
chown -R ispwatch:ispwatch "$LIB_DIR" "$LOG_DIR"
chmod 0700 "$LIB_DIR"
chmod 0750 "$LOG_DIR"
chown root:ispwatch "$ETC_DIR"
chmod 0750 "$ETC_DIR"

# Cleanup do work dir (o trap on_exit cobre os /tmp/ispwatch-install-*.*).
rm -rf "$WORK_DIR"

# === EnvironmentFile do agent (certless) ===============================
# O systemd lê este arquivo (EnvironmentFile) e injeta as vars no processo do
# agent. Modo 0640 root:ispwatch: contém o token iwI_ (segredo), legível só
# pelo root e pelo usuário do serviço.
HOSTNAME_VALUE="${ISPWATCH_HOSTNAME:-$(hostname -f 2>/dev/null || hostname)}"

umask 077
{
    echo "# Gerado por install.sh — modelo certless (Bearer iwI_)."
    echo "# Edite à vontade e rode: sudo systemctl restart ispwatch-agent"
    echo "ISPWATCH_INGEST_URL=${ISPWATCH_INGEST_URL}"
    echo "ISPWATCH_INGEST_TOKEN=${ISPWATCH_INGEST_TOKEN}"
    echo "ISPWATCH_AGENT_KIND=${ISPWATCH_AGENT_KIND}"
    echo "ISPWATCH_NODE_NAME=${HOSTNAME_VALUE}"
    # Cursor dos logs (se ligados) fica sob o dir gravável do serviço; o default
    # do binário (/var/lib/ispwatch-collector) cai fora do ReadWritePaths da unit.
    echo "ISPWATCH_LOGS_CURSOR_PATH=${LIB_DIR}/log_cursors.json"
} > "$ENV_FILE"

# Repasse dos toggles: qualquer ISPWATCH_*/COLLECTOR_LOG_LEVEL que o operador
# passou (via sudo -E) vai pro agent.env, MENOS as vars de controle do próprio
# instalador (já consumidas acima). Mantém o contrato "1 agente, toggles" sem
# este script precisar conhecer cada capability — evita a defasagem que
# quebrava a instalação quando o front ganhava um toggle novo.
INSTALLER_VARS=" ISPWATCH_AGENT_VERSION ISPWATCH_GITHUB_REPO ISPWATCH_DOWNLOAD_BASE ISPWATCH_INSTALL_ONLY ISPWATCH_HOSTNAME ISPWATCH_ENROLL_TOKEN ISPWATCH_SITE ISPWATCH_DOCKER_INTEGRATION ISPWATCH_INGEST_URL ISPWATCH_INGEST_TOKEN ISPWATCH_AGENT_KIND ISPWATCH_NODE_NAME ISPWATCH_LOGS_CURSOR_PATH "
for name in $(compgen -v); do
    case "$name" in
        ISPWATCH_*|COLLECTOR_LOG_LEVEL) ;;
        *) continue ;;
    esac
    case "$INSTALLER_VARS" in *" $name "*) continue ;; esac
    printf '%s=%s\n' "$name" "${!name}" >> "$ENV_FILE"
done
umask 022

chown root:ispwatch "$ENV_FILE"
chmod 0640 "$ENV_FILE"

# === Docker integration (opt-in) =======================================
# ISPWATCH_DOCKER_INTEGRATION=true dá ao usuário `ispwatch` acesso ao socket
# do Docker (/var/run/docker.sock) via grupo `docker`. Esse grupo é
# root-equivalente no host (membros podem montar / como root via container);
# por isso é opt-in explícito. Default OFF.
if [[ "${ISPWATCH_DOCKER_INTEGRATION:-false}" == "true" ]]; then
    # groupadd -f cria o grupo se ainda não existir (hosts sem Docker). Quando
    # o operador instalar Docker depois, o grupo é o mesmo (gid pode mudar, mas
    # a pertinência permanece pelo nome).
    groupadd -f docker >/dev/null 2>&1 || true
    usermod -aG docker ispwatch
    echo "Integração Docker habilitada: usuário 'ispwatch' adicionado ao grupo 'docker'."
    echo "AVISO de segurança: membros do grupo 'docker' têm acesso root-equivalente"
    echo "                    ao daemon Docker. Audite quem mais está no grupo."
fi

# === Start =============================================================
systemctl daemon-reload
if [[ "${ISPWATCH_INSTALL_ONLY:-}" != "true" ]]; then
    systemctl enable --now ispwatch-agent.service
    echo ""
    echo "OK — ispwatch-agent instalado e iniciado (kind=${ISPWATCH_AGENT_KIND})."
    echo "Status: systemctl status ispwatch-agent"
    echo "Logs:   journalctl -u ispwatch-agent -f"
else
    echo ""
    echo "OK — ispwatch-agent instalado (ISPWATCH_INSTALL_ONLY=true; não iniciado)."
    echo "Iniciar: sudo systemctl enable --now ispwatch-agent"
fi
