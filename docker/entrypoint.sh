#!/bin/sh
# Translates the env-var contract into the CLI flags the Go binary expects.
#
# Two boot modes:
#
# (1) Pre-baked cert (legacy / install-collector.sh / docker-compose):
#     Required envs — COLLECTOR_TENANT_ID, COLLECTOR_ID, COLLECTOR_SERVER,
#     COLLECTOR_CLIENT_CERT, COLLECTOR_CLIENT_KEY, COLLECTOR_TRUST_BUNDLE.
#
# (2) Bootstrap enrollment (k8s DaemonSet / fleet installs):
#     Required envs — ISPWATCH_BOOTSTRAP_TOKEN, ISPWATCH_ENROLL_URL, NODE_NAME.
#     Optional      — ISPWATCH_CLUSTER, ISPWATCH_PKI_DIR (default
#                     $WAL_DIR/pki), ISPWATCH_AGENT_KIND.
#     On first boot we exec `collector --enroll-only` which writes
#     client.cert.pem, client.key.pem, ca.crt and identity.env into the PKI
#     dir. We then source identity.env to get tenant/collector/server values
#     and proceed exactly as mode (1).
#
# Optional always: COLLECTOR_LOG_LEVEL (default: info).

set -eu

LOG_LEVEL="${COLLECTOR_LOG_LEVEL:-info}"

# Modo webhook (admission controller): roda como Deployment separado, não
# DaemonSet. Tem precedência sobre o ingest mode (também usa ISPWATCH_INGEST_URL
# pro Bearer). Repassa os args pro binário (--webhook).
for a in "$@"; do
  if [ "$a" = "--webhook" ] || [ "$a" = "-webhook" ]; then
    echo "entrypoint: webhook mode (mutating admission controller)" >&2
    exec /usr/local/bin/collector "$@"
  fi
done

# Modo ingest certless (Datadog-style): manda OTLP+Bearer pro gateway, sem
# enrollment/mTLS. O binário detecta ISPWATCH_INGEST_URL e roda esse modo.
if [ -n "${ISPWATCH_INGEST_URL:-}" ]; then
  echo "entrypoint: ingest mode (certless OTLP -> gateway)" >&2
  exec /usr/local/bin/collector
fi

if [ -n "${ISPWATCH_BOOTSTRAP_TOKEN:-}" ]; then
  PKI_DIR="${ISPWATCH_PKI_DIR:-/var/lib/ispwatch-collector/pki}"
  IDENTITY_FILE="${PKI_DIR}/identity.env"

  if [ ! -f "${IDENTITY_FILE}" ]; then
    echo "entrypoint: running bootstrap enrollment (no identity.env yet)" >&2
    /usr/local/bin/collector --enroll-only
  fi

  if [ ! -f "${IDENTITY_FILE}" ]; then
    echo "entrypoint: enrollment finished but ${IDENTITY_FILE} missing — aborting" >&2
    exit 1
  fi

  # shellcheck source=/dev/null
  . "${IDENTITY_FILE}"
  COLLECTOR_CLIENT_CERT="${PKI_DIR}/client.cert.pem"
  COLLECTOR_CLIENT_KEY="${PKI_DIR}/client.key.pem"
  COLLECTOR_TRUST_BUNDLE="${PKI_DIR}/ca.crt"
fi

: "${COLLECTOR_TENANT_ID:?Missing COLLECTOR_TENANT_ID}"
: "${COLLECTOR_ID:?Missing COLLECTOR_ID}"
: "${COLLECTOR_SERVER:?Missing COLLECTOR_SERVER}"
: "${COLLECTOR_CLIENT_CERT:?Missing COLLECTOR_CLIENT_CERT}"
: "${COLLECTOR_CLIENT_KEY:?Missing COLLECTOR_CLIENT_KEY}"
: "${COLLECTOR_TRUST_BUNDLE:?Missing COLLECTOR_TRUST_BUNDLE}"

exec /usr/local/bin/collector \
  -tenant-id="${COLLECTOR_TENANT_ID}" \
  -collector-id="${COLLECTOR_ID}" \
  -server="${COLLECTOR_SERVER}" \
  -client-cert="${COLLECTOR_CLIENT_CERT}" \
  -client-key="${COLLECTOR_CLIENT_KEY}" \
  -trust-bundle="${COLLECTOR_TRUST_BUNDLE}" \
  -log-level="${LOG_LEVEL}" \
  "$@"
