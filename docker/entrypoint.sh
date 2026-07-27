#!/bin/sh
# Launches the Telvyn agent (certless-only). The agent ships telemetry over
# HTTP/OTLP with a Bearer ingest token — no enrollment, no mTLS, no per-agent
# cert.
#
# Two boot modes:
#
# (1) Ingest (DaemonSet / docker / linux / cluster-agent):
#     Required envs — ISPWATCH_INGEST_URL, ISPWATCH_INGEST_TOKEN.
#     Optional      — ISPWATCH_CLUSTER, ISPWATCH_AGENT_KIND, NODE_NAME and the
#                     per-capability toggles (ISPWATCH_EBPF_TRACING, …).
#     The binary detects ISPWATCH_INGEST_URL and runs this mode.
#
# (2) Webhook (mutating admission controller): runs as a separate Deployment,
#     triggered by the --webhook arg. Also uses ISPWATCH_INGEST_URL/TOKEN for
#     the Bearer the injected agents receive.
#
# Optional always: COLLECTOR_LOG_LEVEL (default: info; read from env by the binary).

set -eu

# Modo webhook (admission controller): roda como Deployment separado, não
# DaemonSet. Repassa os args pro binário (--webhook).
for a in "$@"; do
  if [ "$a" = "--webhook" ] || [ "$a" = "-webhook" ]; then
    echo "entrypoint: webhook mode (mutating admission controller)" >&2
    exec /usr/local/bin/collector "$@"
  fi
done

# Modo ingest certless (Datadog-style): manda OTLP+Bearer pro gateway. O binário
# detecta ISPWATCH_INGEST_URL e roda esse modo (e aborta se estiver ausente).
: "${ISPWATCH_INGEST_URL:?Missing ISPWATCH_INGEST_URL (certless ingest mode)}"
echo "entrypoint: ingest mode (certless OTLP -> gateway)" >&2
exec /usr/local/bin/collector
