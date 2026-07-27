# Telvyn Agent

Agente de monitoramento do [Telvyn](https://telvyn.com) — coleta métricas,
logs e traces L7 (eBPF) do host/cluster e envia via HTTP/OTLP com um ingest
token (certless, estilo Datadog) pro servidor Telvyn. Um agent por host.

## Kubernetes (DaemonSet)

Instala um pod por nó. O comando exato (com seu token e a URL do seu portal)
é gerado no painel Telvyn em **Monitores → Kubernetes**. Forma geral:

```bash
# Instala o chart direto do GHCR (OCI) — sem --version instala a mais recente.
# Autenticação certless: só a URL do portal + o ingest token (iwI_..., gerado
# no painel em Monitores → Kubernetes). Sem cert, sem enrollment.
helm install telvyn-agent \
  oci://ghcr.io/davidandersonar/charts/ispwatch-agent \
  --namespace telvyn --create-namespace \
  --set ingest.url='https://<SEU_PORTAL>' \
  --set ingest.token='<SEU_INGEST_TOKEN>' \
  --set clusterName=<NOME_DO_CLUSTER>
```

Toggles opcionais (`--set`): `logs.enabled=true` (logs de pod),
`ebpfTracing.enabled=true` (traces L7 zero-código), `profiling.enabled=true`
(flame graph de CPU), `clusterAgent.enabled=true` (eventos do cluster),
`sbomScan.enabled=true` (vulnerabilidades de aplicação). Com eBPF/profiler
ligados o chart aplica automaticamente `resourcesEbpf` (limite 2Gi) e os
privilégios necessários.

Os nós aparecem no painel ~30s depois com o badge **Kubernetes**.

## Docker / Portainer (modo ingest, certless)

Um container do agente por máquina Docker, autenticado só com o ingest token
(`iwI_...`, gerado no painel). Ele registra a máquina no inventário, mede os
containers via `/var/run/docker.sock` (CPU/mem/rede/restarts por container) e
recebe OTLP das suas apps na porta 4318:

```bash
docker run -d --name telvyn-agent --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -p 4318:4318 \
  -e ISPWATCH_INGEST_URL='https://<SEU_PORTAL>' \
  -e ISPWATCH_INGEST_TOKEN='<SEU_INGEST_TOKEN>' \
  -e ISPWATCH_AGENT_KIND=docker \
  -e ISPWATCH_NODE_NAME="$(hostname)" \
  ghcr.io/davidandersonar/telvyn-agent:latest
```

Aponte as apps para `OTEL_EXPORTER_OTLP_ENDPOINT=http://<host>:4318`
(`OTEL_EXPORTER_OTLP_PROTOCOL=http/json`). A máquina aparece em
**Aplicações**; cada app instrumentada aparece no catálogo de serviços com as
métricas do próprio container.

## Linux (Docker / systemd)

```bash
curl -fsSL https://raw.githubusercontent.com/DavidAndersonAR/telvyn-agent/main/packaging/install.sh \
  | ISPWATCH_INGEST_URL='https://<SEU_PORTAL>' ISPWATCH_INGEST_TOKEN='<SEU_INGEST_TOKEN>' sudo -E bash
```

## Imagens / artefatos

| Artefato | Local |
|----------|-------|
| Imagem   | `ghcr.io/davidandersonar/telvyn-agent:<versão>` (multi-arch amd64/arm64) |
| Chart    | `oci://ghcr.io/davidandersonar/charts/ispwatch-agent` |
| Install  | `https://raw.githubusercontent.com/DavidAndersonAR/telvyn-agent/main/packaging/install.sh` |

Publicados pelo workflow [`publish.yml`](.github/workflows/publish.yml) a cada tag `v*`.

## Build local

```bash
make build          # binário em ./collector
make proto          # regenera stubs gRPC
docker build -t telvyn-agent:dev .
```

Ver [HARDENING-NOTES.md](HARDENING-NOTES.md) e [TUNING.md](TUNING.md) para
endurecimento e ajuste fino. Licença Apache-2.0 (ver [NOTICE](NOTICE)).
