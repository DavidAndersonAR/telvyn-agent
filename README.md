# Telvyn Agent

Agente de monitoramento do [Telvyn](https://telvyn.com) — coleta métricas,
logs e traces L7 (eBPF) do host/cluster e envia via mTLS pro servidor Telvyn.
Um agent por host (cada um troca um bootstrap token por um cert único no boot).

## Kubernetes (DaemonSet)

Instala um pod por nó. O comando exato (com seu token e a URL do seu portal)
é gerado no painel Telvyn em **Monitores → Kubernetes**. Forma geral:

```bash
# 1. Secret com o bootstrap token (gerado no painel)
kubectl create namespace telvyn 2>/dev/null || true
kubectl -n telvyn create secret generic telvyn-agent-bootstrap \
  --from-literal=token=<SEU_BOOTSTRAP_TOKEN>

# 2. Instala o chart direto do GHCR (OCI) — sem --version instala a mais recente
helm install telvyn-agent \
  oci://ghcr.io/davidandersonar/charts/ispwatch-agent \
  --namespace telvyn \
  --set bootstrap.enrollUrl='https://<SEU_PORTAL>/api/agents/enroll' \
  --set clusterName=<NOME_DO_CLUSTER>
```

Toggles opcionais (`--set`): `logs.enabled=true` (logs de pod),
`ebpfTracing.enabled=true` (traces L7 zero-código), `profiling.enabled=true`
(flame graph de CPU), `clusterAgent.enabled=true` (eventos do cluster),
`sbomScan.enabled=true` (vulnerabilidades de aplicação). Com eBPF/profiler
ligados o chart aplica automaticamente `resourcesEbpf` (limite 2Gi) e os
privilégios necessários.

Os nós aparecem no painel ~30s depois com o badge **Kubernetes**.

## Linux (Docker / systemd)

```bash
curl -fsSL https://raw.githubusercontent.com/DavidAndersonAR/telvyn-agent/main/install.sh \
  | sudo bash -s -- \
    --enroll-url 'https://<SEU_PORTAL>/api/agents/enroll' \
    --enroll-token '<SEU_TOKEN>'
```

## Imagens / artefatos

| Artefato | Local |
|----------|-------|
| Imagem   | `ghcr.io/davidandersonar/telvyn-agent:<versão>` (multi-arch amd64/arm64) |
| Chart    | `oci://ghcr.io/davidandersonar/charts/ispwatch-agent` |
| Install  | `https://raw.githubusercontent.com/DavidAndersonAR/telvyn-agent/main/install.sh` |

Publicados pelo workflow [`publish.yml`](.github/workflows/publish.yml) a cada tag `v*`.

## Build local

```bash
make build          # binário em ./collector
make proto          # regenera stubs gRPC
docker build -t telvyn-agent:dev .
```

Ver [HARDENING-NOTES.md](HARDENING-NOTES.md) e [TUNING.md](TUNING.md) para
endurecimento e ajuste fino. Licença Apache-2.0 (ver [NOTICE](NOTICE)).
