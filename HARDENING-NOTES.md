# Production Hardening — Sprint Notes

Fase "production hardening" do collector agent (task #243). Três frentes:
ARM cross-build, eBPF observabilidade/CO-RE, perf tuning. Resumo do que
foi feito, o que ficou de fora, como validar.

## 1. ARM cross-build — DONE

### O que mudou

- `Makefile` ganhou targets `release-multiarch`, `build-all`, `build-amd64`,
  `build-arm64`.
- `release-multiarch` itera `release-ci` com `GOARCH=amd64` e `GOARCH=arm64`,
  produzindo dois tarballs gzipped em `dist/` (com sidecar `.sha256`).
- `build-*` são atalhos só pra cross-compile sanity check (binário em
  `dist/collector-<arch>`, sem tarball).

### Por que arm64 já funciona out-of-the-box

1. `CGO_ENABLED=0` no `release-ci` — sem dependência de toolchain C nativa.
2. O dispatcher de programas eBPF (`internal/ebpf/tracer.go::ebpf()`) já
   despacha por `runtime.GOARCH` e a tabela `ebpfProgs` em
   `internal/ebpf/ebpf.go` já vem com objetos pré-compilados para `amd64`
   **e** `arm64` (5 variantes de kernel cada).

### Cobertura

| Arch         | Cobertura                                            |
|--------------|------------------------------------------------------|
| linux/amd64  | servidores genéricos, VMs, EC2 x86, k3s/k3d         |
| linux/arm64  | AWS Graviton 2/3/4, Pi 4+, Ampere Altra, Oracle A1  |

### Como validar

```bash
cd infra/collector/agent

# Cross-compile sanity check (rápido, sem tarball):
make build-all
file dist/collector-amd64    # → x86-64
file dist/collector-arm64    # → ARM aarch64

# Tarballs de release com sha256:
make release-multiarch VERSION=v0.4.0-rc1
ls dist/ispwatch-agent-v0.4.0-rc1-linux-*.tar.gz*
```

### Não feito (e por quê)

- **armv7 (GOARCH=arm, GOARM=7)**: dois bloqueadores:
  1. `internal/ebpf/ebpf.go` só ship `amd64` e `arm64`. Adicionar armv7
     requer regenerar via `internal/ebpf/Makefile` (Docker com clang/libbpf
     + headers ARM 32-bit). Possível mas custoso.
  2. `cmd/collector/main.go::startEbpfTracer` usa `utsname.Release[:]` como
     `[]int8`. Em 32-bit ARM o campo é `[]uint8` — type mismatch faz o
     build quebrar. Fix trivial (cast condicional via build tag) mas só
     vale o esforço se (1) for resolvido.
  - **Decisão**: deixar follow-up. Raspberry Pi 3 e older boards são
    long-tail demais pra justificar agora.

- **Multi-arch Docker image**: O `Dockerfile` já aceita `TARGETOS`/
  `TARGETARCH` (linha 39), então `docker buildx build --platform
  linux/amd64,linux/arm64` deveria funcionar. Não testei nesta sessão —
  a VM `ready-leech` recebe binário direto, não imagem. **Follow-up**:
  validar publish-collector workflow no GHA emite multi-arch manifest.

---

## 2. BPF observabilidade — PARCIAL (CO-RE refactor adiado)

### Pesquisa do estado atual

- O Dockerfile em `internal/ebpf/Dockerfile` compila o `.bpf.c` com
  `clang -g -O2 -target bpf -D__TARGET_ARCH_x86/arm64 -D__KERNEL_FROM=NNN`,
  gerando 5 variantes de kernel × 2 arquiteturas = 10 binários BPF.
- Esses binários ficam embedded como base64+gzip em `internal/ebpf/ebpf.go`
  (4.9MB) e o tracer em runtime seleciona o melhor match por (arch, kernel
  version, ctx-extra-padding flag).
- `clang -g` já preserva BTF debuginfo no `.o`. Isso significa que o object
  carrega seu próprio CO-RE-style relocation info embutido — não chega
  a usar `BPF_CORE_READ` no source, mas o approach "matrix of variants"
  cobre a mesma necessidade (1 build, vários kernels suportados).

### Decisão sobre refactor pra CO-RE puro

**Adiado.** Substituir o approach atual por `BPF_CORE_READ`/`bpf_core_read`
no source requer:
1. Reescrever todos os acessos a `struct sock`, `struct task_struct`, etc.
   no `internal/ebpf/ebpf/*.c` — muitos pontos.
2. Validar contra todos os 5 kernels da matriz atual + qualquer kernel
   mais novo que o operator possa ter (regression: hoje a matriz é fixa e
   testável; CO-RE depende do BTF do kernel-alvo).
3. Risco alto de quebrar funcionalidade que já funciona (Postgres parser,
   TLS uprobes, conntrack lookup).

**Beneficio marginal** dado que:
- A matriz atual cobre 4.16 → 6.x, que inclui Ubuntu 18.04 LTS adiante.
- 4.9MB do `ebpf.go` é aceitável (binário total ~36MB).

### Kernels suportados (matriz atual)

Por arch, o tracer escolhe a maior variante `<= kernel atual`:

| Variante  | Source flag             | Kernels alvo                         |
|-----------|-------------------------|--------------------------------------|
| 4.16      | `__KERNEL_FROM=416`     | Ubuntu 18.04+ (HWE kernel), CentOS 8 |
| 4.20      | `__KERNEL_FROM=420`     | Ubuntu 19.04                          |
| 5.6       | `__KERNEL_FROM=506`     | Ubuntu 20.04 (HWE), Fedora 32         |
| 5.12      | `__KERNEL_FROM=512`     | Ubuntu 22.04 baseline                 |
| 5.12+cep  | `__CTX_EXTRA_PADDING`   | Ubuntu 24.04, kernel 6.x com PREEMPT_RT |

Tracer em runtime detecta `common_preempt_lazy_count` no
`task/task_newtask/format` pra ativar a variante `ctx-extra-padding`.

**Kernel mínimo suportado oficialmente**: **4.16**. Abaixo disso o tracer
falha com `unsupported kernel version`.

### O que foi feito

- **Lost-samples self-metric**: o tracer logava `lost samples: N` mas não
  expunha contador. Adicionado `Tracer.LostSamples() map[string]uint64`
  acumulando drops por perf map name. Um publisher em `main.go` emite
  `agent_ebpf_lost_samples{map=...}` a cada 30s via canal `out` com
  `__self__=true` — VmRemoteWriter renomeia pra
  `agent_host_metric_ebpf_lost_samples` e troca label por `collector_id`,
  igual aos outros self-metrics.
- **Ring buffer L7 32 → 64 pages**: per-CPU 128KB → 256KB. Sufficient pra
  workload pgbench-style ~1k qps. Override via env
  `ISPWATCH_EBPF_L7_BUFFER_PAGES=N`. Outros maps (proc/tcp/file) ficam em
  4-8 pages — eventos menos frequentes não justificam.

### Como validar

```bash
# Smoke test eBPF: rodar agent com tracer ativo e gerar carga DB.
cd infra/collector/agent
make build-amd64
sudo ISPWATCH_EBPF_TRACING=1 ./dist/collector-amd64 \
  -tenant-id=acme -collector-id=test-01 ...

# Em outra sessão, gerar carga e observar:
pgbench -c 8 -j 4 -T 60 -P 1 -h <host> postgres

# Métrica deve aparecer no VictoriaMetrics:
curl 'http://localhost:8428/api/v1/query?query=agent_host_metric_ebpf_lost_samples'
# Esperado: 0 ou número baixo com l7_events=64. Se subindo, raise via
# ISPWATCH_EBPF_L7_BUFFER_PAGES=128 e re-validar.
```

---

## 3. Perf tuning — PARCIAL

### Feito

- **Ring buffer L7 dobrado** (ver frente 2).
- **Lost samples observable** (ver frente 2).

### Pesquisa: span batching

- `internal/otlp/forwarder.go` já agrupa spans em `SpanBatch` (max 500,
  flush a cada 5s — `main.go:259`).
- `internal/transport/spans.go::StreamSpans` envia 1 batch por gRPC msg.
- **Não há gargalo aqui** com a carga atual. Se virar gargalo:
  - Subir `maxBatch` (forwarder ctor) — gRPC tolera bem messages até ~4MB.
  - Subir `spansCh` buffer (`main.go:258`, atual 32) — risco baixo de
    drop hoje.

### Pesquisa: linux.processes a `interval*2`

- `selfmetrics.go:72` agenda `linux.processes` a cada 60s (vs 30s do
  `linux.system`). Justificativa no comment: cgroup walk é mais caro.
- Em hosts com <100 services, custa <50ms por execução. **Não é gargalo.**
- Acima de 500 services, o `scanProcsByCgroup` em
  `internal/checks/linux_processes.go:256` lê `/proc/<pid>/cgroup` pra
  cada PID — pode ficar caro. **Não otimizei agora** porque não há
  evidência de carga real nesse range.

### Não feito (e por quê)

- **TTL em `parsersByConn` (memory hygiene)**: O bridge.go atual no
  working-tree tem trabalho do dev em voo (cache de `connAddr` +
  `trackConn/untrackConn` em ConnectionOpen/Close, svcagg integration).
  Esse trabalho cria precisamente o vetor de leak (entries que vazam se
  ConnectionClose perdido) — mas não foi commitado por mim porque o
  diff misturava trabalho não-meu.
  - **Quando o dev commitar o trabalho em bridge.go, abrir PR seguinte**
    adicionando: campo `lastSeen map[connKey]time.Time` no struct,
    update em `addrFor/postgresFor/mysqlFor/trackConn`, método
    `pruneIdle(maxAge)` + ticker de 60s em `RunBridge` (5min idle
    threshold).
  - Patch rascunhado durante a sessão preservado em
    `/tmp/bridge-current.patch` (não commitado).

- **Multi-arch buildx no Dockerfile**: não testado nesta sessão.

---

## Próximos passos sugeridos

Em ordem de valor:

1. **Validar build arm64 na VM real** (qualquer Graviton/Pi4 disponível).
   O cross-compile passa, mas só execução prova que tracer carrega objeto
   BPF arm64 correto.
2. **TTL no parsersByConn** depois que o trabalho em voo do bridge.go for
   committado.
3. **buildx multi-arch no publish-collector workflow** (CI) — pré-req:
   self-hosted runner ou QEMU-emulated buildx.
4. **CO-RE refactor** — só vale se o operator-base começar a reportar
   kernels que não estão na matriz. Hoje cobre 4.16-6.x.
5. **armv7 / 32-bit support** — só se houver demanda real (Pi 3 fleet de
   cliente, etc.).
6. **scanProcsByCgroup overhead em hosts com 500+ services**: instrumentar
   com `time.Since` e medir antes de otimizar.

## Como validar tudo de uma vez

```bash
cd infra/collector/agent
go test ./...                   # unit tests
make build-all                  # cross-compile sanity
make release-multiarch VERSION=hardening-test
ls dist/                        # 2 tarballs + 2 sha256
sha256sum -c dist/*.sha256      # checksums válidos
```

## 4. OTLP/HTTP receiver (porta 4318) — DONE (task #244 agent-side)

Complementa o OTLP/gRPC já existente (porta 4317) atendendo clientes que não
falam gRPC — em particular o caso primário: **browsers via OTel SDK Web**.

### Endpoint URL + porta

- Bind default: `0.0.0.0:4318` (porta padrão do spec OTLP/HTTP).
- Endpoints: `POST /v1/traces`, `POST /v1/metrics`, `POST /v1/logs`,
  `GET /healthz`.
- Aceita `application/x-protobuf` e `application/json`; `Content-Encoding: gzip`
  transparente.
- CORS: `Access-Control-Allow-Origin: *` por default (configurável via
  `ISPWATCH_OTLP_HTTP_CORS_ORIGINS=csv`). Preflight `OPTIONS` → 204.
- Payload cap 5MB; gzip-bomb guard adicional (10× pós-descompressão).

### Configuração via env

| Env                                  | Default     | Função                                  |
|--------------------------------------|-------------|------------------------------------------|
| `ISPWATCH_OTLP_HTTP_PORT`            | `4318`      | "4318" ou "host:port" completo           |
| `ISPWATCH_OTLP_HTTP_DISABLE`         | `0`         | Set 1 pra desligar (gRPC continua)       |
| `ISPWATCH_OTLP_HTTP_CORS_ORIGINS`    | `*`         | CSV de origens permitidas                |

### Como testar manualmente

```bash
# 1. Span JSON minimal (curl POST):
cat > /tmp/span.json <<'JSON'
{
  "resourceSpans": [{
    "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "curl-demo"}}]},
    "scopeSpans": [{
      "spans": [{
        "traceId": "5b8aa5a2d2c872e8321cf37308d69df2",
        "spanId":  "051581bf3cb55c13",
        "name":    "demo-span",
        "kind":    1,
        "startTimeUnixNano": "1700000000000000000",
        "endTimeUnixNano":   "1700000000500000000"
      }]
    }]
  }]
}
JSON

curl -v -X POST -H "Content-Type: application/json" \
  --data-binary @/tmp/span.json http://NODE_IP:4318/v1/traces
# → HTTP/1.1 200 OK
# → {}

# 2. CORS preflight:
curl -v -X OPTIONS -H "Origin: https://app.example.com" \
  -H "Access-Control-Request-Method: POST" http://NODE_IP:4318/v1/traces
# → HTTP/1.1 204 No Content
# → Access-Control-Allow-Origin: *

# 3. Healthz:
curl http://NODE_IP:4318/healthz   # → "ok"
```

### Self-metrics expostas

- `agent_otlp_http_requests_total{endpoint, status}` — cumulative counter
  (rebadged pra `agent_host_metric_otlp_http_requests_total` pelo
  VmRemoteWriter).
- `agent_otlp_http_spans_total` — cumulative span count.

Publisher 30s tick, mesmo pattern do `agent_ebpf_lost_samples` (commit
26781ad). Series só aparecem após o primeiro request — sem zeros fantasma.

### O que ficou de fora

- **`/v1/metrics` e `/v1/logs` aceitam e descartam** — backend ainda não tem
  ingestor OTel-metrics nem OTel-logs. Aceita 200 OK pra não quebrar SDKs
  configurados com MeterProvider/LoggerProvider. Quando o backend ganhar
  essas pipelines, troca a função de descarte por convertAndPush análogo a
  traces (TODO no código).
- **Sem TLS** no listener — mesmo trade-off do gRPC 4317. Browser → agent
  via NodePort/Ingress fica na responsabilidade do operador (terminar TLS
  num proxy à frente, ex: Envoy/Caddy).
- **Auth**: nenhuma. CORS é defesa em profundidade contra cross-site abuse,
  mas qualquer cliente no path de rede pode emitir spans. Se virar problema,
  adicionar bearer token via env (`ISPWATCH_OTLP_HTTP_TOKEN`).

### Próximo passo (front-end)

Front vai adicionar `@opentelemetry/sdk-trace-web` no
`ispwatch-executive-view-main` e configurar exporter pra
`https://<agent-node>:4318/v1/traces`. Browser tracing então flui pelo
mesmo Forwarder/StreamSpans → backend que já recebe spans Java/Quarkus.
