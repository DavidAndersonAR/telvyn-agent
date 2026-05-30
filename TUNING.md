# Tuning do Agent IspWatch

Guia rápido pra dimensionar o agent conforme a quantidade de hosts que ele monitora. Equivalente ao `zabbix_agentd.conf` / `zabbix_proxy.conf`.

## Defaults atuais

Calibrados pra **500-1000 hosts** em uma máquina pequena/média (4 CPU, 4 GB RAM):

```ini
ConfigPollSeconds = 15
SNMPPollers      = 50
ICMPPingers      = 20
CheckJitterMs    = 10000
BatchSize        = 1000
FlushSeconds     = 5
WALMaxMB         = 1024
```

## Como ajustar

Crie `/etc/ispwatch/collector.conf` (ou outro path) e passe via flag `-config-file`:

```bash
ispwatch-collector \
  -tenant-id=acme \
  -collector-id=collector-01 \
  -server=ispwatch.local:8443 \
  -config-file=/etc/ispwatch/collector.conf \
  ...
```

CLI flags têm precedência sobre o arquivo. Tudo que não estiver no arquivo cai no default.

## Perfis recomendados

### Edge box pequena (até 100 hosts)

VM modesta, IoT/SBC, máquina compartilhada. Foco: **footprint mínimo**.

```ini
SNMPPollers       = 10
ICMPPingers       = 5
CheckJitterMs     = 5000
BatchSize         = 500
ConfigPollSeconds = 30
WALMaxMB          = 256
```

### Standard (500-1000 hosts) — DEFAULT

Os valores padrão já cobrem esse perfil. Não precisa criar arquivo de config.

### Heavy (1000-5000 hosts)

Servidor dedicado (8+ CPUs, 16 GB RAM). Walks SNMP pesados, possivelmente vários POPs.

```ini
SNMPPollers       = 200
ICMPPingers       = 50
CheckJitterMs     = 30000
BatchSize         = 5000
FlushSeconds      = 3
ConfigPollSeconds = 30
WALMaxMB          = 8192
```

### Extreme (5000+ hosts)

Servidor robusto (16+ CPUs, 32+ GB RAM). Pra essa escala, considere **múltiplos collectors** divididos por POP ou CIDR — mais resiliente que 1 collector gigante.

```ini
SNMPPollers       = 500
ICMPPingers       = 100
CheckJitterMs     = 60000
BatchSize         = 10000
FlushSeconds      = 2
ConfigPollSeconds = 60
WALMaxMB          = 16384
```

## Dimensionamento — como pensar

### `SNMPPollers`

Quantos walks SNMP em paralelo. Não há "certo": depende de **quão pesados são os walks** e **quanto seu hardware aguenta**.

**Cálculo rápido:**
- Tempo médio de um walk no seu maior host: `W` segundos
- Hosts totais: `N`
- Intervalo de scrape: `I` segundos (padrão 60)
- **Pool mínimo:** `N × W / I`

Exemplo: 1000 hosts, walk de 3s, scrape a cada 60s → `1000 × 3 / 60 = 50 pollers`.

Se o pool ficar curto, walks entram em fila e o intervalo efetivo cresce (você vê o gráfico ficar com pontos espaçados). Aí sobe `SNMPPollers`.

**Limites superiores:**
- 1 goroutine por poller ativa = ~5KB stack ⇒ 500 pollers = ~2.5 MB
- File descriptors: cada walk abre 1 UDP socket; ulimit padrão é 1024, suba pra 65535 se passar de ~500 pollers

### `CheckJitterMs`

Distribui o **primeiro tick** de cada check no tempo. Crítico quando muitos checks são criados em batch.

Sem jitter: 100 checks criados na mesma janela disparam o primeiro walk no mesmo segundo → roteador sufoca.

Com jitter de 10s: aqueles 100 checks se distribuem aleatoriamente em 10s → ~10 walks/seg.

**Regra:** `CheckJitterMs ≥ intervalo do menor check` evita rajadas mas mantém latência aceitável no warm-up. Pra 1000+ hosts, 30s-60s é razoável.

### `BatchSize` / `FlushSeconds`

Quanto métrica espera antes de enviar pro backend.

- `BatchSize` grande = menos RPC overhead, mais latência (espera encher)
- `FlushSeconds` curto = mais latência baixa, mais RPCs

Trade-off: gRPC tem custo fixo ~ms por request. Batches de 1000+ amortizam bem. `FlushSeconds=5` garante que dado nunca espera mais de 5s mesmo se o batch não encher.

### `ConfigPollSeconds`

Quanto tempo entre `GET /api/collector/v1/config?since=N`. Server-side a query é uma única SELECT indexed (~ms). Network round-trip + parse JSON são o custo real.

- 10s → resposta a mudança de UI quase imediata. Bom pra dev / poucos collectors
- 30s → economia de RPCs. Bom pra produção
- 60s → quase silencioso. Aceitável se mudanças de config são raras

A versão é monotônica: o agent envia `since=<última>`, server responde *no change* em ~30ms se nada mudou — então o custo é baixíssimo mesmo com poll frequente.

## Métricas de observabilidade

Pra saber se o tuning está OK, o agent emite **self-metrics** (`agent_host_metric_*`) — vão pra VictoriaMetrics com label `collector_id`:

| Métrica | O que olhar |
|---|---|
| `agent_host_metric_cpu_user` | CPU do agent. Se >50% sustentado, raise pool/pode estar undersized |
| `agent_host_metric_mem_used` | RAM do agent. Cresce com nº de checks ativos |
| `agent_host_metric_wal_size` | WAL bytes. Crescendo = backend não está acompanhando |

Logs warn que indicam undersizing:

- `check run exceeded timeout` em vários check_ids → walks demorando demais; sobe `SNMPPollers` ou aumenta scrape interval por check
- `wal: dropping batch (size cap)` → backend offline há tempo demais; sobe `WALMaxMB` ou investiga conectividade

## Resumo de "quando subir vs descer"

| Sintoma | Aumentar | Diminuir |
|---|---|---|
| Walks SNMP timing out | `SNMPPollers` | scrape interval por host |
| Gráficos com gaps | `SNMPPollers`, `CheckJitterMs` (se muitos hosts criados juntos) | — |
| CPU do agent alta sustentado | — | `SNMPPollers` ou contrata um 2º collector pra dividir |
| Latência de visualização ruim | — | `FlushSeconds`, `ConfigPollSeconds` |
| WAL crescendo | — | (não é tuning de agent, é network/backend) |
| Roteador alvo sufocando | `CheckJitterMs` | `SNMPPollers` |
