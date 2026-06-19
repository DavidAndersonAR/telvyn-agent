# SNMP Profiles — Como adicionar OIDs de equipamentos

## TL;DR — Onde os OIDs ficam?

**Em arquivo**, não em banco. Cada vendor é um **YAML embedded no binário do
collector** via `embed.FS`. Banco guarda apenas qual profile cada host usa
(coluna `snmp_profile` na tabela `host`); os OIDs em si vivem aqui.

```
infra/collector/agent/internal/snmp/profiles/
├── cisco-ios.yaml
├── cisco-nx-os.yaml
├── generic-snmpv2.yaml
├── juniper-junos.yaml
├── linux-net-snmp.yaml
├── mikrotik-ccr1036.yaml
├── mikrotik-routeros.yaml
└── README.md         ← este arquivo
```

**Por que arquivo e não banco?** Profiles são *configuração de produto*
(igual aos profiles do Datadog), não dado de tenant. Vão
junto com o release do collector, versionam via git, e o operador final
só **seleciona** o profile pela UI/API — não edita OID.

---

## Passo-a-passo para adicionar um vendor novo

### 1. Crie o arquivo `<vendor>.yaml`

Nome do arquivo = nome do profile (sem `.yaml`). Use kebab-case.
Exemplos: `cisco-asr-9000.yaml`, `huawei-ar2200.yaml`, `fortigate-100f.yaml`.

### 2. Descubra o `sysObjectID` do equipamento

```bash
snmpget -v2c -c <community> <ip> 1.3.6.1.2.1.1.2.0
# Saída tipo: SNMPv2-SMI::enterprises.9.1.1208
# → sysObjectID = 1.3.6.1.4.1.9.1.1208 (Cisco enterprise=9)
```

Use **o prefixo mais específico que ainda casa todos os modelos** que
esse profile deve atender. Mais específico vence (`MatchSysObjectID`).

### 3. Liste os OIDs que quer coletar

Para cada métrica, decida:

- **Escalar** (CPU% único, uptime, mem total) → `symbol`
- **Tabela** (1 row por interface, 1 row por core, 1 row por peer BGP) → `table` + `symbols`

### 4. Preencha o YAML — estrutura mínima

```yaml
# vendor-modelo.yaml
sysobjectid:
  - 1.3.6.1.4.1.9.1.1208      # prefixo; aceita múltiplos

metrics:
  # ---- métrica ESCALAR ----
  - mib: SNMPv2-MIB
    symbol:
      oid: 1.3.6.1.2.1.1.3.0
      name: snmp.sys.uptime    # nome canônico (vira métrica no VictoriaMetrics)

  - mib: CISCO-PROCESS-MIB
    symbol:
      oid: 1.3.6.1.4.1.9.9.109.1.1.1.1.7.1
      name: cisco.cpu.5min

  # ---- métrica de TABELA ----
  - mib: IF-MIB
    table:
      oid: 1.3.6.1.2.1.2.2     # ifTable
      name: ifTable
    symbols:
      - { oid: 1.3.6.1.2.1.2.2.1.10, name: snmp.if.in_octets }
      - { oid: 1.3.6.1.2.1.2.2.1.16, name: snmp.if.out_octets }
      - { oid: 1.3.6.1.2.1.2.2.1.14, name: snmp.if.in_errors  }
      - { oid: 1.3.6.1.2.1.2.2.1.20, name: snmp.if.out_errors }
    metric_tags:
      # ifDescr (col .2) vira a label `interface_name` em todas as métricas da tabela
      - { tag: interface_name, symbol: { oid: 1.3.6.1.2.1.2.2.1.2, name: ifDescr } }

# Tags estáticas aplicadas em TODAS as métricas deste profile
metric_tags:
  - { tag: vendor, value: cisco }
  - { tag: family, value: asr-9000 }
```

### 5. Recompile o collector

```bash
cd infra/collector/agent
go build ./cmd/collector
# OU se estiver usando o compose:
docker compose build collector && docker compose up -d collector
```

O `//go:embed *.yaml` em `profiles/embed.go` puxa o arquivo automaticamente.
**Não precisa mexer em nenhum código Go.**

### 6. Selecione o profile no host

Hoje a seleção é manual (Phase 3 closeout). Via API Quarkus:

```bash
PATCH /api/noc/hosts/{uuid}/snmp-profile
{ "profile": "cisco-asr-9000" }
```

Ou pela UI no drawer do host (`features/app/pages/hosts/...`).
Auto-detect por `sysObjectID` está planejado mas ainda não está em prod —
por enquanto o operador escolhe.

---

## Convenção de nomes de métricas

| Tipo | Padrão | Exemplo |
|---|---|---|
| Universal (qualquer vendor) | `snmp.<grupo>.<nome>` | `snmp.if.in_octets`, `snmp.sys.uptime` |
| Específico do vendor | `<vendor>.<grupo>.<nome>` | `mikrotik.health.temp_cpu_dc`, `cisco.cpu.5min` |
| Tabela com label | label vai em `metric_tags` | `interface_name`, `cpu_index`, `bgp_peer` |

A UI do host-metrics-page **agrupa por nome canônico** — usar o mesmo nome
em vendors diferentes faz o gráfico mesclar séries automaticamente.
Exemplos: `snmp.if.in_octets` aparece igual pra Mikrotik, Cisco, Juniper.

---

## Counter vs gauge — atenção

OIDs como `ifInOctets`, `ifInErrors` são **counters** (acumulam desde
último boot). O backend não converte — quem aplica `rate()` é o
**frontend** (em `host-metrics-page.component.ts`, marcado com `rate: true`
na definição da métrica) ou queries Grafana/PromQL diretas.

Se a sua métrica é um valor instantâneo (gauge), não precisa fazer nada
no frontend — só plotar. Counter precisa de `rate: true` na categoria
correspondente.

---

## Onde puxar OIDs prontos

1. **MIB browser do vendor** — sempre o mais correto (Cisco MIB Locator, MikroTik wiki, Juniper Knowledge Base).
2. **Datadog SNMP profiles** — `github.com/DataDog/integrations-core/tree/master/snmp/datadog_checks/snmp/data/default_profiles` (mesma estrutura YAML, fonte de muita coisa que está aqui).
3. **Observium / LibreNMS** — `mibs/<vendor>/` (texto MIB tradicional, precisa converter).
4. **Test rápido**: `snmpwalk -v2c -c public <host> <oid>` antes de adicionar.

---

## Checklist antes de fazer commit

- [ ] `sysObjectID` testado com `snmpget` no equipamento real
- [ ] OIDs testados com `snmpwalk` retornando os valores esperados
- [ ] Nomes seguem convenção `snmp.<grupo>.<nome>` ou `<vendor>.<grupo>.<nome>`
- [ ] Tabela tem pelo menos 1 `metric_tags` pra identificar a row (caso contrário séries colidem)
- [ ] `go test ./internal/snmp/...` passa (carrega o profile, valida shape)
- [ ] Profile aparece na UI ao listar profiles disponíveis (recompilou o collector)
