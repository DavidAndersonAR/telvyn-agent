# convert-datadog-profiles

Gera o catálogo de SNMP profiles do agente (`internal/snmp/profiles/*.yaml`) a partir
da biblioteca oficial open-source do Datadog (NDM), convertida para o **nosso formato**.

## Por que existe

Os profiles do Datadog **não são drop-in** no nosso agente:

- usam **herança** (`extends: [_base.yaml, _generic-if.yaml, ...]`) — um device típico
  (ex. `cisco-catalyst`) tem **zero** métrica inline; tudo vem dos arquivos-base. Nosso
  agente **não** entende `extends`;
- usam chaves **MAIÚSCULAS** (`OID`, `MIB`) e recursos que nosso agente não modela
  (`metric_type`, `mapping`, tags por índice/tabela-cruzada, `constant_value_one`).

Este conversor resolve a herança em **build-time** e reescreve no formato flat que o
agente já entende. O motor de coleta **não muda** — e como a canonicalização de métrica
do agente é **por OID** (`ifMibCanonical` em `internal/snmp/profile.go`), os sinais de
interface (tráfego/status) acendem sozinhos em qualquer fabricante.

## Como regenerar

```bash
# do diretório deste README:
python3 -m venv .venv && ./.venv/bin/pip install pyyaml
./.venv/bin/python convert.py datadog-source ../../internal/snmp/profiles
```

O conversor:
- resolve `extends` recursivo (guarda de ciclo + dedup de bloco);
- normaliza IF-MIB (rótulo `interface_name`/`interface_alias` in-subtree);
- descarta o que o agente não usa (conta no relatório final);
- aplica a **política de conflito**: os prefixos em `DEFAULT_OWN` pertencem aos nossos
  profiles hand-curated e são removidos dos do Datadog (o profile do DD é descartado se
  ficar sem sysObjectID) — a nossa curadoria vence o empate exato, deterministicamente.

## Fonte

`datadog-source/` é uma cópia vendorizada de
`DataDog/integrations-core` @ `6e9d2c5fd681d34d7f862e5fbb396792e653e771`,
path `snmp/datadog_checks/snmp/data/default_profiles/` (239 arquivos = 65 base + 174
device). Licença **BSD-3-Clause** — ver `datadog-source/LICENSE` e `NOTICE.md`.

## Categorias geradas

- **auto-match**: tem sysObjectID + métrica (maioria).
- **manual-only**: métrica sem sysObjectID (ex. `brocade`, `a10`) — o operador escolhe
  pelo nome; nunca auto-matcha.
- **só-identificação**: sysObjectID sem métrica (ex. `tripplite`, `zebra-printer`) —
  reconhece o aparelho, fiel ao Datadog (que também só identifica esses).

Nossos 8 hand-curated (`cisco-ios`, `cisco-nx-os`, `juniper-junos`, `mikrotik-routeros`,
`mikrotik-ccr1036`, `linux-net-snmp`, `fiberhome-an5516`, `generic-snmpv2`) **não** são
gerados por aqui — são mantidos à mão e o conversor os respeita (política de conflito).
