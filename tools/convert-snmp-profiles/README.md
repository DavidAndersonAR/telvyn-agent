# convert-snmp-profiles

Gera o catálogo de SNMP profiles do agente (`internal/snmp/profiles/*.yaml`) a partir
de um catálogo NDM open source, convertido para o formato do Telvyn Agent.

## Por que existe

Os profiles de origem **não são drop-in** no nosso agente:

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
./.venv/bin/python convert.py upstream-source ../../internal/snmp/profiles
```

O conversor:
- resolve `extends` recursivo (guarda de ciclo + dedup de bloco);
- normaliza IF-MIB (rótulo `interface_name`/`interface_alias` in-subtree);
- descarta o que o agente não usa (conta no relatório final);
- aplica a **política de conflito**: os prefixos em `DEFAULT_OWN` pertencem aos nossos
  profiles hand-curated e são removidos do catálogo importado (o profile é descartado se
  ficar sem sysObjectID) — a nossa curadoria vence o empate exato, deterministicamente.

## Fonte

`upstream-source/` contém a cópia vendorizada usada para gerar o catálogo (239 arquivos:
65 bases e 174 devices). Origem, revisão, copyright e licença BSD-3-Clause estão
documentados em `../../THIRD_PARTY_NOTICES.md`.

## Categorias geradas

- **auto-match**: tem sysObjectID + métrica (maioria).
- **manual-only**: métrica sem sysObjectID (ex. `brocade`, `a10`) — o operador escolhe
  pelo nome; nunca auto-matcha.
- **só-identificação**: sysObjectID sem métrica (ex. `tripplite`, `zebra-printer`) —
  reconhece o aparelho sem iniciar coleta automática.

Nossos 8 hand-curated (`cisco-ios`, `cisco-nx-os`, `juniper-junos`, `mikrotik-routeros`,
`mikrotik-ccr1036`, `linux-net-snmp`, `fiberhome-an5516`, `generic-snmpv2`) **não** são
gerados por aqui — são mantidos à mão e o conversor os respeita (política de conflito).
