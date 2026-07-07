# NOTICE — SNMP profiles derivados do Datadog

Parte do catálogo de SNMP profiles do Telvyn agent (`internal/snmp/profiles/*.yaml`) é
**derivada** da biblioteca oficial open-source de NDM profiles do Datadog:

> **Datadog integrations-core**
> https://github.com/DataDog/integrations-core
> path: `snmp/datadog_checks/snmp/data/default_profiles/`
> commit vendorizado: `6e9d2c5fd681d34d7f862e5fbb396792e653e771`
>
> Copyright (c) 2016, Datadog, Inc. All rights reserved.
> Licenciado sob **BSD-3-Clause** — texto completo em `datadog-source/LICENSE`.

Os arquivos gerados foram **transformados** (herança `extends` resolvida em build,
convertidos para o formato de profile do Telvyn agent) por `convert.py`. A fonte original
e a licença estão vendorizadas em `datadog-source/` para reprodutibilidade e para cumprir
a cláusula de retenção do aviso de copyright da BSD-3-Clause.

Os profiles hand-curated do Telvyn (cisco-ios, mikrotik-routeros, etc.) são obra própria e
não derivam da biblioteca do Datadog.
