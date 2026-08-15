# AGENTS.md — Telvyn Agent

Leia `CONTEXT.md` antes de alterar este repositório. O produto se chama Telvyn;
nomes `ispwatch` ainda presentes em variáveis e caminhos são legado compatível e não
devem ser renomeados incidentalmente.

Regras essenciais:

- um agente por host, com token próprio;
- ingest canônico por HTTP/OTLP certless e Bearer token `iwI_...`;
- faça mudanças cirúrgicas e rode `go test ./...` antes de publicar;
- não versione tokens, chaves, credenciais ou artefatos de build.
