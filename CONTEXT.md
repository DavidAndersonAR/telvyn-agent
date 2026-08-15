# Contexto atual — Telvyn Agent

Snapshot: 2026-08-15. Repositório oficial: `TelvynMonitoring/telvyn-agent`; branch
canônica: `main`.

## Estado publicado

- `v0.4.8`: checks reportam o motivo concreto de falha ao backend.
- `v0.4.9`: o workflow de publicação produz a tag de série da imagem, seguindo o
  modelo de distribuição do Datadog.
- O agente usa HTTP/OTLP certless com Bearer token `iwI_...`.
- Cada host executa uma instância com token próprio.

## Relação com a plataforma

O backend e o portal ficam em `DavidAndersonAR/ispwacthinfra`. O handoff operacional
mais recente fica em `docs/CURRENT-HANDOFF.md` desse repositório.

Antes de continuar, rode `git status`, `git log -5 --oneline` e `go test ./...`.
Não presuma que este snapshot substitui a verificação do estado remoto e dos testes.
