# Arquitetura

```text
Browser :1984
    │
    ▼
Frontend / Nginx ──► FastAPI ──► SQLite volume ◄── Worker
                         │                           │
                         ▼                           ▼
                       Redis ───── fila ─────► Módulo web
```

O Nginx entrega o frontend e encaminha `/api/*` ao backend. Nenhum serviço interno publica porta no host. A API registra uma execução no SQLite e envia seu identificador ao Redis. O worker consome a fila, executa o módulo, registra progresso e salva a evidência original no mesmo volume SQLite.

## ADRs

- [ADR-001 — Monorepo modular](ADR-001-monorepo.md)
- [ADR-002 — Aplicação web em Docker](ADR-002-docker-web-platform.md)
- [ADR-003 — Persistência e trabalho assíncrono](ADR-003-persistence-and-workers.md)
- [ADR-004 — Segurança por padrão](ADR-004-security-boundaries.md)
- [ADR-005 — Contrato de módulos e execuções](ADR-005-module-execution-contract.md)
- [ADR-006 — Escopos, exportações e reteste](ADR-006-scopes-exports-and-retests.md)
- [ADR-007 — Preservação integral das evidências](ADR-007-integral-evidence-storage.md)
