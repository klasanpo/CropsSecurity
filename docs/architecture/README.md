# Arquitetura

```text
Browser :1984
    │
    ▼
Frontend / Nginx ──► FastAPI ──► SQLite volume
                         │
                         ▼
                       Redis ◄── Worker
```

O Nginx entrega o frontend e encaminha `/api/*` ao backend. Nenhum serviço interno publica porta no host. O worker mantém um heartbeat no Redis; scanners e filas reais entram em sprints posteriores.

## ADRs

- [ADR-001 — Monorepo modular](ADR-001-monorepo.md)
- [ADR-002 — Aplicação web em Docker](ADR-002-docker-web-platform.md)
- [ADR-003 — Persistência e trabalho assíncrono](ADR-003-persistence-and-workers.md)
- [ADR-004 — Segurança por padrão](ADR-004-security-boundaries.md)
