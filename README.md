# CropsSecurity

Plataforma modular para organizar e executar ferramentas autorizadas de segurança. A Sprint 1 entrega a fundação: interface web, API, worker, persistência local e ambiente Docker reproduzível.

## Início rápido

Pré-requisito: Docker Desktop ou Docker Engine com Compose.

```bash
cp .env.example .env
docker compose up --build -d
```

Acesse `http://localhost:1984`. A porta 8000 permanece interna ao container do backend e não conflita com o SysReptor.

```bash
docker compose ps
docker compose logs -f
docker compose down
```

Os dados do SQLite e do Redis permanecem em volumes nomeados. `docker compose down` não os remove; para apagá-los deliberadamente use `docker compose down -v`.

## Desenvolvimento e qualidade

- Backend: `cd backend && python -m pip install -e '.[dev]' && pytest && ruff check .`
- Frontend: `cd frontend && pnpm install --frozen-lockfile && pnpm lint && pnpm test -- --run && pnpm build`
- Stack: `docker compose config && docker compose build`

Consulte [docs/getting-started.md](docs/getting-started.md), [docs/architecture/README.md](docs/architecture/README.md) e [CONTRIBUTING.md](CONTRIBUTING.md).

## Estado

Sprint 1: fundação. Ainda não existem scanners, autenticação nem execução de trabalhos de pentest.
