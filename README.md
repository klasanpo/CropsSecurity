# CropsSecurity

Plataforma modular para organizar e executar ferramentas autorizadas de segurança. A versão 0.2 integra a primeira ferramenta operacional à fundação Docker: o Detector de Dados Sensíveis para aplicações web.

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

## Primeira ferramenta

Em **Web → Exposição de Informações**, o Detector de Dados Sensíveis percorre páginas e recursos textuais autorizados para procurar segredos, credenciais, dados pessoais, arquivos sensíveis e indicadores personalizados.

- execução assíncrona pelo worker;
- controle de domínio, profundidade, quantidade e tamanho dos recursos;
- cancelamento e progresso persistidos;
- validação de CPF, CNPJ e cartão para reduzir falsos positivos;
- valores sensíveis mascarados antes da persistência e exibição;
- resultados organizados por severidade e confiança.

Consulte [docs/modules/sensitive-data-finder.md](docs/modules/sensitive-data-finder.md) para parâmetros, limites e comportamento esperado.

## Estado

- Sprint 1: fundação concluída.
- Sprint 2: primeiro módulo operacional implementado.
- Antes de liberar acesso pela rede, ainda será necessário implementar autenticação e autorização de usuários.
