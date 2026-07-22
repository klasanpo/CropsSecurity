# Primeiros passos

## Produção local

1. Copie `.env.example` para `.env`.
2. Execute `docker compose up --build -d`.
3. Aguarde todos os serviços ficarem `healthy` em `docker compose ps`.
4. Abra `http://localhost:1984`.

Somente a porta 1984 é publicada. Backend, Redis e worker ficam na rede interna do Compose.

## Diagnóstico

- Estado: `docker compose ps`
- Logs: `docker compose logs -f frontend backend worker redis`
- API pela entrada pública: `curl http://localhost:1984/api/v1/health`
- Documentação OpenAPI interna: ainda não é exposta diretamente nesta Sprint.

## Dados

O volume `crops_data` contém `cropssecurity.db`. O volume `redis_data` preserva o estado do Redis. Nunca armazene segredos ou dados reais de clientes no código-fonte.
