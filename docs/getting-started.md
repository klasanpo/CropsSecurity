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

## Desenvolvimento sem Docker

Para conviver com o SysReptor na porta 8000, o backend de desenvolvimento usa `127.0.0.1:8001`. O servidor Vite encaminha `/api` para essa porta e serve a interface em sua porta padrão. O Docker continua sendo a forma oficial de execução integrada.

## Dados

O volume `crops_data` contém `cropssecurity.db`. O volume `redis_data` preserva o estado do Redis. Nunca armazene segredos ou dados reais de clientes no código-fonte.

## Primeira análise

1. Abra **Ferramentas** e selecione **Detector de Dados Sensíveis**.
2. Informe uma URL pertencente ao escopo autorizado.
3. Ajuste os limites ou mantenha os valores conservadores sugeridos.
4. Confirme a autorização e inicie a análise.
5. Acompanhe a fila, o progresso e os achados em **Execuções**.

O alvo permanece no mesmo domínio por padrão. A opção de referências externas deve ser usada apenas quando esses domínios também fizerem parte do escopo autorizado.
