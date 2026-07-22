# ADR-002: Aplicação web distribuída com Docker Compose

- Status: Aceito
- Data: 2026-07-22

## Decisão

Usar React + TypeScript no navegador, FastAPI no backend e Docker Compose como distribuição principal. Publicar apenas a porta configurável `1984` no host.

## Consequências

Windows, macOS e Linux compartilham o mesmo ambiente de execução. São necessárias imagens multi-arquitetura em releases futuras. A porta 8000 do backend permanece interna e não conflita com o SysReptor.
