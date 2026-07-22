# ADR-001: Monorepo modular

- Status: Aceito
- Data: 2026-07-22

## Decisão

Manter frontend, backend, testes, documentação e infraestrutura no mesmo repositório, com fronteiras explícitas entre eles.

## Consequências

Mudanças transversais podem ser revisadas juntas e a CI valida o produto completo. Cada componente preserva dependências e comandos próprios, evitando acoplamento de implementação.

