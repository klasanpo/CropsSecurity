# ADR-004: Segurança por padrão

- Status: Aceito
- Data: 2026-07-22

## Decisão

Expor somente o frontend/reverse proxy, não incluir scanners na fundação e exigir que módulos futuros tratem escopo autorizado, auditoria, limites e cancelamento seguro como requisitos.

## Consequências

A Sprint 1 não executa ações ofensivas. Autenticação será obrigatória antes de acesso em rede ou uso multiusuário.

