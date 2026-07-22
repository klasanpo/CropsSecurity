# ADR-003: SQLite, Redis e worker separado

- Status: Aceito
- Data: 2026-07-22

## Decisão

Começar com SQLite em volume nomeado e Redis para coordenação. Manter um processo worker separado do servidor HTTP.

## Consequências

A instalação individual permanece simples e execuções longas futuras não bloquearão a API. Migração para PostgreSQL e uma fila formal será avaliada antes do uso multiusuário.

