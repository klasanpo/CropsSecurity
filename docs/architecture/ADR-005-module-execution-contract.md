# ADR-005: Contrato de módulos e execuções assíncronas

- Status: Aceito
- Data: 2026-07-22

## Contexto

Ferramentas de pentest podem durar minutos, gerar resultados sensíveis e depender de cancelamento. Executá-las dentro de uma requisição HTTP bloquearia a API e acoplaria a lógica de segurança à interface.

## Decisão

Cada ferramenta possui um manifesto estável no registro de módulos e uma implementação independente de FastAPI, React, Redis e banco de dados. A API valida e persiste a solicitação, coloca apenas seu identificador no Redis e retorna imediatamente. O worker recupera a configuração do SQLite, executa o módulo e persiste progresso e achados.

Todo módulo deve:

- aceitar opções tipadas e limites conservadores;
- respeitar escopo autorizado;
- oferecer progresso e cancelamento cooperativo;
- devolver achados estruturados com severidade e confiança;
- mascarar valores sensíveis antes de persistir;
- possuir testes de regressão, inclusive contra falsos positivos conhecidos.

## Consequências

A API permanece responsiva e novos módulos podem reutilizar a mesma fila, histórico e interface. Alterações no contrato exigem testes de compatibilidade e um novo ADR quando afetarem consumidores existentes.
