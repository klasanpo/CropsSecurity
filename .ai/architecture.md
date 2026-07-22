# Contexto de arquitetura para o Codex

CropsSecurity é uma plataforma web modular de segurança autorizada. Preserve as fronteiras: frontend apresenta; backend oferece API e persistência; worker executa tarefas assíncronas; módulos contêm lógica reutilizável e independente da interface.

O registro de módulos fica em `backend/src/crops_security/tools/registry.py`. Um módulo não deve depender de React, FastAPI, Redis ou SQLAlchemy. Recebe opções validadas, relata progresso por callback, consulta cancelamento por callback e devolve achados estruturados. A API nunca executa scanners no processo HTTP.

Resultados sensíveis devem ser mascarados no módulo antes da persistência. O worker e o backend compartilham exclusivamente o volume `crops_data`; o Redis transporta identificadores de execução, não resultados.

Consulte `docs/architecture/` e registre decisões duradouras em ADR. Não exponha Redis, SQLite ou backend diretamente no host sem decisão documentada.
