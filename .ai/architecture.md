# Contexto de arquitetura para o Codex

CropsSecurity é uma plataforma web modular de segurança autorizada. Preserve as fronteiras: frontend apresenta; backend oferece API e persistência; worker executa tarefas assíncronas; módulos futuros contêm lógica reutilizável e independente da interface.

Consulte `docs/architecture/` e registre decisões duradouras em ADR. Não exponha Redis, SQLite ou backend diretamente no host sem decisão documentada.

