# Contexto de arquitetura para o Codex

CropsSecurity é uma plataforma web modular de segurança autorizada. Preserve as fronteiras: frontend apresenta; backend oferece API e persistência; worker executa tarefas assíncronas; módulos contêm lógica reutilizável e independente da interface.

O registro de módulos fica em `backend/src/crops_security/tools/registry.py`. Um módulo não deve depender de React, FastAPI, Redis ou SQLAlchemy. Recebe opções validadas, relata progresso por callback, consulta cancelamento por callback e devolve achados estruturados. A API nunca executa scanners no processo HTTP.

Achados devem preservar exatamente o trecho e o valor encontrados. Módulos, persistência, API, interface e exportações não podem mascarar, ocultar, normalizar, truncar ou substituir o conteúdo da evidência. A interface pode destacar visualmente o valor sem alterar a string. O worker e o backend compartilham exclusivamente o volume `crops_data`; o Redis transporta identificadores de execução, não resultados.

Execuções em lote compartilham um `batch_id`, mas cada alvo mantém limites, progresso, erros e resultados próprios. Exportações usam a evidência integral armazenada. Comparações de reteste não alteram os achados originais.

A exclusão de uma execução é permanente e transacional: primeiro remove seus achados e depois o registro da execução. A API deve recusar exclusão de itens em fila ou em andamento, exigindo cancelamento prévio.

O crawler não pode usar a presença de uma extensão como requisito para navegar. Rotas limpas e extensões desconhecidas são elegíveis dentro do escopo; o `Content-Type` da resposta decide se o conteúdo será analisado. A URL final de redirecionamentos é a base para referências relativas. O limite por alvo controla tentativas sobre URLs únicas, enquanto `pages_scanned` representa somente recursos textuais efetivamente analisados.

Consulte `docs/architecture/` e registre decisões duradouras em ADR. Não exponha Redis, SQLite ou backend diretamente no host sem decisão documentada.
