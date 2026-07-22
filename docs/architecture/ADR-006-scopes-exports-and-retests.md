# ADR-006: Escopos, exportações e comparação de reteste

- Status: Aceito
- Data: 2026-07-22

## Contexto

O script original aceitava listas de URLs e produzia relatórios por alvo. Na plataforma, esse comportamento precisa coexistir com fila assíncrona, persistência, cancelamento e proteção dos resultados sensíveis.

## Decisão

Cada alvo permanece uma execução independente. Execuções iniciadas juntas recebem um `batch_id` comum e podem carregar um rótulo de escopo nos parâmetros. Assim, uma falha ou cancelamento não elimina o histórico dos demais alvos e o worker continua aplicando limites individualmente.

As exportações HTML, CSV e JSON são geradas pelo backend a partir da evidência integral armazenada no SQLite. O navegador apenas inicia o download e não altera nem reconstrói o conteúdo.

A comparação de reteste é calculada sob demanda entre duas execuções concluídas do mesmo módulo. Um achado é identificado por indicador, URL, arquivo, linha e evidência original. Os registros originais não são alterados.

Execuções finalizadas podem ser removidas pelo operador. A exclusão é transacional e elimina primeiro os achados relacionados; execuções em fila ou em andamento precisam ser canceladas antes. A interface exige confirmação explícita porque não há lixeira nem restauração nesta fase.

## Consequências

- O painel pode agregar progresso e totais sem criar uma segunda fonte de resultados.
- Arquivos TXT são processados na interface e enviados como alvos tipados pela API.
- Alterações de caminho ou linha podem fazer um achado persistente aparecer como resolvido e novo; o analista deve revisar a comparação.
- Projetos, clientes e políticas permanentes de escopo continuam sendo uma evolução separada.
