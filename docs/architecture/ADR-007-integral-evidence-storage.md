# ADR-007: Preservação integral das evidências

- Status: Aceito
- Data: 2026-07-22

## Contexto

Uma evidência de pentest precisa representar fielmente o conteúdo observado para permitir validação, comunicação ao cliente e correção. Mascarar, abreviar ou normalizar o valor encontrado reduz essa fidelidade e pode impedir que a empresa localize a ocorrência original.

## Decisão

O CropsSecurity preserva no SQLite o trecho e o valor exatamente como foram extraídos do recurso textual. A aplicação não mascara, oculta, normaliza espaços, remove quebras de linha, abrevia nem substitui caracteres. Interface e relatório HTML podem envolver o valor em marcação visual para destacá-lo, mas o texto permanece inalterado. CSV e JSON também recebem o valor integral.

Resultados produzidos antes desta decisão e já armazenados com mascaramento não são reversíveis. Somente uma nova execução pode capturar a evidência original.

## Consequências

- credenciais, chaves, dados pessoais e outros conteúdos sensíveis podem permanecer legíveis no volume SQLite, nos backups e nas exportações;
- o operador deve restringir acesso, compartilhamento, cópias e prazo de retenção;
- a exclusão de uma execução remove os achados relacionados, mas não elimina cópias ou backups externos;
- testes de regressão devem falhar se qualquer camada voltar a alterar a evidência.
