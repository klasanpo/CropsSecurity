# Detector de Dados Sensíveis

## Objetivo

Identificar exposição acidental de segredos, credenciais, dados pessoais e artefatos internos em páginas e recursos textuais de uma aplicação web autorizada.

## Localização na interface

**Web → Exposição de Informações → Detector de Dados Sensíveis**

## O que a ferramenta procura

- chaves e tokens com formatos conhecidos;
- credenciais em atribuições e URLs de banco;
- chaves privadas;
- nomes de arquivos e caminhos internos sensíveis;
- e-mails, CPF, CNPJ, RG contextual e cartões válidos;
- hosts privados, localhost e caminhos internos Linux ou Windows;
- palavras adicionais informadas pelo operador.

CPF, CNPJ e cartão passam por validação matemática. Valores de exemplo, placeholders, campos HTML de senha, referências a variáveis de ambiente e expressões de template são ignorados para reduzir falsos positivos.

O crawler reconhece referências HTML (`href`, `src`, `srcset`, `action` e `poster`), além de `@import` e `url()` em CSS. Rotas sem extensão, como `/login`, `/part1` e `/api/users`, URLs com parâmetros e extensões desconhecidas são visitadas dentro do escopo. A resposta HTTP define se o recurso é textual por meio do `Content-Type`; arquivos claramente binários são descartados. Recursos textuais como JavaScript, TypeScript, JSON, mapas de código-fonte, XML, logs e SQL podem ser analisados.

Redirecionamentos preservam a URL final. Assim, referências relativas encontradas depois de um redirecionamento são resolvidas a partir do endereço efetivamente carregado, e não da URL anterior. Redirecionamentos para outro domínio são registrados como ignorados quando referências externas estão desativadas.

## Limites operacionais

| Parâmetro | Padrão | Finalidade |
|---|---:|---|
| Limite de segurança por alvo | 200 | Limita quantas URLs únicas podem gerar tentativas de requisição em cada alvo. Pode ser ajustado entre 1 e 500. Somente respostas textuais efetivamente analisadas aparecem na contagem de recursos analisados. |
| Profundidade | 2 | Limita quantos níveis de referências serão seguidos. |
| Tempo por recurso | 10 s | Evita que uma resposta lenta bloqueie toda a execução. |
| Tamanho por recurso | 2 MB | Evita consumo excessivo com arquivos muito grandes. |
| Certificado TLS | Validar | Preserva a validação normal da conexão HTTPS. |
| Referências externas | Desativado | Mantém a navegação no domínio autorizado. |
| Contexto antes e depois | 1.500 caracteres por lado | Preserva até 1.500 caracteres anteriores e 1.500 posteriores ao indicador, totalizando aproximadamente 3.000 caracteres de contexto. |

Os limites são de segurança e previsibilidade; não representam quantidade de vulnerabilidades. Aumente-os gradualmente conforme o tamanho da aplicação e a autorização recebida.

Cada parâmetro operacional possui um botão de ajuda na interface. Em computadores, o painel abre ao passar o mouse ou focar pelo teclado e fecha automaticamente ao sair. Em telas sensíveis ao toque, o botão alterna o painel. A ajuda explica o alcance da opção, apresenta um exemplo e informa o impacto de aumentar ou desativar a proteção.

## Escopos com múltiplos alvos

O formulário aceita uma URL por linha e também arquivos TXT. Linhas vazias, duplicadas ou iniciadas por `#` são ignoradas. Cada alvo recebe sua própria execução e seus próprios limites, enquanto um identificador comum permite apresentar o andamento agregado do escopo.

## Resultados e exportação

A interface permite filtrar por severidade, indicador ou busca livre. Um seletor escolhe a execução e reserva toda a largura útil da tela para o resultado selecionado. Cada evidência apresenta primeiro uma janela de aproximadamente 700 caracteres centralizada no achado e pode ser expandida para todo o contexto salvo. O valor original correspondente ao achado aparece destacado em vermelho, sem alteração do conteúdo.

Execuções criadas antes desta configuração mantêm somente o trecho que foi armazenado originalmente. Para obter contexto maior em um resultado antigo, é necessário executar novamente a análise.

Ao concluir uma execução, os resultados podem ser baixados em HTML, CSV ou JSON. O HTML é independente, responsivo, inclui filtros locais e preserva o destaque visual do achado. Execuções finalizadas podem ser excluídas permanentemente pela interface; execuções em andamento precisam ser canceladas antes da exclusão.

Uma execução concluída pode ser comparada com outro teste anterior do mesmo alvo e módulo. A aplicação apresenta achados novos, resolvidos e persistentes; a confirmação final continua sendo responsabilidade do analista.

## Preservação e proteção dos resultados

O detector preserva o valor e o contexto exatamente como foram encontrados no recurso textual. Não há mascaramento, truncamento do valor, normalização de espaços nem substituição de caracteres antes da persistência. A interface apenas envolve visualmente o valor em um destaque, sem modificar a evidência. SQLite e exportações HTML, CSV e JSON podem, portanto, conter credenciais e dados pessoais completos em texto legível. O acesso ao ambiente, aos volumes, aos backups e aos relatórios deve ser restrito, e a exclusão deve seguir a política de retenção do projeto.

Resultados antigos que já tenham sido salvos com mascaramento não podem ser reconstruídos. Uma nova execução é necessária para capturar a evidência integral.

## Limitações conhecidas

- arquivos binários não são analisados;
- conteúdo que só aparece após execução complexa de JavaScript pode não ser descoberto;
- o crawler faz requisições HTTP e não renderiza a aplicação como um navegador completo;
- subdomínios não são incluídos automaticamente;
- a comparação de reteste usa a localização e a evidência original do achado; mudanças de linha podem exigir revisão manual;
- nenhum detector substitui revisão manual e confirmação do achado.
