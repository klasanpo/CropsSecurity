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
- e-mails, CPF, CNPJ e cartões válidos;
- palavras adicionais informadas pelo operador.

CPF, CNPJ e cartão passam por validação matemática. Valores de exemplo, placeholders e campos HTML de senha são ignorados para reduzir falsos positivos.

## Limites operacionais

| Parâmetro | Padrão | Finalidade |
|---|---:|---|
| URLs e recursos | 80 | Limita quantas páginas, scripts, folhas de estilo e respostas textuais serão lidos. |
| Profundidade | 2 | Limita quantos níveis de referências serão seguidos. |
| Tempo por recurso | 10 s | Evita que uma resposta lenta bloqueie toda a execução. |
| Tamanho por recurso | 2 MB | Evita consumo excessivo com arquivos muito grandes. |
| Certificado TLS | Validar | Preserva a validação normal da conexão HTTPS. |
| Referências externas | Desativado | Mantém a navegação no domínio autorizado. |

Os limites são de segurança e previsibilidade; não representam quantidade de vulnerabilidades. Aumente-os gradualmente conforme o tamanho da aplicação e a autorização recebida.

## Privacidade dos resultados

O detector mascara o valor encontrado antes de salvar no SQLite. A interface mostra contexto, tipo, severidade, confiança, recurso e linha, mas não preserva o segredo completo. Resultados reais continuam sendo dados de cliente e devem seguir as políticas de retenção e proteção aplicáveis ao projeto.

## Limitações conhecidas

- arquivos binários não são analisados;
- conteúdo que só aparece após execução complexa de JavaScript pode não ser descoberto;
- subdomínios não são incluídos automaticamente;
- nenhum detector substitui revisão manual e confirmação do achado.
