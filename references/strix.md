# Teste dinâmico com Strix

O [Strix](https://github.com/usestrix/strix) é uma ferramenta open source (Apache-2.0) de pentest com agentes de IA. Ele roda o sistema num sandbox Docker, testa e só reporta o que conseguiu validar com prova de conceito. Nesta skill ele entra como **validação dinâmica** e **re-teste**: a análise estática encontra candidatos, o Strix confirma o que é explorável de fato e verifica se a correção funcionou.

Esta skill só orquestra o Strix (quando rodar, com que escopo, como ler e incorporar os resultados). A execução dos testes fica com a própria ferramenta. Se as skills oficiais do Strix estiverem instaladas (`npx skills add usestrix/strix`, que adiciona `penetration-testing-with-strix`, `fix-security-vulnerabilities-with-strix`, `ci-security-scanning-with-strix` e outras), use-as para os detalhes de execução e volte aqui para incorporar os resultados ao relatório.

## Regras de uso

- **Só alvos autorizados.** O usuário precisa ser dono do sistema ou ter autorização escrita. Confirme na Fase 0. O Strix Cloud exige verificação de domínio; no CLI, a responsabilidade é do usuário.
- **Prefira staging**, com dados fictícios. Teste dinâmico pode criar, alterar ou apagar registros. Se só existir produção, avise o usuário do risco e faça backup antes.
- **Diretório local é montado com permissão de escrita** no sandbox: rode sobre um clone limpo ou git worktree, nunca sobre trabalho não commitado.
- Sempre `-n` (modo headless) e `--max-budget` (teto de gasto em dólares com o LLM).
- Nunca coloque senhas reais ou chaves de produção nos arquivos de instrução; use contas de teste criadas para isso.

## Pré-requisitos

| Modo | Requisitos |
|---|---|
| CLI open source | Docker rodando; `curl -sSL https://strix.ai/install \| bash` (ou `pipx install strix-agent`); `STRIX_LLM` (id de modelo LiteLLM) e `LLM_API_KEY` |
| Strix Cloud (app.strix.ai) | Conta; `strix cloud login`; sem Docker nem chave de LLM; créditos |

Alguns provedores exigem programas de acesso para uso de seus modelos em pentest (o README do Strix cita, por exemplo, o Cyber Verification Program para modelos da Anthropic); confira a lista de modelos recomendados no README atual.

Se o ambiente desta sessão não tiver Docker, entregue os comandos ao usuário para rodar na máquina dele e peça a pasta `strix_runs/<run>/` (ou ao menos `vulnerabilities.json` e `penetration_test_report.md`) de volta.

## Escolha do modo de varredura

| Momento | Comando base |
|---|---|
| A cada PR / iteração rápida | `strix -n -t ./ --scan-mode quick --max-budget 5` |
| Auditoria final (modo B) | `strix -n -t ./ -t https://staging.exemplo.com --scan-mode standard --instruction-file strix-instrucoes.md --max-budget 20` |
| Auditoria completa (modo C) ou antes de lançamento grande | `strix -n -t ./ -t https://staging.exemplo.com --scan-mode deep --instruction-file strix-instrucoes.md --max-budget 50` |
| API com especificação | adicionar `-t ./openapi.yaml` junto da URL base |

Código + aplicação rodando juntos (white-box + teste dinâmico) dá a melhor cobertura. `quick` leva minutos; `deep`, horas: rode em segundo plano.

Códigos de saída no modo headless: `0` sem achados no que foi analisado, `1` erro fatal, `2` achados. `--fail-on high` faz o código 2 aparecer só para alta ou crítica (útil em CI).

## Instruções do teste

Escreva um arquivo de instruções (Markdown) para `--instruction-file`, com seções Credenciais, Foco e Fora de escopo. Credenciais vêm de contas de teste criadas para isso e o arquivo não é commitado. O essencial:

- **Duas contas de teste do mesmo papel (A e B)** e, se houver, uma conta admin e uma de outra empresa (multi-tenant). Sem isso o teste de controle de acesso entre usuários fica limitado.
- Foco nos fluxos de maior risco levantados nas fases 1 a 3 (dados pessoais, pagamento, admin, IA).
- Candidatos da análise estática que precisam de confirmação.
- Fora de escopo: integrações de terceiros (gateway de pagamento, provedor de e-mail), rotas que disparam ações reais (envio de SMS em massa, cobrança).

## Ler e incorporar os resultados

Em `strix_runs/<run>/`:

| Arquivo | Uso |
|---|---|
| `penetration_test_report.md` | Leia primeiro; resumo da execução e da cobertura |
| `vulnerabilities.json` | Achados estruturados (título, severidade, endpoint, CWE, locais no código, correção) |
| `vulnerabilities/*.md` | Detalhe e prova de cada achado |
| `findings.sarif` | Para o code scanning do GitHub |
| `run.json` | Status e custo: confira se a execução terminou ou parou pelo orçamento |

Incorpore com `scripts/consolidar_achados.py ... strix_runs/<run>/vulnerabilities.json`. No relatório:

- achados do Strix entram como **validados** (com prova); candidatos estáticos confirmados por ele sobem de confiança; candidatos que ele testou e não conseguiu explorar continuam no relatório com confiança menor, sem ser descartados automaticamente;
- converta a severidade para a escala da skill e acrescente o efeito LGPD;
- um resultado `0` não prova ausência de falhas: confira em `run.json` se o status é de conclusão e se o custo não bateu no `--max-budget`, e registre a cobertura real.

## Re-teste após correção

Depois de corrigir, rode de novo focado nos achados (`--instruction "Re-testar os achados X, Y e Z após correção"`, modo `quick` ou `standard`) ou use `fix-security-vulnerabilities-with-strix` se instalada. Um achado só fecha quando o re-teste não consegue mais reproduzi-lo.

## CI

Um workflow de segurança no GitHub Actions para cada PR deve ter: varredura de segredos (gitleaks), auditoria de dependências (`npm audit`/`pip-audit` ou osv-scanner), Semgrep e, opcionalmente, Strix em modo `quick` (que restringe o escopo às mudanças do PR; o checkout precisa de `fetch-depth: 0`), com `STRIX_LLM` e `LLM_API_KEY` como secrets do repositório e `--fail-on high` para bloquear o merge. O README do Strix traz o exemplo oficial de workflow. Alternativa sem infraestrutura: a integração do Strix Cloud com GitHub/GitLab. Fixe as actions de terceiros por SHA.
