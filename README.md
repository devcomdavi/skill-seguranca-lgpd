# seguranca-lgpd-vibecode

Skill para agentes de código (Claude Code e compatíveis com `SKILL.md`) que leva segurança da informação e conformidade com a LGPD para sistemas vibecodados, isto é, sistemas construídos com ajuda de IA.

## O que ela faz

| Modo | Quando usar |
|---|---|
| **A: Construção segura** | No início ou durante o desenvolvimento: kickoff de segurança e LGPD, modelo de ameaças leve, fundação segura no dia 1 e gatilhos automáticos ("ao criar uma tabela, cria a RLS; ao criar uma rota, valida sessão, dono do recurso e input"). |
| **B: Auditoria final** | Antes de publicar um sistema construído no modo A. |
| **C: Auditoria e correção** | Para sistemas já prontos: varredura, revisão guiada, verificação LGPD, teste dinâmico, correção e relatório. |

Cobre:

- OWASP Top 10:2025 e OWASP Top 10 para aplicações com LLM (2025)
- 20 medidas práticas de segurança, com código (chaves de API, RLS, autenticação, RBAC, mass assignment, cookies, hash de senhas, rate limit, uploads, cabeçalhos, HTTPS, supply chain e mais)
- LGPD: inventário de dados, bases legais, consentimento e cookies, direitos do titular, retenção, dados sensíveis, crianças e adolescentes (ECA Digital), operadores, transferência internacional, encarregado, RIPD e incidentes (Resolução CD/ANPD nº 15/2024)
- Configuração segura de Supabase, Firebase, PostgreSQL e outros bancos, Next.js, Vercel, pagamentos, automações e provedores de IA
- Teste dinâmico e re-teste com o [Strix](https://github.com/usestrix/strix)

## Estrutura

```
SKILL.md                      fluxo dos três modos, severidade e mapa de referências
references/
  construcao-segura.md        modo A
  owasp-top10-2025.md         roteiro de revisão por categoria
  owasp-llm-top10-2025.md     controles para sistemas com LLM
  lgpd.md                     LGPD traduzida em requisitos e evidências
  stacks-vibecode.md          configuração segura por plataforma
  strix.md                    pentest dinâmico, re-teste e CI
  medidas/                    as 20 medidas, uma por arquivo, com índice
scripts/
  recon.py                    reconhecimento da stack, rotas e integrações
  scan_secrets.py             segredos no código, no build e no histórico do git
  deps_audit.py               dependências e supply chain
  mapear_dados_pessoais.py    rascunho do inventário de dados (LGPD)
  check_headers.py            HTTPS, cabeçalhos de segurança e cookies
  consolidar_achados.py       junta resultados (incluindo Semgrep e Strix) por severidade
  postgres_auditoria.sql      RLS, políticas, funções e colunas com dados pessoais (qualquer PostgreSQL)
  supabase_storage.sql        buckets e políticas do Storage do Supabase
```

Os scripts usam só a biblioteca padrão do Python 3. Ferramentas externas (gitleaks, Semgrep, pip-audit, osv-scanner, Strix) são usadas quando estão instaladas; quando faltam, a lacuna aparece no relatório.

## Instalação

**Claude Code:** copie a pasta para `~/.claude/skills/seguranca-lgpd-vibecode/` (uso pessoal) ou `.claude/skills/seguranca-lgpd-vibecode/` dentro do projeto.

```bash
git clone https://github.com/devcomdavi/seguranca-lgpd-vibecode ~/.claude/skills/seguranca-lgpd-vibecode
```

**Claude (app):** baixe o repositório como `.zip` e envie em Configurações → Capacidades → Skills.

## Uso

Basta pedir em linguagem natural, por exemplo: "audita a segurança e a LGPD deste projeto", "vou começar um SaaS com Supabase, quero fazer seguro desde o início" ou "meu app está pronto para produção?".

## Avisos

- Testes contra sistemas no ar (verificação de cabeçalhos, Strix) só devem ser feitos em sistemas próprios ou com autorização escrita, de preferência em staging.
- O conteúdo sobre LGPD é orientação técnica, não parecer jurídico. Normas mudam: confirme o texto vigente na ANPD e no Planalto quando o ponto for decisivo.

## Sequência de skills

Esta skill faz parte de uma sequência para construir sistemas **legais, documentados e funcionais**. Ela compartilha a pasta `docs/` e os identificadores (RF, RNF, UC, ADR) com a [documentacao-sistema](https://github.com/devcomdavi/claude-skill-documentacao-sistema) e mantém `docs/07-seguranca-privacidade/`.

## Licença

[MIT](LICENSE)
