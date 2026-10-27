---
name: seguranca-lgpd-vibecode
description: Segurança da informação e conformidade com a LGPD para sistemas vibecodados, escrita para agentes de código como o Claude Code (sistemas feitos com IA em stacks como Supabase, Firebase, Next.js e Vercel). Use para construir um sistema seguro desde o início, para a auditoria final antes de publicar e para auditar e corrigir um sistema já pronto. Cobre OWASP Top 10 2025, OWASP LLM Top 10, chaves expostas, RLS, autenticação, dados pessoais, bases legais, direitos dos titulares, política de privacidade, incidentes à ANPD e pentest com Strix. Acione sempre que o usuário falar em segurança, auditoria, pentest, vulnerabilidade, LGPD, dados pessoais, privacidade, ANPD, "deixar pronto para produção" ou "meu app está seguro?", mesmo sem citar a skill.
---

# Segurança e LGPD para sistemas vibecodados

Sistemas gerados por IA costumam funcionar bem e falhar nos mesmos pontos: chave secreta no frontend, banco acessível pela chave pública sem RLS, rota de API que confia no `userId` enviado pelo cliente, verificação de permissão só na interface, dados pessoais coletados "por precaução" e nenhum caminho para o titular pedir exclusão. Esta skill existe para pegar esses furos de forma sistemática e consertá-los, sem quebrar o sistema.

Três ideias guiam tudo:

1. **O servidor é o único lugar onde segurança existe.** Tudo que roda no navegador ou no app pode ser lido e alterado pelo usuário. Esconder um botão não é controle de acesso; a regra precisa estar na API, no banco (RLS) ou nas regras do Firebase.
2. **Evidência, não impressão.** Cada achado aponta arquivo e linha (ou requisição), explica o impacto concreto e traz a correção. Quando algo não foi verificado, o relatório diz isso em vez de presumir que está seguro.
3. **Segurança e LGPD são o mesmo trabalho visto de dois ângulos.** A LGPD (art. 46) exige medidas técnicas de segurança; um vazamento é ao mesmo tempo uma vulnerabilidade e um incidente a comunicar à ANPD. Por isso cada achado técnico é ligado ao seu efeito na LGPD, e cada exigência da LGPD vira algo implementado no código.

## Escolha o modo

| Situação | Modo |
|---|---|
| Vai começar um sistema, ou está no meio da construção | **A — Construção segura** |
| O sistema foi feito com o modo A e vai para produção | **B — Auditoria final** (pipeline de auditoria, focada em confirmar e no que mudou) |
| O sistema já existe, foi feito sem esse cuidado, ou ninguém sabe como foi feito | **C — Auditoria e correção de sistema existente** (pipeline completo) |

Se não estiver claro, pergunte em uma frase se o sistema já está no ar e se trata dados reais. Um sistema em produção com usuários muda a prioridade: primeiro conter o que é crítico (chave vazada, tabela aberta), depois o resto.

## Modo A — Construção segura

Leia `references/construcao-segura.md` no início do projeto. Em resumo:

1. **Antes de codar:** responda o questionário de kickoff (que dados pessoais, quem acessa, papéis, multiusuário/multiempresa, pagamentos, IA, crianças, dados sensíveis, onde fica hospedado). Isso gera o modelo de ameaças leve e o mapa de dados inicial.
2. **Fundação no dia 1:** `.gitignore` e pre-commit de segredos, variáveis de ambiente separadas por ambiente, autenticação pronta (não caseira), RLS "nega por padrão", biblioteca de validação de schema, tratador global de erros, logs com redação de dados pessoais, cabeçalhos de segurança, rate limit nas rotas sensíveis, Dependabot.
3. **Durante a construção, aplique os gatilhos:** ao criar uma tabela, já escreva a RLS; ao criar uma rota, já valide o input com schema e verifique autorização por recurso; ao adicionar um formulário, colete só o necessário e registre a finalidade e a base legal; ao integrar IA, siga `references/owasp-llm-top10-2025.md`. A tabela completa de gatilhos está na referência. Faça isso sem esperar o usuário pedir, porque é aí que a segurança fica barata.
4. **LGPD por padrão:** política de privacidade gerada a partir do mapa de dados, consentimento só onde ele é a base legal, endpoints de direitos do titular (exportar, corrigir, excluir), rotina de retenção.
5. **Ao terminar uma entrega relevante e antes do deploy,** rode o modo B.

## Modos B e C — Pipeline de auditoria

Crie uma lista de tarefas com as fases abaixo, porque a auditoria é longa e o usuário precisa ver o progresso. No modo B, as fases 2 a 5 podem focar no que mudou desde a última auditoria e no que o modo A não cobre; no modo C, faça todas por completo.

### Fase 0 — Escopo e autorização

Confirme o que será auditado (repositório, URL de staging/produção, projeto Supabase/Firebase) e que o usuário é dono ou tem autorização escrita para testar. Verificações contra o sistema no ar (`check_headers.py`, Strix) só rodam contra alvos autorizados, de preferência staging. Trabalhe numa cópia ou branch: o Strix monta o diretório local com permissão de escrita.

### Fase 1 — Reconhecimento

```bash
python3 scripts/recon.py <dir-do-projeto> --saida recon.json
```

Mostra a stack, a BaaS, rotas de API, server actions, migrações, arquivos `.env` (e se estão no git), integrações de IA, pagamentos e uploads, e diz quais referências ler. Leia `references/stacks-vibecode.md` na seção das stacks detectadas: ela lista onde cada plataforma costuma falhar.

### Fase 2 — Varredura automatizada

Rode os scanners. Eles produzem **candidatos** (heurísticas por padrão de texto), não veredictos: cada um precisa ser confirmado lendo o código antes de entrar no relatório.

```bash
python3 scripts/scan_secrets.py <dir> --git --saida segredos.json      # chaves no código, no bundle e no histórico
python3 scripts/deps_audit.py <dir> --saida deps.json                  # CVEs e riscos de supply chain
python3 scripts/mapear_dados_pessoais.py <dir> --saida dados.json      # rascunho do inventário de dados (LGPD)
python3 scripts/check_headers.py https://staging.exemplo.com --saida headers.json   # HTTPS, cabeçalhos e cookies
semgrep scan --config p/owasp-top-ten --config p/secrets --json -o semgrep.json <dir>   # análise estática (SAST)
```

O Semgrep (`pip install semgrep`) é o analisador estático recomendado: regras mantidas pela comunidade para as principais linguagens. Se não puder ser instalado, faça a leitura de código da fase 3 com mais cuidado e registre a lacuna.

Verificação do banco, conforme a stack (todas as consultas são só leitura; peça ao usuário para rodar e colar o resultado, ou rode você mesmo se houver acesso ao banco):

- **Supabase:** `scripts/postgres_auditoria.sql` + `scripts/supabase_storage.sql` no SQL Editor. É a forma mais confiável de achar tabela sem RLS, política `using (true)`, bucket público e função `security definer` exposta.
- **Outro PostgreSQL** (Neon, RDS, Railway, local): só `scripts/postgres_auditoria.sql`. Se o banco é acessado apenas pelo backend (não por uma API automática como PostgREST/Hasura), tabela sem RLS não é falha por si só: o controle de acesso precisa estar na API, e a RLS vira defesa em profundidade, sobretudo em sistemas multiempresa.
- **Firebase:** leia `firestore.rules`/`storage.rules` contra a seção de Firebase em `references/stacks-vibecode.md`.
- **MySQL, MongoDB e outros:** sem script; revise a configuração com a seção "Banco de dados em geral" de `references/stacks-vibecode.md` e o controle de acesso na API (fase 3).

Se faltar uma ferramenta (gitleaks, osv-scanner, pip-audit), os scripts avisam e seguem com o que têm. Registre a lacuna no relatório.

### Fase 3 — Revisão manual guiada

Os scanners não enxergam lógica de negócio, que é onde moram os piores furos (IDOR, escalada de privilégio, pular etapa de pagamento). Percorra `references/owasp-top10-2025.md` categoria por categoria: para cada uma há a pergunta de revisão, onde olhar e a medida que corrige, com link para a página oficial da OWASP. Priorize nesta ordem, porque é a ordem de impacto típico:

1. **A01 controle de acesso:** para cada rota ou server action, pergunte "o que impede o usuário B de ler ou alterar o recurso do usuário A trocando o ID?". Confira RLS/regras em cada tabela.
2. **Segredos e configuração (A02/A04):** confirme os achados de `scan_secrets.py`; chave que já esteve no git ou no bundle **precisa ser rotacionada**, apagar do código não basta.
3. **Autenticação (A07):** verificação do token no servidor, sessão, recuperação de senha, rate limit no login.
4. **Injeção e validação (A05):** queries montadas com string, HTML renderizado sem escape, comandos de shell.
5. **Integridade e mass assignment (A08):** `update(req.body)`, campos como `role`, `plan`, `credits` graváveis pelo cliente, webhooks sem assinatura.
6. **Design inseguro (A06), logging (A09), exceções (A10), supply chain (A03).**

Se o sistema usa LLM (chatbot, agente, RAG, geração de conteúdo), percorra também `references/owasp-llm-top10-2025.md`.

Para detalhes de implementação de qualquer correção, abra o arquivo da medida correspondente em `references/medidas/` (o índice `references/medidas/README.md` mapeia as 20 medidas para OWASP e LGPD). Leia só as medidas que o achado pede, porque cada uma é longa.

### Fase 4 — Conformidade com a LGPD

Siga `references/lgpd.md`. Partindo do rascunho de `mapear_dados_pessoais.py`, monte o inventário de dados com o usuário (finalidade, base legal, retenção e compartilhamento são decisões de negócio: proponha, mas confirme com ele). Depois verifique, com evidência no código ou no produto:

- base legal adequada para cada finalidade, e consentimento válido onde ele é a base (granular, registrado, revogável);
- dados sensíveis (art. 11) e de crianças e adolescentes (art. 14 e ECA Digital) com proteção reforçada;
- política de privacidade completa e coerente com o que o código realmente faz;
- direitos do titular implementados (acesso/exportação, correção, exclusão/anonimização, revogação), com verificação de identidade;
- retenção e eliminação reais, incluindo logs e backups;
- operadores e transferência internacional (Supabase, Vercel, OpenAI etc. costumam processar dados fora do Brasil);
- canal do encarregado, registro de operações e plano de resposta a incidentes.

Divergência entre a política de privacidade e o código é achado (ex.: política diz "não compartilhamos" e o código envia e-mail e CPF para um pixel de anúncios).

### Fase 5 — Teste dinâmico com Strix (recomendado no modo C e antes de lançamentos)

O Strix roda agentes de pentest que exploram o sistema de verdade e só reportam o que conseguem provar com PoC. Isso confirma ou derruba os candidatos das fases 2 e 3 e acha falhas de lógica que leitura de código perde. Leia `references/strix.md` para pré-requisitos (Docker, chave de LLM ou Strix Cloud), comandos, o modelo de instruções com dois usuários de teste (essencial para testar IDOR entre contas) e como incorporar os resultados. Sempre `-n` e `--max-budget`.

Se o ambiente não tiver Docker nem acesso ao Strix Cloud, entregue ao usuário os comandos prontos para rodar na máquina dele e, quando ele trouxer `strix_runs/<run>/vulnerabilities.json`, incorpore com `consolidar_achados.py`. Se o teste dinâmico não acontecer, o relatório diz claramente que a validação foi só estática.

### Fase 6 — Correção

Consolide tudo e classifique:

```bash
python3 scripts/consolidar_achados.py segredos.json deps.json headers.json semgrep.json \
  [strix_runs/<run>/vulnerabilities.json] --saida achados.md
```

Corrija em ordem de severidade, com estes cuidados:

- **Conter antes de consertar** quando há exposição ativa: rotacionar chave vazada, fechar bucket ou tabela aberta, desligar a rota. Diga ao usuário exatamente o que fazer no painel do provedor, porque rotação de chave normalmente não é algo que você consegue fazer pelo código.
- **Uma correção por vez, testável.** Para cada correção de acesso, escreva (ou descreva) o teste que prova que o usuário B não acessa o dado de A.
- **Não reescreva o histórico do git nem rode nada destrutivo sem confirmação explícita** (`git filter-repo`, `force push`, migração que apaga dados). Explique o impacto e espere o "pode".
- **RLS em produção:** ativar RLS sem políticas bloqueia o app inteiro. Escreva as políticas primeiro, teste em staging, depois ative (ver `references/medidas/04-ativar-rls.md`).
- Corrija a causa, não o sintoma: validar no servidor em vez de esconder o campo; política no banco em vez de filtro no frontend.

Depois de corrigir, rode de novo os scanners e, se houve Strix, o re-teste dos achados (ver `references/strix.md`). Achado só fecha com evidência de que a exploração deixou de funcionar.

### Fase 7 — Relatório e entregáveis

Escreva o relatório final com: resumo executivo em linguagem simples (para o dono do negócio), placar por severidade, achados com evidência, impacto e correção (e status: corrigido, pendente, risco aceito), situação LGPD, o que foi e o que **não** foi verificado, e próximos passos. O relatório é para alguém agir, então deve ser útil sozinho, sem precisar desta conversa.

Gere também, sob medida para o sistema e a partir do que foi levantado, os entregáveis LGPD que faltarem. O conteúdo obrigatório de cada um está em `references/lgpd.md`:

- **Inventário de dados** (registro das operações, art. 37): §3.
- **Política de privacidade**, coerente com o que o código faz: §6.
- **Plano de resposta a incidentes**, com os prazos da Resolução CD/ANPD nº 15/2024: §16.
- **Workflow de CI** com varredura de segredos e dependências em cada PR (e Strix opcional): `references/strix.md`, seção CI.

Documentos que dependem de decisões de negócio (finalidades, prazos de retenção, quem é o encarregado) saem com essas lacunas marcadas para o responsável preencher, nunca com valores inventados. Siga as regras do ambiente sobre o formato de entrega (documento, arquivo no repositório).

**Onde salvar no repositório.** Os entregáveis ficam em `docs/07-seguranca-privacidade/`, a mesma estrutura da skill `documentacao-sistema`: `inventario-dados.md`, `modelo-de-ameacas.md`, `plano-resposta-incidentes.md` e `auditorias/AAAA-MM-DD.md` (relatório com data). A política de privacidade fica onde o produto a publica (página do site/app), com cópia de referência na mesma pasta. Se a documentação do projeto segue a skill `documentacao-sistema`, também: registre os requisitos de segurança e privacidade como RNF na categoria "Privacidade e segurança" do documento de requisitos, transforme decisões estruturais de segurança em ADR (`docs/06-decisoes/`) e marque as colunas pessoais no modelo de dados apontando para o inventário. Não duplique: o inventário é a fonte única de finalidade, base legal e retenção.

## Severidade

Classifique pelo impacto real no sistema auditado, não pelo nome da categoria:

| Nível | Critério | Exemplos |
|---|---|---|
| **Crítica** | Exploração remota simples, sem login ou com qualquer conta, que expõe ou altera dados de outros usuários em massa, ou dá controle do sistema | `service_role` no frontend; tabela com dados pessoais sem RLS; SQL injection; rota admin sem auth |
| **Alta** | Exploração viável com impacto sério, mas limitada (exige conta, atinge um recurso por vez, ou depende de condição) | IDOR por ID sequencial; usuário consegue mudar o próprio `role`; webhook de pagamento sem assinatura; chave de LLM sem limite de gasto exposta |
| **Média** | Enfraquece defesas ou facilita outro ataque | Sem rate limit no login; erro devolvendo stack trace; cookies sem `HttpOnly`; CSP ausente; dependência com CVE não alcançável |
| **Baixa** | Boa prática ausente, impacto pequeno | Cabeçalho `X-Powered-By`; política de senha fraca com MFA disponível |
| **Info** | Observação, sem risco direto | Sugestões de arquitetura |

Achados de LGPD usam a mesma escala pelo risco aos titulares: tratar dado sensível sem base legal ou não ter como atender pedido de exclusão é **alta**; política de privacidade incompleta costuma ser **média**. Sempre que um achado técnico expõe dados pessoais, anote o efeito LGPD (ex.: "se explorado, é incidente comunicável à ANPD em 3 dias úteis").

## Limites e honestidade

- Isto não é parecer jurídico. Para decisões com risco legal relevante (dados de saúde em escala, dados de crianças, transferência internacional complexa, incidente já ocorrido), recomende validar com advogado ou DPO.
- Normas mudam. As referências citam LGPD, resoluções da ANPD e ECA Digital vigentes até a data de escrita; quando o ponto for decisivo, confirme o texto atual na fonte oficial (gov.br/anpd, planalto.gov.br).
- Sem teste dinâmico, a confiança é menor; sem acesso ao banco, RLS não pode ser confirmada. Diga isso no relatório.
- Só teste o que o usuário tem autorização para testar.

## Mapa de referências

| Arquivo | Quando ler |
|---|---|
| `references/construcao-segura.md` | Modo A: kickoff, modelo de ameaças, fundação, gatilhos por tipo de mudança, checklist de pronto |
| `references/owasp-top10-2025.md` | Fase 3: revisão por categoria, com o que verificar e a medida que corrige |
| `references/owasp-llm-top10-2025.md` | Sistema com chatbot, agente, RAG ou geração por LLM |
| `references/lgpd.md` | Fase 4 e modo A: requisitos da LGPD traduzidos em código e evidências |
| `references/stacks-vibecode.md` | Fase 1: configuração segura de Supabase, Firebase, bancos de dados em geral, Next.js, Vercel, Replit, Stripe, n8n |
| `references/strix.md` | Fase 5: pentest dinâmico, instruções, re-teste e CI |
| `references/medidas/README.md` | Índice das 20 medidas com mapeamento OWASP/LGPD; abra a medida específica para implementar a correção |
