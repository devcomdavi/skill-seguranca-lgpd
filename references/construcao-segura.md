# Modo A: construção segura

Segurança barata é a que entra junto com o código. Este roteiro segue a ideia de *secure by design, by default, by deployment* (SD3) e do ciclo de desenvolvimento seguro (SDL): requisitos, desenho, implementação, verificação, liberação e manutenção.

## 1. Kickoff: 10 perguntas antes de codar

Pergunte ao usuário (ou deduza do pedido e confirme). As respostas definem o nível de proteção e alimentam o inventário de dados.

1. Que dados pessoais o sistema vai coletar? Algum sensível (saúde, biometria, religião, etnia, vida sexual, opinião política, sindicato) ou financeiro?
2. Quem são os usuários? Pode haver crianças ou adolescentes?
3. Quais papéis existem (cliente, funcionário, admin) e o que cada um pode fazer?
4. Vários clientes/empresas compartilham o sistema (multi-tenant)?
5. Há pagamentos, créditos, saldo ou planos?
6. Há IA (chatbot, agente, geração, RAG)? Que dados vão para o modelo?
7. Há upload de arquivos? De que tipo e tamanho?
8. Que serviços externos recebem dados (e-mail, WhatsApp, analytics, CRM, automação)?
9. Onde vai ficar hospedado e em que região?
10. Quem é o controlador dos dados (o próprio usuário ou um cliente dele)?

## 2. Modelo de ameaças leve (15 minutos)

Desenhe o fluxo de dados em texto: navegador/app → API/server actions → banco/storage → serviços externos. Marque as **fronteiras de confiança** (tudo que vem do cliente é não confiável). Para cada fluxo crítico (login, pagamento, dados pessoais, admin, IA), passe pelo STRIDE com perguntas defensivas:

| Letra | Pergunta | Controle típico |
|---|---|---|
| S – Falsificação de identidade | Como o servidor sabe quem está chamando? | Auth de provedor, token verificado, MFA para admin |
| T – Adulteração | O que impede alterar preço, papel, dono do recurso? | Valores calculados no servidor, allowlist de campos, assinatura de webhook |
| R – Repúdio | Conseguimos provar quem fez o quê? | Trilha de auditoria |
| I – Divulgação | Quem pode ver este dado? | RLS, respostas enxutas, cifra, logs sem dados pessoais |
| D – Negação de serviço | O que acontece com 10 mil requisições ou um arquivo enorme? | Rate limit, cotas, limites de tamanho, teto de gasto de IA |
| E – Elevação de privilégio | Um usuário comum consegue virar admin? | RBAC no servidor, papel fora do alcance do cliente |

Registre as decisões num `SECURITY.md` do projeto (curto): ameaças, controles escolhidos, riscos aceitos.

## 3. Fundação do dia 1

Monte antes da primeira funcionalidade:

- **Repositório:** `.gitignore` com `.env*` (exceto `.env.example` sem valores), pre-commit com gitleaks, branch principal protegida. Medidas 1, 2 e 20.
- **Segredos:** chave secreta só em variável de servidor; nada secreto com prefixo `NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_`; credenciais diferentes para dev, preview e produção.
- **Autenticação:** provedor pronto (Supabase Auth, Clerk, Auth.js, Firebase Auth); helper único `getUsuarioAtual()` usado em toda rota e server action; confirmação de e-mail ligada; MFA disponível. Medida 6.
- **Autorização:** RLS ativa em toda tabela desde a migração inicial, políticas por operação; helper de checagem de permissão; matriz de papéis escrita. Medidas 4 e 7.
- **Validação:** biblioteca de schema (zod, valibot, pydantic) em toda entrada; schemas por operação, só com campos permitidos. Medidas 8 e 14.
- **Erros e logs:** tratador global, mensagens genéricas ao usuário, logger estruturado com redação de dados pessoais e segredos, trilha de auditoria para eventos de segurança. Medida 15 e `owasp-top10-2025.md` (A09, A10).
- **Borda:** HTTPS com HSTS, cabeçalhos de segurança (CSP inicial), rate limit no login, cadastro, recuperação de senha e rotas de IA. Medidas 11, 18 e 19.
- **Dependências:** lockfile commitado, Dependabot/Renovate, workflow de segurança no CI (ver `strix.md`, seção CI).
- **LGPD:** inventário de dados iniciado (`docs/lgpd/inventario-dados.md`, ver `lgpd.md` §3), região de hospedagem escolhida, rascunho da política de privacidade.

## 4. Gatilhos durante a construção

Aplique automaticamente, sem esperar o usuário pedir. Quando a mudança dispara um gatilho, implemente o controle na mesma entrega e mencione em uma linha o que foi feito.

| Ao... | Faça também | Ref. |
|---|---|---|
| Criar tabela | `enable row level security` + políticas por operação na mesma migração; `owner_id`/`tenant_id` quando aplicável | Medida 4 |
| Criar rota de API ou server action | Exigir sessão; tirar a identidade do token; checar dono/papel do recurso; validar input com schema; devolver só os campos necessários | Medidas 6, 7, 8, 14, 17 |
| Gravar dados vindos do cliente | Allowlist de campos; `role`, `plan`, `credits`, `owner_id`, preços definidos só pelo servidor | Medida 8 |
| Escrever query | Parametrizada ou via query builder; nunca concatenar texto do usuário | Medida 13 |
| Renderizar conteúdo do usuário ou de IA | Escape padrão do framework; sanitizar se for HTML/Markdown | Medida 18 |
| Adicionar campo de dado pessoal | Perguntar se é necessário; registrar finalidade, base legal e retenção no inventário; cifrar se sensível; atualizar a política | `lgpd.md` §§ 3, 4, 9 |
| Adicionar formulário público | Rate limit e proteção contra bots; aviso de privacidade no ponto de coleta | Medidas 11, 12 |
| Adicionar login, cadastro, recuperação de senha | Mensagens que não revelam se a conta existe; limite de tentativas; tokens com aleatoriedade criptográfica e expiração | Medidas 6, 10, 11 |
| Adicionar upload | Tipo verificado pelo conteúdo, tamanho máximo, nome gerado pelo servidor, bucket privado com URL assinada | Medida 16 |
| Integrar pagamento | Preço no servidor; liberação só via webhook com assinatura verificada; idempotência | `owasp-top10-2025.md` A06, A08 |
| Integrar IA | Chave no servidor; cota e teto de gasto; ferramentas mínimas; saída tratada como não confiável; minimizar dados pessoais no prompt | `owasp-llm-top10-2025.md` |
| Adicionar serviço de terceiro (analytics, e-mail, CRM) | Registrar como operador no inventário; checar país e termos; carregar scripts não essenciais só após consentimento | `lgpd.md` §§ 5, 12, 13 |
| Adicionar dependência | Confirmar que o pacote existe, é o oficial, ativo e popular; evitar pacote para coisa trivial | Medida 20 |
| Criar função admin | Papel verificado no servidor; trilha de auditoria; MFA para admins | Medida 7 |
| Criar job, cron ou webhook | Autenticar a chamada (segredo/assinatura); idempotência; tratar falhas | Medida 6 |

## 5. Definição de pronto (por funcionalidade)

- [ ] Rotas novas exigem sessão e checam autorização por recurso
- [ ] Tabelas novas com RLS e políticas testadas
- [ ] Inputs validados por schema; respostas sem campos extras
- [ ] Nenhum segredo novo no cliente
- [ ] Teste de autorização: usuário B não acessa dados de A
- [ ] Erros não expõem detalhes internos; eventos de segurança logados sem dados pessoais
- [ ] Inventário de dados e política atualizados se houve dado pessoal novo
- [ ] Dependências novas verificadas

## 6. Antes do deploy

Rode o modo B (pipeline de auditoria). Em produção, mantenha: Dependabot e workflow de segurança no CI, Strix `quick` nos PRs se possível (`strix.md`), revisão de acessos ao painel a cada trimestre, teste de restauração de backup, e auditoria completa a cada mudança grande ou pelo menos uma vez por ano.

## 7. Memória do projeto

Para que os gatilhos valham em todas as sessões do agente, registre no arquivo de instruções do projeto (`CLAUDE.md`, `AGENTS.md` ou equivalente) um resumo curto: a matriz de papéis, as regras "toda tabela com RLS", "toda rota com sessão, autorização por recurso e schema", "nenhum segredo no cliente", e onde ficam `SECURITY.md` e o inventário de dados.
