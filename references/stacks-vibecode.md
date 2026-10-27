# Configuração segura por stack

Pontos de configuração a revisar em cada plataforma comum em sistemas vibecodados. Leia só as seções das stacks que `recon.py` detectou. Confirme nomes de telas e opções na documentação atual do provedor, que muda com frequência.

## Supabase

- **Chaves:** a chave pública (anon/publishable) pode ir ao cliente; a `service_role`/secret key nunca. Ela ignora a RLS e só pode existir em servidor, edge function ou script administrativo.
- **RLS:** ativa em toda tabela do schema exposto (`public` ou outros expostos na API); políticas por operação usando `auth.uid()`; `update` com `using` e `with check`; nada de `using (true)` em tabela com dados privados. Rode `scripts/postgres_auditoria.sql` e `scripts/supabase_storage.sql`. O Security Advisor do painel também aponta tabelas sem RLS e funções inseguras.
- **Colunas privilegiadas:** se o cliente pode dar `update` na própria linha de `profiles`, ele não pode conseguir alterar `role`, `plan` ou `credits`. Use tabela separada, grants por coluna ou trigger que bloqueia a mudança (medida 4, seção 3; medida 8).
- **Views e funções:** views no schema exposto com `security_invoker = true` (PG15+); funções `security definer` só quando necessário, com `set search_path = ''` e checagem de permissão dentro; revogar `execute` de `anon`/`public` em funções administrativas.
- **Storage:** bucket público só para conteúdo público; políticas em `storage.objects` restritas à pasta do usuário; URLs assinadas com expiração para arquivos privados; limite de tamanho e de tipos no bucket.
- **Auth:** confirmação de e-mail ligada; URLs de redirecionamento permitidas restritas aos seus domínios; proteção contra senhas vazadas e MFA quando disponíveis no plano; desligar cadastro aberto se o sistema é por convite; ajustar limites de envio de e-mail/OTP.
- **Edge functions:** verificar o JWT (padrão) e não usar a `service_role` para agir em nome do usuário sem checar permissão.
- **Operação:** backups/PITR conforme o plano, região do projeto (há opção no Brasil), MFA na conta do painel, acessos da equipe revisados.

## Firebase

- **Regras** do Firestore, Realtime Database e Storage: nada de `allow read, write: if true` nem regras de teste com data de expiração esquecidas; `request.auth != null` sozinho deixa qualquer conta ler tudo, então amarre ao dono (`request.auth.uid == resource.data.ownerId`) e valide os campos gravados (`request.resource.data`).
- Teste as regras com o Emulator e a biblioteca de testes de regras.
- **App Check** para reduzir abuso das APIs pelo cliente.
- Credenciais do Admin SDK (conta de serviço) só no servidor; a configuração web do Firebase pode ser pública, a conta de serviço não.
- Custom claims para papéis, definidos só pelo servidor.

## Banco de dados em geral (PostgreSQL, MySQL, MongoDB, Redis e outros)

Vale para qualquer banco, inclusive gerenciados (Neon, RDS, PlanetScale, Railway, MongoDB Atlas, Upstash):

- **Fora da internet pública:** o banco aceita conexões só da aplicação (rede privada, VPC, lista de IPs permitidos). Nada de `0.0.0.0/0` liberado em produção. MongoDB e Redis nunca expostos sem autenticação.
- **Usuário da aplicação com privilégio mínimo:** a aplicação não conecta como superusuário/`root`/dono do banco. Um usuário para a aplicação (só `SELECT/INSERT/UPDATE/DELETE` nas tabelas necessárias), outro para migrações, e acesso administrativo separado e com MFA no painel. Se a aplicação só lê uma tabela, o usuário só lê.
- **Credenciais:** string de conexão só em variável de ambiente do servidor; senha forte e única por ambiente; rotação quando alguém sai da equipe ou houver suspeita de vazamento.
- **TLS na conexão:** `sslmode=require` (ou `verify-full`) no Postgres, `ssl` no MySQL, `tls=true` no MongoDB; sem desabilitar a verificação de certificado.
- **Controle de acesso por registro na aplicação:** sem RLS, toda query de dado privado filtra pelo dono/empresa vindos da sessão (`where id = $1 and owner_id = $2`). Num ORM, centralize isso (escopos, middleware do Prisma, repositórios) para não depender de lembrar em cada rota. Em sistemas multiempresa no Postgres, considere RLS mesmo com backend próprio, como defesa em profundidade.
- **Queries parametrizadas** sempre (medida 13); no MongoDB, valide tipos de entrada para que objetos com operadores não cheguem às consultas.
- **Criptografia em repouso** ligada no provedor; campos sensíveis cifrados na aplicação (medida 5).
- **Backups:** automáticos, cifrados, com retenção definida (entra no inventário LGPD) e **restauração testada**. Point-in-time recovery quando disponível.
- **Logs e auditoria:** logs de conexão e de erros do banco ativados; alertas para falhas de autenticação; logs de queries lentas sem gravar valores de parâmetros com dados pessoais.
- **Ambientes separados:** desenvolvimento e preview nunca usam o banco de produção; dados reais não são copiados para teste sem anonimização.
- **Atualizações:** versão do banco suportada e com patches; extensões só as necessárias.

## Next.js e Vercel

- Server actions e route handlers são endpoints públicos: cada um verifica sessão e autorização, mesmo que a página que os chama seja protegida.
- Não dependa só do `middleware.ts` para proteger dados; ele é uma primeira camada. Mantenha o Next.js atualizado (houve correção de segurança importante no middleware em 2025, CVE-2025-29927) e repita a checagem perto do dado.
- Componentes de servidor que passam objetos inteiros para componentes de cliente enviam todos os campos ao navegador; selecione só o necessário. Use `server-only` em módulos com segredos.
- `NEXT_PUBLIC_*` vai para o bundle.
- Desligue `productionBrowserSourceMaps` (padrão é desligado) ou não publique os mapas.
- Cabeçalhos em `next.config.js` (`headers()`) ou middleware; CSP com nonce se possível.
- Vercel: variáveis separadas por ambiente (Production, Preview, Development); previews não usam o banco de produção; Deployment Protection ligada para previews; MFA na conta e no time.

## React/Vite SPA

- Tudo em `VITE_*` (ou `REACT_APP_*`) é público. Chamadas que precisam de chave secreta passam por um backend ou função serverless.
- Guardas de rota no frontend são só experiência de uso; a proteção real está na API/RLS.

## Lovable, Bolt, v0, Replit e similares

- Costumam gerar acesso direto do frontend ao Supabase: a segurança inteira depende da RLS. Revise-a tabela por tabela.
- Verifique se a ferramenta colocou chaves de terceiros (OpenAI, Stripe secret, Resend) no código do cliente; mova para edge functions/servidor.
- Use os scanners de segurança das próprias ferramentas (o Lovable tem um) como complemento, não como substituto.
- Replit: segredos no painel de Secrets, não no código; deployments públicos usam as variáveis de produção.
- Exporte o código para um repositório git para ter histórico, revisão e CI.

## Backends Node (Express, Fastify, NestJS) e Python (FastAPI, Flask, Django)

- `helmet` (Express) ou equivalente para cabeçalhos; CORS com lista de origens; limite de tamanho do body; `trust proxy` configurado corretamente atrás de proxy (afeta IP do rate limit e cookies `Secure`).
- Django/Flask: `DEBUG` desligado em produção, `SECRET_KEY` de variável de ambiente, `ALLOWED_HOSTS` definido; Django com `SECURE_*` e `SESSION_COOKIE_SECURE`.
- FastAPI: dependências de autenticação em todas as rotas privadas; modelos Pydantic separados para entrada e saída.

## Pagamentos (Stripe, Mercado Pago, Asaas, Pagar.me)

- Chave secreta só no servidor; chave publicável pode ir ao cliente.
- Preço e itens definidos no servidor (IDs de preço do provedor), nunca o valor enviado pelo cliente.
- Acesso pago liberado apenas pelo webhook, com verificação de assinatura (`stripe.webhooks.constructEvent` ou o equivalente do provedor) e tratamento idempotente (o mesmo evento pode chegar mais de uma vez).
- Não guardar dados de cartão; usar o checkout/tokenização do provedor.

## Automação (n8n, Make, Zapier) e webhooks próprios

- Webhooks com autenticação (cabeçalho secreto, assinatura HMAC ou basic auth) e URL não divulgada.
- Instância n8n self-hosted atualizada, atrás de login e HTTPS, com credenciais guardadas no cofre da ferramenta.
- Mapear no inventário de dados quais dados pessoais passam pelos fluxos.

## Provedores de IA (OpenAI, Anthropic, Google)

- Chave só no servidor; teto de gasto e alertas no painel do provedor; cota por usuário no sistema.
- Verificar retenção de dados e uso para treino nos termos da conta/API; registrar como operador e como transferência internacional.
- Ver `owasp-llm-top10-2025.md`.

## E-mail, monitoramento e analytics

- Provedores de e-mail: domínio com SPF, DKIM e DMARC para evitar falsificação.
- Sentry e similares: `sendDefaultPii` desligado, scrubbing de campos sensíveis; session replay com mascaramento de inputs e textos.
- Google Analytics, Meta Pixel, Hotjar: carregar após consentimento, sem enviar e-mail, CPF ou telefone em eventos e URLs.
