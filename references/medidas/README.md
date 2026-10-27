# Índice das 20 medidas

Cada arquivo explica o que é a medida, por que importa e como implementá-la em camadas, com código (Node.js, Next.js, Python, PostgreSQL/Supabase, Nginx). Abra só o arquivo que o achado pede.

| # | Medida | Arquivo | OWASP 2025 | LGPD | Sinal típico em código vibecodado |
|---|---|---|---|---|---|
| 1 | Esconder API keys | `01-esconder-api-keys.md` | A02, A04, A07 | art. 46 | `NEXT_PUBLIC_`/`VITE_` em chave secreta; chave de OpenAI/Stripe no frontend |
| 2 | Limpar secrets do histórico do git | `02-limpar-secrets-historico-git.md` | A02, A03 | art. 46 | `.env` commitado em algum momento; chave em commit antigo |
| 3 | Anon key do banco | `03-anon-key-do-banco.md` | A01, A02 | art. 46 | Supabase/Firebase acessado direto do navegador sem RLS/regras |
| 4 | Ativar RLS | `04-ativar-rls.md` | A01 | art. 46; art. 6º, VII | Tabela sem `enable row level security`; política `using (true)` |
| 5 | Criptografia de dados | `05-criptografia-de-dados.md` | A04 | art. 46; art. 48 §3º (dado ilegível reduz o risco do incidente) | CPF, documentos e dados de saúde em texto puro; backup sem cifra |
| 6 | Autenticação no servidor | `06-autenticacao-no-lado-do-servidor.md` | A07, A01 | art. 46 | `jwt.decode` sem verificar; `userId` vindo do body; guarda só na rota do frontend |
| 7 | Restringir acessos (RBAC) | `07-restringir-acessos.md` | A01, A06 | art. 46; art. 6º, VII | `if (user.role === 'admin')` só no componente; papel salvo em `localStorage` |
| 8 | Bloquear mass assignment | `08-bloquear-mass-assignment.md` | A08, A01 | art. 46 | `update(req.body)`, `...body`, cliente gravando `role`, `plan`, `credits` |
| 9 | Proteger cookies | `09-proteger-cookies.md` | A02, A07 | arts. 7º e 8º (cookies não essenciais exigem base legal) | Token em `localStorage`; cookie sem `HttpOnly`/`Secure`; banner de cookies que não bloqueia nada |
| 10 | Hash nas senhas | `10-hash-nas-senhas.md` | A04, A07 | art. 46 | Senha própria com MD5/SHA-256 ou em texto; tabela `users` com coluna `password` |
| 11 | Rate limit | `11-rate-limit.md` | A06, A07, A10; LLM10 | art. 46 | Login, OTP, recuperação de senha e rota de IA sem limite |
| 12 | Proteção contra bots | `12-protecao-contra-bots.md` | A06, A07 | art. 6º, III (minimizar dados do desafio) | Cadastro e formulário de contato abertos a automação |
| 13 | Queries parametrizadas | `13-queries-parametrizadas.md` | A05 | art. 46 | Template string em SQL; `$queryRawUnsafe`; filtro do Supabase montado com input |
| 14 | Validação dos inputs | `14-validacao-dos-inputs.md` | A05, A10 | art. 6º, V (qualidade dos dados) | Rota sem schema (zod/pydantic); tamanho e tipo não limitados |
| 15 | Prevenir vazamento de dados sensíveis | `15-vazamento-de-dados-sensiveis.md` | A01, A09, A10 | arts. 6º III, 46, 48 | Logs com CPF/senha; erro com string de conexão; source maps em produção |
| 16 | Restringir uploads | `16-restringir-uploads.md` | A06, A01 | art. 46 | Bucket público; upload sem limite de tipo/tamanho; nome de arquivo do cliente |
| 17 | Enxugar respostas de API | `17-enxugar-respostas-de-api.md` | A01, A08 | art. 6º, III (necessidade) | `select('*')` devolvido inteiro; hash de senha ou e-mail de terceiros no JSON |
| 18 | Cabeçalhos de segurança | `18-adicionar-cabecalhos-de-seguranca.md` | A02, A05 | art. 46 | Sem CSP, HSTS, `frame-ancestors`; `X-Powered-By` exposto |
| 19 | Forçar HTTPS | `19-forcar-https.md` | A04, A02 | art. 46 | HTTP sem redirecionamento; sem HSTS; `rejectUnauthorized: false` |
| 20 | Supply chain | `20-supply-chain-dependencias.md` | A03, A08 | arts. 39 e 46 (operadores e segurança) | Sem lockfile; pacote alucinado pela IA; `postinstall` desconhecido; script de CDN sem SRI |

## Cobertura que vai além das 20 medidas

Alguns riscos do OWASP 2025 não têm medida própria neste índice e estão detalhados direto em `../owasp-top10-2025.md`:

- **A06 Design inseguro:** modelagem de ameaças, regras de negócio (limites, estados, pagamentos), isolamento entre empresas (multi-tenant).
- **A09 Logging e alertas:** trilha de auditoria, eventos que precisam ser registrados, alertas, retenção de logs (Marco Civil, art. 15).
- **A10 Condições excepcionais:** tratador global de erros, falhar fechado, transações com rollback, limites de recursos.
- **SSRF, CSRF, open redirect, path traversal:** dentro de A01 e A05.
