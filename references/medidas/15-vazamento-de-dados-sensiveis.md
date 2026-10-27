# 15. Prevenir vazamento de conteúdo, credenciais e dados sensíveis

### O que é e por que importa

Vazamentos raramente vêm de ataques sofisticados; vêm de **canais esquecidos**: respostas com campos demais, erros com a string de conexão, logs com CPF, bucket público, `.env` acessível, backup esquecido, analytics gravando o que o usuário digita. Esta seção dá a visão de conjunto: mapear os caminhos de saída, fechá-los, reduzir o que pode vazar e detectar rápido. Pela LGPD, incidentes com risco ou dano relevante precisam ser comunicados à ANPD e aos titulares.

### Princípio 1: saber o que você tem

Faça um **inventário de dados** (o que, onde, quem acessa, por quanto tempo, com quem é compartilhado), base também do registro de operações da LGPD, e **classifique**:

| Classe | Exemplos |
| --- | --- |
| Público | Nome de produto, preço, artigo publicado |
| Interno | Métricas internas, documentação |
| Confidencial | Nome, e-mail, endereço, telefone, CPF, histórico de pedidos |
| Restrito | Credenciais, pagamento, senhas (mesmo em hash), dados sensíveis da LGPD, dados de crianças, documentos |

Cada classe tem regras de armazenamento, criptografia, logs, acesso e retenção.

### Princípio 2: o dado que não existe não vaza

Colete só o necessário, use **tokenização** do gateway em vez de guardar cartões, guarde versões reduzidas, pseudonimize para análises e defina **prazos de retenção** com exclusão automática:

```sql
delete from logs_acesso where criado_em < now() - interval '180 days';

update leads
set nome = null, email = null, telefone = null, anonimizado_em = now()
where criado_em < now() - interval '2 years' and convertido = false and anonimizado_em is null;
```

### Os canais de vazamento

**1. Respostas da API:** schemas de saída por visão (seção 17) e mascaramento.

```typescript
const UsuarioPublico = z.object({ id: z.string(), nome: z.string(), avatarUrl: z.string().nullable() });
const UsuarioProprio = UsuarioPublico.extend({ email: z.string(), telefone: z.string().nullable() });
res.json(ehOProprio ? UsuarioProprio.parse(u) : UsuarioPublico.parse(u));

const mascararCpf   = (cpf: string) => `***.${cpf.slice(3, 6)}.***-**`;
const mascararEmail = (e: string) => e.replace(/^(.{2}).*(@.*)$/, '$1***$2');
```

Em GraphQL, desative a introspecção em produção e limite profundidade e complexidade.

**2. Erros e modo de depuração:**

```javascript
app.use((err, req, res, next) => {
  const idErro = crypto.randomUUID();
  logger.error({ idErro, err, rota: req.path, userId: req.user?.id }, 'Erro não tratado');
  const status = err.statusPublico ?? 500;
  res.status(status).json({
    erro: status < 500 ? err.mensagemPublica : 'Erro interno. Tente novamente.',
    referencia: idErro,
  });
});
```

Debug desligado (`NODE_ENV=production`, `DEBUG=False`, `APP_DEBUG=false`) e endpoints de diagnóstico removidos ou protegidos (`phpinfo()`, `/actuator/env` e `/actuator/heapdump` do Spring).

**3. Logs e observabilidade:** redação automática no logger.

```javascript
import pino from 'pino';
const logger = pino({
  redact: {
    paths: [
      'req.headers.authorization', 'req.headers.cookie', 'res.headers["set-cookie"]',
      '*.senha', '*.password', '*.token', '*.accessToken', '*.refreshToken',
      '*.cpf', '*.cartao', '*.apiKey', '*.secret',
    ],
    censor: '[REMOVIDO]',
  },
});

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  sendDefaultPii: false,
  beforeSend(evento) {
    if (evento.request) {
      delete evento.request.cookies;
      delete evento.request.data;
      if (evento.request.headers) delete evento.request.headers.authorization;
    }
    return evento;
  },
});
```

Session replay com mascaramento de todos os campos e desligado em páginas sensíveis; acesso restrito e retenção curta dos logs.

**4. Código no navegador:** sem segredos em variáveis de build, source maps não publicados, atenção ao que é serializado para Client Components (use `server-only`), nada sensível em `localStorage`.

```javascript
// vite.config.js
export default { build: { sourcemap: 'hidden' } };
```

**5. Arquivos expostos no servidor web:** publique só a pasta de build e bloqueie o resto.

```nginx
location ~ /\.(?!well-known) { deny all; return 404; }
location ~* \.(bak|old|sql|log|sh|ini|yml|yaml|env|swp)$ { deny all; return 404; }
autoindex off;
server_tokens off;
```

Swagger e painéis com autenticação; como higiene (não como defesa), remova `X-Powered-By` e `Server`.

**6. Storage na nuvem:** buckets privados, bloqueio de acesso público na conta e URLs assinadas curtas após checar permissão.

```javascript
import { GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

app.get('/api/documentos/:id/download', requireAuth, async (req, res) => {
  const doc = await buscarDocumentoDoUsuario(req.params.id, req.user.id);
  if (!doc) return res.sendStatus(404);
  const url = await getSignedUrl(s3,
    new GetObjectCommand({ Bucket: 'docs-privados', Key: doc.chave,
                           ResponseContentDisposition: 'attachment' }),
    { expiresIn: 60 });
  res.json({ url });
});
```

**7. Cache:** respostas personalizadas com `Cache-Control: private, no-store`; CDN sem cachear APIs autenticadas; cuidado com web cache deception.

**8. URLs e Referer:** nada sensível em URLs; tokens de uso único curtos e trocados por sessão; `Referrer-Policy: strict-origin-when-cross-origin`.

**9. Terceiros e dependências:** menos scripts, SRI, CSP com `connect-src` e `form-action`, nada pessoal em pixels, fornecedores tratados como operadores pela LGPD, lockfiles e alertas de dependências (seção 20).

**10. IA:** verifique retenção e uso para treino nos contratos, envie só o necessário, nunca segredos no prompt, filtros de permissão e organização também no RAG e no banco vetorial, e restrição de domínios em links e imagens renderizados da resposta.

**11. E-mails, notificações e exportações:** nada sensível no corpo; exportações com permissão, registro, volume limitado e links temporários.

**12. Metadados:** remova EXIF e metadados de documentos.

**13. Ambientes de teste:** dados sintéticos ou anonimizados de forma irreversível (Faker, Neosync, Tonic, `postgresql_anonymizer`), sem acesso público e sem credenciais de produção.

**14. Backups:** cifrados, separados, com retenção e restauração testada.

### Credenciais: cuidados adicionais

Credenciais de curta duração (IAM roles, Workload Identity, OIDC, STS). Imagens Docker sem segredos nas camadas:

```dockerfile
# syntax=docker/dockerfile:1
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
USER node
CMD ["node", "dist/server.js"]
```

Kubernetes Secrets com criptografia em repouso e RBAC; logs de CI sem `env`, `printenv` ou `set -x`; variáveis de ambiente fora de crash dumps; contas administrativas com MFA forte e sem compartilhamento.

### Cabeçalhos relacionados

```http
Cache-Control: private, no-store
Referrer-Policy: strict-origin-when-cross-origin
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; connect-src 'self' https://api.seusite.com.br; form-action 'self'; frame-ancestors 'none'
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### Detectar vazamentos

Auditoria de acesso com alertas de volume anormal; **honeytokens** (Canarytokens); secret scanning e monitoramento de exposição; controle de saída de rede; DLP; varreduras de configuração (AWS Security Hub, Security Command Center, Prowler, ScoutSuite); pentests e `/.well-known/security.txt`.

### Monitoramento centralizado e SIEM

Cada controle deste guia gera sinais isolados: falhas de login, 429 do rate limit, desafios de bot, violações de CSP, campos extras rejeitados, 403 de autorização, reuso de refresh token, exportações grandes, logins em países novos. Sozinho, cada sinal parece ruído; **correlacionados**, revelam um ataque em andamento. Por exemplo: o mesmo IP gerando falhas de login em várias contas, depois um login bem-sucedido, uma troca de e-mail e uma exportação, tudo em 20 minutos.

Um **SIEM** (Security Information and Event Management) centraliza os eventos de segurança de todas as fontes (aplicação, banco, nuvem, CDN e WAF, provedor de identidade, GitHub, CI) e aplica regras de correlação que disparam alertas quando vários limites são violados juntos. Opções incluem **Wazuh** (código aberto), **Elastic Security**, **Datadog Cloud SIEM**, **Microsoft Sentinel**, **Google Security Operations** e **Splunk**.

Adote de forma proporcional ao tamanho do time:

1. **Primeiro passo, para qualquer sistema:** logs estruturados em JSON com campos padronizados (`evento`, `userId`, `orgId`, `ip`, `resultado`, `requestId`), enviados a um destino central (Datadog, Grafana Loki, Elastic, CloudWatch, Better Stack), com retenção definida e acesso restrito. Logs espalhados em cada servidor não servem para investigar nada.
2. **Eventos de segurança como categoria própria:** registre explicitamente login e falha, MFA, troca de senha e e-mail, mudança de papel, negação de acesso, reuso de token, bloqueio de rate limit e de bot, exportações e acesso administrativo, para que possam ser filtrados e correlacionados.
3. **Alertas correlacionados simples**, mesmo sem SIEM: "mais de N falhas de login seguidas de sucesso na mesma conta", "mudança de e-mail logo após login de dispositivo novo", "volume de leitura muito acima do normal para o usuário", "uso de credencial de nuvem fora do horário ou de IP desconhecido".
4. **SIEM completo** quando houver volume, exigência de conformidade (clientes corporativos, setor financeiro ou de saúde) ou uma pessoa ou equipe para tratar os alertas. Um SIEM sem ninguém olhando os alertas só gera custo.

Em qualquer etapa: mantenha os logs de segurança imutáveis para quem pode ser investigado, sincronize os relógios (os eventos precisam estar na mesma linha do tempo), use um `requestId` que atravesse todos os serviços, revise e ajuste as regras para reduzir falsos positivos, e lembre que esses logs também contêm dados pessoais e seguem as mesmas regras de redação e retenção desta seção.

### Quando o vazamento acontece

1. **Conter:** revogar credenciais, fechar o recurso exposto, encerrar sessões.
2. **Investigar:** o que vazou, de quem, desde quando e como, preservando evidências.
3. **Comunicar:** pelo regulamento da ANPD, incidentes com risco ou dano relevante são comunicados à ANPD e aos titulares em até 3 dias úteis do conhecimento; confira a regulamentação vigente e envolva DPO e jurídico.
4. **Corrigir e aprender:** causa raiz, problemas similares e registro do incidente (exigido mesmo quando não comunicado).

### Testar

Respostas sem chaves como `senha`, `hash`, `token`, `cpf`; erros sem stack trace; `/.git/config`, `/.env` e `/backup.sql` retornando 404; `Cache-Control` correto; source maps inacessíveis; logs sem os dados enviados nos testes. Use OWASP ZAP, Nuclei e gitleaks também sobre builds e imagens.

### Resumo

Inventário e classificação, minimização e retenção, respostas enxutas, erros genéricos, logs com redação, navegador sem segredos e source maps, servidor publicando só o necessário, buckets privados, cache correto, URLs limpas, terceiros e IA controlados, ambientes de teste sem dados reais, backups protegidos, credenciais curtas, cabeçalhos, detecção e plano de resposta com comunicação à ANPD.
