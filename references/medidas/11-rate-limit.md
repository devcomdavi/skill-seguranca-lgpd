# 11. Rate limit

### O que é e por que importa

Rate limit controla **quantas requisições** (ou quanto custo) um cliente pode consumir num intervalo; acima do limite, o sistema recusa ou atrasa. Sem ele, o sistema fica exposto a força bruta e credential stuffing, enumeração (inclusive de códigos de 6 dígitos), scraping, negação de serviço, abuso de custo (IA, SMS, e-mail, funções serverless) e spam. Também garante justiça entre usuários.

### Algoritmos

| Algoritmo | Como funciona | Observação |
| --- | --- | --- |
| Janela fixa | Conta por blocos fixos de tempo | Simples; permite rajada dupla na borda |
| Janela deslizante (log) | Guarda o horário de cada requisição | Preciso, mais memória |
| Janela deslizante (contador) | Janela atual + fração da anterior | Boa escolha padrão |
| Token bucket | Balde reabastecido a taxa constante | Permite rajadas controladas |
| Leaky bucket | Fila processada a taxa constante | Suaviza picos |
| Concorrência | Limita requisições simultâneas | Ideal para operações longas e IA |

### Por qual chave limitar

**IP:** para usuários não autenticados; limites generosos (CGNAT é comum no Brasil) e agrupamento por `/64` em IPv6. **Usuário:** a mais justa nas rotas logadas. **Conta-alvo:** no login e na recuperação de senha, pelo e-mail tentado. **API key ou organização:** ligado ao plano. **Rota:** limites próprios por tipo. **Global:** teto para proteger serviços caros.

Atrás de proxy, o IP real vem de `X-Forwarded-For` ou `CF-Connecting-IP`, que o cliente também pode forjar. Confie só nos seus proxies (`app.set('trust proxy', 1)`) ou no cabeçalho do provedor.

### Camada 1: borda

Cloudflare, AWS WAF, Cloud Armor, Vercel Firewall e gateways de API barram volume bruto antes da aplicação, mas não conhecem o contexto de negócio.

### Camada 2: Nginx

```nginx
limit_req_zone $binary_remote_addr zone=geral:10m rate=20r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

server {
  location /api/ {
    limit_req zone=geral burst=40 nodelay;
    limit_req_status 429;
    proxy_pass http://app;
  }
  location /api/auth/login {
    limit_req zone=login burst=3 nodelay;
    limit_req_status 429;
    proxy_pass http://app;
  }
}
```

### Camada 3: aplicação

Com várias instâncias ou serverless, os contadores precisam de armazenamento **compartilhado** (Redis); contadores em memória multiplicam o limite real.

```javascript
import rateLimit from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
import { createClient } from 'redis';

const redis = createClient({ url: process.env.REDIS_URL });
await redis.connect();

const store = (prefixo) => new RedisStore({
  prefix: prefixo,
  sendCommand: (...args) => redis.sendCommand(args),
});

export const limiteApi = rateLimit({
  windowMs: 60_000,
  limit: 100,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) => req.user?.id ?? req.ip,
  store: store('rl:api:'),
});

export const limiteRecuperacao = rateLimit({
  windowMs: 60 * 60_000,
  limit: 3,
  keyGenerator: (req) => `email:${String(req.body.email).toLowerCase()}`,
  store: store('rl:recuperacao:'),
  handler: (req, res) => res.status(200).json({
    mensagem: 'Se o e-mail estiver cadastrado, você receberá um link.',
  }),
});

app.use('/api/', limiteApi);
app.post('/api/auth/recuperar-senha', limiteRecuperacao, recuperarSenha);
```

Next.js e serverless com **Upstash Ratelimit**:

```typescript
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';
import { NextResponse, type NextRequest } from 'next/server';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(60, '1 m'),
  prefix: 'rl:api',
});

export async function middleware(req: NextRequest) {
  const ip = req.headers.get('x-real-ip') ?? 'desconhecido';
  const { success, limit, remaining, reset } = await ratelimit.limit(ip);
  if (!success) {
    return NextResponse.json({ erro: 'Muitas requisições' }, {
      status: 429,
      headers: {
        'Retry-After': String(Math.ceil((reset - Date.now()) / 1000)),
        'RateLimit-Limit': String(limit),
        'RateLimit-Remaining': String(remaining),
      },
    });
  }
  return NextResponse.next();
}
export const config = { matcher: '/api/:path*' };
```

Outros: `slowapi` e `fastapi-limiter` (FastAPI), `django-ratelimit`, `RateLimiter` do Laravel, `Rack::Attack` e `rate_limit` no Rails.

Implementação própria com Redis, atômica:

```javascript
async function permitir(chave, limite, janelaSeg) {
  const k = `rl:${chave}:${Math.floor(Date.now() / 1000 / janelaSeg)}`;
  const [[, contagem]] = await redis.multi().incr(k).expire(k, janelaSeg).exec();
  return contagem <= limite;
}
```

### Limites por tipo de rota

Login: 5 a 10 tentativas por conta a cada 15 minutos e algumas dezenas por IP. Cadastro: poucos por IP por hora, com CAPTCHA. Recuperação de senha e envio de códigos: 3 a 5 por hora por destinatário. Verificação de códigos: poucas tentativas por código, depois invalidar. Leitura: generoso por usuário. Escrita, buscas e relatórios: restrito e com limite de concorrência. Webhooks e formulários públicos: por origem ou IP. Ajuste ao tráfego real.

### Login: atrasos progressivos sem trancar a vítima

Bloqueio permanente permite que alguém tranque a vítima. Prefira atrasos progressivos, CAPTCHA após algumas falhas, bloqueio curto com aviso por e-mail e tolerância maior para dispositivos conhecidos.

```javascript
async function verificarTentativasLogin(email, ip) {
  const falhas = Number(await redis.get(`login:falhas:${email}`) ?? 0);
  if (falhas >= 10) return { bloqueado: true };
  if (falhas >= 5)  return { exigirCaptcha: true };
  if (falhas >= 3)  await esperar(2 ** (falhas - 3) * 1000);
  return { ok: true };
}
async function registrarFalha(email) {
  const k = `login:falhas:${email}`;
  await redis.multi().incr(k).expire(k, 15 * 60).exec();
}
async function registrarSucesso(email) {
  await redis.del(`login:falhas:${email}`);
}
```

Em produção, prefira responder 429 com `Retry-After` a esperar dentro da requisição.

### Limite por custo (essencial para IA)

```javascript
async function consumirCota(userId, custoEstimado) {
  const chave = `cota:ia:${userId}:${new Date().toISOString().slice(0, 10)}`;
  const limiteDiario = await limiteDoPlano(userId);
  const usado = await redis.incrby(chave, custoEstimado);
  await redis.expire(chave, 86_400);
  if (usado > limiteDiario) {
    await redis.decrby(chave, custoEstimado);
    return false;
  }
  return true;
}
```

Limite entrada e `max_tokens` no servidor, registre o consumo real, use limite de concorrência, teto global diário e limites de gasto no painel do provedor.

### Quotas por plano

Rate limit protege o sistema no curto prazo; a quota (diária ou mensal) faz parte do produto. Mostre o consumo, avise antes do limite e explique o que acontece ao atingi-lo.

### Resposta ao atingir o limite

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 30
RateLimit-Limit: 100
RateLimit-Remaining: 0
RateLimit-Reset: 30
Content-Type: application/json

{ "erro": "Limite de requisições atingido. Tente novamente em 30 segundos." }
```

Nos clientes, respeite `Retry-After` e use backoff exponencial com jitter; muitos "ataques" são bugs do frontend, como um `useEffect` em loop.

### Fail open ou fail closed

Se o Redis cair: na API geral, deixar passar costuma ser melhor; em login, SMS e IA, considere bloquear ou usar limite local. Gere alerta em ambos os casos.

### Supabase e Firebase

Eles limitam e-mails, OTPs e autenticação, mas não o uso das suas tabelas, funções e serviços pagos. Aplique limite dentro das funções, proteja a borda e use App Check no Firebase.

### Monitoramento e testes

Registre bloqueios em dashboards, crie alertas para falhas de login, 429 e consumo de custo, e comece limites novos em modo de observação. Teste 429 e `Retry-After`, isolamento por chave, funcionamento entre instâncias, falsificação de `X-Forwarded-For` e o login sem trancar o usuário legítimo; use k6, Artillery ou autocannon.

### Resumo

Borda contra volume bruto e aplicação com contexto; sliding window ou token bucket; chaves combinadas e IP real obtido com segurança; Redis compartilhado; limites por rota, atrasos e CAPTCHA no login; custo e concorrência para IA; quotas por plano; 429 com `Retry-After` e backoff nos clientes; decisão sobre fail open; monitoramento e testes.
