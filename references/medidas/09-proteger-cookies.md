# 9. Proteger cookies

### O que é e por que importa

Cookies são enviados **automaticamente** pelo navegador em cada requisição ao site, e o cookie de sessão funciona como crachá: quem o rouba vira o usuário, sem senha nem MFA. Protegê-los é controlar quem os lê, por onde trafegam, para onde são enviados, quanto duram e o que guardam.

Ataques evitados: roubo por XSS (`document.cookie`), interceptação na rede, CSRF, fixação de sessão e ataques por subdomínio comprometido.

### Os atributos

**HttpOnly:** impede o acesso por JavaScript. Protege contra roubo por XSS, mas não contra requisições feitas pelo script na página; não substitui a prevenção de XSS e a CSP.

**Secure:** só trafega por HTTPS. Combine com HSTS. Atrás de proxy que termina o TLS, configure o framework para confiar nele (`app.set('trust proxy', 1)` no Express, `SECURE_PROXY_SSL_HEADER` no Django).

**SameSite:**

| Valor | Comportamento |
| --- | --- |
| Strict | Enviado só quando a navegação começa no próprio site; links vindos de fora chegam "deslogados" |
| Lax | Padrão moderno; enviado em navegações de nível superior com GET, não em POST, fetch, imagens e iframes de outros sites |
| None | Enviado em qualquer contexto; só quando necessário e sempre com Secure |

Para o SameSite, `app.seusite.com` e `blog.seusite.com` são o mesmo site, então ele não protege contra subdomínio comprometido. Uma estratégia útil: um cookie `Lax` para navegação e outro `Strict` exigido em ações sensíveis.

**Domain:** omitido, o cookie fica restrito ao host exato. Definido (`Domain=seusite.com`), vai para todos os subdomínios. Omita sempre que possível.

**Path:** organização, não barreira de segurança.

**Expires / Max-Age:** sessões curtas para sistemas sensíveis; "lembrar de mim" como escolha explícita. O servidor também expira a sessão.

**Prefixos:** `__Secure-` exige Secure e HTTPS; `__Host-` exige Secure, HTTPS, `Path=/` e nenhum `Domain`, impedindo que subdomínios plantem ou sobrescrevam o cookie (cookie tossing).

```text
Set-Cookie: __Host-sessao=abc123; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=86400
```

**Partitioned (CHIPS):** para cookies em widgets incorporados em outros sites, guardados separadamente por site.

### O que guardar no cookie

Prefira um **identificador aleatório** (128+ bits, gerador criptográfico), com os dados no servidor:

```javascript
import crypto from 'node:crypto';
const sessionId = crypto.randomBytes(32).toString('base64url');
```

Se precisar guardar dados, **assine e cifre**, porque o usuário pode editar o cookie (`papel=usuario` vira `papel=admin`):

```typescript
import { getIronSession } from 'iron-session';

const session = await getIronSession(cookies(), {
  password: process.env.SESSION_SECRET!,
  cookieName: '__Host-sessao',
  cookieOptions: { secure: true, httpOnly: true, sameSite: 'lax', path: '/' },
});
```

Cookies stateless não são revogáveis antes de expirar; o limite é de cerca de 4 KB.

### Ciclo de vida da sessão

Regenere o id após login e elevação de privilégio:

```javascript
req.session.regenerate((err) => {
  if (err) return next(err);
  req.session.userId = usuario.id;
  res.redirect('/painel');
});
```

Defina tempo limite por inatividade e absoluto; no logout, destrua a sessão no servidor e apague o cookie (mesmo nome, Path e Domain, expiração no passado); revogue todas as sessões ao trocar senha, desativar a conta ou suspeitar de comprometimento.

### Configuração nos frameworks

**Express:**

```javascript
app.set('trust proxy', 1);
app.use(session({
  name: '__Host-sessao',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: new RedisStore({ client: redis }),   // não use MemoryStore em produção
  cookie: { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 8 * 3600 * 1000 },
}));
```

**Next.js:**

```typescript
import { cookies } from 'next/headers';
(await cookies()).set('__Host-sessao', sessionId, {
  httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 60 * 60 * 8,
});
```

**Django:**

```python
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_NAME = "__Host-sessionid"
SESSION_COOKIE_AGE = 60 * 60 * 8
CSRF_COOKIE_SECURE = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
```

**Laravel:** `'secure' => true`, `'http_only' => true`, `'same_site' => 'lax'`, `'encrypt' => true` em `config/session.php`.

**Supabase com `@supabase/ssr`:** por padrão os cookies de sessão não são HttpOnly, porque o cliente do navegador precisa lê-los. Isso torna XSS e CSP ainda mais importantes; a alternativa é concentrar a autenticação no servidor. Confira a documentação da versão atual.

### CSRF, complementando o SameSite

Nunca altere dados via GET, valide `Origin` em requisições que mudam estado e use tokens CSRF em formulários.

### Cookies de terceiros e consentimento

Pela LGPD, cookies não essenciais (analytics, marketing) exigem base legal, normalmente consentimento; a ANPD publicou um guia sobre cookies. Banner por categoria sem caixas pré-marcadas, scripts carregados só após o consentimento, política de cookies e possibilidade de mudar de ideia. Reduza scripts de terceiros e use SRI e CSP.

### Outros cuidados

Não registre `Cookie` e `Set-Cookie` em logs ou no Sentry; nada de ids de sessão em URLs; nomes genéricos (evite `PHPSESSID`, `connect.sid`); `localhost` é contexto seguro para testar `Secure`.

### Como verificar

No DevTools (Application/Storage), confira os atributos; `document.cookie` não deve mostrar o cookie de sessão. Automatize:

```javascript
const res = await request(app).post('/auth/login').send(credenciais);
const cookie = res.headers['set-cookie'].find(c => c.startsWith('__Host-sessao='));
expect(cookie).toMatch(/HttpOnly/i);
expect(cookie).toMatch(/Secure/i);
expect(cookie).toMatch(/SameSite=Lax/i);
expect(cookie).not.toMatch(/Domain=/i);
```

### Resumo

Cookie de sessão com `HttpOnly`, `Secure`, `SameSite=Lax` (ou `Strict` em ações críticas), sem `Domain` e com `__Host-`; conteúdo opaco ou assinado e cifrado; regeneração no login, tempos limite e destruição real no logout; proxy configurado; CSRF e XSS cobertos; consentimento LGPD; nada em logs ou URLs; testes automatizados.
