# 18. Adicionar cabeçalhos de segurança

### O que é e por que importa

Cabeçalhos de segurança instruem o **navegador** a reforçar as defesas: só HTTPS, scripts apenas de origens autorizadas, nada de iframes de outros sites, sem adivinhar tipos de arquivo, URLs completas não enviadas a terceiros, câmera e microfone bloqueados. São baratos, configurados uma vez, e limitam o estrago quando algo escapa das outras camadas.

### Os cabeçalhos

| Cabeçalho | Valor recomendado | Protege contra |
| --- | --- | --- |
| Strict-Transport-Security | max-age=63072000; includeSubDomains; preload | Rebaixamento para HTTP |
| Content-Security-Policy | CSP estrita com nonce (abaixo) | XSS e exfiltração |
| X-Frame-Options | DENY (com frame-ancestors 'none') | Clickjacking |
| X-Content-Type-Options | nosniff | Arquivos interpretados como HTML/JS |
| Referrer-Policy | strict-origin-when-cross-origin | Vazamento de URLs |
| Permissions-Policy | camera=(), microphone=(), geolocation=(), payment=(), usb=() | Uso indevido de recursos do navegador |
| Cross-Origin-Opener-Policy | same-origin | Manipulação entre janelas |
| Cross-Origin-Resource-Policy | same-origin (ou cross-origin para arquivos públicos) | Incorporação indevida de recursos |
| Cache-Control | private, no-store (respostas autenticadas) | Cache compartilhado de dados |
| Clear-Site-Data | "cache", "cookies", "storage" (no logout) | Dados residuais no navegador |

**HSTS:** implante gradualmente (comece com `max-age=300`), confirme que todos os subdomínios funcionam em HTTPS antes de `includeSubDomains` e `preload` (hstspreload.org), e lembre que sair da lista leva meses.

**COEP** (`require-corp` ou `credentialless`) ativa o isolamento entre origens junto com COOP; só quando necessário, pois pode quebrar recursos de terceiros.

### Content Security Policy em detalhe

Diretivas principais: `default-src`, `script-src`, `style-src`, `img-src`, `font-src`, `media-src`, `connect-src` (para onde a página envia dados), `frame-src`, `frame-ancestors` (quem pode te incorporar), `form-action`, `base-uri`, `object-src` (sempre `'none'`) e `upgrade-insecure-requests`.

**Comece sempre pelo modo report-only.** Uma CSP restritiva aplicada direto em produção costuma bloquear scripts de analytics, chat, pagamentos, fontes e mapas, e quebrar funcionalidades, sobretudo em aplicações antigas. O cabeçalho `Content-Security-Policy-Report-Only` usa exatamente a mesma sintaxe, mas não bloqueia nada: o navegador apenas relata o que teria bloqueado. O fluxo seguro é: (1) publicar a política em report-only; (2) coletar os relatórios por alguns dias ou semanas, descartando o ruído de extensões de navegador; (3) ajustar a política até sobrarem só violações realmente indevidas; (4) só então trocar para `Content-Security-Policy`. Dá para manter as duas ao mesmo tempo: a política atual aplicada e uma versão mais estrita em teste. A sintaxe que você vai testar e depois aplicar é a da CSP estrita, descrita logo abaixo.

```http
Content-Security-Policy-Report-Only: script-src 'nonce-...' 'strict-dynamic'; object-src 'none'; base-uri 'none'; report-to csp
Reporting-Endpoints: csp="https://seusite.com.br/api/csp-relatorios"
```

Allowlists de domínios costumam ser contornáveis (CDNs públicas, endpoints JSONP), e `'unsafe-inline'` em `script-src` anula a proteção. A abordagem recomendada é a **CSP estrita com nonce**:

```http
Content-Security-Policy:
  script-src 'nonce-R4nd0mBase64==' 'strict-dynamic' https: 'unsafe-inline';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'none';
  form-action 'self'
```

```html
<script nonce="R4nd0mBase64==" src="/app.js"></script>
```

`'strict-dynamic'` deixa scripts autorizados carregarem outros; `https:` e `'unsafe-inline'` são ignorados por navegadores modernos e só servem de compatibilidade. O nonce é único por resposta; páginas estáticas usam hashes. `style-src` pode ser mais tolerante. `require-trusted-types-for 'script'` ativa Trusted Types contra XSS de DOM.

O endpoint de relatórios precisa de rate limit, limite de tamanho e validação. `frame-ancestors` não funciona em CSP por tag `<meta>`.

### CORS

CORS **libera** exceções; configurado errado, enfraquece a segurança. Use allowlist exata, nunca reflita o `Origin`, nunca combine credenciais com origens amplas, recuse `null` e compare origens exatamente.

```javascript
import cors from 'cors';
const ORIGENS = new Set(['https://app.seusite.com.br', 'https://admin.seusite.com.br']);

app.use('/api', cors({
  origin: (origem, cb) => cb(null, !origem || ORIGENS.has(origem)),
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600,
}));
```

APIs públicas sem cookies podem usar `*` sem `credentials`. CORS não impede chamadas de servidores ou `curl`.

### Remover e evitar

Remova `X-Powered-By`, `Server` com versão, `X-AspNet-Version`, cabeçalhos de debug e `Server-Timing` interno. Obsoletos: `X-XSS-Protection` (omitir ou `0`), `Public-Key-Pins`, `Expect-CT`, `Feature-Policy`.

Remover esses cabeçalhos é **higiene, não defesa**. Esconder a versão reduz o ruído de scanners automatizados que procuram versões específicas, mas ferramentas modernas identificam a tecnologia por outros sinais (comportamento, ordem de cabeçalhos, arquivos estáticos, mensagens de erro). Leva um minuto e vale fazer, mas a proteção real vem de manter o software atualizado e das defesas ativas descritas neste guia: CSP, validação, autenticação, rate limit e WAF.

### Páginas versus APIs

Respostas JSON precisam de uma política mínima:

```http
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Cache-Control: private, no-store
Cross-Origin-Resource-Policy: same-origin
```

### Como implementar

Defina tudo num único lugar para evitar duplicações e conflitos.

**Express com Helmet:**

```javascript
import helmet from 'helmet';
import crypto from 'node:crypto';

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      scriptSrc: [(req, res) => `'nonce-${res.locals.nonce}'`, "'strict-dynamic'", 'https:', "'unsafe-inline'"],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: [],
    },
    reportOnly: process.env.CSP_REPORT_ONLY === 'true',
  },
  strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  crossOriginEmbedderPolicy: false,
  xFrameOptions: { action: 'deny' },
}));
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  next();
});
```

**Next.js:** cabeçalhos fixos no `next.config.js` e CSP com nonce no middleware.

```javascript
const cabecalhos = [
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
];
module.exports = {
  poweredByHeader: false,
  async headers() { return [{ source: '/:path*', headers: cabecalhos }]; },
};
```

```typescript
// middleware.ts
import { NextResponse, type NextRequest } from 'next/server';

export function middleware(req: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  const csp = [
    `script-src 'nonce-${nonce}' 'strict-dynamic' https: 'unsafe-inline'`,
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' blob: data: https://arquivos.seusiteusercontent.com.br`,
    `connect-src 'self' https://api.seusite.com.br`,
    `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`, `form-action 'self'`,
    `upgrade-insecure-requests`,
  ].join('; ');
  const headers = new Headers(req.headers);
  headers.set('x-nonce', nonce);
  headers.set('Content-Security-Policy', csp);
  const res = NextResponse.next({ request: { headers } });
  res.headers.set('Content-Security-Policy', csp);
  return res;
}

export const config = {
  matcher: [{ source: '/((?!api|_next/static|_next/image|favicon.ico).*)',
              missing: [{ type: 'header', key: 'next-router-prefetch' }] }],
};
```

Com nonce, as páginas passam a ser dinâmicas; confira a documentação da sua versão.

**Nginx:**

```nginx
server_tokens off;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
```

Um `add_header` dentro de `location` cancela a herança dos do `server`; agrupe num arquivo incluído. CSP com nonce fica na aplicação.

**Plataformas:** Vercel (`vercel.json`), Netlify (`_headers`), Cloudflare (regras ou Workers), CloudFront (response headers policies), Firebase Hosting (`firebase.json`). **Outros:** Django (`SecurityMiddleware`, `django-csp`, `manage.py check --deploy`), Laravel (`spatie/laravel-csp`), FastAPI (middleware ou `secure`), ASP.NET Core (`NetEscapades.AspNetCore.SecurityHeaders`, `UseHsts`), Spring Security.

### Scripts de terceiros

Com `'strict-dynamic'`, basta o nonce no script de carregamento; consulte cada fornecedor para `connect-src`, `img-src` e `frame-src`; restrinja quem publica no Google Tag Manager; e use o report-only para descobrir o que cada ferramenta carrega.

### Testar e monitorar

Mozilla HTTP Observatory, securityheaders.com e CSP Evaluator, mais testes no CI:

```typescript
describe('cabeçalhos de segurança', () => {
  it('página HTML tem os cabeçalhos essenciais', async () => {
    const res = await request(app).get('/');
    expect(res.headers['strict-transport-security']).toMatch(/max-age=\d{7,}/);
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
    expect(res.headers['x-powered-by']).toBeUndefined();
    const csp = res.headers['content-security-policy'];
    expect(csp).toMatch(/script-src 'nonce-[A-Za-z0-9+/=]+'/);
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
  });
  it('o nonce muda a cada requisição', async () => {
    const [a, b] = await Promise.all([request(app).get('/'), request(app).get('/')]);
    const nonce = (r) => r.headers['content-security-policy'].match(/'nonce-([^']+)'/)[1];
    expect(nonce(a)).not.toBe(nonce(b));
  });
  it('CORS não aceita origens desconhecidas', async () => {
    const res = await request(app).get('/api/perfil').set('Origin', 'https://atacante.com');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});
```

Teste origens parecidas e `null`, confirme os cabeçalhos em respostas de erro e monitore violações de CSP.

### Resumo

HSTS gradual até o preload; CSP estrita com nonce, `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'` e `form-action`, via report-only; proteção contra clickjacking; `nosniff`; `Referrer-Policy`; `Permissions-Policy`; COOP e CORP; `Cache-Control` e `Clear-Site-Data`; CORS com allowlist; remoção de cabeçalhos reveladores e obsoletos; configuração num só lugar, por tipo de resposta, com testes e monitoramento.
