# 19. Forçar HTTPS

### O que é e por que importa

Forçar HTTPS é garantir que **toda** comunicação seja criptografada e autenticada, sem nenhum caminho por HTTP. O HTTPS garante confidencialidade, integridade e autenticidade. Um único acesso por HTTP já é perigoso: no *SSL stripping*, o atacante intercepta a primeira requisição e serve uma versão HTTP do site. Por isso as camadas: redirecionamento, HSTS e preload.

### Camada 1: redirecionar todo HTTP

Use **308** (preserva método e corpo) ou **301**, com o **domínio canônico fixo**, nunca o `Host` recebido.

```nginx
server {
  listen 80;
  listen [::]:80;
  server_name seusite.com.br www.seusite.com.br;
  location /.well-known/acme-challenge/ { root /var/www/certbot; }
  location / { return 308 https://seusite.com.br$request_uri; }
}

server {
  listen 80 default_server;
  listen [::]:80 default_server;
  return 444;   # recusa hosts desconhecidos
}
```

```javascript
// Express atrás de proxy
app.set('trust proxy', 1);
app.use((req, res, next) => {
  if (req.secure) return next();
  if (req.method === 'GET' || req.method === 'HEAD') {
    return res.redirect(308, `https://seusite.com.br${req.originalUrl}`);
  }
  return res.status(403).json({ erro: 'Use HTTPS' });
});
```

**Django:** `SECURE_SSL_REDIRECT = True` com `SECURE_PROXY_SSL_HEADER`. **Laravel:** middleware, `URL::forceScheme('https')` e `TrustProxies`. **Rails:** `config.force_ssl = true`. **ASP.NET Core:** `UseHttpsRedirection()` e `UseHsts()`. **Spring:** `requiresChannel().anyRequest().requiresSecure()`. Vercel, Netlify, Firebase Hosting e Render já forçam; Cloudflare tem *Always Use HTTPS* e *Automatic HTTPS Rewrites*; ALB, Cloud Load Balancing e Front Door têm redirecionamento no listener.

**APIs: recuse em vez de redirecionar.** O redirecionamento chega tarde: o token já trafegou em texto claro. Considere comprometida uma credencial recebida por HTTP.

### Camada 2: HSTS e preload

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

Requisitos do preload (hstspreload.org): certificado válido, redirecionamento no mesmo host, todos os subdomínios em HTTPS e cabeçalho com pelo menos um ano, `includeSubDomains` e `preload`. Implante gradualmente. O registro DNS do tipo **HTTPS (SVCB)** também informa aos navegadores que o site exige HTTPS.

### Camada 3: eliminar conteúdo misto

Corrija URLs `http://` no código, templates, CSS, banco e configurações; use URLs relativas ou `https://`; gere URLs absolutas a partir de configuração fixa (`APP_URL`), não de `req.protocol`; adicione `upgrade-insecure-requests` na CSP; use os relatórios da CSP para achar o restante.

```sql
update artigos
set conteudo = replace(conteudo, 'http://seusite.com.br/', 'https://seusite.com.br/')
where conteudo like '%http://seusite.com.br/%';
```

### Camada 4: configuração de TLS forte

Apenas **TLS 1.2 e 1.3**; no 1.2, só ECDHE com AES-GCM ou ChaCha20-Poly1305; ECDSA P-256 ou RSA 2048+; HTTP/2 (e HTTP/3); evite 0-RTT em requisições que alteram dados. Gere a configuração no **ssl-config.mozilla.org** (perfil *Intermediate* para a maioria):

```nginx
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  http2 on;
  server_name seusite.com.br;

  ssl_certificate     /etc/letsencrypt/live/seusite.com.br/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/seusite.com.br/privkey.pem;

  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
  ssl_prefer_server_ciphers off;
  ssl_session_timeout 1d;
  ssl_session_cache shared:TLS:10m;
  ssl_session_tickets off;

  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}
```

O **Caddy** já vem com TLS moderno e certificados automáticos.

### Camada 5: certificados bem gerenciados

Emissão e renovação automáticas via ACME (Let's Encrypt, ZeroSSL, Google Trust Services; Certbot, Caddy, cert-manager) ou certificados gerenciados da nuvem e da CDN. A validade dos certificados está sendo reduzida gradualmente pelo setor, o que torna a automação indispensável.

```bash
sudo certbot certonly --webroot -w /var/www/certbot -d seusite.com.br -d www.seusite.com.br
sudo systemctl list-timers | grep certbot
sudo certbot renew --dry-run
```

Alertas de expiração com semanas de antecedência; registro **CAA** no DNS:

```text
seusite.com.br.  CAA 0 issue "letsencrypt.org"
seusite.com.br.  CAA 0 issue "amazon.com"
seusite.com.br.  CAA 0 iodef "mailto:seguranca@seusite.com.br"
```

Monitoramento de **Certificate Transparency** (crt.sh, Cert Spotter, Cloudflare) e chave privada tratada como credencial.

### Camada 6: proxies, CDNs e balanceadores

Na Cloudflare, use **Full (strict)**, nunca *Flexible* (que deixa o trecho até a origem em HTTP e causa loops de redirecionamento); use *Origin Certificates*. Confie no `X-Forwarded-Proto` só vindo dos seus proxies. **Bloqueie o acesso direto à origem**: firewall só para IPs da CDN, túneis (Cloudflare Tunnel), *Authenticated Origin Pulls* e sub-redes privadas.

### Camada 7: tráfego interno criptografado

Banco com TLS verificado (`sslmode=verify-full`, `rejectUnauthorized: true`) e recusa de conexões sem TLS (`hostssl` no `pg_hba.conf`, `rds.force_ssl`); Redis com `rediss://`, RabbitMQ com AMQPS, Kafka com TLS; HTTPS entre serviços e **mTLS** via service mesh (Istio, Linkerd).

**Nunca desative a verificação de certificados.** Procure e bloqueie no CI:

```bash
grep -rnE "rejectUnauthorized:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|verify\s*=\s*False|InsecureSkipVerify:\s*true" src/
```

### Camada 8: conexões que o sistema faz

Webhooks e integrações só com `https://`, certificados validados, sem redirecionamentos de HTTPS para HTTP; links de e-mail e de rastreamento em HTTPS.

### Camada 9: aplicativos móveis

**iOS:** App Transport Security, sem `NSAllowsArbitraryLoads`. **Android:**

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
</network-security-config>

<!-- AndroidManifest.xml -->
<application android:networkSecurityConfig="@xml/network_security_config"
             android:usesCleartextTraffic="false" ... >
```

**Certificate pinning** para apps de alto risco, fixando a chave pública, com chaves de reserva e plano de rotação.

### Camada 10: desenvolvimento

HTTPS local com **mkcert** ou recursos dos frameworks (`next dev --experimental-https`, plugins do Vite) e homologação idêntica à produção.

### Testar e monitorar

**SSL Labs** (meta A ou A+), **testssl.sh** e Mozilla Observatory, mais verificações automáticas:

```bash
curl -sI http://seusite.com.br/conta | grep -Ei "^(HTTP|location)"
curl -sI -H "Host: atacante.com" http://seusite.com.br/ | grep -i location
openssl s_client -connect seusite.com.br:443 -tls1_1 </dev/null 2>&1 | grep -i "alert\|error"
curl -sI https://seusite.com.br/ | grep -i strict-transport-security
curl -sk --max-time 5 https://IP_DA_ORIGEM/ -H "Host: seusite.com.br" && echo "ORIGEM EXPOSTA"
```

Verifique também API recusando HTTP, subdomínios em HTTPS e ausência de conteúdo misto; monitore expiração, Certificate Transparency, violações de CSP e configuração da nuvem.

### Resumo

Redirecionamento 308/301 para o domínio fixo e recusa de HTTP nas APIs; HSTS até o preload; sem conteúdo misto; TLS 1.2/1.3 com cifras modernas; certificados automáticos com alertas, CAA e CT; Cloudflare em Full (strict) e origem protegida; tráfego interno com TLS verificado e mTLS; HTTPS nas conexões de saída; ATS e bloqueio de texto claro nos apps; HTTPS no desenvolvimento; e testes contínuos.
