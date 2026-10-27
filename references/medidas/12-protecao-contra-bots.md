# 12. Proteção contra bots

### O que é e por que importa

Proteção contra bots distingue **humanos e bots legítimos** (buscadores, monitores) de automações abusivas. O rate limit pergunta "quanto?"; a proteção contra bots pergunta "**quem**?". Bots sofisticados ficam abaixo dos limites, espalhando o ataque por milhares de IPs residenciais.

Principais abusos: credential stuffing; contas falsas (créditos grátis, cupons, cotas de IA); scraping, inclusive para treino de IA; carding; scalping; **SMS pumping** (envios para números premium do atacante); spam; abuso de promoções; fraude de cliques.

### Sinais de detecção

Nenhum sinal é conclusivo sozinho; combine-os numa pontuação de risco.

**Rede:** reputação do IP, tráfego de datacenter (ASN), proxies, VPN, Tor, proxies residenciais, geografia incoerente.

**Cliente:** user agent e cabeçalhos inconsistentes, impressão digital de TLS e HTTP/2 (JA3/JA4, difícil de falsificar), detecção de automação (Puppeteer, Playwright, Selenium).

**Comportamento:** interação (mouse, digitação), tempo de preenchimento, navegação direta a endpoints.

**Conta e negócio:** velocidade de cadastros, e-mails descartáveis, padrões repetidos, contas que usam o bônus e somem.

### Camada 1: gerenciamento de bots na borda

A borda vê milhões de sites e tem sinais que você não tem. Cloudflare (Bot Fight Mode, Super Bot Fight Mode, Bot Management com pontuação 1 a 99, controles para crawlers de IA), AWS WAF Bot Control, Cloud Armor com reCAPTCHA Enterprise, Akamai, DataDome, HUMAN, e opções para desenvolvedores como **Vercel BotID** e **Arcjet**. Com a pontuação, crie regras como "bloquear pontuações baixas em `/api/auth/*`".

### Camada 2: desafios (CAPTCHA e alternativas)

**Cloudflare Turnstile** (gratuito, invisível ou um clique), **hCaptcha**, **reCAPTCHA v3/Enterprise** (pontuação 0 a 1) e prova de trabalho (**ALTCHA**, **Friendly Captcha**). O erro mais comum: **o token precisa ser verificado no servidor**, senão o bot chama a API direto.

```html
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<form action="/api/cadastro" method="POST">
  <input name="email" type="email" required />
  <input name="senha" type="password" required />
  <div class="cf-turnstile" data-sitekey="SUA_SITE_KEY" data-action="cadastro"></div>
  <button type="submit">Criar conta</button>
</form>
```

```javascript
async function verificarTurnstile(token, ip, acaoEsperada) {
  const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ secret: process.env.TURNSTILE_SECRET, response: token, remoteip: ip }),
  });
  const dados = await resp.json();
  return dados.success === true
    && dados.action === acaoEsperada
    && dados.hostname === 'seusite.com.br';
}

app.post('/api/cadastro', async (req, res) => {
  const token = req.body['cf-turnstile-response'];
  if (!token || !(await verificarTurnstile(token, req.ip, 'cadastro'))) {
    return res.status(400).json({ erro: 'Verificação falhou. Tente novamente.' });
  }
  // ... segue com o cadastro
});
```

Verifique `action` e `hostname`; tokens são de uso único e expiram. Com reCAPTCHA v3, defina limiares por rota (aceitar acima de 0,7, verificar entre 0,3 e 0,7, recusar abaixo).

### Camada 3: armadilhas no formulário

**Honeypot** (campo escondido que bots preenchem) e **tempo mínimo** com horário assinado:

```html
<div style="position:absolute; left:-9999px" aria-hidden="true">
  <label for="site">Não preencha este campo</label>
  <input id="site" name="site" type="text" tabindex="-1" autocomplete="off" />
</div>
<input type="hidden" name="t" value="{{ timestampAssinado }}" />
```

```javascript
function pareceBot(body) {
  if (body.site) return true;
  const exibidoEm = verificarAssinatura(body.t);   // HMAC
  if (!exibidoEm) return true;
  return Date.now() - exibidoEm < 3000;
}
```

Responder com sucesso falso atrasa a adaptação do atacante. Cuide da acessibilidade com `aria-hidden` e `tabindex="-1"`.

### Camada 4: atestação de dispositivo

**Play Integrity** (Android), **App Attest/DeviceCheck** (iOS) e **Firebase App Check** provam que a requisição vem do app original num dispositivo real; muito úteis com Firebase ou Supabase acessados direto do cliente.

### Camada 5: proteger a API, não só a página

Toda verificação é checada no endpoint; tokens de desafio vinculados à sessão e à ação; fluxos em etapas exigidos em ordem; nada de endpoints de depuração que pulem as checagens.

### Camada 6: fricção progressiva baseada em risco

```javascript
function pontuarRisco({ ip, emailDominio, tempoPreenchimento, botScore, dispositivoConhecido }) {
  let risco = 0;
  if (ip.datacenter)                  risco += 30;
  if (ip.proxyOuTor)                  risco += 20;
  if (ip.reputacaoRuim)               risco += 30;
  if (emailDescartavel(emailDominio)) risco += 40;
  if (tempoPreenchimento < 3000)      risco += 30;
  if (botScore !== undefined && botScore < 30) risco += 40;
  if (dispositivoConhecido)           risco -= 30;
  return risco;
}

const risco = pontuarRisco(sinais);
if (risco >= 80)      return recusarSilenciosamente();
else if (risco >= 40) return exigirDesafio();
else                  return prosseguir();
```

Pesos ilustrativos: calibre em modo de observação. Escale em degraus (desafio invisível, clique, verificação de e-mail ou telefone, revisão manual).

### Proteções por tipo de abuso

**Credential stuffing:** rate limit por conta e IP, bloqueio de senhas vazadas, MFA, erros genéricos, aviso de novo dispositivo e monitoramento da taxa global de falhas.

**Contas falsas:** confirmação de e-mail antes de liberar benefícios, bloqueio de domínios descartáveis e normalização de endereços:

```javascript
function normalizarEmail(email) {
  let [local, dominio] = email.trim().toLowerCase().split('@');
  if (['gmail.com', 'googlemail.com'].includes(dominio)) {
    local = local.split('+')[0].replace(/\./g, '');
    dominio = 'gmail.com';
  } else {
    local = local.split('+')[0];
  }
  return `${local}@${dominio}`;
}
```

**SMS pumping:** restrinja países de destino, limite por número, IP e global, CAPTCHA antes do envio, proteções antifraude do provedor (como Fraud Guard do Twilio Verify), alertas de gasto e monitoramento da taxa de conversão. Prefira e-mail, TOTP ou passkeys.

**Scraping:** login para conteúdo de valor, limites por usuário, respostas enxutas, ids não sequenciais, paginação por cursor e monitoramento. O **robots.txt** é um pedido, não uma barreira; use-o para declarar política (inclusive para `GPTBot`, `ClaudeBot`, `Google-Extended`, `CCBot`) e bloqueie na borda.

**Carding:** antifraude do gateway (Stripe Radar e equivalentes), CAPTCHA e login antes do checkout, limites por sessão, cartão e conta, 3-D Secure, e alerta para picos de recusas de baixo valor.

**Scalping:** filas virtuais, limite por conta, reservas curtas, contas verificadas e atestação na compra.

### Não bloquear os bots bons

Mantenha uma lista de bots permitidos e verifique a identidade por DNS reverso (o IP resolve para `googlebot.com` e volta ao mesmo IP). Ofereça uma API oficial para integrações legítimas.

### Privacidade, LGPD e acessibilidade

Impressão digital, comportamento e IP são dados pessoais: transparência na política de privacidade, coleta mínima, retenção definida e avaliação de fornecedores. Prefira desafios invisíveis ou de um clique e ofereça um caminho para quem for barrado por engano.

### Monitoramento, resposta e testes

Acompanhe falhas de login, cadastros e confirmação de e-mail, conversão de SMS, tráfego de datacenter, pontuações da borda, desafios e recusas de pagamento. Tenha um plano para endurecer regras durante ataques e limpar contas falsas. Teste com `curl`, Python e Playwright chamando a API direto, tokens reutilizados, honeypot, e-mails descartáveis e, igualmente, usuários reais com VPN, rede móvel e leitor de tela.

### Resumo

Gerenciamento de bots na borda, desafios verificados no servidor com ação e domínio, honeypots e tempo mínimo, atestação em apps, proteção na API, fricção por risco, defesas específicas por abuso, bots bons verificados, LGPD e acessibilidade, e monitoramento contínuo.
