# 6. Autenticação no lado do servidor

### O que é e por que importa

Autenticação confirma **quem** é o usuário; autorização decide **o que** ele pode fazer. "Auth server-side" significa que essas decisões são verificadas no servidor, em cada requisição, nunca só no frontend. Esconder botões ou redirecionar páginas no React é experiência, não segurança: qualquer um pode chamar a API diretamente.

Regra de ouro: **o cliente pode ser manipulado; o servidor decide**.

### Sessões e tokens

**Sessões no servidor:** o servidor guarda a sessão (banco, Redis) e envia só um identificador aleatório num cookie. Fácil de revogar.

**JWT:** o servidor emite um token assinado com id, papel e expiração, validado pela assinatura. Prático para APIs, mas difícil de revogar; use access token curto (5 a 15 minutos) e refresh token.

O lugar mais seguro para guardar a sessão no navegador é um cookie com as flags corretas (seção 9). Tokens em `localStorage` podem ser lidos por qualquer script da página.

```text
Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=...
```

### 1. Verificar o token de verdade

Verificar é validar **assinatura e expiração**, não só decodificar. Valide também `issuer` e `audience` e fixe os algoritmos.

```javascript
import { jwtVerify, createRemoteJWKSet } from 'jose';

const JWKS = createRemoteJWKSet(new URL(process.env.AUTH_JWKS_URL));

export async function requireAuth(req, res, next) {
  const token = req.cookies.access_token
    ?? req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ erro: 'Não autenticado' });
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: process.env.AUTH_ISSUER,
      audience: 'authenticated',
    });
    req.user = { id: payload.sub, papel: payload.app_metadata?.papel };
    next();
  } catch {
    return res.status(401).json({ erro: 'Sessão inválida ou expirada' });
  }
}
```

No **Supabase**, não confie em `getSession()` no servidor (lê o cookie sem validar). Use `getUser()` ou `getClaims()`.

### 2. Middleware e verificação em cada operação

```typescript
// middleware.ts (Next.js + Supabase)
import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';

export async function middleware(req: NextRequest) {
  let res = NextResponse.next({ request: req });
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    { cookies: {
        getAll: () => req.cookies.getAll(),
        setAll: (cookies) => cookies.forEach(({ name, value, options }) =>
          res.cookies.set(name, value, options)),
    } }
  );
  const { data: { user } } = await supabase.auth.getUser();
  if (!user && req.nextUrl.pathname.startsWith('/painel')) {
    return NextResponse.redirect(new URL('/login', req.url));
  }
  return res;
}

export const config = { matcher: ['/painel/:path*', '/api/:path*'] };
```

O middleware **não basta sozinho** (já houve falhas que permitiam contorná-lo). Cada Server Action, Route Handler e Server Component que acessa dados repete a verificação:

```typescript
'use server';
export async function excluirProjeto(projetoId: string) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) throw new Error('Não autenticado');

  const { data: membro } = await supabase
    .from('membros').select('papel')
    .eq('user_id', user.id).eq('org_id', /* org do projeto */).single();
  if (membro?.papel !== 'admin') throw new Error('Sem permissão');

  await supabase.from('projetos').delete().eq('id', projetoId);
}
```

Server Actions são endpoints públicos. Centralize a lógica numa camada de acesso a dados com funções como `getUsuarioAtual()` e `exigirPapel('admin')`.

### 3. Identidade sempre vinda do token

```javascript
// ERRADO: o cliente escolhe de quem são os dados
app.get('/api/pedidos', requireAuth, (req, res) =>
  db.pedidos.findMany({ where: { userId: req.query.userId } }));

// CERTO
app.get('/api/pedidos', requireAuth, (req, res) =>
  db.pedidos.findMany({ where: { userId: req.user.id } }));
```

### 4. Autorização por recurso (contra IDOR)

IDOR é acessar recursos de outros trocando um id na URL. Inclua o dono no filtro e devolva 404 em vez de 403:

```javascript
app.get('/api/faturas/:id', requireAuth, async (req, res) => {
  const fatura = await db.faturas.findFirst({
    where: { id: req.params.id, userId: req.user.id },
  });
  if (!fatura) return res.status(404).json({ erro: 'Não encontrada' });
  res.json(fatura);
});
```

UUIDs dificultam a adivinhação, mas não substituem a verificação; o RLS é a segunda camada.

### 5. Login contra força bruta

```javascript
app.use('/auth/login', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  message: { erro: 'Muitas tentativas. Tente novamente mais tarde.' },
}));
```

Complemente com atrasos progressivos, CAPTCHA em comportamento suspeito e mensagens genéricas ("E-mail ou senha incorretos"; "Se o e-mail estiver cadastrado, você receberá um link").

### 6. Ciclo de vida da sessão

Access tokens curtos com **rotação de refresh tokens** (reuso de um refresh antigo revoga a família). Logout invalida a sessão no servidor. Ofereça "sair de todos os dispositivos" e revogue sessões ao trocar senha ou e-mail ou desativar a conta. Regenere o id da sessão após o login.

**Como modelar a família de refresh tokens.** Cada login cria uma **família** nova. Cada renovação marca o token usado e emite um filho na mesma família. Se um token já usado aparecer de novo, alguém o copiou: a família inteira é revogada de uma vez.

```sql
create table refresh_tokens (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references usuarios(id),
  family_id   uuid not null,                       -- igual em toda a cadeia de um mesmo login
  parent_id   uuid references refresh_tokens(id),  -- token que foi trocado por este (rastreabilidade)
  token_hash  text not null unique,                -- SHA-256 do token; nunca o token em claro (seção 10)
  expires_at  timestamptz not null,
  used_at     timestamptz,                         -- preenchido quando o token é trocado por um novo
  revoked_at  timestamptz,
  created_at  timestamptz not null default now()
);
create index on refresh_tokens (family_id);
create index on refresh_tokens (user_id);
```

O `family_id` torna a revogação em cascata um único `update`, sem percorrer a cadeia recursivamente; o `parent_id` serve para auditoria (reconstruir a sequência de renovações numa investigação).

```javascript
async function renovarSessao(tokenRecebido) {
  const hash = sha256(tokenRecebido);
  return db.tx(async (tx) => {
    const atual = await tx.oneOrNone(
      'select * from refresh_tokens where token_hash = $1 for update', [hash]);
    if (!atual || atual.revoked_at || atual.expires_at < new Date()) throw new ErroAuth();

    if (atual.used_at) {
      // Reuso de token já trocado: provável roubo. Revoga a família inteira.
      await tx.none(
        'update refresh_tokens set revoked_at = now() where family_id = $1 and revoked_at is null',
        [atual.family_id]);
      await registrarEventoSeguranca('refresh_token_reuse', { userId: atual.user_id });
      throw new ErroAuth();
    }

    await tx.none('update refresh_tokens set used_at = now() where id = $1', [atual.id]);
    const novo = crypto.randomBytes(32).toString('base64url');
    await tx.none(
      `insert into refresh_tokens (user_id, family_id, parent_id, token_hash, expires_at)
       values ($1, $2, $3, $4, now() + interval '30 days')`,
      [atual.user_id, atual.family_id, atual.id, sha256(novo)]);

    return { refreshToken: novo, accessToken: emitirAccessToken(atual.user_id) };
  });
}
```

No login, insira o primeiro token com um `family_id` novo e `parent_id` nulo. O logout revoga a família daquela sessão; "sair de todos os dispositivos" e a troca de senha revogam tudo por `user_id`. O `for update` evita que duas renovações simultâneas usem o mesmo token. Para não derrubar usuários legítimos quando o app dispara duas renovações quase ao mesmo tempo (várias abas, rede instável), alguns sistemas aceitam o reuso dentro de uma janela curta (poucos segundos) devolvendo o mesmo filho já emitido. Defina também uma expiração absoluta da família (por exemplo, 30 a 90 dias desde o login), após a qual é preciso entrar de novo. Uma rotina periódica apaga tokens expirados e revogados antigos. Provedores como Supabase e Auth0 já implementam esse mecanismo; o modelo acima é para quem tem autenticação própria.

### 7. CSRF

Com autenticação por cookie, `SameSite=Lax` bloqueia a maioria dos casos. Em ações sensíveis, adicione token CSRF ou valide `Origin`/`Referer`. Server Actions do Next.js já comparam a origem.

### 8. MFA e reautenticação

Para contas privilegiadas ou dados sensíveis, exija MFA com TOTP ou passkeys (evite SMS como único fator) e verifique no servidor (no Supabase, exija `aal2` em rotas sensíveis, inclusive no RLS). Peça reautenticação para trocar e-mail ou senha, exportar dados e apagar conta.

### 9. Passkeys e WebAuthn (autenticação sem senha)

Passkeys usam o padrão **FIDO2/WebAuthn**: no cadastro, o dispositivo do usuário (celular, computador, chave física) gera um par de chaves; o servidor guarda só a **chave pública**, e a privada nunca sai do dispositivo. No login, o servidor envia um desafio aleatório, o dispositivo o assina após desbloqueio (biometria ou PIN) e o servidor confere a assinatura.

Isso elimina vetores inteiros de ataque. Não há senha para ser roubada, reutilizada ou vazada do banco (o que vaza é uma chave pública, inútil para o atacante). E a credencial é **vinculada ao domínio**: o navegador só a usa no site verdadeiro, então uma página de phishing com domínio parecido simplesmente não recebe nada. Por isso passkeys são consideradas resistentes a phishing, ao contrário de senha + SMS ou códigos TOTP, que podem ser digitados num site falso. Passkeys sincronizadas (iCloud Keychain, Gerenciador de Senhas do Google, gerenciadores como 1Password) ainda permitem usar a mesma credencial em vários aparelhos.

Antes de implementar do zero, verifique se seu provedor de autenticação já oferece passkeys. Para implementação própria, use bibliotecas consolidadas, como **SimpleWebAuthn** (Node), **py\_webauthn** (Python) e **webauthn4j** (Java). Um esboço com SimpleWebAuthn (os nomes de campos mudam entre versões; confira a documentação da que você usar):

```typescript
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const rpID = 'seusite.com.br';
const origin = 'https://seusite.com.br';

// 1. Cadastro: gerar opções (usuário já autenticado)
app.post('/api/passkeys/registro/opcoes', requireAuth, async (req, res) => {
  const existentes = await listarPasskeys(req.user.id);
  const opcoes = await generateRegistrationOptions({
    rpName: 'Seu Sistema', rpID,
    userName: req.user.email,
    attestationType: 'none',
    excludeCredentials: existentes.map(p => ({ id: p.credentialId })),
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
  });
  await salvarDesafio(req.user.id, opcoes.challenge, { expiraEmSeg: 300 });  // uso único
  res.json(opcoes);
});

// 2. Cadastro: verificar resposta do navegador
app.post('/api/passkeys/registro/verificar', requireAuth, async (req, res) => {
  const desafio = await consumirDesafio(req.user.id);
  const { verified, registrationInfo } = await verifyRegistrationResponse({
    response: req.body, expectedChallenge: desafio,
    expectedOrigin: origin, expectedRPID: rpID,
  });
  if (!verified) return res.status(400).json({ erro: 'Falha ao registrar a passkey' });
  await salvarPasskey(req.user.id, registrationInfo);   // id da credencial, chave pública, contador
  res.sendStatus(204);
});
```

O login segue o mesmo padrão com `generateAuthenticationOptions` e `verifyAuthenticationResponse`, conferindo a credencial salva e atualizando o contador. No navegador, a biblioteca `@simplewebauthn/browser` chama a API WebAuthn; com *conditional UI*, as passkeys aparecem no preenchimento automático do campo de e-mail.

Pontos que não podem faltar:

- **Desafio aleatório, de uso único e com expiração curta**, guardado no servidor.
- **Verificar origem e RP ID** em toda resposta; são eles que garantem a resistência a phishing.
- **Guardar por credencial:** id, chave pública, contador de assinaturas, transportes e data de criação e de último uso; um usuário pode ter várias passkeys, e deve poder ver e revogar cada uma.
- **Recuperação de conta não pode ser o elo fraco:** incentive cadastrar mais de uma passkey e ofereça códigos de recuperação (guardados como hash, seção 10); se a recuperação for só um link por e-mail, o atacante vai mirar o e-mail.
- **Migração gradual:** comece oferecendo passkey como alternativa ou segundo fator, depois como método principal, e só então considere desativar senhas para quem já tem passkey.
- Em rotas sensíveis, exija verificação do usuário (`userVerification: 'required'`), que garante biometria ou PIN no momento do uso.

### 10. Armazenamento de tokens em aplicativos móveis

No navegador, a recomendação é o cookie `HttpOnly` (seção 9). Apps nativos não têm esse mecanismo, então tokens de sessão e refresh tokens precisam ir para o **armazenamento seguro do sistema operacional**, que protege as chaves com hardware dedicado quando disponível:

- **iOS:** **Keychain**, com acessibilidade `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (ou `AfterFirstUnlockThisDeviceOnly` se o app precisar renovar sessão em segundo plano). O sufixo `ThisDeviceOnly` impede que o token vá para backups e seja restaurado em outro aparelho.
- **Android:** **Android Keystore** para as chaves, preferencialmente com suporte de hardware (StrongBox, quando disponível), cifrando os dados com elas, por exemplo usando **Tink** com **DataStore**. Atenção: a biblioteca Jetpack Security Crypto, que oferecia o `EncryptedSharedPreferences`, foi **descontinuada pelo Google**; não a adote em projetos novos e planeje a migração em projetos que já a usam.
- **Frameworks multiplataforma:** `expo-secure-store` ou `react-native-keychain` (React Native) e `flutter_secure_storage` (Flutter) usam Keychain e Keystore por baixo; confira a configuração e a versão de cada um.

Nunca guarde tokens em `AsyncStorage`, `SharedPreferences`, `UserDefaults`, arquivos comuns ou banco SQLite sem criptografia, que são legíveis em aparelhos com root ou jailbreak, em backups e por ferramentas de depuração. Complementos: mantenha o access token só em memória e o refresh token no armazenamento seguro; apague tudo no logout; exclua esses dados dos backups em nuvem; para ações sensíveis, vincule a chave à biometria (`setUserAuthenticationRequired` no Android, controle de acesso com biometria no Keychain); e combine com a atestação de dispositivo (seção 12) e o bloqueio de tráfego em texto claro (seção 19). Nenhum segredo do servidor (API keys, chaves de serviço) deve estar dentro do app: o binário pode ser descompilado, e o que vale para o frontend web (seção 1) vale aqui.

### 11. Registro e monitoramento

Registre logins com e sem sucesso, trocas de senha, MFA, logout e mudanças de permissão (data, IP, user agent; nunca senhas ou tokens), com alertas para padrões suspeitos.

### 12. Não reinvente a autenticação

Use provedores ou bibliotecas consolidadas (Supabase Auth, Firebase Auth, Auth0, Clerk, Cognito, Keycloak, Auth.js, Better Auth) e concentre o esforço na autorização.

### Armadilhas comuns

Páginas protegidas e API aberta; JWT decodificado sem verificar assinatura; `getSession()` no servidor; confiar só no middleware; Server Actions sem checagem; `userId` vindo do corpo; IDOR; tokens em `localStorage`; logout só no navegador; login sem limite; erros que revelam e-mails cadastrados.

### Resumo

O servidor verifica em cada requisição uma sessão ou token válido e decide se aquele usuário pode executar aquela ação sobre aquele recurso: cookies seguros, middleware mais checagem por endpoint, identidade do token, autorização por recurso, rate limit, sessões curtas com rotação e revogação, CSRF, MFA, logs e RLS como rede de segurança.
