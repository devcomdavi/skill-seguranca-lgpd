# 10. Hash nas senhas

### O que é e por que importa

O sistema **nunca armazena a senha**, só o resultado de uma função de mão única aplicada a ela; no login, calcula o hash do que foi digitado e compara. Bancos vazam, e senhas em texto claro ou cifradas entregam todas as contas, inclusive em outros serviços, porque as pessoas reutilizam senhas. Com hash bem feito, reverter custa anos de processamento. Provedores de autenticação já fazem isso; este tópico importa para login próprio, sistemas legados e auditorias.

**Hash, não criptografia:** criptografia é reversível e o sistema não precisa saber a senha original. Se um sistema consegue enviar sua senha atual por e-mail, ele a guarda de forma reversível.

**Hashes comuns não servem:** MD5, SHA-1, SHA-256 e SHA-512 são rápidos demais; uma GPU testa bilhões por segundo, e há rainbow tables para MD5 e SHA-1. Senhas exigem algoritmos propositalmente lentos (100 a 500 ms são imperceptíveis para o usuário e devastadores para o atacante).

### Conceitos

**Salt:** valor aleatório único por senha; senhas iguais geram hashes diferentes e tabelas pré-calculadas deixam de funcionar. Não é segredo e as bibliotecas o embutem no hash.

**Pepper:** segredo extra, igual para todas as senhas, guardado **fora do banco** (no cofre). Aplique via HMAC antes do hash ou cifrando o hash com KMS. Precisa de backup seguro e plano de rotação; perdê-lo trava todos os logins.

**Fator de custo:** parâmetros de tempo, memória e iterações, ajustados ao hardware e aumentados com o tempo.

### Algoritmos

| Algoritmo | Quando usar | Configuração de referência |
| --- | --- | --- |
| Argon2id | Primeira escolha (OWASP); exige memória, dificulta GPUs | \~19 MiB de memória, 2 iterações, paralelismo 1 |
| bcrypt | Aceitável, comum em sistemas existentes | custo ≥ 10 (12 é comum); só usa os primeiros 72 bytes |
| scrypt | Alternativa quando não há Argon2 | nativo no Node (`crypto.scrypt`) |
| PBKDF2 | Exigência de FIPS-140 | \~600.000 iterações com HMAC-SHA-256 |

No bcrypt, senhas longas com o mesmo começo têm o mesmo hash, e algumas implementações param no byte nulo. Para aceitar senhas longas, aplique antes um HMAC-SHA-256 com pepper codificado em base64.

### 1. Gerar e verificar

```javascript
import argon2 from 'argon2';

const OPCOES = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };

export const gerarHash = (senha) => argon2.hash(senha, OPCOES);
export const verificar = (hash, senha) => argon2.verify(hash, senha);
```

O resultado (`$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`) contém algoritmo, parâmetros e salt; guarde-o inteiro numa coluna.

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
hash_ = ph.hash(senha)

def verificar(hash_, senha):
    try:
        return ph.verify(hash_, senha)
    except VerifyMismatchError:
        return False
```

**PHP:** `password_hash($senha, PASSWORD_ARGON2ID)` e `password_verify`. **Django:** `Argon2PasswordHasher` primeiro em `PASSWORD_HASHERS`. **Laravel:** `'driver' => 'argon2id'`. Sempre use a função de verificação da biblioteca (tempo constante), nunca `===`.

### 2. Calibrar o custo

Meça no servidor de produção e mire 200 a 500 ms, considerando logins simultâneos e memória disponível.

### 3. Rehash automático

```javascript
async function login(email, senha) {
  const usuario = await buscarPorEmail(email);
  const ok = usuario && await argon2.verify(usuario.senha_hash, senha);
  if (!ok) return null;
  if (argon2.needsRehash(usuario.senha_hash, OPCOES)) {
    await atualizarHash(usuario.id, await argon2.hash(senha, OPCOES));
  }
  return usuario;
}
```

Python: `ph.check_needs_rehash(hash_)`; PHP: `password_needs_rehash()`.

### 4. Migrar legado com MD5 ou SHA

Não espere o login. Primeiro, envolva todos os hashes antigos imediatamente:

```javascript
for (const u of usuariosLegados) {
  const novo = await argon2.hash(u.md5_hash, OPCOES);  // argon2(md5(senha))
  await salvar(u.id, { senha_hash: novo, formato: 'argon2_sobre_md5' });
}
```

Depois, no próximo login de cada usuário, troque pelo hash normal:

```javascript
if (usuario.formato === 'argon2_sobre_md5') {
  const md5 = crypto.createHash('md5').update(senha).digest('hex');
  if (!await argon2.verify(usuario.senha_hash, md5)) return null;
  await salvar(usuario.id, { senha_hash: await argon2.hash(senha, OPCOES), formato: 'argon2' });
}
```

Se havia senhas em texto claro ou cifradas: gere todos os hashes, apague a versão original (inclusive de backups, quando possível) e considere forçar a troca.

### 5. Evitar enumeração pelo tempo de resposta

```javascript
const HASH_FALSO = await argon2.hash('senha-inexistente-para-equalizar-tempo', OPCOES);

async function login(email, senha) {
  const usuario = await buscarPorEmail(email);
  const ok = await argon2.verify(usuario?.senha_hash ?? HASH_FALSO, senha);
  if (!usuario || !ok) return null;
  return usuario;
}
```

### 6. Proteger o servidor contra abuso

Rate limiting no login (seção 11), tamanho máximo de senha (64 a 128 caracteres; recuse, nunca corte em silêncio) e funções assíncronas no Node.

### 7. Política de senhas moderna (NIST SP 800-63B)

Comprimento mínimo razoável (pelo menos 8; a revisão mais recente do NIST recomenda 15 quando a senha é o único fator), aceitar senhas longas com espaços e Unicode, **sem** regras de composição e **sem** troca periódica forçada, bloqueio de senhas comuns e vazadas, permitir colar, medidor de força (`zxcvbn`) e normalização NFKC.

Verificação de senhas vazadas com Have I Been Pwned (k-anonimato, só o prefixo do hash sai do servidor):

```javascript
async function senhaVazada(senha) {
  const sha1 = crypto.createHash('sha1').update(senha).digest('hex').toUpperCase();
  const prefixo = sha1.slice(0, 5), sufixo = sha1.slice(5);
  const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefixo}`);
  const lista = await resp.text();
  return lista.split('\n').some(linha => linha.startsWith(sufixo));
}
```

### 8. Outros segredos guardados com hash

Tokens de recuperação, links mágicos, códigos de convite e API keys emitidas pelo sistema: mostrados uma vez e guardados como hash (SHA-256 basta, por terem alta entropia), com expiração curta e invalidação após uso. Códigos de recuperação de MFA também; o segredo do TOTP é cifrado, não hasheado.

### 9. Onde a senha não pode aparecer

Logs, monitoramento, analytics, e-mails, URLs, mensagens de erro. Hash no frontend não substitui o hash no servidor: o valor enviado vira a senha de fato.

### 10. Testar e auditar

Verifique o prefixo do algoritmo, hashes diferentes para senhas iguais, ausência da senha no banco, falha com senha errada e rehash ao mudar parâmetros. Colunas com 32, 40 ou 64 caracteres hexadecimais indicam MD5, SHA-1 ou SHA-256.

### Resumo

Argon2id (ou bcrypt, scrypt, PBKDF2 conforme o caso), salt automático, pepper opcional fora do banco, custo calibrado, rehash no login, migração imediata do legado, verificação em tempo constante com hash falso, limites de tamanho e tentativas, política NIST com bloqueio de senhas vazadas, hash para tokens e API keys, e nenhuma senha em logs.
