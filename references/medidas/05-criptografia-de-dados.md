# 5. Criptografia de dados

### O que é e por que importa

Criptografia transforma dados legíveis em algo ilegível para quem não tem a chave. É a última linha de defesa: se alguém rouba um backup, acessa o disco, intercepta o tráfego ou consegue um dump do banco, os dados cifrados continuam inúteis, desde que a chave não tenha vazado junto. A LGPD exige medidas técnicas adequadas, e a criptografia é uma das principais formas de demonstrá-las.

### Conceitos

**Os três estados do dado:** em trânsito (rede, protegido com TLS), em repouso (banco, disco, backups) e em uso (memória; o foco prático é não deixá-lo vazar em logs e erros).

**Simétrica e assimétrica:** na simétrica, a mesma chave cifra e decifra; é rápida e usada para dados armazenados (padrão: **AES-256-GCM** ou ChaCha20-Poly1305, que também garantem integridade). Na assimétrica, a chave pública cifra e só a privada decifra; é usada em troca de chaves, assinaturas e TLS.

**Hash não é criptografia:** é uma via de mão única, usada para senhas (seção 10) e integridade. Senhas nunca são criptografadas; são transformadas em hash com Argon2id, bcrypt ou scrypt.

**Codificação não é criptografia:** Base64, hexadecimal, URL encoding e similares são apenas **esquemas de codificação**, ou seja, uma tradução de bytes para caracteres que podem trafegar em texto (JSON, URLs, e-mails). Não existe chave e não existe segredo: qualquer pessoa reverte com `atob()` ou `base64 -d` em um segundo. Por isso, um campo "protegido" com Base64 está, para todos os efeitos, em texto claro. O mesmo vale para outras transformações reversíveis sem chave, como ROT13, XOR com valor fixo no código ou "embaralhamento" de caracteres. Um sinal comum dessa confusão é o JWT: o conteúdo (payload) de um JWT é apenas Base64URL, legível por qualquer um; a assinatura garante que ele não foi alterado, mas **não** esconde nada, então nunca coloque dados sensíveis dentro dele. Base64 aparece corretamente em criptografia só como forma de **transportar** o resultado cifrado (como nos exemplos abaixo), nunca como a proteção em si.

### Camada 1: criptografia em trânsito

Todo tráfego em HTTPS com TLS 1.2 ou 1.3, redirecionamento de HTTP para HTTPS e HSTS (seções 18 e 19). Exija TLS também com o banco:

```text
postgresql://user:senha@host:5432/db?sslmode=verify-full
```

`sslmode=require` cifra mas não valida o certificado; `verify-full` protege também contra intermediários.

### Camada 2: em repouso na infraestrutura

AWS RDS, Cloud SQL, Azure e Supabase criptografam disco e backups por padrão ou com uma opção simples; confirme, inclusive em snapshots, réplicas e buckets (S3 com SSE-KMS). O limite: essa camada é transparente para quem consulta o banco. Quem conseguir fazer SQL (injection, credencial vazada, falha de RLS) vê tudo em texto claro.

### Camada 3: criptografia na aplicação (por campo)

Para CPF, documentos, dados de saúde, dados bancários e tokens de integrações, a aplicação cifra antes de gravar. Um dump do banco não revela nada sem a chave, que fica em outro lugar.

```javascript
import crypto from 'node:crypto';

const KEY = Buffer.from(process.env.DATA_KEY, 'base64'); // 32 bytes, vindo do cofre

export function encrypt(texto) {
  const iv = crypto.randomBytes(12);                    // único por operação
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const dados = Buffer.concat([cipher.update(texto, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, dados]).toString('base64');
}

export function decrypt(payload) {
  const buf = Buffer.from(payload, 'base64');
  const iv = buf.subarray(0, 12), tag = buf.subarray(12, 28), dados = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(dados), decipher.final()]).toString('utf8');
}
```

```python
import os, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

aes = AESGCM(base64.b64decode(os.environ["DATA_KEY"]))

def encrypt(texto: str) -> str:
    nonce = os.urandom(12)
    return base64.b64encode(nonce + aes.encrypt(nonce, texto.encode(), None)).decode()

def decrypt(payload: str) -> str:
    raw = base64.b64decode(payload)
    return aes.decrypt(raw[:12], raw[12:], None).decode()
```

O **IV/nonce** precisa ser aleatório e nunca repetido com a mesma chave. Passar o id do registro como "dado associado" (AAD) amarra o valor cifrado à sua linha e impede que alguém copie o CPF cifrado de um usuário para outro.

### Camada 4: gestão de chaves (KMS e envelope encryption)

Guardar a chave no mesmo banco dos dados, ou no código, anula o esforço. O padrão profissional é a **envelope encryption** com KMS (AWS KMS, Cloud KMS, Azure Key Vault, Vault Transit):

1. Uma chave mestra fica dentro do KMS e nunca sai.
2. A aplicação pede uma chave de dados (DEK); o KMS devolve a DEK aberta e cifrada.
3. A aplicação cifra os dados com a DEK aberta, descarta-a e grava só a DEK cifrada junto aos dados.
4. Para decifrar, envia a DEK cifrada ao KMS, que a devolve aberta se houver permissão.

```python
import boto3
kms = boto3.client("kms")

resp = kms.generate_data_key(KeyId="alias/app-dados", KeySpec="AES_256")
dek_aberta, dek_cifrada = resp["Plaintext"], resp["CiphertextBlob"]
# cifra os dados com dek_aberta (AES-GCM), grava dek_cifrada junto

dek_aberta = kms.decrypt(CiphertextBlob=dek_cifrada)["Plaintext"]
```

Vantagens: a chave mestra nunca é exposta, todo uso é auditado, permissões via IAM, e a rotação da mestra não exige recriptografar os dados. No Supabase, o **Supabase Vault** guarda segredos cifrados no Postgres; para dados de usuários em escala, a cifragem na aplicação com KMS externo mantém a chave fora do banco.

### Camada 5: buscar dados cifrados (blind index)

Com nonce aleatório, o mesmo CPF gera valores diferentes, então `where cpf = ...` não funciona. Grave também um HMAC do valor normalizado, com outra chave:

```javascript
const INDEX_KEY = Buffer.from(process.env.INDEX_KEY, 'base64');

function blindIndex(cpf) {
  const normalizado = cpf.replace(/\D/g, '');
  return crypto.createHmac('sha256', INDEX_KEY).update(normalizado).digest('hex');
}
// gravar: { cpf_cifrado: encrypt(cpf), cpf_index: blindIndex(cpf) }
// buscar: where cpf_index = blindIndex(cpfDigitado)
```

Permite busca exata e unicidade, não `like` nem ordenação. Use HMAC com chave, nunca hash simples: um CPF tem poucas combinações e seria quebrado por força bruta.

### Camada 6: senhas

```javascript
import argon2 from 'argon2';
const hash = await argon2.hash(senha, { type: argon2.argon2id });
const ok = await argon2.verify(hash, senhaDigitada);
```

### Camada 7: rotação de chaves

Guarde junto ao dado um identificador da versão da chave (por exemplo, o prefixo `v2:`). Chaves antigas servem só para decifrar; a mais nova cifra; um job recriptografa os registros antigos.

### Camada 8: backups, logs e exportações

Backups cifrados e com acesso restrito, logs sem dados decifrados, exportações com a mesma política e ambientes de teste sem dados reais de produção.

### Armadilhas comuns

Inventar algoritmos ou "ofuscar" com Base64; ECB ou CBC sem autenticação; reutilizar nonce; gerar chaves com `Math.random()`; guardar a chave junto dos dados; MD5, SHA-1 ou SHA-256 para senhas; confiar só na criptografia de disco; um único processo com acesso a todas as chaves. Use bibliotecas consolidadas (`crypto` do Node, `cryptography` do Python, libsodium).

### Resumo

TLS em todo tráfego (inclusive com o banco), criptografia em repouso na infraestrutura e nos backups, AES-256-GCM por campo para dados sensíveis, chaves em KMS com envelope encryption, blind index com HMAC, Argon2id para senhas, rotação com versionamento e nada decifrado em logs, exportações ou ambientes de teste.
