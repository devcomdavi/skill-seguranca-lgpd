# 16. Restringir uploads

### O que é e por que importa

Upload é aceitar **arquivos inteiros** de fora, que serão gravados, processados por bibliotecas pesadas, exibidos em navegadores e abertos por outras pessoas. Sem restrições: execução de código (web shell), XSS armazenado, ataques a processadores de imagem, PDF e vídeo, negação de serviço, distribuição de malware, hospedagem gratuita às suas custas e vazamento de arquivos privados.

### Cada caso de uso tem sua regra

```typescript
const REGRAS_UPLOAD = {
  avatar:      { tipos: ['image/jpeg', 'image/png', 'image/webp'], maxBytes: 2 * 1024 ** 2, maxPorUsuario: 1 },
  comprovante: { tipos: ['image/jpeg', 'image/png', 'application/pdf'], maxBytes: 10 * 1024 ** 2 },
  documento:   { tipos: ['application/pdf'], maxBytes: 20 * 1024 ** 2 },
  planilha:    { tipos: ['text/csv', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
                 maxBytes: 5 * 1024 ** 2 },
  video:       { tipos: ['video/mp4', 'video/webm'], maxBytes: 500 * 1024 ** 2 },
} as const;
```

### Opção A: upload passando pelo servidor

Simples e com controle total, mas consome recursos e é limitado em serverless. Configure limites no parser para recusar arquivos ainda chegando:

```javascript
import multer from 'multer';

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 1, fields: 10, fieldSize: 100 * 1024, parts: 12 },
});

app.post('/api/comprovantes', requireAuth, upload.single('arquivo'), async (req, res) => {
  const tipo = await validarArquivo(req.file.buffer, REGRAS_UPLOAD.comprovante);
  // ... gravar no storage privado, registrar no banco, enviar para escaneamento
});
```

### Opção B: upload direto com URL pré-assinada

Recomendada para arquivos médios e grandes. Use **POST pré-assinado** com condições; a chave é definida pelo servidor e o arquivo cai em quarentena:

```javascript
import { createPresignedPost } from '@aws-sdk/s3-presigned-post';

app.post('/api/uploads/autorizar', requireAuth, validar({ body: PedidoUpload }), async (req, res) => {
  const { finalidade, tipoDeclarado } = req.validado.body;
  const regra = REGRAS_UPLOAD[finalidade];
  if (!regra.tipos.includes(tipoDeclarado)) return res.status(422).json({ erro: 'Tipo não permitido' });
  if (!(await dentroDaCota(req.user.id, finalidade))) return res.status(429).json({ erro: 'Cota excedida' });

  const id = crypto.randomUUID();
  const chave = `quarentena/${req.user.orgId}/${req.user.id}/${id}`;
  const { url, fields } = await createPresignedPost(s3, {
    Bucket: 'uploads-privados',
    Key: chave,
    Conditions: [
      ['content-length-range', 1, regra.maxBytes],
      ['eq', '$Content-Type', tipoDeclarado],
      ['eq', '$key', chave],
    ],
    Fields: { 'Content-Type': tipoDeclarado },
    Expires: 120,
  });
  await registrarUploadPendente({ id, chave, userId: req.user.id, finalidade });
  res.json({ id, url, fields });
});

app.post('/api/uploads/:id/concluir', requireAuth, async (req, res) => {
  const pendente = await buscarUploadPendente(req.params.id, req.user.id);
  if (!pendente) return res.sendStatus(404);
  await filaProcessamento.add('processar-upload', { uploadId: pendente.id });
  res.status(202).json({ status: 'processando' });
});
```

O tipo declarado é só uma afirmação; a verificação real vem depois. Eventos do storage podem disparar o processamento; pendentes abandonados são apagados por regras de ciclo de vida.

### Restrições no próprio storage

```sql
-- Supabase
update storage.buckets
set public = false,
    file_size_limit = 5242880,
    allowed_mime_types = array['image/jpeg','image/png','image/webp']
where id = 'avatares';

create policy "usuario envia apenas para a propria pasta"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'avatares'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);
```

```javascript
// Firebase Storage
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /avatares/{userId}/{arquivo} {
      allow write: if request.auth != null
                   && request.auth.uid == userId
                   && request.resource.size < 2 * 1024 * 1024
                   && request.resource.contentType.matches('image/(jpeg|png|webp)');
      allow read: if request.auth != null;
    }
  }
}
```

Uploads retomáveis (tus, multipart do S3) seguem os mesmos limites, com expiração e limpeza de partes abandonadas.

### Pipeline seguro

1. Recebimento em quarentena isolada.
2. Validação de tamanho, tipo real (magic bytes) e coerência com a finalidade.
3. Escaneamento (antivírus e, se aplicável, moderação).
4. Processamento e sanitização.
5. Publicação só da versão processada.
6. Registro de metadados e liberação apenas com status "aprovado".

Processamento assíncrono em worker isolado, com privilégios mínimos, sem rede e com tempo máximo:

```javascript
filaProcessamento.process('processar-upload', async (job) => {
  const upload = await buscarUpload(job.data.uploadId);
  const buffer = await baixarDoStorage('uploads-privados', upload.chave);
  const tipo = await validarArquivo(buffer, REGRAS_UPLOAD[upload.finalidade]);
  if (!(await escanearAntivirus(buffer))) return marcarRejeitado(upload, 'malware');
  const processado = await processarPorTipo(tipo, buffer, upload.finalidade);
  const chaveFinal = `arquivos/${upload.orgId}/${crypto.randomUUID()}.${tipo.ext}`;
  await enviarAoStorage('arquivos-privados', chaveFinal, processado, tipo.mime);
  await removerDoStorage('uploads-privados', upload.chave);
  await marcarAprovado(upload, { chaveFinal, mime: tipo.mime, tamanho: processado.length,
                                 sha256: hash(processado) });
});
```

### Processar cada tipo

**Imagens:** reprocesse com limite de pixels (contra decompression bombs) e formato de saída fixo, eliminando poliglotas e metadados.

```javascript
import sharp from 'sharp';

async function processarImagem(buffer, finalidade) {
  const img = sharp(buffer, { limitInputPixels: 40_000_000, failOn: 'error' });
  const meta = await img.metadata();
  if (!meta.width || !meta.height) throw new ErroValidacao('Imagem inválida');
  const tamanhoMax = finalidade === 'avatar' ? 512 : 2048;
  return img.rotate()
    .resize(tamanhoMax, tamanhoMax, { fit: 'inside', withoutEnlargement: true })
    .webp({ quality: 82 })
    .toBuffer();
}
```

Com ImageMagick, restrinja formatos e recursos no `policy.xml` e mantenha atualizado; libvips (`sharp`) tem superfície menor.

**SVG:** recuse, converta para PNG ou sanitize com DOMPurify (perfil SVG). **PDF:** reconstrua (qpdf, remoção de JavaScript, anexos e ações, ou rasterização); Ghostscript isolado com `-dSAFER`. **Office:** sem macros (`.docm`, `.xlsm`) e formatos antigos; conversão para PDF como CDR. **Planilhas:** limites de linhas, colunas e células, schema por linha, processamento no worker. **Vídeo e áudio:** FFmpeg isolado, sem rede, com `-protocol_whitelist file`, formato de entrada explícito e limites; ou serviços gerenciados (MediaConvert, Mux, Cloudflare Stream).

**Arquivos compactados:**

```javascript
import path from 'node:path';
const LIMITE_TOTAL = 200 * 1024 * 1024, LIMITE_ARQUIVOS = 1000, RAZAO_MAX = 100;

function validarEntradaZip(entrada, destino, estado) {
  const final = path.resolve(destino, entrada.nome);
  if (!final.startsWith(path.resolve(destino) + path.sep)) throw new Error('Caminho inválido no ZIP');
  if (entrada.ehLinkSimbolico) throw new Error('Links simbólicos não permitidos');
  estado.arquivos += 1;
  estado.bytes += entrada.tamanhoDescompactado;
  if (estado.arquivos > LIMITE_ARQUIVOS || estado.bytes > LIMITE_TOTAL) throw new Error('ZIP grande demais');
  if (entrada.tamanhoCompactado > 0 && entrada.tamanhoDescompactado / entrada.tamanhoCompactado > RAZAO_MAX)
    throw new Error('Taxa de compressão suspeita');
  return final;
}
```

Recuse ZIPs com senha sem motivo para aceitá-los.

### Escaneamento de malware

```javascript
import NodeClam from 'clamscan';

const clam = await new NodeClam().init({
  clamdscan: { host: process.env.CLAMD_HOST, port: 3310, timeout: 60000 },
  preference: 'clamdscan',
});

async function escanearAntivirus(buffer) {
  const { isInfected, viruses } = await clam.scanStream(Readable.from(buffer));
  if (isInfected) logger.warn({ viruses }, 'Arquivo infectado bloqueado');
  return !isInfected;
}
```

Atualize as assinaturas (`freshclam`) ou use GuardDuty Malware Protection for S3. Não envie arquivos inteiros a serviços públicos de análise; consulte só o hash.

### Moderação de conteúdo

Para conteúdo visível a outros: Rekognition, Cloud Vision SafeSearch, Azure Content Safety, Hive, Sightengine; para abuso infantil, ferramentas de hash (PhotoDNA, Thorn) e processo jurídico de remoção e comunicação; canal de denúncias.

### Servir os arquivos com segurança

**Domínio separado** (de preferência registrável próprio, como `seusiteusercontent.com.br`); `Content-Type` determinado por você e `nosniff`; `Content-Disposition: attachment` quando não precisar exibir; CSP com sandbox; nunca em pasta executável; autorização a cada acesso com URLs assinadas.

```nginx
location /arquivos/ {
  add_header X-Content-Type-Options "nosniff" always;
  add_header Content-Security-Policy "default-src 'none'; img-src 'self'; media-src 'self'; sandbox" always;
  add_header Cache-Control "private, max-age=300" always;
  add_header Cross-Origin-Resource-Policy "cross-origin" always;
}
```

### Cotas e abuso de custo

Cotas por usuário e organização, rate limit de uploads, conta verificada, controle de hotlinking, alertas de storage e egress, deduplicação por SHA-256 e limpeza de órfãos:

```sql
select a.id, a.chave
from arquivos a
left join anexos_mensagem am on am.arquivo_id = a.id
left join perfis p on p.avatar_arquivo_id = a.id
where am.arquivo_id is null and p.avatar_arquivo_id is null
  and a.atualizado_em < now() - interval '30 days';
```

### Registro e testes

Registre quem enviou, quando, de onde, finalidade, tamanho, tipo, hash e resultados. Teste tamanhos no limite, `.php` e `.html` renomeados, poliglotas, SVG com script, PDF com JavaScript, macros, decompression bombs, zip bombs, `../` em ZIPs, o arquivo **EICAR**, autorização entre usuários e organizações, cabeçalhos de entrega e cotas.

### Resumo

Regras por finalidade, limites no proxy e no parser ou POST pré-assinado com condições, restrições nos buckets, pipeline assíncrono com quarentena, validação real, escaneamento e reprocessamento isolado, tratamento específico por formato, entrega por domínio separado com cabeçalhos restritivos, cotas e limpeza, registro e testes com arquivos maliciosos.
