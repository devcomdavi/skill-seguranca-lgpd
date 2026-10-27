# 14. Validação dos inputs

### O que é e por que importa

Validar inputs é verificar, **no servidor**, que todo dado vindo de fora tem formato, tipo, tamanho e significado esperados antes de usá-lo. Sem isso, o sistema fica exposto a injeções (SQL, comandos, XSS), acesso a arquivos indevidos, requisições forçadas à rede interna, travamentos por entradas gigantes, corrupção de dados e erros de negócio.

**Input é tudo que cruza uma fronteira de confiança:** corpo, query string, parâmetros de rota, cabeçalhos, cookies, arquivos e seus nomes, webhooks, respostas de APIs de terceiros, filas, planilhas importadas, configuração, saída de modelos de IA e até dados do próprio banco usados para montar comandos.

### Conceitos

**Cliente é experiência, servidor é segurança;** compartilhar o schema (Zod) entre os dois evita divergência. **Validar** (rejeitar), **sanitizar** (modificar) e **codificar a saída** (escapar conforme o destino) são coisas diferentes, e a validação de entrada não dispensa o escape na saída. **Allowlist, não denylist.** Validação **sintática** (formato) e **semântica** (faz sentido no contexto). **Parse, don't validate:** transforme a entrada num objeto tipado e use só ele. **Valide na fronteira, de forma centralizada.**

### Por tipo de dado

**Textos:** tamanho máximo sempre, `trim`, normalização NFC e rejeição de caracteres de controle (inclusive os de direção de texto, usados para disfarçar `.exe` como `.pdf`).

```typescript
const textoSeguro = (max: number) =>
  z.string()
    .trim()
    .transform((s) => s.normalize('NFC'))
    .pipe(z.string()
      .min(1, 'Campo obrigatório')
      .max(max, `Máximo de ${max} caracteres`)
      .refine((s) => !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E]/.test(s),
              'Contém caracteres inválidos'));

const Perfil = z.object({ nome: textoSeguro(100), bio: textoSeguro(500).optional() }).strict();
```

Campos de formato fixo: `z.string().regex(/^[a-z0-9-]{3,40}$/)`.

**Números:** converta e valide, com mínimo, máximo, inteiro e sem `NaN`/`Infinity`. Cuidado: `coerce` transforma string vazia em `0`. Dinheiro em centavos inteiros ou decimais, nunca ponto flutuante.

```typescript
const Quantidade = z.coerce.number().int().min(1).max(999);
const Pagina     = z.coerce.number().int().min(1).max(10_000).default(1);
```

**Datas:** ISO 8601, UTC, limites semânticos.

```typescript
const Agendamento = z.object({
  inicio: z.coerce.date()
    .refine((d) => d > new Date(), 'A data deve ser no futuro')
    .refine((d) => d < new Date(Date.now() + 365 * 86_400_000), 'Máximo de 1 ano à frente'),
  duracaoMin: z.number().int().min(15).max(480),
});
```

**E-mails:** validador da biblioteca, minúsculas, até 254 caracteres e confirmação por link. **Ids:** formato exato (UUID), sem dispensar a autorização. **Enumerações:** `z.enum([...])`. **Arrays e objetos:** limite de itens e de profundidade.

```typescript
const Pedido = z.object({
  itens: z.array(z.object({
    produtoId: z.string().uuid(),
    quantidade: z.number().int().min(1).max(99),
  })).min(1).max(50),
}).strict();
```

**Tamanho da requisição:**

```javascript
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
```

**ReDoS:** regex com quantificadores aninhados (`(a+)+`) podem travar o servidor. Limite o tamanho antes da regex, prefira validadores prontos, use `safe-regex`, Semgrep ou `re2`.

O risco é maior justamente onde a tentação de usar regex "completa" é maior. **E-mails:** expressões que tentam cobrir toda a especificação RFC 5322 ficam enormes e cheias de grupos repetidos e alternativos, e algumas dessas regex amplamente copiadas da internet são vulneráveis a ReDoS; uma entrada de algumas dezenas de caracteres bem escolhidos pode prender a CPU por segundos ou minutos. Prefira um validador simples da biblioteca (algo, `@`, domínio com ponto), limite de 254 caracteres **antes** da validação e a confirmação por link. **XML, HTML, JSON e outros formatos estruturados:** nunca valide nem extraia dados com regex; use um parser de verdade, com limites. No caso de XML, configure o parser para desativar entidades externas e DTDs (contra XXE) e limitar a expansão de entidades (contra o ataque *billion laughs*), por exemplo com `defusedxml` em Python ou as opções seguras do parser na sua linguagem. A regra geral é a mesma do HTML: regex serve para formatos simples e fechados (CEP, slug, código de cupom), aplicada a entradas já limitadas em tamanho; para qualquer coisa com estrutura aninhada, use um parser ou validador dedicado.

### Validação semântica e de negócio

```typescript
async function validarPedido(userId: string, dados: PedidoInput) {
  const produtos = await buscarProdutos(dados.itens.map(i => i.produtoId));
  for (const item of dados.itens) {
    const p = produtos.get(item.produtoId);
    if (!p || !p.ativo)                   throw new ErroValidacao('Produto indisponível', item.produtoId);
    if (p.estoque < item.quantidade)      throw new ErroValidacao('Estoque insuficiente', item.produtoId);
    if (item.quantidade > p.maxPorPedido) throw new ErroValidacao('Quantidade acima do permitido');
  }
  if (dados.cupom) {
    const cupom = await buscarCupom(dados.cupom);
    if (!cupom || cupom.expiraEm < new Date() || await jaUsouCupom(userId, cupom.id))
      throw new ErroValidacao('Cupom inválido');
  }
}
```

Em estoque e saldo, valide dentro da mesma transação da gravação. Reforce no banco:

```sql
alter table pedidos
  add constraint quantidade_positiva check (quantidade > 0),
  add constraint status_valido check (status in ('pendente','pago','enviado','cancelado'));
alter table usuarios
  add constraint email_tamanho check (char_length(email) <= 254),
  add constraint email_unico unique (email);
```

### Dados brasileiros

**CPF e CNPJ:** valide dígitos verificadores e rejeite sequências repetidas; guarde sem pontuação.

```typescript
function cpfValido(valor: string): boolean {
  const cpf = valor.replace(/\D/g, '');
  if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) return false;
  const digito = (base: string, pesoInicial: number) => {
    const soma = [...base].reduce((acc, n, i) => acc + Number(n) * (pesoInicial - i), 0);
    const resto = (soma * 10) % 11;
    return resto === 10 ? 0 : resto;
  };
  return digito(cpf.slice(0, 9), 10) === Number(cpf[9])
      && digito(cpf.slice(0, 10), 11) === Number(cpf[10]);
}
```

**CNPJ alfanumérico:** a partir de julho de 2026, a Receita Federal passou a emitir CNPJs com letras na raiz e na ordem, mantendo os dois dígitos verificadores numéricos com cálculo adaptado. Atualize validadores, colunas numéricas, regex `\d{14}` e máscaras, e confira a documentação oficial e as bibliotecas (`@brazilian-utils/brazilian-utils`, `validation-br`, `validate-docbr`).

**CEP:** oito dígitos e consulta a API, tratada como não confiável. **Telefone:** E.164 com `libphonenumber`. **Pix, placas e outros:** validadores específicos.

### Usos perigosos: validar para o destino

**HTML e XSS:** escape na saída (React, Vue, Angular e Svelte já escapam; o risco está em `dangerouslySetInnerHTML`, `v-html`, `innerHTML`, `|safe`). Para HTML rico, sanitize no servidor com allowlist:

```javascript
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
const DOMPurify = createDOMPurify(new JSDOM('').window);

const htmlLimpo = DOMPurify.sanitize(htmlDoUsuario, {
  ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'a', 'h2', 'h3', 'blockquote'],
  ALLOWED_ATTR: ['href'],
  ALLOWED_URI_REGEXP: /^(https?:|mailto:)/i,
});
```

Nunca sanitize HTML com regex; bloqueie `javascript:` em links; configure CSP (seção 18).

**Arquivos:** tamanho, tipo real por magic bytes, nome aleatório, storage privado fora da pasta pública, reprocessamento de imagens, cuidado com SVG, zip bombs e CSV injection (detalhes na seção 16).

```javascript
import { fileTypeFromBuffer } from 'file-type';
const PERMITIDOS = new Set(['image/jpeg', 'image/png', 'image/webp', 'application/pdf']);

async function validarArquivo(buffer) {
  if (buffer.length > 5 * 1024 * 1024) throw new ErroValidacao('Arquivo maior que 5 MB');
  const tipo = await fileTypeFromBuffer(buffer);
  if (!tipo || !PERMITIDOS.has(tipo.mime)) throw new ErroValidacao('Tipo de arquivo não permitido');
  return tipo;
}
```

**Path traversal:**

```javascript
import path from 'node:path';
const BASE = path.resolve('/srv/app/relatorios');

function caminhoSeguro(nomeArquivo) {
  if (!/^[a-zA-Z0-9_-]+\.pdf$/.test(nomeArquivo)) throw new ErroValidacao('Nome inválido');
  const destino = path.resolve(BASE, nomeArquivo);
  if (!destino.startsWith(BASE + path.sep)) throw new ErroValidacao('Caminho inválido');
  return destino;
}
```

**Command injection:**

```javascript
import { execFile } from 'node:child_process';
// VULNERÁVEL: exec(`convert ${entrada} -resize 200x200 ${saida}`);
execFile('convert', [entrada, '-resize', '200x200', saida], callback);
```

Em Python, `subprocess.run([...], shell=False)`; use `--` para separar opções de argumentos.

**SSRF:** aceite só `https`, bloqueie IPs privados, loopback, link-local (inclusive `169.254.169.254`) e reservados no IP efetivamente conectado, não siga redirecionamentos sem revalidar, limite tempo e tamanho, use allowlist de domínios quando possível, isole a rede e exija IMDSv2 na AWS (`ssrf-req-filter` ajuda).

**Open redirect:**

```javascript
function destinoSeguro(valor) {
  if (typeof valor !== 'string' || !valor.startsWith('/') || valor.startsWith('//') || valor.includes('\\')) {
    return '/painel';
  }
  return valor;
}
```

**CRLF injection:** nada de `\r` e `\n` em cabeçalhos HTTP, de e-mail e em logs. **Prototype pollution:** schemas estritos, sem merges profundos com dados brutos. **Webhooks:** verifique a assinatura (corpo bruto, tempo constante, timestamp), valide o schema e confirme o estado na API do provedor. **Saída de IA:** valide JSON com schema, escape o texto exibido e aplique autorização às ações que o modelo decide.

### Estrutura no sistema

```typescript
import { z, ZodSchema } from 'zod';

export function validar(schemas: { body?: ZodSchema; query?: ZodSchema; params?: ZodSchema }) {
  return (req, res, next) => {
    const erros = {};
    for (const parte of ['body', 'query', 'params'] as const) {
      const schema = schemas[parte];
      if (!schema) continue;
      const r = schema.safeParse(req[parte]);
      if (!r.success) erros[parte] = r.error.flatten().fieldErrors;
      else req.validado = { ...req.validado, [parte]: r.data };
    }
    if (Object.keys(erros).length) return res.status(422).json({ erro: 'Dados inválidos', campos: erros });
    next();
  };
}

app.post('/api/orgs/:orgId/pedidos',
  requireAuth,
  validar({ params: z.object({ orgId: z.string().uuid() }), body: Pedido }),
  exigirPermissao('pedido:criar'),
  criarPedido);
```

Equivalentes: `ValidationPipe` (NestJS), Pydantic (FastAPI), Form Requests (Laravel), serializers (DRF). Regra de equipe: nenhuma rota sem schema. Responda 400 ou 422 com mensagens por campo, sem detalhes internos nem a entrada bruta sem escape, e registre falhas de validação.

### Testar

Testes de limite (máximo e máximo + 1, zero, negativos, listas vazias, tipos errados, `null`, campos extras, Unicode, *D'Ávila*), testes baseados em propriedades (**fast-check**, **Hypothesis**), fuzzing de API (**Schemathesis**) e casos de abuso (HTML, `../`, URLs internas, extensões trocadas, fórmulas em CSV, redirecionamentos externos, quebras de linha).

### Resumo

Todo dado de fora é suspeito: schemas com allowlist na fronteira, limites de tamanho, tratamento correto de números, dinheiro, datas, e-mails, ids e enums, validação de negócio em transações com restrições no banco, documentos brasileiros (incluindo CNPJ alfanumérico), e a defesa específica de cada destino perigoso, com erros claros e discretos e testes de limite, propriedades e fuzzing.
