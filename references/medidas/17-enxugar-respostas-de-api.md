# 17. Enxugar respostas de API

### O que é e por que importa

Cada resposta deve conter **só o que o cliente precisa e o usuário pode ver**. O atalho de devolver o registro inteiro do banco expõe tudo no DevTools (OWASP: **Broken Object Property Level Authorization**). Escapam com frequência: `senha_hash`, `mfa_secret`, tokens; contato e documentos de outros usuários; `custo`, `margem`, `notas_internas`, `score_fraude`; flags internas; e objetos completos aninhados em listas. Respostas enxutas também são menores, mais rápidas e com contrato explícito.

### Princípios

**Negar por padrão** (allowlist de campos). **Separar o modelo do banco do contrato da API.** **Cortar o mais cedo possível**, na consulta. **A resposta depende de quem pergunta** (o próprio, outro usuário, membro da organização, admin, parceiro).

### 1. Selecionar só as colunas necessárias

```typescript
// Prisma
const usuario = await prisma.usuario.findUnique({
  where: { id },
  select: { id: true, nome: true, avatarUrl: true, criadoEm: true },
});

// Drizzle
const [u] = await db
  .select({ id: usuarios.id, nome: usuarios.nome, avatarUrl: usuarios.avatarUrl })
  .from(usuarios)
  .where(eq(usuarios.id, id));
```

Abandone o `SELECT *`. No Supabase, prefira `.select('id, nome, avatar_url')`, mas como o cliente monta o select que quiser, use permissões por coluna ou views:

```sql
create view public.perfis_publicos with (security_invoker = true) as
  select id, nome, avatar_url, bio from public.perfis;

revoke select on public.perfis from anon, authenticated;
grant select on public.perfis_publicos to anon, authenticated;
```

### 2. Schemas de saída, um por visão

```typescript
const AutorResumo    = z.object({ id: z.string(), nome: z.string(), avatarUrl: z.string().nullable() });
const UsuarioPublico = AutorResumo.extend({ bio: z.string().nullable() });
const UsuarioProprio = UsuarioPublico.extend({ email: z.string(), telefone: z.string().nullable(),
                                               plano: z.string(), mfaAtivo: z.boolean() });
const UsuarioAdmin   = UsuarioProprio.extend({ criadoEm: z.date(), ultimoLogin: z.date().nullable(),
                                               bloqueado: z.boolean() });

function serializarUsuario(u: unknown, visao: 'publica' | 'propria' | 'admin') {
  const schema = { publica: UsuarioPublico, propria: UsuarioProprio, admin: UsuarioAdmin }[visao];
  return schema.parse(u);   // descarta chaves não declaradas
}
```

```python
# FastAPI: response_model filtra a saída
class UsuarioPublico(BaseModel):
    id: UUID
    nome: str
    avatar_url: str | None

@app.get("/usuarios/{id}", response_model=UsuarioPublico)
def obter(id: UUID):
    return repo.buscar_usuario(id)
```

```typescript
// NestJS
@Exclude()
export class UsuarioDto {
  @Expose() id: string;
  @Expose() nome: string;
  @Expose({ groups: ['proprio', 'admin'] }) email: string;
  @Expose({ groups: ['admin'] }) ultimoLogin: Date;
}
return plainToInstance(UsuarioDto, usuario, { groups: [visao], excludeExtraneousValues: true });
```

**DRF:** `fields` explícitos e serializers por visão. **Laravel:** API Resources e `$hidden`. **Rails:** serializers ou `jbuilder`.

### 3. Visão escolhida pelo servidor

```typescript
async function visaoDoUsuario(solicitante: Usuario, alvoId: string) {
  if (solicitante.id === alvoId) return 'propria';
  if (await pode(solicitante, 'usuario:ver_detalhes')) return 'admin';
  return 'publica';
}
```

Nunca por parâmetro do cliente (`?visao=admin`).

### 4. Relações aninhadas

```typescript
const comentarios = await prisma.comentario.findMany({
  where: { postId },
  select: {
    id: true, texto: true, criadoEm: true,
    autor: { select: { id: true, nome: true, avatarUrl: true } },  // nunca autor: true
  },
  take: 50,
});
```

### 5. Campos sob demanda com allowlist

```typescript
const CAMPOS_PRODUTO = {
  publica: ['id', 'nome', 'preco', 'imagemUrl', 'categoria'],
  admin:   ['id', 'nome', 'preco', 'imagemUrl', 'categoria', 'custo', 'estoque', 'fornecedorId'],
} as const;

function camposSolicitados(param: string | undefined, visao: keyof typeof CAMPOS_PRODUTO) {
  const permitidos = new Set(CAMPOS_PRODUTO[visao]);
  if (!param) return [...permitidos];
  const pedidos = param.split(',').map(s => s.trim()).filter(c => permitidos.has(c as any));
  return pedidos.length ? pedidos : [...permitidos];
}
```

O mesmo vale para expansões (`?incluir=autor`).

### 6. GraphQL

Em GraphQL, o cliente escolhe os campos e pode montar consultas arbitrárias, então as proteções de APIs REST (rota, verbo, middleware por endpoint) não bastam: tudo passa por um único endpoint, e o controle precisa estar no schema, nos resolvers e na análise da consulta.

**Schema mínimo.** Não exponha campos que nenhum cliente deveria ver, e não gere o schema automaticamente a partir das tabelas sem revisão. Desative a **introspecção** em produção (ela entrega o mapa completo da API) e as sugestões de campos nas mensagens de erro ("você quis dizer `senhaHash`?"), que revelam o schema mesmo sem introspecção.

**Autorização no resolver, não só na entrada.** Verificar o login no início da requisição não basta, porque um campo aninhado pode levar a dados de outro usuário (`pedido { cliente { email pedidos { ... } } }`). Cada resolver que devolve dados sensíveis verifica a permissão sobre **aquele objeto**, usando a mesma camada de autorização das rotas REST (seção 7), de preferência centralizada em diretivas ou num middleware de resolvers:

```typescript
const resolvers = {
  Usuario: {
    email: (usuario, _args, ctx) =>
      ctx.user?.id === usuario.id || ctx.pode('usuario:ver_detalhes') ? usuario.email : null,
  },
  Query: {
    pedido: async (_p, { id }, ctx) => {
      const pedido = await ctx.db.pedido.findFirst({ where: { id, orgId: ctx.user.orgId } });
      if (!pedido) throw new GraphQLError('Não encontrado', { extensions: { code: 'NOT_FOUND' } });
      return pedido;
    },
  },
};
```

Com DataLoader (para evitar o problema N+1), garanta que o filtro de autorização esteja **dentro** da função de carregamento e que o cache seja por requisição, nunca compartilhado entre usuários.

**Ataques de batching e aliases.** Um rate limit por requisição HTTP não enxerga o que há dentro dela. Com **aliases**, o atacante repete a mesma operação centenas de vezes numa única consulta; com **batching** (um array de operações no mesmo POST), faz o mesmo com operações inteiras. Isso permite testar centenas de senhas ou códigos de verificação numa só requisição, contornando o limite de tentativas:

```graphql
mutation {
  t1: verificarCodigo(codigo: "000001") { ok }
  t2: verificarCodigo(codigo: "000002") { ok }
  # ... centenas de aliases
}
```

Defesas: limitar o número de aliases e de operações por requisição (ou desativar o batching, se não for usado); contar o rate limit por **operação executada** e por resolver sensível, não por requisição HTTP (o contador de tentativas de login e de códigos da seção 11 deve ser incrementado dentro do resolver); e nunca permitir que mutations sensíveis (login, verificação de código, recuperação de senha, pagamentos) apareçam mais de uma vez na mesma requisição.

**Limites de custo da consulta.** Defina profundidade máxima, complexidade máxima (cada campo e lista com um custo, e listas exigindo `first`/`limit` com teto) e tempo máximo de execução, para impedir consultas aninhadas que puxam o banco inteiro ou travam o servidor. Bibliotecas como `graphql-depth-limit`, `graphql-query-complexity` e o **GraphQL Armor** (que reúne limites de profundidade, aliases, diretivas, tokens e custo, e bloqueia sugestões de campos) cobrem a maior parte disso para Apollo, Yoga e Envelop.

**Persisted queries.** Se a API só é consumida pelos seus próprios apps, aceite apenas consultas previamente registradas (*persisted queries* ou *trusted documents*), identificadas por hash. O servidor deixa de executar consultas arbitrárias, o que elimina de uma vez abuso de aliases, consultas abusivas e boa parte da exploração do schema.

**Erros.** Em produção, mascare erros internos (stack traces, mensagens do banco) e devolva apenas códigos e mensagens genéricas, como em REST (seção 15).

### 7. Paginação e limites

```typescript
const Paginacao = z.object({
  limite: z.coerce.number().int().min(1).max(100).default(20),
  cursor: z.string().uuid().optional(),
});
```

Prefira cursor e avalie se o total de registros precisa ser exposto.

### 8. Erros, escritas, cabeçalhos e metadados

Erros genéricos e 404 para recursos invisíveis; respostas de criação e atualização com o mesmo schema; sem `X-Powered-By`, versões de servidor, cabeçalhos de debug e `Server-Timing` interno; sem `__v`, `_rev` e afins.

### 9. Tornar o padrão

```typescript
function responder<T extends z.ZodTypeAny>(res: Response, schema: T, dados: unknown, status = 200) {
  return res.status(status).json(schema.parse(dados));
}
responder(res, UsuarioPublico, usuario);
```

Combine com regra de revisão ou lint contra `res.json(` com objetos do banco.

### 10. Contrato OpenAPI validado

Use `additionalProperties: false` nos schemas de resposta e valide em testes e homologação:

```javascript
app.use(OpenApiValidator.middleware({
  apiSpec: './openapi.yaml',
  validateRequests: true,
  validateResponses: process.env.NODE_ENV !== 'production',
}));
```

### Testar

```typescript
const PROIBIDOS = /senha|password|hash|token|secret|mfa|cpf|cartao|apiKey/i;

function chavesProfundas(obj: unknown, prefixo = ''): string[] {
  if (Array.isArray(obj)) return obj.flatMap((v, i) => chavesProfundas(v, `${prefixo}[${i}]`));
  if (obj && typeof obj === 'object')
    return Object.entries(obj).flatMap(([k, v]) => [`${prefixo}${k}`, ...chavesProfundas(v, `${prefixo}${k}.`)]);
  return [];
}

it('perfil público não expõe dados sensíveis nem de contato', async () => {
  const res = await request(app).get(`/api/usuarios/${outroUsuario.id}`).set(authDe(usuarioA));
  const chaves = chavesProfundas(res.body);
  expect(chaves.filter(k => PROIBIDOS.test(k))).toEqual([]);
  expect(res.body).not.toHaveProperty('email');
  expect(Object.keys(res.body).sort()).toEqual(['avatarUrl', 'bio', 'id', 'nome']);
});
```

Teste cada visão, listas, relações, escritas e parâmetros de campos; monitore o tamanho das respostas por rota.

### Resumo

Allowlist de campos, modelo separado do contrato, colunas selecionadas na consulta (views e permissões por coluna no acesso direto), schemas por visão escolhida pelo servidor, resumos em relações, campos sob demanda limitados, GraphQL com autorização por campo, paginação, erros e cabeçalhos enxutos, schema obrigatório, contrato validado e testes de campos proibidos.
