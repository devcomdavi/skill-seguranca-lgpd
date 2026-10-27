# 8. Bloquear mass assignment

### O que é e por que importa

Mass assignment acontece quando o sistema grava **todos os campos** enviados pelo cliente sem filtrar quais ele pode alterar, o famoso `update(req.body)`:

```javascript
await db.usuario.update({ where: { id: req.user.id }, data: req.body });
```

Um atacante envia:

```json
{ "nome": "Maria", "papel": "admin", "plano": "enterprise", "email_verificado": true, "saldo": 99999 }
```

e se promove a admin, ganha o plano mais caro e cria saldo. Um caso clássico é o do GitHub em 2012, com Rails. No OWASP API Top 10, faz parte de **Broken Object Property Level Authorization**.

Campos que costumam ser alvo: papéis e flags de admin; posse (`user_id`, `owner_id`, `org_id`); dinheiro e planos (`saldo`, `preco`, `desconto`, `plano`); status e verificações; campos de controle (`id`, `created_at`, `deleted_at`); campos de segurança (`senha_hash`, `mfa_secret`).

### 1. Allowlist, nunca denylist

Defina explicitamente os campos aceitos. Uma coluna nova fica protegida por padrão.

```javascript
const { nome, bio, avatar_url } = req.body;
await db.usuario.update({
  where: { id: req.user.id },
  data: { nome, bio, avatar_url },
});
```

### 2. Validar com schemas (DTOs)

**Zod:**

```typescript
import { z } from 'zod';

const AtualizarPerfil = z.object({
  nome: z.string().min(1).max(100),
  bio: z.string().max(500).optional(),
  avatar_url: z.string().url().optional(),
}).strict();   // rejeita campos não declarados

app.patch('/api/perfil', requireAuth, async (req, res) => {
  const parsed = AtualizarPerfil.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ erro: parsed.error.flatten() });
  await db.usuario.update({ where: { id: req.user.id }, data: parsed.data });
  res.sendStatus(204);
});
```

Sem `.strict()`, o Zod remove os campos extras (também seguro); com ele, a requisição é rejeitada e a tentativa aparece nos logs.

**Pydantic (FastAPI):**

```python
from pydantic import BaseModel, ConfigDict, Field

class AtualizarPerfil(BaseModel):
    model_config = ConfigDict(extra="forbid")
    nome: str = Field(min_length=1, max_length=100)
    bio: str | None = Field(default=None, max_length=500)

@app.patch("/perfil")
def atualizar(dados: AtualizarPerfil, user=Depends(usuario_atual)):
    repo.atualizar_usuario(user.id, dados.model_dump(exclude_unset=True))
```

**NestJS:**

```typescript
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
}));
```

### 3. Um schema por operação e por papel

```typescript
const CriarPedido     = z.object({ itens: z.array(ItemSchema).min(1), cupom: z.string().optional() }).strict();
const AtualizarPedido = z.object({ endereco_entrega: EnderecoSchema }).strict();
const AdminPedido     = AtualizarPedido.extend({ status: z.enum(['enviado', 'cancelado']) }).strict();

const schema = await pode(req.user, 'pedido:gerenciar') ? AdminPedido : AtualizarPedido;
```

### 4. Campos sensíveis definidos pelo servidor

```typescript
const dados = CriarPedido.parse(req.body);
const produtos = await buscarProdutos(dados.itens.map(i => i.produto_id));

await db.pedido.create({
  data: {
    user_id: req.user.id,                 // da sessão
    org_id: orgAtual.id,
    status: 'pendente',
    total: calcularTotal(produtos, dados.itens, dados.cupom), // preço do banco
    itens: { create: dados.itens.map(...) },
  },
});
```

O cliente diz o que quer; o servidor decide quanto custa. Mudanças de estado têm endpoints próprios (`POST /pedidos/:id/cancelar`).

### 5. Escritas aninhadas

Com Prisma, `create({ data: req.body })` aceitaria `{ "autor": { "connect": { "id": "id-de-outro" } } }` ou `{ "org": { "update": { "plano": "enterprise" } } }`. Schemas estritos bloqueiam isso.

### 6. Proteções nativas dos frameworks

**Rails:** Strong Parameters (`params.require(:usuario).permit(:nome, :bio)`). **Laravel:** `$fillable` (evite `$guarded = []`). **Django REST Framework:** `fields` explícitos e `read_only_fields` (nunca `'__all__'` para escrita). **Mongoose:** `strict: true` e nada de `Object.assign(doc, req.body)`. **Sequelize:** opção `fields`.

### 7. Frontend gravando direto no banco

```sql
revoke update on public.perfis from authenticated;
grant update (nome, bio, avatar_url) on public.perfis to authenticated;

create or replace function public.proteger_campos_perfil()
returns trigger language plpgsql as $$
begin
  if auth.role() = 'authenticated' and (
       new.papel is distinct from old.papel or
       new.plano is distinct from old.plano or
       new.id    is distinct from old.id) then
    raise exception 'Alteração de campo protegido não permitida';
  end if;
  return new;
end $$;

create trigger trg_proteger_perfil before update on public.perfis
for each row execute function public.proteger_campos_perfil();
```

No Firestore:

```javascript
allow update: if request.auth.uid == resource.data.userId
  && request.resource.data.diff(resource.data).affectedKeys()
       .hasOnly(['nome', 'bio', 'avatarUrl']);
```

### 8. Não devolver campos demais

O espelho do mass assignment é a exposição excessiva (seção 17). Selecione explicitamente as colunas:

```typescript
const usuario = await db.usuario.findUnique({
  where: { id },
  select: { id: true, nome: true, bio: true, avatar_url: true },
});
```

### 9. Filtros e parâmetros de consulta

Repassar `req.query` para o `where` permite filtrar por campos indevidos. Defina campos filtráveis e ordenáveis. Em JavaScript, cuidado com **prototype pollution** (`__proto__`, `constructor`) em merges com dados do cliente.

### 10. Testar e monitorar

Testes que enviam `papel`, `plano`, `user_id`, `org_id`, `preco` e `status` e confirmam a rejeição; logs de requisições com campos extras; e revisão de código atenta a `data: req.body`, `...req.body`, `Object.assign(model, req.body)`, `fields = '__all__'` e `$guarded = []`.

### Resumo

Schemas estritos com allowlist por operação e papel, campos sensíveis preenchidos pelo servidor, endpoints específicos para mudanças de estado, bloqueio de escritas aninhadas, restrição de colunas e triggers quando o frontend grava direto, schemas de saída, filtros validados e testes com campos proibidos.
