# 3. Public key do banco de dados (anon key)

### O que é e por que importa

Plataformas como Supabase e Firebase permitem que o frontend fale **diretamente** com o banco, usando uma chave pública (no Supabase, a `anon key` ou `publishable key`; no Firebase, o `apiKey` do config). Essa chave foi feita para ficar no navegador: ela só identifica o projeto. A proteção real está nas **regras de acesso dentro do banco**: Row Level Security (RLS) no Supabase/Postgres e Security Rules no Firebase.

O problema clássico: tabelas criadas sem RLS (ou com uma política "permitir tudo" de teste) e o app publicado. Com a chave pública, qualquer pessoa lê, altera ou apaga todas as linhas, inclusive dados de outros usuários.

Há dois tipos de chave. A **pública** (`anon`/`publishable`) pode ir para o frontend e respeita o RLS. A **de serviço** (`service_role`/`secret` no Supabase, conta de serviço do Firebase Admin) ignora todas as regras e só pode existir no backend.

### 1. Ativar RLS em todas as tabelas

Com RLS ativado e nenhuma política, ninguém acessa nada pela chave pública: tudo bloqueado, depois libera-se só o necessário. Faça isso em toda tabela do schema `public`.

```sql
alter table public.pedidos enable row level security;
alter table public.perfis  enable row level security;
```

### 2. Políticas por operação, ligadas ao usuário

`auth.uid()` retorna o id do usuário logado a partir do token, que o cliente não consegue falsificar.

```sql
create policy "ler proprios pedidos"
on public.pedidos for select to authenticated
using ( auth.uid() = user_id );

create policy "criar proprio pedido"
on public.pedidos for insert to authenticated
with check ( auth.uid() = user_id );

create policy "atualizar proprio pedido"
on public.pedidos for update to authenticated
using ( auth.uid() = user_id )
with check ( auth.uid() = user_id );
```

`using` filtra quais linhas o usuário alcança; `with check` valida o que ele grava. Sem `with check` no `update`, alguém pode trocar o `user_id` de um registro. Evite `using (true)` em tabelas privadas.

### 3. Proteger colunas e permissões especiais

O RLS controla linhas, não colunas. Se `perfis` tem `is_admin` ou `plano`, o usuário pode se promover:

```sql
revoke update on public.perfis from authenticated;
grant update (nome, avatar_url, bio) on public.perfis to authenticated;
```

Outra opção: dados sensíveis (papéis, saldo, plano) numa tabela separada, só de leitura para o cliente.

### 4. Cuidado com funções e views

Funções `security definer` ignoram o RLS. Prefira `security invoker`; quando `security definer` for necessária, valide `auth.uid()` dentro dela e defina `set search_path = ''`. Views também podem contornar o RLS; no Postgres 15+ use `with (security_invoker = true)`.

### 5. Storage (arquivos)

Buckets públicos deixam qualquer arquivo acessível por URL. Para documentos de usuários, use buckets privados com políticas por pasta:

```sql
create policy "usuario acessa sua pasta"
on storage.objects for select to authenticated
using ( bucket_id = 'documentos'
        and (storage.foldername(name))[1] = auth.uid()::text );
```

### 6. Operações sensíveis passam pelo backend

Pagamentos, mudança de plano, envio de e-mails, cálculos de preço e regras críticas vão para um backend ou Edge Function, que valida e só então usa a chave de serviço.

### 7. O equivalente no Firebase

O erro comum é publicar com as regras de "modo de teste".

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{db}/documents {
    match /pedidos/{pedidoId} {
      allow read, update, delete: if request.auth != null
                                  && request.auth.uid == resource.data.userId;
      allow create: if request.auth != null
                    && request.auth.uid == request.resource.data.userId;
    }
  }
}
```

Ative também o **App Check**, que dificulta chamadas feitas fora do app oficial.

### 8. Testar e auditar

Teste tentando violar as regras: logado como A, tente ler, editar e apagar dados de B; sem login, tente acessar só com a chave pública. Use o **Security Advisor** do Supabase e o **Rules Playground** e o emulador do Firebase, com testes no CI. Configure limites de requisição e de cadastro e mantenha os logs ativos.

### Resumo

A chave pública pode ficar no frontend, mas só é segura com regras no banco: RLS em todas as tabelas, políticas com `using` e `with check` ligadas a `auth.uid()`, proteção de colunas, cuidado com `security definer` e views, buckets privados, operações críticas no backend, chave de serviço jamais no cliente, e testes que tentam quebrar as regras.
