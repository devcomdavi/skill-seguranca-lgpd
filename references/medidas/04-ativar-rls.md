# 4. Ativar RLS (Row Level Security)

### O que é e como funciona

RLS é um recurso nativo do PostgreSQL que filtra **linhas** de acordo com quem consulta. Quando ativado, o Postgres adiciona as condições das políticas a toda consulta: um `select * from pedidos` vira, na prática, `select * from pedidos where auth.uid() = user_id`. A regra fica no banco, então vale mesmo se um endpoint esquecer o filtro.

Comportamentos importantes: com RLS ativado e nenhuma política, tudo é negado. O RLS age conforme o papel do Postgres; no Supabase as requisições chegam como `anon`, `authenticated` ou `service_role` (este com `BYPASSRLS`). E o **dono da tabela** ignora o RLS, a menos que você use `FORCE`:

```sql
alter table public.pedidos enable row level security;
alter table public.pedidos force row level security;  -- vale até para o dono
```

### O que cada operação exige

| Operação | Cláusulas usadas |
| --- | --- |
| select | `using` (quais linhas são visíveis) |
| insert | `with check` (a linha nova é válida?) |
| update | `using` (o que pode ser alterado) e `with check` (como pode ficar) |
| delete | `using` |

Um `update` ou `delete` só alcança linhas visíveis pela política de `select`, e um `upsert` precisa de `insert`, `update` e `select`. Quando "o update não faz nada e não dá erro", geralmente falta a política de `select`.

Políticas **permissivas** são combinadas com OR; **restritivas**, com AND. As restritivas servem para regras globais:

```sql
create policy "ocultar excluidos"
on public.pedidos as restrictive
for all to authenticated
using ( deleted_at is null );
```

### Padrões de políticas

**Dono do registro:** `using (auth.uid() = user_id)`.

**Multi-tenant (empresas, equipes):** a tabela de vínculo é a fonte da verdade. Uma função auxiliar evita repetição e recursão infinita:

```sql
create table public.membros (
  org_id  uuid references orgs(id),
  user_id uuid references auth.users(id),
  papel   text check (papel in ('admin','membro','leitor')),
  primary key (org_id, user_id)
);

create or replace function public.orgs_do_usuario()
returns setof uuid
language sql stable security definer set search_path = ''
as $$
  select org_id from public.membros where user_id = auth.uid()
$$;

create policy "ver projetos da minha org"
on public.projetos for select to authenticated
using ( org_id in (select public.orgs_do_usuario()) );
```

O `security definer` aqui é controlado: só retorna dados do próprio usuário, não recebe parâmetros e tem `search_path` fixo. Coloque essas funções num schema não exposto pela API se quiser impedir chamadas diretas.

**Papéis:**

```sql
create policy "apenas admins apagam projetos"
on public.projetos for delete to authenticated
using ( exists (
  select 1 from public.membros m
  where m.org_id = projetos.org_id
    and m.user_id = auth.uid()
    and m.papel = 'admin'
));
```

Papéis em custom claims do JWT (`auth.jwt() ->> 'papel'`) evitam consultas, mas só mudam quando o token é renovado. Nunca use `user_metadata` para autorização (o usuário pode alterá-lo); use `app_metadata` ou uma tabela.

**Conteúdo público com escrita restrita:**

```sql
create policy "qualquer um le artigos publicados"
on public.artigos for select to anon, authenticated
using ( publicado = true );

create policy "autor gerencia seus artigos"
on public.artigos for all to authenticated
using ( autor_id = auth.uid() )
with check ( autor_id = auth.uid() );
```

### Desempenho

Crie índices nas colunas usadas nas políticas, envolva funções em `select` (calculadas uma vez por consulta) e especifique o papel com `to authenticated`. Repetir o filtro na consulta da aplicação também ajuda o planejador.

```sql
create index on public.pedidos (user_id);
create index on public.projetos (org_id);
-- na política:
using ( (select auth.uid()) = user_id )
```

### Ativando num sistema em produção

Mapeie as tabelas desprotegidas:

```sql
select schemaname, tablename
from pg_tables
where schemaname = 'public' and rowsecurity = false;
```

Para cada tabela, liste como o app a usa, escreva as políticas antes de ativar, teste em homologação com cópia do banco e leve à produção numa migração, ativando RLS e políticas na mesma transação. Se o banco está totalmente aberto agora, ative imediatamente nas tabelas mais sensíveis e ajuste depois.

### Garantir que nenhuma tabela nova fique sem RLS

Um event trigger ativa o RLS automaticamente em toda tabela criada no `public`:

```sql
create or replace function public.auto_enable_rls()
returns event_trigger language plpgsql as $$
declare obj record;
begin
  for obj in select * from pg_event_trigger_ddl_commands()
             where command_tag = 'CREATE TABLE' and schema_name = 'public'
  loop
    execute format('alter table %s enable row level security', obj.object_identity);
  end loop;
end $$;

create event trigger trg_auto_rls on ddl_command_end
when tag in ('CREATE TABLE')
execute function public.auto_enable_rls();
```

Complemente com uma verificação no CI que falha se a consulta de tabelas sem RLS retornar linhas, e com o Security Advisor do Supabase.

### Testando as políticas

```sql
begin;
set local role authenticated;
set local request.jwt.claims = '{"sub":"<uuid-do-usuario-A>"}';

select count(*) from public.pedidos;                -- só os pedidos de A
update public.pedidos set valor = 0
  where user_id = '<uuid-do-usuario-B>';           -- deve afetar 0 linhas
rollback;
```

Para uma suíte completa, use **pgTAP** (`supabase test db`) com casos como "A não vê dados de B", "anônimo não lê perfis" e "usuário não altera o próprio papel", rodando no CI a cada migração.

### Armadilhas comuns

Políticas `using (true)` esquecidas; `update` sem `with check`; autorização via `user_metadata`; views sem `security_invoker`; funções `security definer` que recebem um id e devolvem dados de qualquer usuário; backend conectado como dono da tabela; recursão infinita em políticas.

### Resumo

RLS em todas as tabelas expostas (com `FORCE` quando necessário), políticas por operação com `using` e `with check`, restritivas para regras globais, funções auxiliares para multi-tenant e papéis, índices e `(select auth.uid())` para desempenho, migração planejada, event trigger e checagem no CI, e testes automatizados.
