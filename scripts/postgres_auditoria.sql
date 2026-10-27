-- Auditoria de configuração de PostgreSQL (somente leitura).
-- Funciona em qualquer Postgres (Supabase, Neon, RDS, Railway, local). No Supabase,
-- rode também supabase_storage.sql. Use o SQL Editor do provedor ou psql e cole os resultados.
-- Os blocos 5 e 8 só retornam linhas onde existe o papel 'anon' (Supabase/PostgREST).
-- Cada bloco retorna linhas apenas quando há algo a revisar.
-- Ajuste a lista de schemas expostos se o projeto expõe outros além de 'public'.

-- 1. Tabelas sem RLS em schemas expostos pela API
select '1_tabela_sem_rls' as verificacao, n.nspname as schema, c.relname as tabela
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p')
  and n.nspname in ('public')
  and not c.relrowsecurity
order by 2, 3;

-- 2. Tabelas com RLS ativa mas nenhuma política (o app fica bloqueado; às vezes é intencional)
select '2_rls_sem_politica' as verificacao, n.nspname as schema, c.relname as tabela
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p')
  and n.nspname in ('public')
  and c.relrowsecurity
  and not exists (select 1 from pg_policies p where p.schemaname = n.nspname and p.tablename = c.relname)
order by 2, 3;

-- 3. Políticas permissivas: condição sempre verdadeira para anon/public/authenticated
select '3_politica_permissiva' as verificacao, schemaname, tablename, policyname, cmd, roles,
       qual as using_expr, with_check
from pg_policies
where schemaname in ('public')
  and (coalesce(trim(qual), '') in ('true', '(true)') or coalesce(trim(with_check), '') in ('true', '(true)'))
order by tablename, policyname;

-- 4. Políticas de UPDATE sem WITH CHECK (usuário pode mover a linha para outro dono)
select '4_update_sem_with_check' as verificacao, schemaname, tablename, policyname, roles, qual
from pg_policies
where schemaname in ('public')
  and cmd in ('UPDATE', 'ALL')
  and with_check is null
order by tablename;

-- 5. Políticas para o papel anon (acesso sem login): revisar se cada uma é intencional
select '5_politica_para_anon' as verificacao, tablename, policyname, cmd, qual
from pg_policies
where schemaname in ('public')
  and ('anon' = any(roles) or 'public' = any(roles))
order by tablename;

-- 6. Funções SECURITY DEFINER em schemas expostos (executam com privilégio do dono)
select '6_security_definer' as verificacao, n.nspname as schema, p.proname as funcao,
       pg_get_function_identity_arguments(p.oid) as argumentos,
       coalesce(array_to_string(p.proconfig, ', '), '(search_path NÃO fixado)') as config,
       case when exists (select 1 from pg_roles where rolname = 'anon')
            then has_function_privilege('anon', p.oid, 'execute') end as anon_executa
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname in ('public')
  and p.prosecdef
order by 3;

-- 7. Views em schemas expostos sem security_invoker (ignoram a RLS de quem consulta; PG15+)
select '7_view_sem_security_invoker' as verificacao, n.nspname as schema, c.relname as view
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('v', 'm')
  and n.nspname in ('public')
  and not coalesce(c.reloptions::text[] && array['security_invoker=true', 'security_invoker=on'], false)
order by 3;

-- 8. Privilégios de escrita do papel anon diretamente nas tabelas
select '8_grant_escrita_anon' as verificacao, table_schema, table_name,
       string_agg(privilege_type, ', ' order by privilege_type) as privilegios
from information_schema.role_table_grants
where grantee = 'anon'
  and table_schema in ('public')
  and privilege_type in ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')
group by 1, 2, 3
order by 3;

-- 12. Colunas que parecem dados pessoais ou sensíveis (insumo do inventário LGPD)
select '12_colunas_dados_pessoais' as verificacao, table_schema, table_name, column_name, data_type
from information_schema.columns
where table_schema in ('public')
  and column_name ~* '(cpf|rg|cnh|passaporte|nascimento|birth|email|telefone|phone|celular|whatsapp|endereco|address|cep|zip|lat|lng|ip_|saude|health|diagnost|doenca|alergi|medic|biometr|selfie|raca|etnia|religi|sexual|genero|gender|renda|salario|cartao|card|pix|senha|password|token|crianca|menor|responsavel)'
order by 3, 4;

-- 13. Extensões instaladas no schema public (recomendado: schema 'extensions')
select '13_extensao_em_public' as verificacao, e.extname, n.nspname
from pg_extension e
join pg_namespace n on n.oid = e.extnamespace
where n.nspname = 'public';
