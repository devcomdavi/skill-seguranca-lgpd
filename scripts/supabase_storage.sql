-- Auditoria do Storage do Supabase (somente leitura). Complementa postgres_auditoria.sql.
-- Só funciona em projetos Supabase (schema 'storage').

-- 9. Buckets de storage públicos (qualquer pessoa com a URL lê os arquivos)
select '9_bucket_publico' as verificacao, id, name, public, file_size_limit, allowed_mime_types
from storage.buckets
where public
order by name;

-- 10. Buckets sem limite de tamanho ou de tipo
select '10_bucket_sem_limites' as verificacao, id, name, file_size_limit, allowed_mime_types
from storage.buckets
where file_size_limit is null or allowed_mime_types is null
order by name;

-- 11. Políticas de storage.objects (conferir se restringem à pasta/dono)
select '11_politicas_storage' as verificacao, policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'storage' and tablename = 'objects'
order by policyname;

