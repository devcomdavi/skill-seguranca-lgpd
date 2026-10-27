# 7. Restringir acessos (RBAC)

### O que é e por que importa

RBAC (controle de acesso baseado em papéis) dá permissões a **papéis** (admin, gerente, atendente, leitor), e os usuários recebem papéis. Em vez de `if`s espalhados pelo código, as regras ficam centralizadas e conceder ou retirar acesso é trocar o papel de alguém. O princípio por trás é o **menor privilégio**, também exigido pela LGPD para dados pessoais.

### Conceitos

Permissões são ações sobre recursos (`fatura:ler`, `fatura:excluir`, `usuario:convidar`); papéis agrupam permissões; usuários recebem papéis.

| Usuário | Papel | Permissões |
| --- | --- | --- |
| Ana | admin | fatura:*, usuario:*, config:\* |
| Bruno | financeiro | fatura:ler, fatura:criar, relatorio:exportar |
| Carla | leitor | fatura:ler |

Em sistemas multi-tenant, o papel vale **dentro de um escopo** (admin da Empresa X, leitora na Y). Papéis internos da plataforma (suporte, operações) ficam separados dos papéis de clientes.

Quando as regras dependem de atributos ("aprova até R$ 5.000", "só edita rascunhos"), entra o **ABAC**; quando dependem de relações ("quem é dono da pasta vê os arquivos"), o **ReBAC**. Na prática, RBAC como base mais algumas regras de atributo ou propriedade, tudo centralizado.

### 1. Desenhar a matriz de permissões

Antes do código, monte a tabela recursos e ações × papéis com quem conhece o negócio. Ela vira especificação, documentação e base dos testes. Comece com poucos papéis; explosão de papéis indica necessidade de ABAC.

### 2. Modelar no banco

```sql
create table public.permissoes (
  id   text primary key,              -- 'fatura:excluir'
  descricao text
);

create table public.papeis (
  id     uuid primary key default gen_random_uuid(),
  org_id uuid references orgs(id),    -- null = papel padrão do sistema
  nome   text not null,
  nivel  int  not null                -- hierarquia: owner 100, admin 80...
);

create table public.papel_permissoes (
  papel_id     uuid references papeis(id) on delete cascade,
  permissao_id text references permissoes(id),
  primary key (papel_id, permissao_id)
);

create table public.membros (
  org_id   uuid references orgs(id),
  user_id  uuid references auth.users(id),
  papel_id uuid references papeis(id),
  primary key (org_id, user_id)
);
```

Com papéis fixos, um `enum` e o mapeamento no código também funcionam.

### 3. Verificar permissões, não papéis

```javascript
// Frágil
if (user.papel === 'admin' || user.papel === 'gerente') { ... }
// Robusto
if (await pode(user, 'fatura:excluir', { orgId })) { ... }
```

### 4. Aplicar em três camadas

**Na API (obrigatório):**

```javascript
export function exigirPermissao(permissao) {
  return async (req, res, next) => {
    const ok = await pode(req.user.id, permissao, req.params.orgId);
    if (!ok) return res.status(403).json({ erro: 'Acesso negado' });
    next();
  };
}

async function pode(userId, permissao, orgId) {
  const { rows } = await db.query(`
    select 1 from membros m
    join papel_permissoes pp on pp.papel_id = m.papel_id
    where m.user_id = $1 and m.org_id = $2 and pp.permissao_id = $3
  `, [userId, orgId, permissao]);
  return rows.length > 0;
}

app.delete('/api/orgs/:orgId/faturas/:id',
  requireAuth, exigirPermissao('fatura:excluir'), excluirFatura);
```

**No banco (rede de segurança):**

```sql
create or replace function public.tem_permissao(p_org uuid, p_perm text)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.membros m
    join public.papel_permissoes pp on pp.papel_id = m.papel_id
    where m.user_id = auth.uid() and m.org_id = p_org and pp.permissao_id = p_perm
  )
$$;

create policy "excluir faturas com permissão"
on public.faturas for delete to authenticated
using ( public.tem_permissao(org_id, 'fatura:excluir') );
```

**Na interface (só experiência):** bibliotecas como **CASL** compartilham as regras entre front e back.

```javascript
import { defineAbility } from '@casl/ability';
const ability = defineAbility((can) => {
  usuario.permissoes.forEach(p => {
    const [recurso, acao] = p.split(':');
    can(acao, recurso);
  });
});
// {ability.can('excluir', 'fatura') && <BotaoExcluir />}
```

### 5. Desempenho: banco ou token

Consultar o banco a cada requisição faz mudanças valerem na hora. Alternativas: cache curto em Redis (invalidado na mudança de papel) ou claims no JWT (mudam só na renovação do token). Claims para alto volume; banco para ações sensíveis. Em remoções urgentes, revogue as sessões.

### 6. Impedir escalada de privilégios

Ninguém concede papel superior ao seu, ninguém altera o próprio papel, a organização nunca fica sem owner, a permissão de gerenciar membros é restrita e o papel não é editável pela rota de perfil.

```javascript
async function alterarPapel(ator, orgId, alvoId, novoPapelId) {
  if (ator.id === alvoId) throw new Error('Não é possível alterar o próprio papel');
  const nivelAtor = await nivelDoUsuario(ator.id, orgId);
  const novoPapel = await buscarPapel(novoPapelId);
  const nivelAlvo = await nivelDoUsuario(alvoId, orgId);
  if (novoPapel.nivel >= nivelAtor || nivelAlvo >= nivelAtor)
    throw new Error('Privilégio insuficiente');
  // ... aplicar e registrar em auditoria
}
```

### 7. Separação de funções

Em processos sensíveis, quem cria um pagamento não o aprova, e alterações financeiras exigem um segundo usuário: permissões distintas por etapa e bloqueio do mesmo usuário nas duas.

### 8. Acesso da equipe interna

Painel interno separado do app (domínio próprio, MFA, SSO ou VPN), suporte com leitura e dados mascarados, e impersonation com justificativa, tempo limitado, aviso visível e auditoria.

### 9. RBAC na infraestrutura

IAM na nuvem com identidades mínimas por serviço, usuários de banco separados (aplicação, migrações, leitura analítica), e poucos administradores com MFA no GitHub, Supabase/Firebase, hospedagem e gateway de pagamento.

### 10. Auditoria e revisão de acessos

Registre toda alteração de acesso e as negações (muitos 403 indicam sondagem), com logs imutáveis. Revise acessos periodicamente e remova tudo no desligamento, no mesmo dia.

### 11. Testar a matriz

Para cada papel, ações permitidas funcionam e proibidas retornam 403; inclua escalada e isolamento entre organizações, rodando no CI.

Ferramentas: **CASL**, **Casbin**, **Oso**, **Cerbos**, **Permit.io**, e **OpenFGA** ou **SpiceDB** para ReBAC.

### Armadilhas comuns

Checagens de papel espalhadas; proteção só na interface; papéis globais num sistema multi-tenant; usuários alterando o próprio papel; organizações sem owner; mesmo "admin" para clientes e equipe; claims válidas após a remoção do acesso; contas compartilhadas; sem log de mudanças; ex-funcionários com acesso.

### Resumo

Matriz de permissões definida com o negócio, papéis com escopo por organização, verificação central de permissões na API e no banco (interface só para experiência), cache ou claims sem perder a revogação, bloqueio de escalada, separação de funções, controle da equipe interna e da infraestrutura, auditoria, revisão periódica e testes.
