# 13. Queries parametrizadas (prevenção de SQL injection)

### O que é e por que importa

Queries parametrizadas escrevem a consulta com marcadores (`$1`, `?`) e enviam os valores **separadamente**; o banco nunca confunde dado com código. Elas impedem o SQL injection, que nasce da concatenação:

```javascript
// VULNERÁVEL
const sql = `SELECT * FROM usuarios WHERE email = '${email}' AND senha_hash = '${hash}'`;
```

Com o e-mail `' OR '1'='1' --`, a consulta vira sempre verdadeira e ignora a senha. Além de entrar no sistema, o atacante pode ler qualquer tabela, alterar ou apagar dados e, em alguns bancos, executar comandos no servidor, anulando RLS, RBAC e criptografia.

### Variações do ataque

**Clássica** (resultado na tela), **UNION-based** (anexa dados de outra tabela), **baseada em erro** (mensagens revelam estrutura e dados), **blind** e **time-based** (perguntas de sim ou não, com `pg_sleep`; o sqlmap extrai bancos inteiros assim), **stacked queries** (`; DROP TABLE pedidos; --`) e **second-order** (valor gravado com segurança, depois concatenado em outra consulta).

### Por que parametrizar, e não escapar

Filtros de aspas e palavras-chave são frágeis: regras variam por banco e contexto, há codificações alternativas, um ponto esquecido basta, e quebram dados legítimos como *D'Ávila*. Com parâmetros, o banco interpreta a estrutura e só depois recebe os valores, sempre como dados.

### Como implementar por linguagem

```javascript
// Node + PostgreSQL (pg)
const { rows } = await pool.query(
  'SELECT id, nome FROM usuarios WHERE email = $1 AND ativo = $2', [email, true]);

// Node + MySQL (mysql2): prefira execute; mantenha multipleStatements desligado
const [rows] = await conn.execute(
  'SELECT id, nome FROM usuarios WHERE email = ? AND ativo = ?', [email, true]);
```

```python
# psycopg: SEGURO, valores no segundo argumento
cur.execute("SELECT id, nome FROM usuarios WHERE email = %s AND ativo = %s", (email, True))

# VULNERÁVEL: f-string ou % formatam antes do driver
cur.execute(f"SELECT * FROM usuarios WHERE email = '{email}'")
cur.execute("SELECT * FROM usuarios WHERE email = '%s'" % email)

# SQLAlchemy
from sqlalchemy import text
conn.execute(text("SELECT id, nome FROM usuarios WHERE email = :email"), {"email": email})
```

Um único valor em Python vai como tupla: `(email,)`.

```java
// Java (JDBC)
String sql = "SELECT id, nome FROM usuarios WHERE email = ? AND ativo = ?";
try (PreparedStatement ps = conn.prepareStatement(sql)) {
    ps.setString(1, email);
    ps.setBoolean(2, true);
    ResultSet rs = ps.executeQuery();
}
```

```php
// PHP (PDO)
$pdo = new PDO($dsn, $user, $pass, [
    PDO::ATTR_EMULATE_PREPARES => false,
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
]);
$stmt = $pdo->prepare('SELECT id, nome FROM usuarios WHERE email = :email');
$stmt->execute(['email' => $email]);
```

```go
// Go
row := db.QueryRowContext(ctx, "SELECT id, nome FROM usuarios WHERE email = $1", email)
```

```csharp
// C# (Dapper)
var usuario = await conn.QuerySingleOrDefaultAsync<Usuario>(
    "SELECT id, nome FROM usuarios WHERE email = @Email", new { Email = email });
```

### ORMs e query builders: seguros, com exceções

Operações comuns são parametrizadas; o risco está nas portas de SQL bruto.

```typescript
// Prisma: tagged template é seguro
const r = await prisma.$queryRaw`SELECT * FROM usuarios WHERE email = ${email}`;
// VULNERÁVEL
const r2 = await prisma.$queryRawUnsafe(`SELECT * FROM usuarios WHERE email = '${email}'`);
// Aceitável só com parâmetros posicionais
const r3 = await prisma.$queryRawUnsafe('SELECT * FROM usuarios WHERE email = $1', email);
```

Chamar `$queryRaw` com parênteses perde a proteção. **Drizzle:** `sql` parametriza; `sql.raw()` não. **Knex:** `knex.raw('... ?', [email])` sim; interpolação não (vale para `whereRaw`, `orderByRaw`). **Sequelize:** `replacements`/`bind` sim; `Sequelize.literal()` com entrada não. **TypeORM:** `.where('email = :email', { email })`. **Django:** `raw()` e `cursor.execute()` com parâmetros; evite `extra()` e `RawSQL` interpolados. **Laravel:** `DB::select('... ?', [$email])`; cuidado com `whereRaw`, `orderByRaw`, `DB::raw`.

Regra de revisão: funções com `raw`, `unsafe`, `literal` ou `execute` no nome, e qualquer interpolação (`${}`, f-string, `+`, `.format()`, `%`) dentro de SQL, são alertas.

### Supabase e filtros em texto

O `.or()` do cliente Supabase recebe uma string de filtros; montá-la com a busca do usuário permite injetar condições:

```javascript
// VULNERÁVEL: o usuário pode digitar algo como  x,user_id.neq.0
supabase.from('pedidos').select().or(`titulo.ilike.%${busca}%,descricao.ilike.%${busca}%`);
```

Sanitize vírgulas, parênteses e pontos, ou mova a busca para uma função chamada com `.rpc()`. O RLS limita o estrago.

### Identificadores e estrutura: allowlist

Parâmetros servem para valores, não para nomes de colunas, direção de ordenação ou palavras-chave:

```javascript
const COLUNAS_ORDENAVEIS = { nome: 'nome', preco: 'preco', recentes: 'created_at' };
const DIRECOES = { asc: 'ASC', desc: 'DESC' };

const coluna  = COLUNAS_ORDENAVEIS[req.query.ordenar] ?? 'created_at';
const direcao = DIRECOES[req.query.direcao] ?? 'DESC';
const limite  = Math.min(Math.max(parseInt(req.query.limite) || 20, 1), 100);

const { rows } = await pool.query(
  `SELECT id, nome, preco FROM produtos
   WHERE categoria_id = $1
   ORDER BY ${coluna} ${direcao}
   LIMIT $2`,
  [categoriaId, limite]
);
```

Para identificadores realmente dinâmicos: `format('%I', ...)` ou `quote_ident()` no PostgreSQL, `pg-format` ou `escapeIdentifier()` no Node, `psycopg.sql.Identifier` em Python.

**Listas no IN:**

```javascript
await pool.query('SELECT * FROM produtos WHERE id = ANY($1::uuid[])', [ids]);        // PostgreSQL
const marcadores = ids.map(() => '?').join(',');                                       // MySQL
await conn.execute(`SELECT * FROM produtos WHERE id IN (${marcadores})`, ids);
```

**Curingas no LIKE:**

```javascript
const termo = busca.replace(/[\\%_]/g, (c) => '\\' + c);
await pool.query("SELECT * FROM produtos WHERE nome ILIKE $1 ESCAPE '\\'", [`%${termo}%`]);
```

### SQL dinâmico dentro do banco

```sql
-- VULNERÁVEL
EXECUTE 'SELECT * FROM ' || nome_tabela || ' WHERE email = ''' || p_email || '''';
-- SEGURO
EXECUTE format('SELECT * FROM %I WHERE email = $1', nome_tabela) USING p_email;
```

Especialmente importante em funções `security definer`.

### NoSQL injection

```javascript
// VULNERÁVEL: { "senha": { "$ne": null } } passa
const usuario = await db.collection('usuarios').findOne({
  email: req.body.email, senha: req.body.senha,
});
```

Valide tipos com schemas, use `mongo-sanitize` ou `sanitizeFilter` do Mongoose, nunca `$where` com entrada do usuário, e compare senhas pelo hash. O mesmo vale para objetos de filtro de ORMs (`where` vindo de `req.body`).

### Defesa em profundidade

Usuário do banco com menor privilégio (sem ser dono nem superusuário), um comando por chamada, erros genéricos, validação de entrada, WAF (Cloudflare, AWS WAF, ModSecurity com OWASP CRS) e RLS.

### Detecção e testes

Semgrep, CodeQL, Bandit (B608), SonarQube e lint no CI. Testes enviando `' OR '1'='1' --`, `'; DROP TABLE x; --`, `' UNION SELECT ...`, `{"$ne": null}` e colunas inexistentes na ordenação, esperando resultado vazio ou erro de validação, e dados legítimos como *D'Ávila* funcionando. sqlmap, OWASP ZAP e Burp Suite, só em ambientes autorizados.

### Resumo

Marcadores do driver com valores separados, cuidado redobrado com SQL bruto nos ORMs, allowlist para colunas e ordenação, recursos próprios para `IN` e `LIKE`, `EXECUTE ... USING` no banco, validação contra NoSQL injection e, em profundidade, menor privilégio, erros genéricos, WAF, RLS, análise estática e testes.
