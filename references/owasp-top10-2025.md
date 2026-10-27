# OWASP Top 10:2025: roteiro de revisão

Fonte oficial (leia a página da categoria quando precisar de detalhe): https://top10.owasp.org/2025/

Para cada categoria: a pergunta de revisão, onde olhar num sistema vibecodado e a medida de `medidas/` que traz a correção. A revisão é defensiva: confirmar que o controle existe e funciona, e implementá-lo quando faltar.

| Categoria | Pergunta de revisão | Onde olhar | Correção |
|---|---|---|---|
| [A01 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/) | Cada rota, server action, função e tabela confere **no servidor** quem é o usuário e se o recurso pertence a ele (ou à empresa dele)? | Rotas de API, server actions, RLS/regras do Firebase, buckets de storage, rotas admin, exportações, CORS | 03, 04, 06 (seção 4), 07, 17 |
| [A02 Security Misconfiguration](https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/) | O ambiente de produção está endurecido: sem debug, sem erros detalhados, sem segredos públicos, com cabeçalhos, previews protegidos e credenciais diferentes por ambiente? | `.env*`, variáveis com prefixo público, configuração do provedor, cabeçalhos HTTP, source maps | 01, 15, 18, 19 |
| [A03 Software Supply Chain Failures](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) | Toda dependência existe, é oficial, está fixada no lockfile, sem CVE alcançável, e o CI é tão protegido quanto a produção? | `package.json`, lockfile, `requirements`, `.github/workflows`, scripts de CDN | 20 |
| [A04 Cryptographic Failures](https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/) | Senhas com hash adaptativo, dados sensíveis cifrados, tokens gerados com aleatoriedade criptográfica, TLS em todas as conexões? | Cadastro/login próprios, geração de tokens e códigos, colunas com CPF/saúde/documentos | 05, 10, 19 |
| [A05 Injection](https://top10.owasp.org/2025/A05_2025-Injection/) | Todo dado externo chega a SQL, HTML, shell ou template de forma parametrizada ou com escape no contexto certo? | Queries montadas com texto, renderização de HTML/Markdown, chamadas de processo | 13, 14, 18 |
| [A06 Insecure Design](https://top10.owasp.org/2025/A06_2025-Insecure_Design/) | Os fluxos de dinheiro, permissão e dados pessoais têm regras aplicadas no servidor, limites e estados que não podem ser pulados? | Checkout e webhooks, créditos/saldo, cupons, convites, multi-empresa, uploads, custo de IA | 11, 16; ver `construcao-segura.md` (modelo de ameaças) |
| [A07 Authentication Failures](https://top10.owasp.org/2025/A07_2025-Authentication_Failures/) | A autenticação é de um provedor confiável, o token é verificado no servidor, há limite de tentativas, sessão que expira e MFA para contas privilegiadas? | Middleware de auth, login, recuperação de senha, sessões, contas admin | 06, 09, 10, 11, 12 |
| [A08 Software or Data Integrity Failures](https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/) | O servidor só aceita os campos que o cliente pode alterar, verifica assinatura de webhooks e não confia em dados serializados vindos do cliente? | Updates com o body inteiro, campos `role`/`plan`/`credits`, webhooks de pagamento | 08, 17, 20 |
| [A09 Security Logging and Alerting Failures](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | Eventos de segurança são registrados sem dados pessoais desnecessários, guardados com integridade e geram alerta quando algo anormal acontece? | Logger, tabela de auditoria, alertas, retenção de logs | 15; ver abaixo |
| [A10 Mishandling of Exceptional Conditions](https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/) | Erros são tratados num lugar central, devolvem mensagem genérica, desfazem transações pela metade e o sistema falha fechado? | Tratador global de erros, `catch` vazios, transações, limites de recursos | 14, 15; ver abaixo |

## A09: o que registrar e como

O guia de 20 medidas trata logs só pelo lado do vazamento (medida 15). Para cobrir A09:

- **Registrar:** login com sucesso e falha, logout, troca de senha/e-mail/MFA, negação de acesso (403), mudança de papel ou permissão, exportação e exclusão de dados pessoais, ações administrativas, pedidos de titulares (LGPD), falhas de validação repetidas, webhooks rejeitados.
- **Formato:** estruturado (JSON) com horário UTC, ID do usuário, ID da requisição, ação, recurso, resultado e IP. Escape de quebras de linha no conteúdo vindo do usuário.
- **Não registrar:** senha, token, chave, número completo de cartão, conteúdo de dado sensível. Mascarar CPF e e-mail quando o log não precisa deles.
- **Integridade:** trilha de auditoria em tabela append-only (sem `update`/`delete` para a aplicação) ou serviço de logs externo; logs não ficam só no disco do servidor.
- **Alertas:** pelo menos para picos de login com falha, muitos 403 do mesmo usuário, exportações em massa e erros 5xx em sequência. Alguém precisa receber e olhar.
- **Retenção:** o Marco Civil da Internet (art. 15) obriga provedores de aplicação constituídos como pessoa jurídica com fins econômicos a guardar registros de acesso (data, hora e IP) por 6 meses, em sigilo. Logs com dados pessoais além disso seguem a retenção definida no inventário de dados (LGPD).

## A10: tratamento de erros

- Um tratador global de erros por aplicação: registra o erro completo no log interno e devolve ao usuário mensagem genérica com um ID de correlação.
- Nenhum `catch` vazio; erro de autorização, de validação e de infraestrutura tratados de forma diferente.
- Operações com vários passos (debitar e creditar, criar pedido e reservar estoque) dentro de transação; em erro, rollback completo.
- Falhar fechado: se a checagem de permissão, o serviço de rate limit ou a verificação de assinatura falhar, a ação é negada.
- Limites em tudo: tamanho de body, de upload, de página, tempo de execução, chamadas a IA.

## Teste de autorização (A01, A06, A07)

O teste mais valioso numa auditoria de sistema vibecodado. Crie duas contas de teste (A e B) e, se houver papéis, uma conta comum e uma admin, em staging. Para cada recurso privado de A, confirme que B recebe 403 ou 404 ao ler, alterar ou excluir; que a conta comum não chega às funções admin; e que sem login nada privado responde. Transforme esses casos em testes automatizados (integração) para que a correção não regrida. O Strix faz isso de forma dinâmica quando recebe as duas contas (ver `strix.md`).
