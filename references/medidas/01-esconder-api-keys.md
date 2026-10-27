# 1. Esconder API keys

### O que é e por que importa

Uma API key é uma credencial: quem a possui consegue agir em nome do seu sistema perante um serviço externo (OpenAI, Stripe, Google Maps, AWS etc.). Se ela vaza, as consequências vão de cobranças altíssimas até vazamento de dados de clientes e invasão de contas. Bots varrem o GitHub o tempo todo procurando chaves expostas, e uma chave publicada costuma ser explorada em minutos.

Os vazamentos mais comuns: chave escrita direto no código e enviada ao repositório, chave no frontend (JavaScript do navegador ou app mobile), chave impressa em logs ou mensagens de erro, e chave exposta em pipelines de CI/CD ou prints de tela.

O princípio central: **tudo que vai para o cliente (navegador ou app) é público**. Não existe forma segura de esconder um segredo no frontend, nem com ofuscação ou variáveis de ambiente do build.

### Camada 1: tirar a chave do código (variáveis de ambiente)

A chave nunca fica no código-fonte. Ela é lida de uma variável de ambiente; em desenvolvimento, fica num arquivo `.env` que nunca é commitado. Crie um `.env.example` com os nomes das variáveis, sem valores.

```bash
# .env  (fora do git)
OPENAI_API_KEY=sk-xxxx

# .gitignore
.env
.env.*
!.env.example
```

```javascript
// Node.js
import 'dotenv/config';
const apiKey = process.env.OPENAI_API_KEY;
if (!apiKey) throw new Error('OPENAI_API_KEY não configurada');
```

```python
# Python
import os
api_key = os.environ["OPENAI_API_KEY"]  # falha cedo se não existir
```

Armadilha frequente: em frameworks de frontend, variáveis com prefixos como `VITE_`, `NEXT_PUBLIC_` ou `REACT_APP_` são embutidas no bundle e ficam visíveis no DevTools. Nunca coloque segredos nelas.

### Camada 2: backend como intermediário (proxy / BFF)

Se o frontend precisa usar uma API paga ou sensível, ele chama o **seu** backend, e só o backend conhece a chave. Isso também permite exigir autenticação, limitar requisições e validar a entrada.

```javascript
import express from 'express';
import rateLimit from 'express-rate-limit';

const app = express();
app.use(express.json());
app.use('/api/', rateLimit({ windowMs: 60_000, max: 20 }));

app.post('/api/chat', requireAuth, async (req, res) => {
  const r = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ model: 'gpt-4o-mini', messages: req.body.messages }),
  });
  res.status(r.status).json(await r.json());
});
```

O proxy não deve repassar qualquer coisa: ele fixa o modelo, limita o tamanho da entrada e exige usuário autenticado, senão vira uma "chave aberta" por outro caminho.

### Camada 3: gerenciador de segredos (produção)

Em produção, guarde as chaves num cofre: AWS Secrets Manager, Google Secret Manager, Azure Key Vault, HashiCorp Vault, Doppler ou Infisical. Eles oferecem criptografia, controle de acesso (IAM), auditoria e rotação.

```python
import boto3, json

def get_secret(name: str) -> dict:
    client = boto3.client("secretsmanager")
    return json.loads(client.get_secret_value(SecretId=name)["SecretString"])

api_key = get_secret("prod/openai")["api_key"]
```

O servidor acessa o cofre por meio de uma identidade (role da instância, service account), sem credencial gravada nele.

### Camada 4: menor privilégio e restrições

Assuma que a chave pode vazar e reduza o estrago: chaves diferentes por ambiente (desenvolvimento, homologação, produção), só as permissões necessárias, restrição por IP, domínio ou app quando o provedor permitir, e limites de gasto com alertas de faturamento.

Chaves que precisam ficar no cliente por natureza (Google Maps JavaScript, "publishable key" do Stripe) dependem dessas restrições de domínio e escopo.

### Camada 5: rotação e revogação

Troque chaves periodicamente e imediatamente quando alguém sai da equipe. O código deve ler a chave em tempo de execução para que a troca não exija deploy. Na rotação: gere a nova, atualize o cofre, confirme o uso da nova e só então revogue a antiga.

### Camada 6: detecção de vazamentos

Use **gitleaks** e **TruffleHog** num hook de pre-commit e no CI, e ative **Secret Scanning** e **Push Protection** no GitHub.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
```

### Camada 7: logs e erros

Não registre cabeçalhos de autorização, corpos completos nem variáveis de ambiente. Mascare campos como `authorization`, `api_key`, `token` e `password`, e não exiba stack traces em produção.

### Camada 8: CI/CD

Guarde segredos nos recursos da plataforma (GitHub Actions Secrets, variáveis protegidas do GitLab) e prefira **OIDC** para obter credenciais temporárias da nuvem, em vez de chaves de longa duração.

### Se uma chave vazar

Primeiro **revogue a chave** e gere outra. Só depois limpe o histórico do git (seção 2), porque a chave continua válida até ser revogada. Verifique os logs de uso do provedor e feche a brecha que causou o vazamento.

### Resumo

Frontend sem segredos chamando o backend; backend lendo chaves de um cofre via identidade do servidor; chaves com escopo mínimo, restrições e limite de gasto; scanners no pre-commit e no CI; logs mascarados; e um procedimento claro de rotação e resposta a incidentes.
