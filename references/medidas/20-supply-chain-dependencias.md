# 20. Golpes e ataques via dependências (supply chain)

### O que é e por que importa

Sistemas modernos são feitos em grande parte de código de terceiros, e cada pacote roda com o mesmo poder do seu código, inclusive executando scripts na instalação. Ataques de cadeia de suprimentos colocam código malicioso em algo que você instala voluntariamente, atingindo milhares de empresas de uma vez.

| Ano | Caso | O que aconteceu |
| --- | --- | --- |
| 2025 | chalk, debug e Shai-Hulud (npm) | Phishing de mantenedor seguido de worm que roubava tokens e se replicava |
| 2025 | tj-actions/changed-files | Ação do GitHub alterada para vazar segredos de CI |
| 2024 | polyfill.io | Domínio de CDN vendido passou a servir código malicioso |
| 2024 | xz utils | Porta dos fundos inserida após cerca de dois anos ganhando confiança |
| 2022 | colors, faker, node-ipc | Protestware de mantenedores |
| 2021 | ua-parser-js | Pacote sequestrado para instalar mineradores e ladrões de senha |
| 2018 | event-stream | Novo mantenedor roubava carteiras de criptomoedas |

### Como os ataques acontecem

**Typosquatting** (`expres`, `crossenv`); **slopsquatting** (pacotes sugeridos por IA que não existiam, registrados por atacantes); **dependency confusion** (pacote público com o nome do seu pacote interno e versão maior); **sequestro de contas de mantenedores**; **mantenedores maliciosos** ou projetos transferidos; **ataques de longo prazo à confiança**; **scripts de instalação** (`preinstall`, `postinstall`, `setup.py`) que roubam credenciais só por instalar; **infraestrutura de build** (ações de CI, imagens, plugins, CDNs, extensões de editor); e **starjacking** (metadados apontando para o repositório de outro projeto).

### Camada 1: pensar antes de adicionar

A dependência mais segura é a que não existe. Ao adicionar, avalie: nome exato na documentação oficial (nunca só por sugestão de IA), popularidade e idade, manutenção e número de mantenedores, repositório correspondente, comportamento (scripts, rede, código ofuscado) e proveniência. Ferramentas: **Socket**, **OpenSSF Scorecard**, **deps.dev**, **Snyk Advisor**. Dependências novas por pull request, com `CODEOWNERS` nos manifestos e lockfiles.

### Camada 2: lockfiles e instalação determinística

Lockfile sempre no repositório e instalação congelada no CI e na produção:

```bash
npm ci                              # nunca "npm install" no CI
pnpm install --frozen-lockfile
yarn install --immutable
poetry install --sync               # ou: uv sync --locked
composer install                    # nunca "composer update" no deploy
bundle install --frozen
```

```bash
npx lockfile-lint --path package-lock.json --type npm \
  --allowed-hosts npm --validate-https --validate-integrity
```

```text
# requirements.txt com hashes (pip-compile --generate-hashes; instalar com --require-hashes)
requests==2.32.3 \
    --hash=sha256:70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6
```

### Camada 3: não instalar versões recém-publicadas

A maioria das versões maliciosas é removida em horas ou dias; espere alguns dias. Os nomes das opções mudam entre versões, então confirme na documentação:

```yaml
# pnpm-workspace.yaml (pnpm 10.16+)
minimumReleaseAge: 4320   # minutos (3 dias)
```

```json
{
  "extends": ["config:recommended"],
  "minimumReleaseAge": "7 days",
  "packageRules": [
    { "matchUpdateTypes": ["major"], "dependencyDashboardApproval": true }
  ]
}
```

Yarn recente, `uv` (`exclude-newer`), npm (`--before`) e Dependabot (*cooldown*) têm recursos equivalentes. Exceções só para correções urgentes verificadas.

### Camada 4: bloquear scripts de instalação

```yaml
# pnpm-workspace.yaml (pnpm 10 não executa scripts por padrão)
onlyBuiltDependencies:
  - esbuild
  - sharp
```

```ini
# .npmrc
ignore-scripts=true
```

```bash
npm ci --ignore-scripts
npm rebuild sharp esbuild
```

`@lavamoat/allow-scripts` ajuda a gerenciar a allowlist; no Python, prefira wheels (`--only-binary :all:`).

### Camada 5: impedir confusão de dependências

Use escopos que você controla e registre-os no registro público, com cada escopo apontando só para o registro correto:

```ini
# .npmrc
@suaempresa:registry=https://npm.pkg.github.com/
//npm.pkg.github.com/:_authToken=${NPM_TOKEN}
```

Reserve nomes internos no registro público ou use um registro intermediário (Artifactory, Nexus, Verdaccio, CodeArtifact, Artifact Registry) como fonte única. Evite `--extra-index-url` no pip.

### Camada 6: proveniência

Proveniência prova de qual repositório, commit e pipeline o pacote veio.

```bash
npm audit signatures
```

PyPI tem attestations via Trusted Publishing; SLSA define níveis de garantia; Cosign assina imagens. Um pacote que perde a proveniência é alerta forte.

### Camada 7: escanear continuamente

```bash
npm audit --omit=dev
pip-audit
osv-scanner scan -r .
composer audit
bundle audit
govulncheck ./...
cargo audit
```

Dependabot ou Renovate, GitHub Dependency Review, Snyk, Socket e Mend. Exemplo de workflow, com cada ação fixada pelo SHA completo do commit da versão que você auditou (os valores entre < > são placeholders: não copie hashes de guias, consulte o repositório oficial da ação e confira o commit da tag no momento da configuração):

```yaml
name: dependencias
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  revisao:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha-da-versao-auditada>                # vX.Y.Z
      - uses: actions/dependency-review-action@<sha-da-versao-auditada> # vX.Y.Z
        with:
          fail-on-severity: high
          comment-summary-in-pr: always
```

O comentário com a versão ao lado do SHA mantém a leitura fácil, e o Dependabot ou o Renovate atualizam os dois juntos, por pull request, quando sair uma versão nova.

Priorize vulnerabilidades em produção, alcançáveis e exploradas (catálogo KEV da CISA, EPSS), com prazos por severidade.

### Camada 8: SBOM

```bash
npx @cyclonedx/cyclonedx-npm --output-file sbom.json
syft dir:. -o cyclonedx-json > sbom.json
syft minha-imagem:1.4.2 -o spdx-json > sbom-imagem.json
```

Gere a cada build e centralize no **Dependency-Track** para saber em minutos se está afetado.

### Camada 9: proteger o CI/CD

Ações e componentes fixados por **SHA**; `permissions` mínimas; segredos fora das etapas que instalam dependências; nada de `pull_request_target` executando código de PR externo; OIDC para a nuvem; runners efêmeros com controle de rede (**Harden-Runner**); análise dos workflows com **zizmor** e **actionlint**.

### Camada 10: máquinas dos desenvolvedores

Dev containers, credenciais curtas (`aws sso login`), nada de `.env` de produção local, tokens de npm e GitHub com escopo e validade limitados, chaves SSH protegidas, extensões de editor mínimas e verificadas, e revisão dos pacotes adicionados por assistentes e agentes de IA.

### Camada 11: se você publica pacotes

MFA resistente a phishing (chaves físicas, passkeys), publicação só pelo CI com Trusted Publishing (OIDC), proveniência em cada versão, poucos mantenedores com revisão periódica, domínio de e-mail protegido e monitoramento de publicações.

### Camada 12: imagens de container

Imagens oficiais e mínimas (distroless, Alpine, Chainguard, Wolfi, slim), fixadas por digest, escaneadas (Trivy, Grype, Docker Scout, scanners dos registros) e reconstruídas periodicamente.

```dockerfile
FROM node:22-alpine@sha256:<digest-verificado>
```

### Camada 13: scripts no navegador

Prefira hospedar as bibliotecas; com CDN, use SRI e versão exata, mais CSP estrita.

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/dayjs/1.11.13/dayjs.min.js"
        integrity="sha384-<hash-do-arquivo>"
        crossorigin="anonymous"></script>
```

### Camada 14: limitar o estrago em tempo de execução

Controle de saída de rede, menor privilégio no processo e na nuvem, modelos de permissão (`--permission` no Node, permissões do Deno) e segredos mínimos no ambiente.

### Quando uma dependência maliciosa é descoberta

1. **Verifique a exposição** com SBOM e lockfiles: projetos, máquinas, pipelines, imagens e datas.
2. **Assuma comprometimento** de todo ambiente onde houve instalação e troque todas as credenciais acessíveis, das mais privilegiadas primeiro.
3. **Contenha e limpe:** versão segura, lockfiles regenerados, artefatos reconstruídos de ambientes limpos, máquinas e runners refeitos.
4. **Investigue** uso das credenciais, tokens, usuários, repositórios e workflows criados, e publicações não autorizadas.
5. **Comunique** conforme a seção 15 (ANPD e titulares, clientes afetados).

Acompanhe avisos do GitHub, OSV e blogs de Socket, Snyk, Aikido, StepSecurity e Wiz.

### Testar e auditar

CI falhando com lockfile ausente ou desatualizado, registros não permitidos, vulnerabilidades altas em produção, ações sem SHA ou scripts fora da allowlist. Revise periodicamente dependências abandonadas ou sem uso (**depcheck**, **knip**, **deptry**).

### Resumo

Menos dependências e avaliação de cada uma; lockfiles e instalação congelada; idade mínima de versões; scripts bloqueados; escopos e registros contra confusão; proveniência; SCA contínua e SBOM; CI com SHAs, permissões mínimas, OIDC e controle de rede; máquinas isoladas; publicação segura; imagens mínimas por digest; SRI e CSP; menor privilégio em produção; e um plano de resposta que troca todas as credenciais.
