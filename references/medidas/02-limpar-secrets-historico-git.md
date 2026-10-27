# 2. Limpar secrets do histórico do git

### O que é e por que importa

O git guarda **todo o histórico**. Se uma chave foi commitada e apagada num commit seguinte, ela continua acessível em qualquer commit antigo. Limpar secrets do git significa reescrever o histórico para que o valor desapareça de todos os commits, branches e tags.

Mas **limpar o histórico não torna a chave segura de novo**. Se o repositório foi enviado a um servidor, assuma que a chave já foi copiada por bots, clones, forks ou caches. A limpeza impede novas exposições; a correção real é revogar a chave.

### A ordem correta

1. Revogue a chave no provedor e gere uma nova (no cofre ou no `.env`).
2. Verifique nos logs do provedor se houve uso indevido.
3. Só então limpe o histórico.

### Caso simples: o commit ainda não foi enviado

Se o segredo está só no repositório local e no último commit:

```bash
# remova o segredo do arquivo, depois:
git rm --cached .env
echo ".env" >> .gitignore
git add .gitignore
git commit --amend
```

Se está alguns commits atrás, use `git rebase -i HEAD~N`, marque o commit como `edit`, corrija e continue com `git rebase --continue`.

### Caso real: o segredo já foi para o servidor

**Passo 1, mapear tudo que vazou.** O gitleaks varre o histórico inteiro, evitando limpar uma chave e esquecer outras:

```bash
gitleaks detect --source . --log-opts="--all" --report-path vazamentos.json
```

**Passo 2, clone espelho e backup.** A reescrita deve ser feita num clone mirror, que inclui todas as branches, tags e refs:

```bash
git clone --mirror git@github.com:empresa/projeto.git
cp -r projeto.git projeto-backup.git
cd projeto.git
```

**Passo 3, reescrever com git filter-repo.** É a ferramenta recomendada pelo próprio git (substitui o `git filter-branch`). Instale com `pip install git-filter-repo`.

Para substituir o valor do segredo em todo o histórico:

```text
# replacements.txt
sk-proj-abc123SEGREDOREAL==>***REMOVIDO***
regex:AKIA[0-9A-Z]{16}==>***REMOVIDO***
```

```bash
git filter-repo --replace-text ../replacements.txt
```

Para remover um arquivo inteiro de todo o histórico:

```bash
git filter-repo --path .env --path config/credentials.json --invert-paths
```

A substituição de texto serve quando o arquivo deve continuar existindo; a remoção por caminho, quando ele nunca deveria ter entrado. Uma alternativa é o **BFG Repo-Cleaner**, que por padrão não altera o commit mais recente, então corrija o HEAD manualmente antes.

**Passo 4, verificar** antes de publicar:

```bash
git log --all -p | grep "sk-proj-abc123"   # não deve retornar nada
gitleaks detect --source . --log-opts="--all"
```

**Passo 5, publicar.** Desative temporariamente a proteção de branch, avise a equipe e faça o push forçado de todas as refs:

```bash
git push --force --mirror origin
```

**Passo 6, alinhar a equipe.** Clones antigos ainda contêm o segredo e podem reintroduzir o histórico sujo. Todos devem apagar o clone local e clonar de novo; branches não publicadas podem ser salvas com `git format-patch` e reaplicadas.

**Passo 7, caches do servidor.** No GitHub, commits antigos podem continuar acessíveis pelo hash, por refs de pull requests (`refs/pull/*`) e por forks. Abra um chamado no suporte pedindo a limpeza de dados sensíveis e a coleta de lixo. No GitLab, use a limpeza do repositório (Settings → Repository → Repository cleanup, enviando o `commit-map` do filter-repo) e a housekeeping. Forks de terceiros estão fora do seu controle, mais um motivo para revogar.

### Como transformar isso em processo

Documente um runbook de incidente com esses passos, defina quem pode fazer force push e desbloquear proteções, e mantenha os scanners da seção 1. Revise o `.gitignore` com padrões como `.env*`, `*.pem`, `*.key`, `credentials*.json` e `*.p12`, e varra o histórico de repositórios antigos.

### Resumo

Revogar a chave vem antes de tudo. Depois: mapear com gitleaks, clonar em mirror com backup, reescrever com `git filter-repo`, verificar, `push --force --mirror`, fazer a equipe reclonar e pedir ao provedor a limpeza dos caches.
