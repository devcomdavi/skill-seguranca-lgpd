#!/usr/bin/env python3
"""Procura segredos expostos: no código, em builds do frontend, em .env versionado e no histórico do git.

Uso: python3 scan_secrets.py <dir> [--git] [--saida segredos.json]

Os valores encontrados são mascarados na saída. Se o gitleaks estiver instalado,
ele também é executado e os resultados são somados.
Qualquer segredo que já esteve no git ou num bundle público deve ser ROTACIONADO.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from comum import achado, iterar_arquivos, ler, mascarar, rel, salvar  # noqa: E402

FONTE = "scan_secrets"

# (regra, título, regex, severidade)
PADROES = [
    ("openai-key", "Chave da OpenAI", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}", "critica"),
    ("anthropic-key", "Chave da Anthropic", r"\bsk-ant-[A-Za-z0-9_\-]{20,}", "critica"),
    ("google-api-key", "Chave de API do Google", r"\bAIza[0-9A-Za-z_\-]{35}\b", "media"),
    ("aws-access-key", "Chave de acesso da AWS", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "critica"),
    ("stripe-secret", "Chave secreta do Stripe", r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}", "critica"),
    ("stripe-test", "Chave secreta de teste do Stripe", r"\bsk_test_[0-9A-Za-z]{20,}", "media"),
    ("github-token", "Token do GitHub", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{50,}", "critica"),
    ("slack-token", "Token do Slack", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}", "alta"),
    ("sendgrid-key", "Chave do SendGrid", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", "alta"),
    ("resend-key", "Chave do Resend", r"\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}", "alta"),
    ("private-key", "Chave privada", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "critica"),
    ("db-url", "String de conexão com senha", r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:'\"@/]+:[^\s'\"@/]{3,}@[^\s'\"]+", "critica"),
    ("supabase-secret", "Chave secreta do Supabase", r"\bsb_secret_[A-Za-z0-9_\-]{20,}", "critica"),
]
JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
# Variáveis com prefixo público que parecem segredo
PUBLICA = re.compile(
    r"\b((?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC|PUBLIC|GATSBY)_[A-Z0-9_]*"
    r"(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|SENHA|OPENAI|ANTHROPIC|STRIPE_SECRET|SK_|API_SECRET|ADMIN|TOKEN)[A-Z0-9_]*)"
)
PLACEHOLDER = re.compile(r"(?i)(x{6,}|your[_-]?|seu[_-]?|example|exemplo|changeme|<|\.\.\.|placeholder|dummy|fake)")


def decodificar_jwt(token: str):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


def eh_build(r: str) -> bool:
    return bool(re.search(r"(^|/)(dist|build|out|\.output|public)/", r)) or r.endswith(".map")


def varrer_texto(texto: str, r: str, achados: list, origem: str):
    for n, linha in enumerate(texto.splitlines(), 1):
        if len(linha) > 5000:
            linha = linha[:5000]
        for regra, titulo, rx, sev in PADROES:
            for m in re.finditer(rx, linha):
                val = m.group(0)
                if PLACEHOLDER.search(val):
                    continue
                s = sev
                if eh_build(r) and sev != "critica":
                    s = "alta"
                achados.append(achado(
                    regra, f"{titulo} {origem}", s, FONTE, confianca="alta", arquivo=r, linha=n,
                    evidencia=mascarar(val), owasp="A02, A04, A07", medida="01, 02",
                    recomendacao="Mover para variável de ambiente do servidor e ROTACIONAR a chave no painel do provedor; se esteve no git, limpar o histórico (medida 02).",
                ))
        for m in JWT.finditer(linha):
            dados = decodificar_jwt(m.group(0)) or {}
            papel = dados.get("role")
            if papel == "service_role":
                achados.append(achado(
                    "supabase-service-role", f"JWT service_role do Supabase {origem}", "critica", FONTE,
                    confianca="alta", arquivo=r, linha=n, evidencia=mascarar(m.group(0)),
                    owasp="A01, A02", medida="01, 03",
                    recomendacao="A service_role ignora toda a RLS. Remover do código, usar só no servidor e gerar nova chave no painel do Supabase.",
                ))
            elif papel == "anon":
                continue  # chave pública: esperado no cliente, desde que exista RLS
            elif dados and not eh_build(r):
                achados.append(achado(
                    "jwt-hardcoded", f"Token JWT fixo no código {origem}", "media", FONTE, confianca="baixa",
                    arquivo=r, linha=n, evidencia=mascarar(m.group(0)), owasp="A07", medida="01",
                    recomendacao="Confirmar se é credencial; tokens não devem ficar no código.",
                ))
        for m in PUBLICA.finditer(linha):
            achados.append(achado(
                "segredo-em-variavel-publica", f"Variável pública com nome de segredo: {m.group(1)} {origem}",
                "alta", FONTE, confianca="media", arquivo=r, linha=n, evidencia=m.group(1),
                owasp="A02", medida="01",
                recomendacao="Variáveis com esse prefixo vão para o bundle do navegador. Renomear sem o prefixo e usar só no servidor; rotacionar se já foi publicada.",
            ))


def rastreados(raiz: Path):
    try:
        out = subprocess.run(["git", "-C", str(raiz), "ls-files"], capture_output=True, text=True, timeout=30)
        return set(out.stdout.splitlines()) if out.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def historico_git(raiz: Path, achados: list, limite_commits: int):
    try:
        out = subprocess.run(
            ["git", "-C", str(raiz), "log", "-p", "--all", f"-n{limite_commits}", "--no-color", "--unified=0"],
            capture_output=True, text=True, timeout=300, errors="ignore",
        )
    except (OSError, subprocess.TimeoutExpired):
        print("Aviso: não foi possível ler o histórico do git.", file=sys.stderr)
        return
    commit, arquivo = "?", "?"
    adicionadas = []
    for linha in out.stdout.splitlines():
        if linha.startswith("commit "):
            commit = linha.split()[1][:10]
        elif linha.startswith("+++ b/"):
            arquivo = linha[6:]
        elif linha.startswith("+") and not linha.startswith("+++"):
            adicionadas.append((commit, arquivo, linha[1:]))
    tmp = []
    for commit, arq, texto in adicionadas:
        antes = len(tmp)
        varrer_texto(texto, arq, tmp, f"(histórico do git, commit {commit})")
        for x in tmp[antes:]:
            x["linha"] = None
            x["regra"] = "historico-" + x["regra"]
    achados.extend(tmp)
    if (raiz / ".git").exists():
        for commit, arq, _ in adicionadas:
            if re.search(r"(^|/)\.env(\.|$)", arq) and not arq.endswith((".example", ".sample", ".template")):
                achados.append(achado(
                    "env-no-historico", f"Arquivo {arq} aparece no histórico do git (commit {commit})", "alta", FONTE,
                    confianca="alta", arquivo=arq, owasp="A02", medida="02",
                    recomendacao="Todos os valores desse arquivo devem ser considerados vazados: rotacionar e limpar o histórico.",
                ))
                break


def rodar_gitleaks(raiz: Path, achados: list):
    if not shutil.which("gitleaks"):
        print("Aviso: gitleaks não instalado; usando só os padrões internos.", file=sys.stderr)
        return False
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        rel_path = f.name
    subprocess.run(["gitleaks", "detect", "-s", str(raiz), "-f", "json", "-r", rel_path, "--redact", "--no-banner"],
                   capture_output=True, timeout=600)
    try:
        dados = json.loads(Path(rel_path).read_text() or "[]")
    except (json.JSONDecodeError, OSError):
        dados = []
    for d in dados:
        achados.append(achado(
            "gitleaks-" + str(d.get("RuleID")), f"gitleaks: {d.get('Description')} (commit {str(d.get('Commit'))[:10]})",
            "alta", "gitleaks", confianca="alta", arquivo=d.get("File"), linha=d.get("StartLine"),
            evidencia="(redigido)", owasp="A02", medida="01, 02",
            recomendacao="Rotacionar e remover do código e do histórico.",
        ))
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir")
    ap.add_argument("--git", action="store_true", help="também varre o histórico do git")
    ap.add_argument("--max-commits", type=int, default=2000)
    ap.add_argument("--saida")
    a = ap.parse_args()
    raiz = Path(a.dir).resolve()

    achados: list = []
    no_git = rastreados(raiz)
    for p in iterar_arquivos(raiz, incluir_build=True):
        r = rel(p, raiz)
        if p.name.endswith((".example", ".sample", ".template")):
            continue
        if p.name.startswith(".env"):
            if no_git is not None and r in no_git:
                achados.append(achado(
                    "env-versionado", f"Arquivo {r} está versionado no git", "alta", FONTE, confianca="alta",
                    arquivo=r, owasp="A02", medida="01, 02",
                    recomendacao="Remover do git (git rm --cached), adicionar ao .gitignore, rotacionar os valores e limpar o histórico.",
                ))
                varrer_texto(ler(p), r, achados, "(arquivo .env versionado)")
            else:
                # .env local não versionado é o lugar certo para segredos; só alertar prefixos públicos
                for n, linha in enumerate(ler(p).splitlines(), 1):
                    for m in PUBLICA.finditer(linha):
                        achados.append(achado(
                            "segredo-em-variavel-publica", f"Variável pública com nome de segredo: {m.group(1)}",
                            "alta", FONTE, confianca="media", arquivo=r, linha=n, evidencia=m.group(1),
                            owasp="A02", medida="01",
                            recomendacao="Variáveis com esse prefixo vão para o bundle do navegador. Renomear sem o prefixo e usar só no servidor; rotacionar se já foi publicada.",
                        ))
            continue
        varrer_texto(ler(p), r, achados, "(build público)" if eh_build(r) else "")

    gi = ler(raiz / ".gitignore")
    if no_git is not None and not re.search(r"^\s*\.env", gi, re.M):
        achados.append(achado("gitignore-sem-env", ".gitignore não ignora arquivos .env", "media", FONTE,
                              confianca="alta", arquivo=".gitignore", owasp="A02", medida="01",
                              recomendacao="Adicionar `.env*` e `!.env.example` ao .gitignore."))
    if a.git and no_git is not None:
        historico_git(raiz, achados, a.max_commits)
    rodar_gitleaks(raiz, achados)

    # remove duplicatas (mesma regra, arquivo e evidência)
    vistos, unicos = set(), []
    for x in achados:
        k = (x["regra"], x["arquivo"], x["evidencia"])
        if k not in vistos:
            vistos.add(k)
            unicos.append(x)
    salvar(unicos, a.saida)
    print(f"{len(unicos)} candidato(s) a segredo exposto.")
    for x in unicos[:40]:
        loc = f"{x['arquivo']}:{x['linha']}" if x["linha"] else x["arquivo"]
        print(f"- [{x['severidade']}] {x['titulo']} — {loc} {x['evidencia'] or ''}")


if __name__ == "__main__":
    main()
