#!/usr/bin/env python3
"""Auditoria de dependências e supply chain (OWASP A03).

Uso: python3 deps_audit.py <dir> [--saida deps.json]

Executa as ferramentas disponíveis (npm/pnpm/yarn audit, pip-audit, osv-scanner)
e faz verificações próprias: lockfile, versões soltas, dependências por URL,
scripts de instalação e scripts de CDN sem SRI. Ferramentas ausentes são
reportadas como lacuna de cobertura, não como erro.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from comum import achado, iterar_arquivos, ler, rel, salvar  # noqa: E402

FONTE = "deps_audit"
MAPA_SEV = {"critical": "critica", "high": "alta", "moderate": "media", "medium": "media",
            "low": "baixa", "info": "info"}


def rodar(cmd, cwd, timeout=600):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"Aviso: falha ao rodar {' '.join(cmd)}: {e}", file=sys.stderr)
        return None


def npm_audit(pasta: Path, raiz: Path, achados, lacunas):
    if (pasta / "pnpm-lock.yaml").exists() and shutil.which("pnpm"):
        cmd = ["pnpm", "audit", "--json"]
    elif (pasta / "yarn.lock").exists() and shutil.which("yarn"):
        lacunas.append(f"{rel(pasta, raiz) or '.'}: yarn audit não é interpretado; rode `yarn npm audit` manualmente")
        return
    elif (pasta / "package-lock.json").exists() and shutil.which("npm"):
        cmd = ["npm", "audit", "--json", "--omit=dev"]
    else:
        lacunas.append(f"{rel(pasta, raiz) or '.'}: sem lockfile npm/pnpm ou ferramenta ausente; audit não executado")
        return
    out = rodar(cmd, pasta)
    if not out:
        return
    try:
        dados = json.loads(out)
    except json.JSONDecodeError:
        lacunas.append(f"{' '.join(cmd)}: saída não interpretável")
        return
    vulns = dados.get("vulnerabilities") or {}
    for nome, v in vulns.items():  # formato npm >= 7
        via = [x for x in v.get("via", []) if isinstance(x, dict)]
        titulo = via[0].get("title") if via else "vulnerabilidade herdada de dependência"
        url = via[0].get("url") if via else None
        achados.append(achado(
            "dep-vulneravel", f"{nome}@{v.get('range', '?')}: {titulo}", MAPA_SEV.get(v.get("severity"), "media"),
            FONTE, confianca="alta", arquivo=rel(pasta / "package.json", raiz), evidencia=url, owasp="A03",
            medida="20", recomendacao="Atualizar para versão corrigida (" + str(v.get("fixAvailable")) + "); avaliar se o código vulnerável é alcançável.",
        ))
    for adv in (dados.get("advisories") or {}).values():  # formato pnpm/npm antigo
        achados.append(achado(
            "dep-vulneravel", f"{adv.get('module_name')}: {adv.get('title')}", MAPA_SEV.get(adv.get("severity"), "media"),
            FONTE, confianca="alta", arquivo=rel(pasta / "package.json", raiz), evidencia=adv.get("url"),
            owasp="A03", medida="20", recomendacao=f"Atualizar para {adv.get('patched_versions')}.",
        ))


def verificar_package_json(pj: Path, raiz: Path, achados):
    try:
        d = json.loads(ler(pj))
    except json.JSONDecodeError:
        return
    r = rel(pj, raiz)
    pasta = pj.parent
    if not any((pasta / n).exists() for n in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock")):
        achados.append(achado("sem-lockfile", f"{r} sem lockfile", "media", FONTE, confianca="alta", arquivo=r,
                              owasp="A03", medida="20",
                              recomendacao="Gerar e commitar o lockfile; instalar com `npm ci` no CI e no deploy."))
    for chave in ("dependencies", "devDependencies"):
        for nome, ver in (d.get(chave) or {}).items():
            v = str(ver)
            if v in {"*", "latest", ""} or v.startswith((">", "x")):
                achados.append(achado("versao-solta", f"{nome}: versão '{v}' sem limite", "media", FONTE,
                                      confianca="alta", arquivo=r, owasp="A03", medida="20",
                                      recomendacao="Fixar faixa de versão e depender do lockfile."))
            if re.match(r"^(git\+|git:|github:|https?://|file:)", v) or ("/" in v and not v.startswith("@") and not v.startswith("npm:")):
                achados.append(achado("dep-url", f"{nome} instalada de URL/repositório: {v}", "media", FONTE,
                                      confianca="media", arquivo=r, owasp="A03, A08", medida="20",
                                      recomendacao="Preferir o pacote publicado no registro oficial, com versão fixa; se necessário, fixar por commit SHA."))
    scripts = d.get("scripts") or {}
    for gancho in ("preinstall", "install", "postinstall", "prepare"):
        if gancho in scripts and gancho != "prepare":
            achados.append(achado("script-instalacao", f"{r} define script '{gancho}': {scripts[gancho][:80]}", "info",
                                  FONTE, confianca="media", arquivo=r, owasp="A03", medida="20",
                                  recomendacao="Confirmar que o script é necessário e conhecido."))


def verificar_dependencias_instaladas(raiz: Path, achados):
    """Lista pacotes em node_modules com scripts de instalação (fonte comum de malware)."""
    nm = raiz / "node_modules"
    if not nm.is_dir():
        return
    encontrados = []
    for pj in nm.glob("*/package.json"):
        encontrados.append(pj)
    for pj in nm.glob("@*/*/package.json"):
        encontrados.append(pj)
    com_script = []
    for pj in encontrados:
        try:
            s = json.loads(ler(pj)).get("scripts") or {}
        except json.JSONDecodeError:
            continue
        if any(k in s for k in ("preinstall", "install", "postinstall")):
            com_script.append(pj.parent.name if not pj.parent.parent.name.startswith("@") else f"{pj.parent.parent.name}/{pj.parent.name}")
    if com_script:
        achados.append(achado("deps-com-install-script", f"{len(com_script)} dependência(s) instaladas executam script na instalação",
                              "info", FONTE, confianca="alta", evidencia=", ".join(sorted(com_script)[:30]), owasp="A03",
                              medida="20", recomendacao="Revisar a lista; considerar `npm config set ignore-scripts true` e liberar só o necessário."))


def verificar_sri(raiz: Path, achados):
    tag = re.compile(r"<script[^>]+src=[\"'](https?://[^\"']+)[\"'][^>]*>", re.I)
    for p in iterar_arquivos(raiz):
        if p.suffix.lower() not in {".html", ".tsx", ".jsx", ".vue", ".astro", ".svelte"}:
            continue
        for n, linha in enumerate(ler(p).splitlines(), 1):
            for m in tag.finditer(linha):
                if "integrity=" not in m.group(0):
                    achados.append(achado("cdn-sem-sri", f"Script externo sem SRI: {m.group(1)[:80]}", "baixa", FONTE,
                                          confianca="media", arquivo=rel(p, raiz), linha=n, owasp="A08", medida="20",
                                          recomendacao="Adicionar atributo integrity (SRI) e crossorigin, ou servir o script localmente."))


def verificar_workflows(raiz: Path, achados):
    for wf in (raiz / ".github" / "workflows").glob("*.y*ml") if (raiz / ".github" / "workflows").is_dir() else []:
        t = ler(wf)
        r = rel(wf, raiz)
        if "pull_request_target" in t:
            achados.append(achado("ci-pull-request-target", "Workflow usa pull_request_target", "media", FONTE,
                                  confianca="media", arquivo=r, owasp="A03", medida="20",
                                  recomendacao="Evitar; se necessário, não fazer checkout nem executar código do PR com segredos disponíveis."))
        for m in re.finditer(r"uses:\s*([\w\-./]+)@([\w.\-]+)", t):
            if not re.fullmatch(r"[0-9a-f]{40}", m.group(2)) and not m.group(1).startswith(("actions/", "./")):
                achados.append(achado("action-sem-sha", f"Action de terceiro fixada por tag: {m.group(1)}@{m.group(2)}", "baixa",
                                      FONTE, confianca="alta", arquivo=r, owasp="A03", medida="20",
                                      recomendacao="Fixar actions de terceiros pelo commit SHA completo."))


def python_audit(raiz: Path, achados, lacunas):
    reqs = [p for p in raiz.rglob("requirements*.txt") if "node_modules" not in p.parts and ".venv" not in p.parts]
    if not reqs and not (raiz / "pyproject.toml").exists():
        return
    if not shutil.which("pip-audit"):
        lacunas.append("Projeto Python sem pip-audit instalado (pip install pip-audit)")
        return
    for req in reqs:
        out = rodar(["pip-audit", "-r", str(req), "-f", "json", "--progress-spinner", "off"], raiz)
        try:
            dados = json.loads(out or "{}")
        except json.JSONDecodeError:
            continue
        for dep in dados.get("dependencies", []):
            for v in dep.get("vulns", []):
                achados.append(achado("dep-vulneravel", f"{dep.get('name')}=={dep.get('version')}: {v.get('id')}", "alta",
                                      "pip-audit", confianca="alta", arquivo=rel(req, raiz),
                                      evidencia=", ".join(v.get("aliases", [])), owasp="A03", medida="20",
                                      recomendacao=f"Atualizar para {', '.join(v.get('fix_versions', [])) or 'versão corrigida'}."))


def osv(raiz: Path, achados, lacunas):
    if not shutil.which("osv-scanner"):
        lacunas.append("osv-scanner não instalado (cobertura multi-ecossistema opcional)")
        return
    out = rodar(["osv-scanner", "--format", "json", "-r", str(raiz)], raiz)
    try:
        dados = json.loads(out or "{}")
    except json.JSONDecodeError:
        return
    for res in dados.get("results", []):
        origem = res.get("source", {}).get("path")
        for pac in res.get("packages", []):
            info = pac.get("package", {})
            for v in pac.get("vulnerabilities", []):
                achados.append(achado("dep-vulneravel", f"{info.get('name')}@{info.get('version')}: {v.get('id')} {v.get('summary', '')}"[:200],
                                      "alta", "osv-scanner", confianca="alta", arquivo=rel(Path(origem), raiz) if origem else None,
                                      owasp="A03", medida="20", recomendacao="Atualizar para versão corrigida."))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir")
    ap.add_argument("--saida")
    a = ap.parse_args()
    raiz = Path(a.dir).resolve()
    achados, lacunas = [], []

    pjs = [p for p in raiz.rglob("package.json") if not any(x in p.parts for x in ("node_modules", ".next", "dist"))]
    for pj in pjs:
        verificar_package_json(pj, raiz, achados)
        npm_audit(pj.parent, raiz, achados, lacunas)
    verificar_dependencias_instaladas(raiz, achados)
    verificar_sri(raiz, achados)
    verificar_workflows(raiz, achados)
    python_audit(raiz, achados, lacunas)
    osv(raiz, achados, lacunas)
    if not (raiz / ".github" / "dependabot.yml").exists() and not (raiz / "renovate.json").exists():
        achados.append(achado("sem-atualizacao-automatica", "Sem Dependabot/Renovate configurado", "baixa", FONTE,
                              confianca="alta", owasp="A03", medida="20",
                              recomendacao="Adicionar .github/dependabot.yml para alertas e PRs de atualização."))

    for l in lacunas:
        achados.append(achado("lacuna-cobertura", l, "info", FONTE, confianca="alta"))
    salvar(achados, a.saida)
    print(f"{len(achados)} item(ns) de dependências/supply chain.")
    for x in achados[:40]:
        print(f"- [{x['severidade']}] {x['titulo']}")


if __name__ == "__main__":
    main()
