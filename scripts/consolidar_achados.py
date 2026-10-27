#!/usr/bin/env python3
"""Consolida achados de várias fontes num único quadro ordenado por severidade.

Uso: python3 consolidar_achados.py <arquivo.json> [...] [--saida achados.md] [--json achados.json]

Aceita: saídas dos scripts desta skill (scan_secrets, deps_audit, check_headers),
JSON do Semgrep (`semgrep --json`) e `vulnerabilities.json` do Strix.
Achados do Strix entram marcados como validados (com prova de conceito).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from comum import SEVERIDADES, achado  # noqa: E402

SEV_SEMGREP = {"ERROR": "alta", "WARNING": "media", "INFO": "baixa"}
SEV_STRIX = {"critical": "critica", "high": "alta", "medium": "media", "low": "baixa", "info": "info"}


def de_semgrep(dados):
    out = []
    for r in dados.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        owasp = meta.get("owasp")
        if isinstance(owasp, list):
            owasp = ", ".join(owasp)
        out.append(achado(
            "semgrep:" + str(r.get("check_id", "")).split(".")[-1], extra.get("message", "")[:160].replace("\n", " "),
            SEV_SEMGREP.get(extra.get("severity"), "media"), "semgrep",
            confianca=str(meta.get("confidence", "media")).lower().replace("medium", "media").replace("high", "alta").replace("low", "baixa"),
            arquivo=r.get("path"), linha=(r.get("start") or {}).get("line"), owasp=owasp,
            evidencia=", ".join(meta.get("cwe", [])) if isinstance(meta.get("cwe"), list) else meta.get("cwe"),
        ))
    return out


def de_strix(lista):
    out = []
    for v in lista:
        locs = v.get("code_locations") or []
        arquivo = locs[0].get("file") if locs else None
        linha = locs[0].get("start_line") if locs else None
        alvo = " ".join(x for x in (v.get("method"), v.get("endpoint")) if x)
        out.append(achado(
            "strix:" + str(v.get("id", "")), v.get("title", "(sem título)"),
            SEV_STRIX.get(str(v.get("severity", "")).lower(), "media"), "strix", confianca="alta",
            arquivo=arquivo or alvo or v.get("target"), linha=linha, evidencia=v.get("cwe"),
            recomendacao=(v.get("remediation_steps") or "")[:300], validado=True,
        ))
    return out


def carregar(caminho: Path):
    dados = json.loads(caminho.read_text(encoding="utf-8"))
    if isinstance(dados, dict) and "results" in dados and "errors" in dados:
        return de_semgrep(dados)
    if isinstance(dados, dict) and "achados" in dados:
        return dados["achados"]
    if isinstance(dados, list) and dados and "regra" in dados[0]:
        return dados
    if isinstance(dados, list) and dados and "title" in dados[0]:
        return de_strix(dados)
    if isinstance(dados, list):
        return []
    print(f"Aviso: formato não reconhecido em {caminho}", file=sys.stderr)
    return []


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("arquivos", nargs="+")
    ap.add_argument("--saida", default="achados.md")
    ap.add_argument("--json")
    a = ap.parse_args()

    todos = []
    for arq in a.arquivos:
        p = Path(arq)
        if not p.exists():
            print(f"Aviso: {arq} não existe, ignorado.", file=sys.stderr)
            continue
        todos.extend(carregar(p))

    lacunas = [x for x in todos if x.get("regra") == "lacuna-cobertura"]
    achados = [x for x in todos if x.get("regra") != "lacuna-cobertura"]
    ordem = {s: i for i, s in enumerate(SEVERIDADES)}
    achados.sort(key=lambda x: (ordem.get(x.get("severidade"), 9), not x.get("validado"), x.get("arquivo") or ""))
    for i, x in enumerate(achados, 1):
        x["id"] = f"ACH-{i:03d}"

    placar = {s: sum(1 for x in achados if x.get("severidade") == s) for s in SEVERIDADES}
    linhas = ["# Achados consolidados", "",
              "| Crítica | Alta | Média | Baixa | Info |", "|---|---|---|---|---|",
              "| " + " | ".join(str(placar[s]) for s in SEVERIDADES) + " |", "",
              "Candidatos de ferramentas estáticas precisam de confirmação manual antes de entrar no relatório final. "
              "Itens marcados ✅ foram validados dinamicamente.", "",
              "| ID | Sev. | Título | Local | OWASP | Medida | Fonte | Status |",
              "|---|---|---|---|---|---|---|---|"]
    for x in achados:
        loc = f"{x.get('arquivo') or '-'}" + (f":{x['linha']}" if x.get("linha") else "")
        status = "✅ validado" if x.get("validado") else "a confirmar"
        titulo = str(x.get("titulo", "")).replace("|", "\\|")
        linhas.append(f"| {x['id']} | {x.get('severidade')} | {titulo} | `{loc}` | {x.get('owasp') or '-'} | "
                      f"{x.get('medida') or '-'} | {x.get('fonte')} | {status} |")
    if lacunas:
        linhas += ["", "## Lacunas de cobertura", ""] + [f"- {x['titulo']}" for x in lacunas]
    Path(a.saida).write_text("\n".join(linhas) + "\n", encoding="utf-8")
    if a.json:
        Path(a.json).write_text(json.dumps(achados, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{len(achados)} achado(s) consolidados em {a.saida}: " + ", ".join(f"{s}={placar[s]}" for s in SEVERIDADES))


if __name__ == "__main__":
    main()
