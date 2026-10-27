"""Utilitários compartilhados pelos scripts da skill (somente biblioteca padrão)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

IGNORAR_DIRS = {
    "node_modules", ".git", ".next", ".nuxt", ".svelte-kit", ".turbo", ".vercel",
    ".venv", "venv", "env", "__pycache__", ".pytest_cache", ".mypy_cache",
    "coverage", ".cache", "strix_runs", ".idea", ".vscode", "vendor", "target",
}
# Diretórios de build: ignorados na leitura de código, mas incluídos na busca de segredos
DIRS_BUILD = {"dist", "build", "out", ".output"}

EXT_TEXTO = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro",
    ".py", ".rb", ".php", ".go", ".java", ".kt", ".cs", ".rs", ".dart", ".swift",
    ".sql", ".prisma", ".graphql", ".gql", ".json", ".yaml", ".yml", ".toml",
    ".env", ".ini", ".cfg", ".conf", ".xml", ".html", ".md", ".txt", ".sh",
    ".rules", ".tf", ".properties", ".map",
}
TAMANHO_MAX = 2_000_000  # bytes

SEVERIDADES = ["critica", "alta", "media", "baixa", "info"]


def iterar_arquivos(raiz: Path, incluir_build: bool = False):
    """Percorre arquivos de texto relevantes, pulando dependências e caches."""
    for pasta, dirs, arquivos in os.walk(raiz):
        dirs[:] = [
            d for d in dirs
            if d not in IGNORAR_DIRS and (incluir_build or d not in DIRS_BUILD)
        ]
        for nome in arquivos:
            p = Path(pasta) / nome
            ext = p.suffix.lower()
            if ext in EXT_TEXTO or nome.startswith(".env") or nome in {
                "Dockerfile", "Procfile", ".npmrc", "firestore.rules", "storage.rules"
            }:
                try:
                    if p.stat().st_size <= TAMANHO_MAX:
                        yield p
                except OSError:
                    continue


def ler(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def rel(p: Path, raiz: Path) -> str:
    try:
        return str(p.relative_to(raiz))
    except ValueError:
        return str(p)


def achado(regra, titulo, severidade, fonte, *, confianca="media", arquivo=None,
           linha=None, evidencia=None, recomendacao=None, owasp=None, medida=None,
           lgpd=None, validado=False):
    return {
        "regra": regra, "titulo": titulo, "severidade": severidade,
        "confianca": confianca, "fonte": fonte, "arquivo": arquivo, "linha": linha,
        "evidencia": evidencia, "recomendacao": recomendacao, "owasp": owasp,
        "medida": medida, "lgpd": lgpd, "validado": validado,
    }


def mascarar(valor: str) -> str:
    valor = valor.strip()
    if len(valor) <= 8:
        return "****"
    return valor[:4] + "…" + f"({len(valor)} caracteres)"


def salvar(dados, caminho: str | None):
    texto = json.dumps(dados, ensure_ascii=False, indent=2)
    if caminho:
        Path(caminho).write_text(texto, encoding="utf-8")
        print(f"Resultado salvo em {caminho}", file=sys.stderr)
    return texto
