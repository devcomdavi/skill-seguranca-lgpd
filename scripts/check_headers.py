#!/usr/bin/env python3
"""Verifica HTTPS, cabeçalhos de segurança e atributos de cookies de uma URL.

Uso: python3 check_headers.py <url> [--saida headers.json]

Faz apenas requisições GET comuns à URL informada (e à versão http:// para
conferir o redirecionamento). Use só em sistemas que você tem autorização para avaliar.
"""
from __future__ import annotations

import argparse
import ssl
import sys
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from comum import achado, salvar  # noqa: E402

FONTE = "check_headers"


class SemRedirecionar(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def buscar(url, seguir=True):
    ctx = ssl.create_default_context()
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not seguir:
        handlers.append(SemRedirecionar())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": "auditoria-seguranca-lgpd/1.0"})
    try:
        resp = opener.open(req, timeout=20)
        return resp.status, resp.headers, resp.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, url
    except (urllib.error.URLError, OSError) as e:
        return None, str(e), url


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("--saida")
    a = ap.parse_args()
    url = a.url if "://" in a.url else "https://" + a.url
    host = urlparse(url).netloc
    achados = []

    status, h, final = buscar(url)
    if status is None:
        sys.exit(f"Não foi possível acessar {url}: {h}")

    if not final.startswith("https://"):
        achados.append(achado("sem-https", "A página final não é servida por HTTPS", "alta", FONTE, confianca="alta",
                              evidencia=final, owasp="A04", medida="19", lgpd="art. 46",
                              recomendacao="Servir tudo por HTTPS e redirecionar HTTP → HTTPS."))
    s_http, h_http, _ = buscar(f"http://{host}/", seguir=False)
    if s_http is not None and isinstance(h_http, object) and s_http not in (301, 302, 307, 308):
        achados.append(achado("http-sem-redirecionar", f"http://{host}/ responde {s_http} sem redirecionar para HTTPS",
                              "media", FONTE, confianca="alta", owasp="A04", medida="19",
                              recomendacao="Redirecionar todo HTTP para HTTPS (301/308) e ativar HSTS."))

    def cab(nome):
        return h.get(nome) if hasattr(h, "get") else None

    hsts = cab("Strict-Transport-Security")
    if not hsts:
        achados.append(achado("sem-hsts", "Sem cabeçalho Strict-Transport-Security (HSTS)", "media", FONTE,
                              confianca="alta", owasp="A04", medida="18, 19",
                              recomendacao="Strict-Transport-Security: max-age=31536000; includeSubDomains"))
    elif "max-age=" in hsts and int((hsts.split("max-age=")[1].split(";")[0] or "0").strip() or 0) < 15552000:
        achados.append(achado("hsts-curto", f"HSTS com max-age baixo: {hsts}", "baixa", FONTE, confianca="alta",
                              owasp="A04", medida="19", recomendacao="Usar max-age de pelo menos 6 meses (ideal 1 ano)."))

    csp = cab("Content-Security-Policy")
    if not csp:
        sev = "media"
        achados.append(achado("sem-csp", "Sem Content-Security-Policy", sev, FONTE, confianca="alta", owasp="A02, A05",
                              medida="18", recomendacao="Definir CSP (começar em Report-Only e endurecer)."))
    else:
        if "'unsafe-inline'" in csp and "script-src" in csp and "nonce-" not in csp and "strict-dynamic" not in csp:
            achados.append(achado("csp-unsafe-inline", "CSP permite 'unsafe-inline' em scripts", "baixa", FONTE,
                                  confianca="media", evidencia=csp[:200], owasp="A05", medida="18",
                                  recomendacao="Usar nonce ou hash para scripts inline."))
        if "frame-ancestors" not in csp and not cab("X-Frame-Options"):
            achados.append(achado("sem-anti-clickjacking", "Sem frame-ancestors nem X-Frame-Options", "media", FONTE,
                                  confianca="alta", owasp="A02", medida="18",
                                  recomendacao="Adicionar frame-ancestors 'none' (ou 'self') na CSP."))
    if not csp and not cab("X-Frame-Options"):
        achados.append(achado("sem-anti-clickjacking", "Sem frame-ancestors nem X-Frame-Options", "media", FONTE,
                              confianca="alta", owasp="A02", medida="18",
                              recomendacao="Adicionar frame-ancestors 'none' na CSP ou X-Frame-Options: DENY."))
    if (cab("X-Content-Type-Options") or "").lower() != "nosniff":
        achados.append(achado("sem-nosniff", "Sem X-Content-Type-Options: nosniff", "baixa", FONTE, confianca="alta",
                              owasp="A02", medida="18", recomendacao="X-Content-Type-Options: nosniff"))
    if not cab("Referrer-Policy"):
        achados.append(achado("sem-referrer-policy", "Sem Referrer-Policy", "baixa", FONTE, confianca="alta",
                              owasp="A02", medida="18", lgpd="evita vazar dados pessoais em URLs para terceiros",
                              recomendacao="Referrer-Policy: strict-origin-when-cross-origin"))
    if not cab("Permissions-Policy"):
        achados.append(achado("sem-permissions-policy", "Sem Permissions-Policy", "info", FONTE, confianca="alta",
                              owasp="A02", medida="18", recomendacao="Desabilitar câmera, microfone e geolocalização se não usados."))
    for nome in ("Server", "X-Powered-By", "X-AspNet-Version"):
        v = cab(nome)
        if v and any(ch.isdigit() for ch in v) or nome == "X-Powered-By" and v:
            achados.append(achado("versao-exposta", f"Cabeçalho {nome} expõe tecnologia/versão: {v}", "baixa", FONTE,
                                  confianca="alta", owasp="A02", medida="18", recomendacao=f"Remover {nome}."))
    acao = cab("Access-Control-Allow-Origin")
    if acao == "*" and (cab("Access-Control-Allow-Credentials") or "").lower() == "true":
        achados.append(achado("cors-credenciais-wildcard", "CORS com origem '*' e credenciais", "alta", FONTE,
                              confianca="alta", owasp="A01", medida="18",
                              recomendacao="Usar lista explícita de origens permitidas."))

    cookies = h.get_all("Set-Cookie") if hasattr(h, "get_all") else []
    for bruto in cookies or []:
        nome = bruto.split("=", 1)[0].strip()
        baixo = bruto.lower()
        sessao = any(k in nome.lower() for k in ("sess", "auth", "token", "sb-", "jwt", "sid"))
        faltando = [x for x, ok in (("Secure", "secure" in baixo), ("HttpOnly", "httponly" in baixo),
                                     ("SameSite", "samesite" in baixo)) if not ok]
        if faltando:
            achados.append(achado("cookie-sem-atributos", f"Cookie '{nome}' sem {', '.join(faltando)}",
                                  "media" if sessao else "baixa", FONTE, confianca="alta" if sessao else "media",
                                  owasp="A02, A07", medida="09",
                                  recomendacao="Cookies de sessão: Secure; HttpOnly; SameSite=Lax (ou Strict); Path=/; preferir prefixo __Host-."))

    salvar({"url": url, "status": status, "url_final": final, "achados": achados}, a.saida)
    print(f"{url} → {status} ({final})")
    for x in achados:
        print(f"- [{x['severidade']}] {x['titulo']}")
    if not achados:
        print("Nenhum problema de cabeçalho encontrado.")


if __name__ == "__main__":
    main()
