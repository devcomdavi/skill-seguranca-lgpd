#!/usr/bin/env python3
"""Reconhecimento de um projeto: stack, superfície de API, dados e integrações.

Uso: python3 recon.py <dir-do-projeto> [--saida recon.json]

Só lê arquivos locais. Imprime um resumo em Markdown e salva os detalhes em JSON.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from comum import iterar_arquivos, ler, rel, salvar  # noqa: E402

# dependência (npm/pip) -> (categoria, rótulo)
DEPS = {
    "next": ("framework", "Next.js"), "react": ("framework", "React"),
    "vite": ("framework", "Vite"), "vue": ("framework", "Vue"), "nuxt": ("framework", "Nuxt"),
    "svelte": ("framework", "Svelte"), "@sveltejs/kit": ("framework", "SvelteKit"),
    "astro": ("framework", "Astro"), "express": ("framework", "Express"),
    "fastify": ("framework", "Fastify"), "@nestjs/core": ("framework", "NestJS"),
    "hono": ("framework", "Hono"), "expo": ("framework", "Expo/React Native"),
    "react-native": ("framework", "React Native"),
    "fastapi": ("framework", "FastAPI"), "flask": ("framework", "Flask"), "django": ("framework", "Django"),
    "@supabase/supabase-js": ("baas", "Supabase"), "@supabase/ssr": ("baas", "Supabase"),
    "supabase": ("baas", "Supabase"), "firebase": ("baas", "Firebase"),
    "firebase-admin": ("baas", "Firebase Admin"), "appwrite": ("baas", "Appwrite"),
    "@prisma/client": ("orm", "Prisma"), "prisma": ("orm", "Prisma"),
    "drizzle-orm": ("orm", "Drizzle"), "mongoose": ("orm", "Mongoose"),
    "sequelize": ("orm", "Sequelize"), "typeorm": ("orm", "TypeORM"), "pg": ("orm", "node-postgres"),
    "sqlalchemy": ("orm", "SQLAlchemy"),
    "next-auth": ("auth", "Auth.js"), "@auth/core": ("auth", "Auth.js"),
    "@clerk/nextjs": ("auth", "Clerk"), "@clerk/clerk-react": ("auth", "Clerk"),
    "lucia": ("auth", "Lucia"), "better-auth": ("auth", "Better Auth"),
    "jsonwebtoken": ("auth", "jsonwebtoken (JWT manual)"), "jose": ("auth", "jose (JWT)"),
    "passport": ("auth", "Passport"), "bcrypt": ("auth", "bcrypt"), "bcryptjs": ("auth", "bcryptjs"),
    "argon2": ("auth", "argon2"),
    "openai": ("ia", "OpenAI"), "@anthropic-ai/sdk": ("ia", "Anthropic"), "anthropic": ("ia", "Anthropic"),
    "@google/generative-ai": ("ia", "Google Gemini"), "@google/genai": ("ia", "Google Gemini"),
    "ai": ("ia", "Vercel AI SDK"), "langchain": ("ia", "LangChain"), "@langchain/core": ("ia", "LangChain"),
    "llamaindex": ("ia", "LlamaIndex"), "@pinecone-database/pinecone": ("ia", "Pinecone (vetores)"),
    "stripe": ("pagamento", "Stripe"), "@stripe/stripe-js": ("pagamento", "Stripe (cliente)"),
    "mercadopago": ("pagamento", "Mercado Pago"), "asaas": ("pagamento", "Asaas"),
    "multer": ("upload", "multer"), "formidable": ("upload", "formidable"),
    "busboy": ("upload", "busboy"), "uploadthing": ("upload", "UploadThing"),
    "@aws-sdk/client-s3": ("upload", "AWS S3"), "cloudinary": ("upload", "Cloudinary"),
    "resend": ("terceiros", "Resend (e-mail)"), "nodemailer": ("terceiros", "Nodemailer (e-mail)"),
    "@sendgrid/mail": ("terceiros", "SendGrid (e-mail)"), "twilio": ("terceiros", "Twilio"),
    "@sentry/nextjs": ("terceiros", "Sentry"), "@sentry/react": ("terceiros", "Sentry"),
    "@sentry/node": ("terceiros", "Sentry"), "posthog-js": ("terceiros", "PostHog"),
    "mixpanel-browser": ("terceiros", "Mixpanel"), "@vercel/analytics": ("terceiros", "Vercel Analytics"),
    "react-ga4": ("terceiros", "Google Analytics"), "@hotjar/browser": ("terceiros", "Hotjar"),
    "zod": ("validacao", "zod"), "valibot": ("validacao", "valibot"), "yup": ("validacao", "yup"),
    "joi": ("validacao", "joi"), "pydantic": ("validacao", "pydantic"),
    "helmet": ("defesa", "helmet"), "express-rate-limit": ("defesa", "express-rate-limit"),
    "@upstash/ratelimit": ("defesa", "Upstash Ratelimit"), "dompurify": ("defesa", "DOMPurify"),
    "isomorphic-dompurify": ("defesa", "DOMPurify"),
}

SINAIS_TEXTO = {
    "googletagmanager.com": ("terceiros", "Google Tag Manager/Analytics"),
    "connect.facebook.net": ("terceiros", "Meta Pixel"),
    "static.hotjar.com": ("terceiros", "Hotjar"),
    "clarity.ms": ("terceiros", "Microsoft Clarity"),
    "api.openai.com": ("ia", "OpenAI (HTTP)"),
    "generativelanguage.googleapis.com": ("ia", "Google Gemini (HTTP)"),
    "api.anthropic.com": ("ia", "Anthropic (HTTP)"),
    "hooks.zapier.com": ("terceiros", "Zapier"), "hook.make.com": ("terceiros", "Make"),
    "/webhook/": ("terceiros", "Webhook (n8n ou similar)"),
}

ROTA_EXPRESS = re.compile(r"\b(?:app|router|server)\.(get|post|put|patch|delete|all)\(\s*['\"`]([^'\"`]+)")
ROTA_PY = re.compile(r"@(?:app|router|bp|blueprint)\.(get|post|put|patch|delete|route)\(\s*['\"]([^'\"]+)")
HANDLER_NEXT = re.compile(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*=")


def carregar_deps(raiz: Path):
    deps = {}
    for pj in raiz.rglob("package.json"):
        if any(part in {"node_modules", ".next", "dist"} for part in pj.parts):
            continue
        try:
            d = json.loads(ler(pj))
        except json.JSONDecodeError:
            continue
        for chave in ("dependencies", "devDependencies"):
            for nome, ver in (d.get(chave) or {}).items():
                deps[nome] = {"versao": ver, "arquivo": rel(pj, raiz), "dev": chave == "devDependencies"}
    for req in list(raiz.rglob("requirements*.txt")) + list(raiz.rglob("pyproject.toml")):
        if any(part in {".venv", "venv", "node_modules"} for part in req.parts):
            continue
        for linha in ler(req).splitlines():
            m = re.match(r"\s*\"?([A-Za-z0-9_.\-]+)", linha)
            if m and not linha.strip().startswith(("#", "[")):
                deps.setdefault(m.group(1).lower(), {"versao": linha.strip(), "arquivo": rel(req, raiz), "dev": False})
    return deps


def arquivos_rastreados(raiz: Path):
    try:
        out = subprocess.run(["git", "-C", str(raiz), "ls-files"], capture_output=True, text=True, timeout=30)
        if out.returncode == 0:
            return set(out.stdout.splitlines())
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir")
    ap.add_argument("--saida")
    a = ap.parse_args()
    raiz = Path(a.dir).resolve()
    if not raiz.is_dir():
        sys.exit(f"Diretório não encontrado: {raiz}")

    deps = carregar_deps(raiz)
    stack: dict[str, set] = {}
    for nome, info in deps.items():
        if nome in DEPS:
            cat, rot = DEPS[nome]
            stack.setdefault(cat, set()).add(rot)

    rotas, server_actions, migracoes, regras_firebase, envs = [], [], [], [], []
    uso_service_role, workflows = [], []
    for p in iterar_arquivos(raiz):
        r = rel(p, raiz)
        nome = p.name
        texto = ler(p)
        if nome.startswith(".env"):
            envs.append(r)
        if p.suffix in {".ts", ".tsx", ".js", ".jsx", ".mjs"}:
            if re.search(r"(^|/)(app/.*?/route|pages/api/.*)\.(t|j)sx?$", r):
                metodos = sorted({m.group(1) or m.group(2) for m in HANDLER_NEXT.finditer(texto)}) or ["(handler padrão)"]
                rotas.append({"arquivo": r, "tipo": "next", "metodos": metodos})
            for m in ROTA_EXPRESS.finditer(texto):
                rotas.append({"arquivo": r, "tipo": "node", "metodos": [m.group(1).upper()], "caminho": m.group(2)})
            if re.search(r"^\s*['\"]use server['\"]", texto, re.M):
                server_actions.append(r)
            if "functions/" in r and "supabase" in r:
                rotas.append({"arquivo": r, "tipo": "supabase-edge-function", "metodos": ["*"]})
        if p.suffix == ".py":
            for m in ROTA_PY.finditer(texto):
                rotas.append({"arquivo": r, "tipo": "python", "metodos": [m.group(1).upper()], "caminho": m.group(2)})
        if p.suffix in {".sql", ".prisma"} or "migrations" in r:
            migracoes.append(r)
        if nome.endswith(".rules") or nome in {"firestore.rules", "storage.rules", "database.rules.json"}:
            regras_firebase.append(r)
        if ".github/workflows" in r:
            workflows.append(r)
        if re.search(r"service_role|SERVICE_ROLE|SUPABASE_SECRET", texto) and not nome.startswith(".env"):
            uso_service_role.append(r)
        for sinal, (cat, rot) in SINAIS_TEXTO.items():
            if sinal in texto:
                stack.setdefault(cat, set()).add(rot)
        if nome == "supabase" or "/supabase/" in f"/{r}":
            stack.setdefault("baas", set()).add("Supabase")

    rastreados = arquivos_rastreados(raiz)
    envs_info = []
    for e in envs:
        envs_info.append({"arquivo": e, "no_git": (e in rastreados) if rastreados is not None else None})
    gitignore = ler(raiz / ".gitignore")
    env_ignorado = bool(re.search(r"^\.env", gitignore, re.M))
    lockfiles = [n for n in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock",
                             "poetry.lock", "uv.lock", "Pipfile.lock") if (raiz / n).exists()]

    resultado = {
        "projeto": str(raiz),
        "stack": {k: sorted(v) for k, v in sorted(stack.items())},
        "rotas": rotas,
        "server_actions": server_actions,
        "migracoes_schema": migracoes,
        "regras_firebase": regras_firebase,
        "arquivos_env": envs_info,
        "env_no_gitignore": env_ignorado,
        "lockfiles": lockfiles,
        "workflows_ci": workflows,
        "arquivos_que_citam_service_role": uso_service_role,
        "git": rastreados is not None,
    }

    # Sugestões de leitura
    sug = ["references/owasp-top10-2025.md", "references/lgpd.md"]
    s = resultado["stack"]
    if s.get("baas") or s.get("framework"):
        sug.append("references/stacks-vibecode.md (seções: " + ", ".join(s.get("baas", []) + s.get("framework", [])) + ")")
    if s.get("ia"):
        sug.append("references/owasp-llm-top10-2025.md")
    if "Supabase" in s.get("baas", []):
        sug.append("scripts/postgres_auditoria.sql + scripts/supabase_storage.sql + references/medidas/04-ativar-rls.md")
    elif s.get("orm"):
        sug.append("stacks-vibecode.md (Banco de dados em geral); se for PostgreSQL, scripts/postgres_auditoria.sql")
    if s.get("pagamento"):
        sug.append("stacks-vibecode.md (Pagamentos): webhooks e preço no servidor")
    if s.get("upload"):
        sug.append("references/medidas/16-restringir-uploads.md")
    resultado["leituras_sugeridas"] = sug

    salvar(resultado, a.saida)

    # Resumo legível
    print(f"# Reconhecimento: {raiz.name}\n")
    for cat, itens in resultado["stack"].items():
        print(f"- **{cat}**: {', '.join(itens)}")
    print(f"\n- Rotas/handlers encontrados: {len(rotas)}; server actions: {len(server_actions)}")
    print(f"- Migrações/schemas: {len(migracoes)}; regras Firebase: {len(regras_firebase)}")
    print(f"- Lockfiles: {', '.join(lockfiles) or 'NENHUM'}; workflows de CI: {len(workflows)}")
    print(f"- `.env` no .gitignore: {'sim' if env_ignorado else 'NÃO'}")
    for e in envs_info:
        alerta = " ⚠ versionado no git" if e["no_git"] and not e["arquivo"].endswith(".example") else ""
        print(f"  - {e['arquivo']}{alerta}")
    if uso_service_role:
        print(f"- Arquivos que citam service_role: {', '.join(uso_service_role[:10])} (confirmar que são só de servidor)")
    if "validacao" not in s:
        print("- Nenhuma biblioteca de validação de schema detectada")
    if "auth" not in s and "baas" not in s:
        print("- Nenhum provedor de autenticação detectado: verificar se a autenticação é caseira")
    print("\n## Leituras sugeridas")
    for x in sug:
        print(f"- {x}")


if __name__ == "__main__":
    main()
