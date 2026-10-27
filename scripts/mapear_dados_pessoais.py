#!/usr/bin/env python3
"""Rascunho do inventário de dados pessoais (LGPD, art. 37) a partir do código.

Uso: python3 mapear_dados_pessoais.py <dir> [--saida dados.json] [--md inventario.md]

Lê schemas SQL, Prisma, modelos Python, tipos/schemas TypeScript e campos de
formulário, e classifica campos que parecem dados pessoais. O resultado é um
RASCUNHO: finalidade, base legal, retenção e compartilhamento precisam ser
confirmados com o responsável pelo sistema.
"""
from __future__ import annotations

import argparse
import re
import sys
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from comum import iterar_arquivos, ler, rel, salvar  # noqa: E402

# categoria -> (descrição, nível, palavras-chave em nomes de campo normalizados)
CATEGORIAS = {
    "sensivel_saude": ("Dado sensível: saúde", "sensivel", [
        "saude", "health", "doenca", "disease", "diagnost", "cid", "medicament", "medication", "alergi",
        "prontuario", "sintoma", "symptom", "exame", "tratamento", "treatment", "gestante", "gravidez",
        "pregnan", "deficienc", "disabilit", "pcd", "peso", "altura", "imc", "sangue", "blood", "terapia",
        "psicolog", "psiquiatr", "anamnese", "condicao_medica", "medical"]),
    "sensivel_biometria": ("Dado sensível: biométrico/genético", "sensivel", [
        "biometr", "digital_impress", "fingerprint", "face_id", "faceid", "facial", "selfie", "genetic",
        "genetico", "dna", "iris", "voz_", "voiceprint"]),
    "sensivel_outros": ("Dado sensível: origem, crença, política, vida sexual, sindicato", "sensivel", [
        "raca", "race", "etnia", "ethnic", "cor_pele", "religi", "crenca", "politic", "partido",
        "sindica", "union_member", "orientacao_sexual", "sexual", "genero_identidade"]),
    "crianca": ("Possível dado de criança/adolescente", "alto", [
        "menor", "crianca", "child", "kid", "aluno", "student", "responsavel", "guardian", "parent",
        "nome_mae", "nome_pai", "idade", "age", "escola", "school", "serie_escolar"]),
    "documento": ("Documento de identificação", "alto", [
        "cpf", "rg", "cnh", "passaporte", "passport", "titulo_eleitor", "pis", "nis", "ctps", "ssn",
        "documento", "document_number", "cns", "cartao_sus", "certidao"]),
    "financeiro": ("Financeiro", "alto", [
        "cartao", "card_number", "cvv", "pan", "conta_bancaria", "bank_account", "agencia", "iban",
        "pix", "renda", "salario", "salary", "income", "score", "divida", "debt", "patrimonio"]),
    "credencial": ("Credencial/autenticação", "alto", [
        "senha", "password", "passwd", "pwd", "secret", "token", "otp", "mfa", "recovery_code",
        "api_key", "hash_senha"]),
    "localizacao": ("Localização/rede", "medio", [
        "endereco", "address", "rua", "street", "logradouro", "bairro", "cidade", "city", "cep",
        "zip", "postal", "latitude", "longitude", "lat", "lng", "geoloc", "location", "ip_address",
        "ip", "user_agent", "device_id"]),
    "contato": ("Contato", "medio", [
        "email", "e_mail", "telefone", "phone", "celular", "mobile", "whatsapp", "telegram"]),
    "identificacao": ("Identificação", "medio", [
        "nome", "name", "first_name", "last_name", "sobrenome", "apelido", "nickname", "nascimento",
        "birth", "dob", "data_nasc", "sexo", "genero", "gender", "foto", "avatar", "photo",
        "estado_civil", "nacionalidade", "profissao", "username"]),
}
EXCLUIR = re.compile(r"^(id|created_at|updated_at|deleted_at|status|type|tipo|slug|title|titulo|"
                     r"description|descricao|price|preco|quantity|quantidade|product_name|company_name|"
                     r"file_name|filename|table_name|role|plan|metadata)$")
# Para evitar falso positivo em palavras curtas, estas exigem correspondência de token inteiro
CURTAS = {"rg", "cid", "pis", "nis", "pan", "ip", "lat", "lng", "age", "kid", "dna", "iris", "zip",
          "otp", "mfa", "cvv", "pwd", "cep", "dob", "pix", "cor_pele", "name", "nome", "score", "peso"}

SQL_TABELA = re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?([\w\".]+)\s*\((.*?)\);", re.I | re.S)
PRISMA_MODEL = re.compile(r"^model\s+(\w+)\s*\{(.*?)^\}", re.M | re.S)
TS_BLOCO = re.compile(r"(?:interface\s+(\w+)|type\s+(\w+)\s*=|(\w+)\s*=\s*z\.object\()\s*\{(.*?)\}", re.S)
PY_MODEL = re.compile(r"class\s+(\w+)\((?:[\w.]*Model|BaseModel|Base|SQLModel)[^)]*\):(.*?)(?=\nclass\s|\Z)", re.S)
FORM = re.compile(r"\bname=[\"']([A-Za-z_][\w\-]*)[\"']")


def normalizar(s: str) -> str:
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()
    s = re.sub(r"([a-z])([A-Z])", r"\1_\2", s).lower()
    return re.sub(r"[^a-z0-9]+", "_", s).strip("_")


def classificar(campo: str):
    n = normalizar(campo)
    if EXCLUIR.match(n):
        return None
    tokens = set(n.split("_"))
    for cat, (_, _, chaves) in CATEGORIAS.items():
        for c in chaves:
            if c in CURTAS or len(c) <= 3:
                if c in tokens or n == c:
                    return cat
            elif c in n:
                return cat
    return None


def registrar(itens, entidade, campo, origem, arquivo):
    cat = classificar(campo)
    if cat:
        itens.append({"entidade": entidade, "campo": campo, "categoria": cat,
                      "descricao": CATEGORIAS[cat][0], "nivel": CATEGORIAS[cat][1],
                      "origem": origem, "arquivo": arquivo})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir")
    ap.add_argument("--saida")
    ap.add_argument("--md", help="grava também uma tabela Markdown de rascunho")
    a = ap.parse_args()
    raiz = Path(a.dir).resolve()
    itens: list = []

    for p in iterar_arquivos(raiz):
        r = rel(p, raiz)
        t = ler(p)
        suf = p.suffix.lower()
        if suf == ".sql":
            for m in SQL_TABELA.finditer(t):
                tabela = m.group(1).replace('"', "")
                for linha in m.group(2).split(","):
                    tok = linha.strip().split()
                    if tok and not tok[0].lower() in {"constraint", "primary", "foreign", "unique", "check"}:
                        registrar(itens, tabela, tok[0].strip('"'), "SQL", r)
            for m in re.finditer(r"alter\s+table\s+([\w\".]+)\s+add\s+column\s+(?:if\s+not\s+exists\s+)?([\w\"]+)", t, re.I):
                registrar(itens, m.group(1).replace('"', ""), m.group(2).strip('"'), "SQL", r)
        elif suf == ".prisma":
            for m in PRISMA_MODEL.finditer(t):
                for linha in m.group(2).splitlines():
                    tok = linha.strip().split()
                    if len(tok) >= 2 and not tok[0].startswith(("@@", "//")):
                        registrar(itens, m.group(1), tok[0], "Prisma", r)
        elif suf == ".py":
            for m in PY_MODEL.finditer(t):
                for c in re.finditer(r"^\s+(\w+)\s*[:=]", m.group(2), re.M):
                    registrar(itens, m.group(1), c.group(1), "Python", r)
        elif suf in {".ts", ".tsx"} and "node_modules" not in r:
            if r.endswith(("database.types.ts", "supabase.ts", "types/supabase.ts")):
                for m in re.finditer(r"(\w+):\s*\{\s*Row:\s*\{(.*?)\}", t, re.S):
                    for c in re.finditer(r"(\w+)\??:", m.group(2)):
                        registrar(itens, m.group(1), c.group(1), "Supabase types", r)
            else:
                for m in TS_BLOCO.finditer(t):
                    nome = m.group(1) or m.group(2) or m.group(3)
                    for c in re.finditer(r"(?:^|[;,{\n])\s*(\w+)\??\s*:", m.group(4)):
                        registrar(itens, nome, c.group(1), "TypeScript/zod", r)
        if suf in {".html", ".tsx", ".jsx", ".vue", ".svelte", ".astro"}:
            for c in FORM.finditer(t):
                registrar(itens, f"formulário ({p.name})", c.group(1), "Formulário", r)

    # agrega por entidade+campo
    agreg = {}
    for i in itens:
        k = (i["entidade"].lower(), normalizar(i["campo"]))
        if k not in agreg:
            agreg[k] = dict(i, arquivos=[i["arquivo"]])
        elif i["arquivo"] not in agreg[k]["arquivos"]:
            agreg[k]["arquivos"].append(i["arquivo"])
    lista = sorted(agreg.values(), key=lambda x: ({"sensivel": 0, "alto": 1, "medio": 2}[x["nivel"]], x["entidade"]))
    for x in lista:
        x.pop("arquivo", None)

    resumo = {}
    for x in lista:
        resumo[x["descricao"]] = resumo.get(x["descricao"], 0) + 1
    alertas = []
    if any(x["nivel"] == "sensivel" for x in lista):
        alertas.append("Há indícios de DADOS SENSÍVEIS (art. 11): exigem base legal do art. 11, cifra por campo e provavelmente RIPD.")
    if any(x["categoria"] == "crianca" for x in lista):
        alertas.append("Há indícios de dados de CRIANÇAS/ADOLESCENTES: verificar art. 14 da LGPD e ECA Digital.")
    if any(x["categoria"] == "credencial" and x["origem"] != "Formulário" for x in lista):
        alertas.append("Credenciais armazenadas pelo próprio sistema: confirmar hash adaptativo (medida 10) ou migrar para provedor de auth.")
    if any(x["categoria"] == "financeiro" and any(s in normalizar(x["campo"]) for s in ("card", "cartao", "cvv"))
           for x in lista):
        alertas.append("Possível armazenamento de cartão: não guardar PAN/CVV; usar tokenização do provedor de pagamento.")

    salvar({"campos": lista, "resumo": resumo, "alertas": alertas,
            "aviso": "Rascunho automático: confirmar finalidade, base legal, retenção e compartilhamento com o responsável."},
           a.saida)

    print(f"{len(lista)} campo(s) com indício de dado pessoal.")
    for k, v in resumo.items():
        print(f"- {k}: {v}")
    for al in alertas:
        print(f"⚠ {al}")

    if a.md:
        linhas = ["| Entidade | Campo | Categoria | Origem | Finalidade | Base legal | Retenção | Compartilhado com |",
                  "|---|---|---|---|---|---|---|---|"]
        for x in lista:
            linhas.append(f"| {x['entidade']} | {x['campo']} | {x['descricao']} | {x['origem']} | _a definir_ | _a definir_ | _a definir_ | _a definir_ |")
        Path(a.md).write_text("\n".join(linhas) + "\n", encoding="utf-8")
        print(f"Tabela de rascunho salva em {a.md}", file=sys.stderr)


if __name__ == "__main__":
    main()
