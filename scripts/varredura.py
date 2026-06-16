#!/usr/bin/env python3
"""
Varredura de fraudes em débitos veiculares via SerpAPI Google Ads.
Executa 24 queries × 3 páginas, filtra pela safelist e gera relatório.
"""

import os
import re
import json
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent
SERPAPI_KEY = os.environ["SERPAPI_KEY"]

QUERIES = [
    ("pagar debitos SP",           "São Paulo, São Paulo, Brazil"),
    ("pagar debitos SC",           "Florianópolis, Santa Catarina, Brazil"),
    ("pagar debitos MG",           "Belo Horizonte, Minas Gerais, Brazil"),
    ("pagar debitos RJ",           "Rio de Janeiro, Rio de Janeiro, Brazil"),
    ("pagar debitos BA",           "Salvador, Bahia, Brazil"),
    ("pagar debitos GO",           "Goiânia, Goiás, Brazil"),
    ("pagar debitos RS",           "Porto Alegre, Rio Grande do Sul, Brazil"),
    ("pagar debitos PR",           "Curitiba, Paraná, Brazil"),
    ("pagar ipva SP",              "São Paulo, São Paulo, Brazil"),
    ("pagar ipva SC",              "Florianópolis, Santa Catarina, Brazil"),
    ("pagar ipva MG",              "Belo Horizonte, Minas Gerais, Brazil"),
    ("pagar ipva RJ",              "Rio de Janeiro, Rio de Janeiro, Brazil"),
    ("pagar ipva BA",              "Salvador, Bahia, Brazil"),
    ("pagar ipva GO",              "Goiânia, Goiás, Brazil"),
    ("pagar ipva RS",              "Porto Alegre, Rio Grande do Sul, Brazil"),
    ("pagar ipva PR",              "Curitiba, Paraná, Brazil"),
    ("detran consulta placa SP",   "São Paulo, São Paulo, Brazil"),
    ("detran consulta placa SC",   "Florianópolis, Santa Catarina, Brazil"),
    ("detran consulta placa MG",   "Belo Horizonte, Minas Gerais, Brazil"),
    ("detran consulta placa RJ",   "Rio de Janeiro, Rio de Janeiro, Brazil"),
    ("detran consulta placa BA",   "Salvador, Bahia, Brazil"),
    ("detran consulta placa GO",   "Goiânia, Goiás, Brazil"),
    ("detran consulta placa RS",   "Porto Alegre, Rio Grande do Sul, Brazil"),
    ("detran consulta placa PR",   "Curitiba, Paraná, Brazil"),
]

# TLDs de países que imitam siglas de estados brasileiros
SUSPICIOUS_TLDS = {".sc", ".mg", ".ba", ".ms", ".mt", ".pa", ".ro", ".to", ".ac"}

# Padrões de domínio que geram classificação ALTO automática
HIGH_RISK_PATTERNS = [
    r"^detran\.(sc|mg|ba|ms|mt|pa|ro|to|ac|go|rj|sp|rs|pr)$",
    r"^sefaz\.(sc|mg|ba|ms|mt|pa|ro|to|ac|go|rj|sp|rs|pr)$",
    r"^transito\.(sc|mg|ba|ms|mt|pa|ro|to|ac|go|rj|sp|rs|pr)$",
    r"ipva-fazenda-.+\.(org|com|net|info|online)$",
    r"^.+-debito\.(com|net|org|com\.br)$",
]

# Marcas legítimas que não devem aparecer em domínios de terceiros
PROTECTED_BRANDS = ["zapay", "gringo", "zul", "detran", "sefaz"]


def load_safelist():
    text = (ROOT / "references" / "safelist.md").read_text()
    domains = set()
    for line in text.splitlines():
        line = line.strip().lstrip("- ")
        # pega apenas linhas que parecem domínios
        if "." in line and " " not in line and not line.startswith("#"):
            domains.add(line.lower().rstrip("/"))
    return domains


def extract_domain(url):
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "https://" + url)
        host = parsed.netloc or parsed.path
        host = host.lower().split(":")[0]
        # remove www.
        return re.sub(r"^www\.", "", host)
    except Exception:
        return url.lower()


def is_safelisted(domain, safelist):
    if domain in safelist:
        return True
    # verifica se é subdomínio de algo na safelist
    for safe in safelist:
        if domain.endswith("." + safe):
            return True
        # gov.br cobre qualquer *.gov.br
        if safe == "gov.br" and domain.endswith(".gov.br"):
            return True
    return False


def classify(domain):
    """Retorna (risco, motivo) para um domínio."""
    d = domain.lower()

    # Verifica TLD de país suspeito
    for tld in SUSPICIOUS_TLDS:
        if d.endswith(tld):
            # Só é suspeito se o nome antes do TLD parece órgão oficial
            base = d[: -len(tld)]
            if any(kw in base for kw in ["detran", "sefaz", "transito", "ipva", "debito"]):
                return "ALTO", f"TLD {tld} imita sigla de estado BR em domínio oficial"

    # Verifica padrões de alto risco
    for pattern in HIGH_RISK_PATTERNS:
        if re.search(pattern, d):
            return "ALTO", f"Padrão de fraude: {pattern}"

    # Verifica uso indevido de marca em subdomínio
    for brand in PROTECTED_BRANDS:
        if d.startswith(brand + ".") and not d.endswith(".gov.br"):
            # ex: zapay.portaldotransito.com.br
            if not any(d == f"{brand}.com.br" or d == f"{brand}.com" for _ in [1]):
                return "MEDIO", f"Marca '{brand}' usada como subdomínio de site terceiro"

    # Flags de risco por nome
    flags = 0
    if re.search(r"(ipva|detran|sefaz|debito|placa|veiculo|licenciamento)", d):
        flags += 1
    if re.search(r"\.(org|net|info|online|store|click|top|xyz)$", d):
        flags += 1
    if re.search(r"(pagar|consultar|emitir|boleto|parcelar)", d):
        flags += 1
    if re.search(r"-(sp|sc|mg|rj|ba|go|rs|pr|df|pe|ce|mt|ms|pa|ro|to|ac|rn|pb|al|se|pi|ma|ap|rr|am)(\.|$)", d):
        flags += 1

    if flags >= 3:
        return "MEDIO", f"{flags} flags de nome suspeito"
    if flags >= 1:
        return "BAIXO", f"{flags} flag(s) de nome suspeito"
    return None, None  # não classificado como suspeito


def serpapi_call(query, location, start):
    params = urllib.parse.urlencode({
        "engine": "google_ads",
        "q": query,
        "location": location,
        "gl": "br",
        "hl": "pt-BR",
        "google_domain": "google.com.br",
        "start": start,
        "api_key": SERPAPI_KEY,
    })
    url = f"https://serpapi.com/search.json?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": "fraud-monitor/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def run():
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%Y-%m-%d %H:%M UTC")

    print(f"[{time_str}] Iniciando varredura...")
    safelist = load_safelist()
    print(f"  Safelist: {len(safelist)} domínios carregados")

    ads_total = 0
    ads_filtered = 0
    api_calls = 0
    suspects = []  # list of dicts

    for query, location in QUERIES:
        uf = query.split()[-1]  # SP, SC, MG...
        for page, start in enumerate([0, 10, 20], start=1):
            try:
                data = serpapi_call(query, location, start)
                api_calls += 1
                ads = data.get("ads", [])
                print(f"  [{uf}] '{query}' pág {page}: {len(ads)} anúncio(s)")

                for ad in ads:
                    ads_total += 1
                    link = ad.get("link", "")
                    displayed = ad.get("displayed_link", "")
                    domain = extract_domain(link)

                    if is_safelisted(domain, safelist):
                        ads_filtered += 1
                        continue

                    risco, motivo = classify(domain)
                    if risco is None:
                        # domínio sem flags — registrar como BAIXO se não está na safelist
                        risco, motivo = "BAIXO", "Fora da safelist, sem flags específicas"

                    suspects.append({
                        "domain": domain,
                        "url": link,
                        "displayed": displayed,
                        "title": ad.get("title", ""),
                        "description": ad.get("description", ""),
                        "uf": uf,
                        "query": query,
                        "page": page,
                        "risco": risco,
                        "motivo": motivo,
                    })

                time.sleep(0.5)  # respeitar rate limit
            except Exception as e:
                print(f"  ERRO [{uf}] '{query}' pág {page}: {e}")

    # deduplicar por domínio (manter o de maior risco)
    seen = {}
    for s in suspects:
        d = s["domain"]
        if d not in seen:
            seen[d] = s
        else:
            order = {"ALTO": 3, "MEDIO": 2, "BAIXO": 1}
            if order.get(s["risco"], 0) > order.get(seen[d]["risco"], 0):
                seen[d] = s
    suspects = sorted(seen.values(), key=lambda x: {"ALTO": 0, "MEDIO": 1, "BAIXO": 2}[x["risco"]])

    alto = [s for s in suspects if s["risco"] == "ALTO"]
    medio = [s for s in suspects if s["risco"] == "MEDIO"]
    baixo = [s for s in suspects if s["risco"] == "BAIXO"]

    print(f"\nResultado: {ads_total} anúncios | {ads_filtered} filtrados | {len(suspects)} suspeitos únicos")
    print(f"  🔴 ALTO: {len(alto)} | 🟠 MÉDIO: {len(medio)} | ⚠️ BAIXO: {len(baixo)}")
    print(f"  API calls: {api_calls} créditos consumidos")

    # gerar relatório
    report = generate_report(date_str, time_str, api_calls, ads_total, ads_filtered, suspects)
    out = ROOT / "reports" / f"{date_str}_varredura.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text(report)
    print(f"\nRelatório salvo em: {out}")

    if alto:
        print("\n⚠️  AÇÃO IMEDIATA — Sites de ALTO RISCO:")
        for s in alto:
            print(f"  {s['domain']} ({s['uf']}) — {s['motivo']}")


def generate_report(date_str, time_str, api_calls, total, filtered, suspects):
    alto  = [s for s in suspects if s["risco"] == "ALTO"]
    medio = [s for s in suspects if s["risco"] == "MEDIO"]
    baixo = [s for s in suspects if s["risco"] == "BAIXO"]

    lines = [
        f"# Relatório de Varredura — Fraudes em Débitos Veiculares",
        f"",
        f"**Data:** {date_str}  ",
        f"**Hora:** {time_str}  ",
        f"**Queries:** 24 (3 termos × 8 UFs)  ",
        f"**Páginas por query:** 3  ",
        f"**Créditos SerpAPI consumidos:** {api_calls}  ",
        f"",
        f"---",
        f"",
        f"## Resumo Executivo",
        f"",
        f"| Métrica | Valor |",
        f"|---|---|",
        f"| Anúncios encontrados | {total} |",
        f"| Filtrados pela safelist | {filtered} |",
        f"| Domínios suspeitos únicos | {len(suspects)} |",
        f"| 🔴 Alto risco | {len(alto)} |",
        f"| 🟠 Médio risco | {len(medio)} |",
        f"| ⚠️ Baixo risco | {len(baixo)} |",
        f"",
    ]

    if alto:
        lines += [
            f"## 🔴 Sites de ALTO RISCO",
            f"",
        ]
        for s in alto:
            lines += [
                f"### {s['domain']}",
                f"- **UF:** {s['uf']}",
                f"- **Termo:** {s['query']} (pág {s['page']})",
                f"- **URL:** {s['url']}",
                f"- **Exibida:** {s['displayed']}",
                f"- **Título:** {s['title']}",
                f"- **Motivo:** {s['motivo']}",
                f"",
            ]

    if medio:
        lines += [f"## 🟠 Sites de MÉDIO RISCO", f""]
        lines += ["| Domínio | UF | Termo | Motivo |", "|---|---|---|---|"]
        for s in medio:
            lines.append(f"| {s['domain']} | {s['uf']} | {s['query']} | {s['motivo']} |")
        lines.append("")

    if baixo:
        lines += [f"## ⚠️ Sites de BAIXO RISCO", f""]
        lines += ["| Domínio | UF | Termo |", "|---|---|---|"]
        for s in baixo:
            lines.append(f"| {s['domain']} | {s['uf']} | {s['query']} |")
        lines.append("")

    lines += [
        f"---",
        f"",
        f"*Próxima varredura recomendada: verificar dia 1 ou 15 do próximo mês*",
    ]

    return "\n".join(lines)


if __name__ == "__main__":
    run()
