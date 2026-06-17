#!/usr/bin/env python3
"""
Varredura de fraudes em débitos veiculares via SerpAPI Google Ads.
Executa 24 queries × 3 páginas, filtra pela safelist e gera relatório.
"""

import os
import re
import sys
import json
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent
SERPAPI_KEY = os.environ["SERPAPI_KEY"]

LOCATIONS = {
    "SP": "São Paulo, São Paulo, Brazil",
    "SC": "Florianópolis, Santa Catarina, Brazil",
    "MG": "Belo Horizonte, Minas Gerais, Brazil",
    "RJ": "Rio de Janeiro, Rio de Janeiro, Brazil",
    "BA": "Salvador, Bahia, Brazil",
    "GO": "Goiânia, Goiás, Brazil",
    "RS": "Porto Alegre, Rio Grande do Sul, Brazil",
    "PR": "Curitiba, Paraná, Brazil",
}

# 4 termos × 4 UFs (rotacionadas) × 2 páginas = 32 créditos por varredura
QUERIES = [
    ("parcelar multa",        "SP"), ("parcelar multa",        "MG"),
    ("parcelar multa",        "RS"), ("parcelar multa",        "BA"),
    ("parcelar debitos",      "RJ"), ("parcelar debitos",      "SC"),
    ("parcelar debitos",      "PR"), ("parcelar debitos",      "GO"),
    ("pagar licenciamento",   "SP"), ("pagar licenciamento",   "MG"),
    ("pagar licenciamento",   "RS"), ("pagar licenciamento",   "BA"),
    ("pagar multa",           "RJ"), ("pagar multa",           "SC"),
    ("pagar multa",           "PR"), ("pagar multa",           "GO"),
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


def run(test_mode=False):
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%Y-%m-%d %H:%M UTC")

    queries = QUERIES[:1] if test_mode else QUERIES
    if test_mode:
        print(f"[{time_str}] Modo teste — 1 query, 1 página (1 crédito)")
    else:
        print(f"[{time_str}] Iniciando varredura completa...")
    safelist = load_safelist()
    print(f"  Safelist: {len(safelist)} domínios carregados")

    ads_total = 0
    ads_filtered = 0
    api_calls = 0
    suspects = []  # list of dicts

    pages = [0] if test_mode else [0, 10]

    for query, uf in queries:
        location = LOCATIONS[uf]
        for page, start in enumerate(pages, start=1):
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
    out_dir = ROOT / "reports"
    out_dir.mkdir(exist_ok=True)

    report = generate_report(date_str, time_str, api_calls, ads_total, ads_filtered, suspects)
    out_md = out_dir / f"{date_str}_varredura.md"
    out_md.write_text(report)
    print(f"\nRelatório salvo em: {out_md}")

    html = generate_dashboard(date_str, time_str, api_calls, ads_total, ads_filtered, suspects)
    out_html = out_dir / f"{date_str}_dashboard.html"
    out_html.write_text(html)
    print(f"Dashboard salvo em:  {out_html}")

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


def generate_dashboard(date_str, time_str, api_calls, total, filtered, suspects):
    alto  = [s for s in suspects if s["risco"] == "ALTO"]
    medio = [s for s in suspects if s["risco"] == "MEDIO"]
    baixo = [s for s in suspects if s["risco"] == "BAIXO"]

    def badge(risco):
        cls = {"ALTO": "badge-alto", "MEDIO": "badge-medio", "BAIXO": "badge-baixo"}.get(risco, "")
        return f'<span class="badge {cls}">{risco}</span>'

    rows_html = ""
    for s in suspects:
        domain_url = s["url"] or f"https://{s['domain']}"
        rows_html += f"""
        <tr data-uf="{s['uf']}" data-risco="{s['risco']}" id="row-{s['domain'].replace('.', '-')}">
          <td class="domain"><a href="{domain_url}" target="_blank">{s['domain']}</a></td>
          <td class="uf"><span>{s['uf']}</span></td>
          <td>{badge(s['risco'])}</td>
          <td class="query"><span>{s['query']}</span></td>
          <td class="motivo">{s['motivo']}</td>
          <td class="enc">{date_str[5:]}</td>
          <td><button class="btn-safe" onclick="addToSafelist(this, '{s['domain']}')">+ Safelist</button></td>
        </tr>"""

    ufs = sorted({s["uf"] for s in suspects})
    uf_options = "\n".join(f"<option>{u}</option>" for u in ufs)

    alert_html = ""
    if alto:
        alert_html = f'<div class="alert">⚠️ <strong>{len(alto)} site(s) de alto risco</strong> identificados na última varredura. Verifique imediatamente.</div>'

    bar_max = max(len(suspects), 1)
    bar_pct = int(len(suspects) / bar_max * 100)

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Monitor de Sites Fraudulentos — {date_str}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f3f4f6; color: #111827; font-size: 14px; }}
  .header {{ background: #1e2533; color: #fff; padding: 14px 24px; display: flex; align-items: center; justify-content: space-between; }}
  .header-left {{ display: flex; align-items: center; gap: 10px; }}
  .header-left h1 {{ font-size: 18px; font-weight: 700; }}
  .header-left p {{ font-size: 12px; color: #94a3b8; margin-top: 2px; }}
  .header-right {{ display: flex; align-items: center; gap: 16px; }}
  .header-right .last {{ font-size: 12px; color: #94a3b8; }}
  .btn-run {{ background: #ef4444; color: #fff; border: none; border-radius: 6px; padding: 8px 14px; font-size: 13px; font-weight: 600; cursor: pointer; }}
  .stats {{ display: flex; gap: 16px; padding: 20px 24px 8px; }}
  .stat-card {{ background: #fff; border-radius: 8px; padding: 18px 24px; flex: 1; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .stat-card .value {{ font-size: 36px; font-weight: 800; line-height: 1; }}
  .stat-card .label {{ font-size: 11px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: .05em; margin-top: 6px; }}
  .stat-card.red .value {{ color: #ef4444; }} .stat-card.green .value {{ color: #10b981; }}
  .stat-card.blue .value {{ color: #3b82f6; }} .stat-card.indigo .value {{ color: #6366f1; }}
  .main {{ padding: 12px 24px 32px; }}
  .alert {{ background: #fff7ed; border-left: 4px solid #f97316; border-radius: 6px; padding: 12px 16px; margin-bottom: 16px; font-size: 13px; color: #9a3412; }}
  .card {{ background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.08); overflow: hidden; }}
  .card-header {{ padding: 14px 18px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #f1f5f9; flex-wrap: wrap; gap: 8px; }}
  .card-header h2 {{ font-size: 15px; font-weight: 700; }}
  .filters {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
  .filter-input, .filter-select {{ border: 1px solid #e2e8f0; border-radius: 6px; padding: 6px 10px; font-size: 13px; outline: none; color: #374151; }}
  .filter-select {{ padding-right: 28px; appearance: none; background: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%236b7280' stroke-width='1.5' fill='none'/%3E%3C/svg%3E") no-repeat right 10px center; cursor: pointer; }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead th {{ padding: 10px 14px; text-align: left; font-size: 11px; font-weight: 700; color: #6b7280; text-transform: uppercase; letter-spacing: .05em; border-bottom: 1px solid #f1f5f9; }}
  tbody tr {{ border-bottom: 1px solid #f9fafb; }}
  tbody tr:last-child {{ border-bottom: none; }}
  tbody tr:hover {{ background: #f8fafc; }}
  tbody td {{ padding: 12px 14px; vertical-align: top; font-size: 13px; }}
  td.domain a {{ color: #3b82f6; text-decoration: none; font-weight: 500; }}
  td.domain a:hover {{ text-decoration: underline; }}
  td.uf span {{ display: inline-block; background: #f1f5f9; color: #374151; border-radius: 4px; padding: 2px 7px; font-size: 12px; font-weight: 600; }}
  td.motivo {{ color: #4b5563; max-width: 240px; line-height: 1.5; }}
  td.enc {{ color: #9ca3af; white-space: nowrap; }}
  td.query span {{ background: #f1f5f9; color: #374151; border-radius: 4px; padding: 3px 8px; font-size: 12px; }}
  .badge {{ display: inline-block; border-radius: 20px; padding: 3px 10px; font-size: 12px; font-weight: 700; }}
  .badge-alto {{ background: #fee2e2; color: #b91c1c; }} .badge-medio {{ background: #ffedd5; color: #c2410c; }} .badge-baixo {{ background: #fefce8; color: #a16207; }}
  .pagination {{ padding: 12px 18px; display: flex; align-items: center; justify-content: space-between; border-top: 1px solid #f1f5f9; font-size: 13px; color: #6b7280; }}
  .pag-buttons {{ display: flex; gap: 4px; }}
  .pag-btn {{ border: 1px solid #e2e8f0; background: #fff; border-radius: 4px; padding: 4px 10px; font-size: 13px; cursor: pointer; color: #374151; }}
  .pag-btn.active {{ background: #1e40af; color: #fff; border-color: #1e40af; }}
  .history-card {{ background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-top: 16px; overflow: hidden; }}
  .history-body {{ padding: 16px 18px; }}
  .bar-row {{ display: flex; align-items: center; gap: 12px; margin-bottom: 10px; font-size: 13px; }}
  .bar-row .date {{ width: 100px; color: #6b7280; }}
  .bar-wrap {{ flex: 1; background: #f1f5f9; border-radius: 4px; height: 14px; overflow: hidden; }}
  .bar {{ height: 100%; background: #ef4444; border-radius: 4px; }}
  .bar-row .count {{ width: 28px; text-align: right; font-weight: 700; color: #ef4444; }}
  footer {{ text-align: center; padding: 20px; color: #9ca3af; font-size: 12px; }}
  .row-hidden {{ display: none; }}
  .btn-safe {{ background: #f0fdf4; color: #16a34a; border: 1px solid #86efac; border-radius: 5px; padding: 3px 9px; font-size: 12px; font-weight: 600; cursor: pointer; white-space: nowrap; }}
  .btn-safe:hover {{ background: #dcfce7; }}
  .btn-safe:disabled {{ background: #f1f5f9; color: #94a3b8; border-color: #e2e8f0; cursor: default; }}
  .toast {{ position: fixed; bottom: 24px; right: 24px; background: #1e2533; color: #fff; border-radius: 8px; padding: 12px 18px; font-size: 13px; box-shadow: 0 4px 12px rgba(0,0,0,.2); z-index: 999; opacity: 0; transition: opacity .3s; pointer-events: none; }}
  .toast.show {{ opacity: 1; }}
</style>
</head>
<body>
<div class="header">
  <div class="header-left">
    <span style="font-size:20px">🔍</span>
    <div>
      <h1>Monitor de Sites Fraudulentos</h1>
      <p>Débitos Veiculares · Varredura automática quinzenal · Zapay &amp; Gringo</p>
    </div>
  </div>
  <div class="header-right">
    <span class="last">Última varredura: {time_str}</span>
    <button class="btn-run" onclick="alert('Varredura agendada via GitHub Actions.\\nPróxima execução automática: dias 1 e 15 do mês.')">▶ Executar agora</button>
  </div>
</div>

<div class="stats">
  <div class="stat-card red"><div class="value">{len(suspects)}</div><div class="label">Sites Suspeitos</div></div>
  <div class="stat-card green"><div class="value">{len(alto)}</div><div class="label">Alto Risco</div></div>
  <div class="stat-card blue"><div class="value">8</div><div class="label">UFs Monitoradas</div></div>
  <div class="stat-card indigo"><div class="value">{api_calls}</div><div class="label">Queries Executadas</div></div>
</div>

<div class="main">
{alert_html}
  <div class="card">
    <div class="card-header">
      <h2>⚠️ Sites Suspeitos Encontrados</h2>
      <div class="filters">
        <input class="filter-input" id="searchInput" type="text" placeholder="Filtrar sites..." oninput="applyFilters()">
        <select class="filter-select" id="ufFilter" onchange="applyFilters()">
          <option value="">Todas as UFs</option>
          {uf_options}
        </select>
        <select class="filter-select" id="riscoFilter" onchange="applyFilters()">
          <option value="">Todos os riscos</option>
          <option>ALTO</option><option>MEDIO</option><option>BAIXO</option>
        </select>
      </div>
    </div>
    <table id="suspectTable">
      <thead><tr>
        <th>Domínio / URL</th><th>UF</th><th>Risco</th>
        <th>Termo de Busca</th><th>Motivo</th><th>Enc.</th><th></th>
      </tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
    <div class="pagination">
      <span id="paginationInfo">Mostrando <strong>1</strong> a <strong>{len(suspects)}</strong> de <strong>{len(suspects)}</strong> resultados</span>
      <div class="pag-buttons">
        <button class="pag-btn">←</button>
        <button class="pag-btn active">1</button>
        <button class="pag-btn">→</button>
      </div>
    </div>
  </div>

  <div class="history-card">
    <div class="card-header"><h2>📈 Histórico</h2></div>
    <div class="history-body">
      <div class="bar-row">
        <span class="date">{date_str}</span>
        <div class="bar-wrap"><div class="bar" style="width:{bar_pct}%"></div></div>
        <span class="count">{len(suspects)}</span>
      </div>
    </div>
  </div>
</div>

<footer>
  <span>Monitoramento de fraudes</span> ·
  <span>Atualizado automaticamente (dias 1 e 15)</span> ·
  <span>Yago Teixeira</span> ·
  <span>Corpay</span>
</footer>
<div class="toast" id="toast"></div>
<script>
const _ENC = '342d3d0f2821263701057516722538331639251c2d056a04281371082d3a352a772b71033b2f1806';
const _PWD = 'SEMPARARDOC';
function _decode(hex, pwd) {{
  const bytes = hex.match(/.{{2}}/g).map(h => parseInt(h, 16));
  return bytes.map((b, i) => String.fromCharCode(b ^ pwd.charCodeAt(i % pwd.length))).join('');
}}
function getToken() {{
  let cached = sessionStorage.getItem('_st');
  if (cached) return cached;
  const pwd = prompt('Senha de acesso:');
  if (!pwd) return null;
  const t = _decode(_ENC, pwd);
  if (!t.startsWith('ghp_')) {{ alert('Senha incorreta.'); return null; }}
  sessionStorage.setItem('_st', t);
  return t;
}}
const GH_TOKEN = null;
const GH_REPO  = 'yagoalmei-da/monitorfraude';
const GH_FILE  = 'references/safelist.md';
const GH_BRANCH = 'main';

function showToast(msg, ok=true) {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.background = ok ? '#16a34a' : '#dc2626';
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}}

async function addToSafelist(btn, domain) {{
  const token = getToken();
  if (!token) {{ showToast('Token não informado', false); return; }}
  btn.disabled = true;
  btn.textContent = '…';
  try {{
    const api = `https://api.github.com/repos/${{GH_REPO}}/contents/${{GH_FILE}}`;
    const headers = {{ Authorization: `Bearer ${{token}}`, Accept: 'application/vnd.github+json' }};
    const meta = await fetch(api + `?ref=${{GH_BRANCH}}`, {{ headers }}).then(r => r.json());
    const current = atob(meta.content.replace(/\\n/g,''));
    if (current.includes(domain)) {{
      btn.textContent = '✓ já existe';
      showToast(`${{domain}} já está na safelist`);
      return;
    }}
    const updated = current.trimEnd() + `\\n- ${{domain}}\\n`;
    await fetch(api, {{
      method: 'PUT',
      headers: {{ ...headers, 'Content-Type': 'application/json' }},
      body: JSON.stringify({{
        message: `chore: adicionar ${{domain}} à safelist`,
        content: btoa(unescape(encodeURIComponent(updated))),
        sha: meta.sha,
        branch: GH_BRANCH,
      }})
    }});
    btn.textContent = '✓ adicionado';
    showToast(`✅ ${{domain}} adicionado à safelist`);
  }} catch(e) {{
    if (e.message && e.message.includes('401')) localStorage.removeItem('gh_safelist_token');
    btn.disabled = false;
    btn.textContent = '+ Safelist';
    showToast(`Erro: ${{e.message}}`, false);
  }}
}}

function applyFilters() {{
  const search = document.getElementById('searchInput').value.toLowerCase();
  const uf = document.getElementById('ufFilter').value;
  const risco = document.getElementById('riscoFilter').value;
  const rows = document.querySelectorAll('#suspectTable tbody tr');
  let visible = 0;
  rows.forEach(row => {{
    const show = (!search || row.textContent.toLowerCase().includes(search))
              && (!uf || row.dataset.uf === uf)
              && (!risco || row.dataset.risco === risco);
    row.classList.toggle('row-hidden', !show);
    if (show) visible++;
  }});
  document.getElementById('paginationInfo').innerHTML =
    `Mostrando <strong>1</strong> a <strong>${{visible}}</strong> de <strong>${{visible}}</strong> resultados`;
}}
</script>
</body>
</html>"""


if __name__ == "__main__":
    run(test_mode="--test" in sys.argv)
