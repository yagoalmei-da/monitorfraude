#!/usr/bin/env python3
"""
Varredura de fraudes em débitos veiculares via SerpAPI Google Ads.
Atualiza data/historico.json e gera dashboard HTML com 4 abas.
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

SUSPICIOUS_TLDS = {".sc", ".mg", ".ba", ".ms", ".mt", ".pa", ".ro", ".to", ".ac"}

HIGH_RISK_PATTERNS = [
    r"^detran\.(sc|mg|ba|ms|mt|pa|ro|to|ac|go|rj|sp|rs|pr)$",
    r"^sefaz\.(sc|mg|ba|ms|mt|pa|ro|to|ac|go|rj|sp|rs|pr)$",
    r"^transito\.(sc|mg|ba|ms|mt|pa|ro|to|ac|go|rj|sp|rs|pr)$",
    r"ipva-fazenda-.+\.(org|com|net|info|online)$",
    r"^.+-debito\.(com|net|org|com\.br)$",
]

PROTECTED_BRANDS = ["zapay", "gringo", "zul", "detran", "sefaz"]


def load_safelist():
    text = (ROOT / "references" / "safelist.md").read_text()
    domains = set()
    for line in text.splitlines():
        line = line.strip().lstrip("- ")
        if "." in line and " " not in line and not line.startswith("#"):
            domains.add(line.lower().rstrip("/"))
    return domains


def extract_domain(url):
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "https://" + url)
        host = parsed.netloc or parsed.path
        host = host.lower().split(":")[0]
        return re.sub(r"^www\.", "", host)
    except Exception:
        return url.lower()


def is_safelisted(domain, safelist):
    if domain in safelist:
        return True
    for safe in safelist:
        if domain.endswith("." + safe):
            return True
        if safe == "gov.br" and domain.endswith(".gov.br"):
            return True
    return False


def classify(domain):
    d = domain.lower()
    for tld in SUSPICIOUS_TLDS:
        if d.endswith(tld):
            base = d[: -len(tld)]
            if any(kw in base for kw in ["detran", "sefaz", "transito", "ipva", "debito"]):
                return "ALTO", f"TLD {tld} imita sigla de estado BR em domínio oficial"
    for pattern in HIGH_RISK_PATTERNS:
        if re.search(pattern, d):
            return "ALTO", f"Padrão de fraude: {pattern}"
    for brand in PROTECTED_BRANDS:
        if d.startswith(brand + ".") and not d.endswith(".gov.br"):
            if not any(d == f"{brand}.com.br" or d == f"{brand}.com" for _ in [1]):
                return "MEDIO", f"Marca '{brand}' usada como subdomínio de site terceiro"
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
    return None, None


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


def load_historico():
    path = ROOT / "data" / "historico.json"
    if path.exists():
        return json.loads(path.read_text())
    return {}


def save_historico(hist):
    path = ROOT / "data" / "historico.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(hist, ensure_ascii=False, indent=2))


def update_historico(hist, date_str, all_ads):
    """Atualiza historico.json com todos os anúncios desta varredura."""
    for ad in all_ads:
        domain = ad["domain"]
        if domain not in hist:
            hist[domain] = {
                "primeira_vez": date_str,
                "ultima_vez": date_str,
                "ocorrencias": 0,
                "safelisted": ad["safelisted"],
                "risco": ad.get("risco"),
                "aparicoes": [],
            }
        entry = hist[domain]
        entry["ultima_vez"] = date_str
        entry["ocorrencias"] += 1
        entry["safelisted"] = ad["safelisted"]
        if ad.get("risco"):
            order = {"ALTO": 3, "MEDIO": 2, "BAIXO": 1}
            if order.get(ad["risco"], 0) > order.get(entry.get("risco"), 0):
                entry["risco"] = ad["risco"]
        entry["aparicoes"].append({
            "data": date_str,
            "termo": ad["query"],
            "uf": ad["uf"],
        })
    return hist


def run(test_mode=False):
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%Y-%m-%d %H:%M UTC")

    queries = QUERIES[:1] if test_mode else QUERIES
    pages = [0] if test_mode else [0, 10]

    if test_mode:
        print(f"[{time_str}] Modo teste — 1 query, 1 página (1 crédito)")
    else:
        print(f"[{time_str}] Iniciando varredura completa...")

    safelist = load_safelist()
    print(f"  Safelist: {len(safelist)} domínios carregados")

    api_calls = 0
    all_ads = []    # todos os anúncios brutos (safelisted + suspeitos)
    query_stats = []  # stats por query para aba Queries

    for query, uf in queries:
        location = LOCATIONS[uf]
        q_total = 0
        for page, start in enumerate(pages, start=1):
            try:
                data = serpapi_call(query, location, start)
                api_calls += 1
                ads = data.get("ads", [])
                q_total += len(ads)
                print(f"  [{uf}] '{query}' pág {page}: {len(ads)} anúncio(s)")

                for ad in ads:
                    domain = extract_domain(ad.get("link", ""))
                    safelisted = is_safelisted(domain, safelist)
                    risco, motivo = (None, None) if safelisted else classify(domain)
                    if not safelisted and risco is None:
                        risco, motivo = "BAIXO", "Fora da safelist, sem flags específicas"

                    all_ads.append({
                        "domain": domain,
                        "url": ad.get("link", ""),
                        "displayed": ad.get("displayed_link", ""),
                        "title": ad.get("title", ""),
                        "uf": uf,
                        "query": query,
                        "page": page,
                        "safelisted": safelisted,
                        "risco": risco,
                        "motivo": motivo,
                    })

                time.sleep(0.5)
            except Exception as e:
                print(f"  ERRO [{uf}] '{query}' pág {page}: {e}")

        query_stats.append({"termo": query, "uf": uf, "location": location, "anuncios": q_total})

    # separar suspeitos (deduplicados por domínio, maior risco)
    seen = {}
    for ad in all_ads:
        if ad["safelisted"]:
            continue
        d = ad["domain"]
        if d not in seen:
            seen[d] = ad
        else:
            order = {"ALTO": 3, "MEDIO": 2, "BAIXO": 1}
            if order.get(ad["risco"], 0) > order.get(seen[d]["risco"], 0):
                seen[d] = ad
    suspects = sorted(seen.values(), key=lambda x: {"ALTO": 0, "MEDIO": 1, "BAIXO": 2}.get(x["risco"], 3))

    alto  = [s for s in suspects if s["risco"] == "ALTO"]
    medio = [s for s in suspects if s["risco"] == "MEDIO"]
    baixo = [s for s in suspects if s["risco"] == "BAIXO"]

    ads_total    = len(all_ads)
    ads_filtered = sum(1 for a in all_ads if a["safelisted"])

    print(f"\nResultado: {ads_total} anúncios | {ads_filtered} safelist | {len(suspects)} suspeitos únicos")
    print(f"  🔴 ALTO: {len(alto)} | 🟠 MÉDIO: {len(medio)} | ⚠️ BAIXO: {len(baixo)}")
    print(f"  API calls: {api_calls} créditos consumidos")

    # atualizar histórico
    hist = load_historico()
    hist = update_historico(hist, date_str, all_ads)
    save_historico(hist)

    # gerar arquivos
    out_dir = ROOT / "reports"
    out_dir.mkdir(exist_ok=True)

    report = generate_report(date_str, time_str, api_calls, ads_total, ads_filtered, suspects)
    (out_dir / f"{date_str}_varredura.md").write_text(report)
    print(f"\nRelatório salvo em: reports/{date_str}_varredura.md")

    html = generate_dashboard(date_str, time_str, api_calls, ads_total, ads_filtered,
                               suspects, all_ads, query_stats, safelist, hist)
    (out_dir / f"{date_str}_dashboard.html").write_text(html)
    print(f"Dashboard salvo em:  reports/{date_str}_dashboard.html")

    if alto:
        print("\n⚠️  AÇÃO IMEDIATA — Sites de ALTO RISCO:")
        for s in alto:
            print(f"  {s['domain']} ({s['uf']}) — {s['motivo']}")


def generate_report(date_str, time_str, api_calls, total, filtered, suspects):
    alto  = [s for s in suspects if s["risco"] == "ALTO"]
    medio = [s for s in suspects if s["risco"] == "MEDIO"]
    baixo = [s for s in suspects if s["risco"] == "BAIXO"]
    lines = [
        "# Relatório de Varredura — Fraudes em Débitos Veiculares", "",
        f"**Data:** {date_str}  ", f"**Hora:** {time_str}  ",
        f"**Queries:** {len(QUERIES)} ({len(set(q for q,_ in QUERIES))} termos × {len(set(u for _,u in QUERIES))} UFs)  ",
        f"**Créditos SerpAPI consumidos:** {api_calls}  ", "", "---", "", "## Resumo Executivo", "",
        "| Métrica | Valor |", "|---|---|",
        f"| Anúncios encontrados | {total} |",
        f"| Filtrados pela safelist | {filtered} |",
        f"| Domínios suspeitos únicos | {len(suspects)} |",
        f"| 🔴 Alto risco | {len(alto)} |",
        f"| 🟠 Médio risco | {len(medio)} |",
        f"| ⚠️ Baixo risco | {len(baixo)} |", "",
    ]
    if alto:
        lines += ["## 🔴 Sites de ALTO RISCO", ""]
        for s in alto:
            lines += [f"### {s['domain']}",
                      f"- **UF:** {s['uf']}", f"- **Termo:** {s['query']}",
                      f"- **URL:** {s['url']}", f"- **Motivo:** {s['motivo']}", ""]
    if medio:
        lines += ["## 🟠 Sites de MÉDIO RISCO", "",
                  "| Domínio | UF | Termo | Motivo |", "|---|---|---|---|"]
        for s in medio:
            lines.append(f"| {s['domain']} | {s['uf']} | {s['query']} | {s['motivo']} |")
        lines.append("")
    if baixo:
        lines += ["## ⚠️ Sites de BAIXO RISCO", "", "| Domínio | UF | Termo |", "|---|---|---|"]
        for s in baixo:
            lines.append(f"| {s['domain']} | {s['uf']} | {s['query']} |")
        lines.append("")
    lines += ["---", "", "*Próxima varredura: dia 1 ou 15 do próximo mês*"]
    return "\n".join(lines)


def generate_dashboard(date_str, time_str, api_calls, total, filtered,
                        suspects, all_ads, query_stats, safelist, hist):
    alto = [s for s in suspects if s["risco"] == "ALTO"]

    def badge(risco):
        if not risco:
            return '<span class="badge badge-safe">SAFELIST</span>'
        cls = {"ALTO": "badge-alto", "MEDIO": "badge-medio", "BAIXO": "badge-baixo"}.get(risco, "")
        return f'<span class="badge {cls}">{risco}</span>'

    def uf_chip(uf):
        return f'<span class="chip">{uf}</span>'

    # --- Aba 1: Suspeitos ---
    rows_suspects = ""
    for s in suspects:
        domain_url = s["url"] or f"https://{s['domain']}"
        safe_id = s['domain'].replace('.', '-').replace('/', '-')
        rows_suspects += f"""
        <tr data-uf="{s['uf']}" data-risco="{s['risco']}">
          <td><a href="{domain_url}" target="_blank" class="link">{s['domain']}</a></td>
          <td>{uf_chip(s['uf'])}</td>
          <td>{badge(s['risco'])}</td>
          <td><span class="chip-query">{s['query']}</span></td>
          <td class="col-motivo">{s['motivo']}</td>
          <td class="col-date">{date_str[5:]}</td>
          <td><button class="btn-safe" onclick="addToSafelist(this,'{s['domain']}')">+ Safelist</button></td>
        </tr>"""

    ufs_sus = sorted({s["uf"] for s in suspects})
    uf_opts = "\n".join(f"<option>{u}</option>" for u in ufs_sus)

    alert_html = ""
    if alto:
        alert_html = f'<div class="alert">⚠️ <strong>{len(alto)} site(s) de alto risco</strong> identificados. Verifique imediatamente.</div>'

    # --- Aba 2: Todos os Anunciantes (histórico) ---
    hist_sorted = sorted(hist.items(), key=lambda x: x[1]["ocorrencias"], reverse=True)
    rows_hist = ""
    for domain, h in hist_sorted:
        ufs_found = sorted({a["uf"] for a in h["aparicoes"]})
        termos_found = sorted({a["termo"] for a in h["aparicoes"]})
        status = "✅ Safelist" if h["safelisted"] else "⚠️ Suspeito"
        status_cls = "safe" if h["safelisted"] else "suspect"
        risco_badge = badge(h.get("risco")) if not h["safelisted"] else ""
        ufs_chips = " ".join(uf_chip(u) for u in ufs_found)
        rows_hist += f"""
        <tr data-safelisted="{'true' if h['safelisted'] else 'false'}">
          <td><a href="https://{domain}" target="_blank" class="link">{domain}</a></td>
          <td class="col-center"><strong>{h['ocorrencias']}</strong></td>
          <td><span class="status-{status_cls}">{status}</span></td>
          <td>{risco_badge}</td>
          <td>{ufs_chips}</td>
          <td class="col-terms">{', '.join(termos_found)}</td>
          <td class="col-date">{h['primeira_vez'][5:]}</td>
          <td class="col-date">{h['ultima_vez'][5:]}</td>
        </tr>"""

    # --- Aba 3: Queries ---
    rows_queries = ""
    for q in query_stats:
        rows_queries += f"""
        <tr>
          <td><span class="chip-query">{q['termo']}</span></td>
          <td>{uf_chip(q['uf'])}</td>
          <td class="col-motivo" style="color:#6b7280">{q['location']}</td>
          <td class="col-center">{q['anuncios']}</td>
        </tr>"""

    # --- Aba 4: Safelist ---
    rows_safelist = ""
    for d in sorted(safelist):
        rows_safelist += f"""
        <tr>
          <td><a href="https://{d}" target="_blank" class="link">{d}</a></td>
        </tr>"""

    # histórico de varreduras (barra)
    sweep_counts = {}
    for domain, h in hist.items():
        for ap in h["aparicoes"]:
            sweep_counts[ap["data"]] = sweep_counts.get(ap["data"], 0) + 1
    bar_max = max(sweep_counts.values(), default=1)
    bars_html = ""
    for d in sorted(sweep_counts.keys()):
        pct = int(sweep_counts[d] / bar_max * 100)
        bars_html += f"""
      <div class="bar-row">
        <span class="date">{d[5:]}</span>
        <div class="bar-wrap"><div class="bar" style="width:{pct}%"></div></div>
        <span class="count">{sweep_counts[d]}</span>
      </div>"""

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Monitor de Fraudes — {date_str}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f3f4f6;color:#111827;font-size:14px}}
.header{{background:#1e2533;color:#fff;padding:14px 24px;display:flex;align-items:center;justify-content:space-between}}
.header h1{{font-size:18px;font-weight:700}}
.header p{{font-size:12px;color:#94a3b8;margin-top:2px}}
.header-right{{display:flex;align-items:center;gap:16px}}
.header-right .last{{font-size:12px;color:#94a3b8}}
.btn-run{{background:#ef4444;color:#fff;border:none;border-radius:6px;padding:8px 14px;font-size:13px;font-weight:600;cursor:pointer}}
.stats{{display:flex;gap:16px;padding:20px 24px 0}}
.stat-card{{background:#fff;border-radius:8px;padding:16px 20px;flex:1;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.stat-card .value{{font-size:32px;font-weight:800;line-height:1}}
.stat-card .label{{font-size:11px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;margin-top:4px}}
.stat-card.red .value{{color:#ef4444}}.stat-card.orange .value{{color:#f97316}}
.stat-card.blue .value{{color:#3b82f6}}.stat-card.indigo .value{{color:#6366f1}}.stat-card.green .value{{color:#10b981}}
.tabs-wrap{{padding:16px 24px 0}}
.tabs{{display:flex;gap:2px;border-bottom:2px solid #e2e8f0}}
.tab{{padding:9px 18px;font-size:13px;font-weight:600;color:#6b7280;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px;white-space:nowrap}}
.tab.active{{color:#1e40af;border-bottom-color:#1e40af}}
.tab:hover:not(.active){{color:#374151}}
.main{{padding:12px 24px 32px}}
.tab-panel{{display:none}}.tab-panel.active{{display:block}}
.alert{{background:#fff7ed;border-left:4px solid #f97316;border-radius:6px;padding:12px 16px;margin-bottom:12px;font-size:13px;color:#9a3412}}
.card{{background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08);overflow:hidden;margin-bottom:16px}}
.card-header{{padding:12px 16px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #f1f5f9;flex-wrap:wrap;gap:8px}}
.card-header h2{{font-size:14px;font-weight:700}}
.filters{{display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.filter-input,.filter-select{{border:1px solid #e2e8f0;border-radius:6px;padding:5px 10px;font-size:13px;outline:none;color:#374151}}
.filter-select{{padding-right:28px;appearance:none;background:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%236b7280' stroke-width='1.5' fill='none'/%3E%3C/svg%3E") no-repeat right 10px center;cursor:pointer}}
table{{width:100%;border-collapse:collapse}}
thead th{{padding:9px 12px;text-align:left;font-size:11px;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid #f1f5f9}}
tbody tr{{border-bottom:1px solid #f9fafb}}
tbody tr:last-child{{border-bottom:none}}
tbody tr:hover{{background:#f8fafc}}
tbody td{{padding:10px 12px;vertical-align:middle;font-size:13px}}
.link{{color:#3b82f6;text-decoration:none;font-weight:500}}.link:hover{{text-decoration:underline}}
.chip{{display:inline-block;background:#f1f5f9;color:#374151;border-radius:4px;padding:2px 7px;font-size:12px;font-weight:600}}
.chip-query{{background:#eff6ff;color:#1d4ed8;border-radius:4px;padding:2px 8px;font-size:12px}}
.col-motivo{{color:#4b5563;max-width:200px;line-height:1.4}}
.col-date{{color:#9ca3af;white-space:nowrap;font-size:12px}}
.col-center{{text-align:center}}
.col-terms{{color:#6b7280;font-size:12px;max-width:180px}}
.badge{{display:inline-block;border-radius:20px;padding:2px 10px;font-size:12px;font-weight:700}}
.badge-alto{{background:#fee2e2;color:#b91c1c}}.badge-medio{{background:#ffedd5;color:#c2410c}}
.badge-baixo{{background:#fefce8;color:#a16207}}.badge-safe{{background:#f0fdf4;color:#16a34a}}
.status-safe{{color:#16a34a;font-weight:600}}.status-suspect{{color:#dc2626;font-weight:600}}
.btn-safe{{background:#f0fdf4;color:#16a34a;border:1px solid #86efac;border-radius:5px;padding:3px 9px;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap}}
.btn-safe:hover{{background:#dcfce7}}.btn-safe:disabled{{background:#f1f5f9;color:#94a3b8;border-color:#e2e8f0;cursor:default}}
.row-hidden{{display:none}}
.history-body{{padding:14px 16px}}
.bar-row{{display:flex;align-items:center;gap:12px;margin-bottom:8px;font-size:13px}}
.bar-row .date{{width:56px;color:#6b7280;font-size:12px}}
.bar-wrap{{flex:1;background:#f1f5f9;border-radius:4px;height:12px;overflow:hidden}}
.bar{{height:100%;background:#ef4444;border-radius:4px}}
.bar-row .count{{width:28px;text-align:right;font-weight:700;color:#ef4444;font-size:13px}}
.toast{{position:fixed;bottom:24px;right:24px;background:#1e2533;color:#fff;border-radius:8px;padding:12px 18px;font-size:13px;box-shadow:0 4px 12px rgba(0,0,0,.2);z-index:999;opacity:0;transition:opacity .3s;pointer-events:none}}
.toast.show{{opacity:1}}
footer{{text-align:center;padding:20px;color:#9ca3af;font-size:12px}}
</style>
</head>
<body>
<div class="header">
  <div style="display:flex;align-items:center;gap:10px">
    <span style="font-size:20px">🔍</span>
    <div>
      <h1>Monitor de Sites Fraudulentos</h1>
      <p>Débitos Veiculares · Varredura automática quinzenal · Zapay &amp; Gringo</p>
    </div>
  </div>
  <div class="header-right">
    <span class="last">Última varredura: {time_str}</span>
    <button class="btn-run" onclick="alert('Varredura automática nos dias 1 e 15 via GitHub Actions.')">▶ Executar agora</button>
  </div>
</div>

<div class="stats">
  <div class="stat-card red"><div class="value">{len(suspects)}</div><div class="label">Suspeitos</div></div>
  <div class="stat-card orange"><div class="value">{len(alto)}</div><div class="label">Alto Risco</div></div>
  <div class="stat-card green"><div class="value">{filtered}</div><div class="label">Safelist (filtrados)</div></div>
  <div class="stat-card blue"><div class="value">{len(hist)}</div><div class="label">Anunciantes únicos</div></div>
  <div class="stat-card indigo"><div class="value">{api_calls}</div><div class="label">Créditos usados</div></div>
</div>

<div class="tabs-wrap">
  <div class="tabs">
    <div class="tab active" onclick="switchTab(0)">⚠️ Suspeitos ({len(suspects)})</div>
    <div class="tab" onclick="switchTab(1)">📊 Todos os Anunciantes ({len(hist)})</div>
    <div class="tab" onclick="switchTab(2)">🔍 Queries ({len(query_stats)})</div>
    <div class="tab" onclick="switchTab(3)">✅ Safelist ({len(safelist)})</div>
    <div class="tab" onclick="switchTab(4)">📈 Histórico</div>
  </div>
</div>

<div class="main">

<!-- ABA 1: SUSPEITOS -->
<div class="tab-panel active" id="panel-0">
{alert_html}
  <div class="card">
    <div class="card-header">
      <h2>Sites fora da safelist desta varredura</h2>
      <div class="filters">
        <input class="filter-input" id="s-search" type="text" placeholder="Filtrar..." oninput="filterTable('suspectTable','s-search','s-uf','s-risco')">
        <select class="filter-select" id="s-uf" onchange="filterTable('suspectTable','s-search','s-uf','s-risco')">
          <option value="">Todas as UFs</option>{uf_opts}
        </select>
        <select class="filter-select" id="s-risco" onchange="filterTable('suspectTable','s-search','s-uf','s-risco')">
          <option value="">Todos os riscos</option>
          <option>ALTO</option><option>MEDIO</option><option>BAIXO</option>
        </select>
      </div>
    </div>
    <table id="suspectTable">
      <thead><tr>
        <th>Domínio</th><th>UF</th><th>Risco</th><th>Termo</th><th>Motivo</th><th>Enc.</th><th></th>
      </tr></thead>
      <tbody>{rows_suspects}</tbody>
    </table>
  </div>
</div>

<!-- ABA 2: TODOS OS ANUNCIANTES -->
<div class="tab-panel" id="panel-1">
  <div class="card">
    <div class="card-header">
      <h2>Todos os anunciantes encontrados (acumulado histórico)</h2>
      <div class="filters">
        <input class="filter-input" id="h-search" type="text" placeholder="Filtrar domínio..." oninput="filterHist()">
        <select class="filter-select" id="h-status" onchange="filterHist()">
          <option value="">Todos</option>
          <option value="false">Suspeitos</option>
          <option value="true">Safelist</option>
        </select>
      </div>
    </div>
    <table id="histTable">
      <thead><tr>
        <th>Domínio</th><th style="text-align:center">Aparições</th><th>Status</th><th>Risco</th>
        <th>UFs</th><th>Termos</th><th>1ª vez</th><th>Última vez</th>
      </tr></thead>
      <tbody>{rows_hist}</tbody>
    </table>
  </div>
</div>

<!-- ABA 3: QUERIES -->
<div class="tab-panel" id="panel-2">
  <div class="card">
    <div class="card-header"><h2>Queries executadas nesta varredura</h2></div>
    <table>
      <thead><tr><th>Termo</th><th>UF</th><th>Localização</th><th style="text-align:center">Anúncios</th></tr></thead>
      <tbody>{rows_queries}</tbody>
    </table>
  </div>
</div>

<!-- ABA 4: SAFELIST -->
<div class="tab-panel" id="panel-3">
  <div class="card">
    <div class="card-header">
      <h2>Domínios na safelist ({len(safelist)})</h2>
      <input class="filter-input" id="sl-search" type="text" placeholder="Filtrar..." oninput="filterSafelist()">
    </div>
    <table id="safelistTable">
      <thead><tr><th>Domínio</th></tr></thead>
      <tbody>{rows_safelist}</tbody>
    </table>
  </div>
</div>

<!-- ABA 5: HISTÓRICO -->
<div class="tab-panel" id="panel-4">
  <div class="card">
    <div class="card-header"><h2>Aparições por varredura (todos os anunciantes)</h2></div>
    <div class="history-body">{bars_html}</div>
  </div>
</div>

</div><!-- /main -->

<footer>
  Monitoramento de fraudes · Atualizado automaticamente (dias 1 e 15) · Yago Teixeira · Corpay
</footer>
<div class="toast" id="toast"></div>

<script>
// ---- autenticação ----
const _ENC = '342d3d0f2821263701057516722538331639251c2d056a04281371082d3a352a772b71033b2f1806';
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

// ---- toast ----
function showToast(msg, ok=true) {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.background = ok ? '#16a34a' : '#dc2626';
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}}

// ---- safelist ----
const GH_REPO = 'yagoalmei-da/monitorfraude';
const GH_FILE = 'references/safelist.md';
const GH_BRANCH = 'main';
async function addToSafelist(btn, domain) {{
  const token = getToken();
  if (!token) {{ showToast('Token não informado', false); return; }}
  btn.disabled = true; btn.textContent = '…';
  try {{
    const api = `https://api.github.com/repos/${{GH_REPO}}/contents/${{GH_FILE}}`;
    const headers = {{ Authorization: `Bearer ${{token}}`, Accept: 'application/vnd.github+json' }};
    const meta = await fetch(api + `?ref=${{GH_BRANCH}}`, {{headers}}).then(r => r.json());
    const current = atob(meta.content.replace(/\\n/g,''));
    if (current.includes(domain)) {{ btn.textContent = '✓ já existe'; showToast(`${{domain}} já está na safelist`); return; }}
    const updated = current.trimEnd() + `\\n- ${{domain}}\\n`;
    await fetch(api, {{
      method: 'PUT', headers: {{...headers, 'Content-Type': 'application/json'}},
      body: JSON.stringify({{ message: `chore: adicionar ${{domain}} à safelist`, content: btoa(unescape(encodeURIComponent(updated))), sha: meta.sha, branch: GH_BRANCH }})
    }});
    btn.textContent = '✓ adicionado'; showToast(`✅ ${{domain}} adicionado à safelist`);
  }} catch(e) {{
    btn.disabled = false; btn.textContent = '+ Safelist'; showToast(`Erro: ${{e.message}}`, false);
  }}
}}

// ---- tabs ----
function switchTab(i) {{
  document.querySelectorAll('.tab').forEach((t,j) => t.classList.toggle('active', i===j));
  document.querySelectorAll('.tab-panel').forEach((p,j) => p.classList.toggle('active', i===j));
}}

// ---- filtros ----
function filterTable(tableId, searchId, ufId, riscoId) {{
  const s = document.getElementById(searchId).value.toLowerCase();
  const u = document.getElementById(ufId)?.value || '';
  const r = document.getElementById(riscoId)?.value || '';
  document.querySelectorAll(`#${{tableId}} tbody tr`).forEach(row => {{
    const show = (!s || row.textContent.toLowerCase().includes(s))
              && (!u || row.dataset.uf === u)
              && (!r || row.dataset.risco === r);
    row.classList.toggle('row-hidden', !show);
  }});
}}
function filterHist() {{
  const s = document.getElementById('h-search').value.toLowerCase();
  const st = document.getElementById('h-status').value;
  document.querySelectorAll('#histTable tbody tr').forEach(row => {{
    const show = (!s || row.textContent.toLowerCase().includes(s))
              && (!st || row.dataset.safelisted === st);
    row.classList.toggle('row-hidden', !show);
  }});
}}
function filterSafelist() {{
  const s = document.getElementById('sl-search').value.toLowerCase();
  document.querySelectorAll('#safelistTable tbody tr').forEach(row => {{
    row.classList.toggle('row-hidden', s && !row.textContent.toLowerCase().includes(s));
  }});
}}
</script>
</body>
</html>"""


if __name__ == "__main__":
    run(test_mode="--test" in sys.argv)
