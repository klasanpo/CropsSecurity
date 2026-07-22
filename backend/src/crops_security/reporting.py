# ruff: noqa: E501

import csv
import html
import io
import json
from collections import Counter
from typing import Any


def findings_csv(findings: list[dict[str, Any]]) -> str:
    output = io.StringIO()
    fields = (
        "severity",
        "confidence",
        "category",
        "indicator",
        "url",
        "file_name",
        "line",
        "snippet",
        "match_text",
    )
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(findings)
    return output.getvalue()


def findings_json(scan: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    return json.dumps(
        {"scan": scan, "findings": findings}, ensure_ascii=False, indent=2, default=str
    )


def findings_html(scan: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    counts = Counter(item["severity"] for item in findings)
    indicators = sorted({str(item["indicator"]) for item in findings})
    rows = "".join(_finding_card(index, finding) for index, finding in enumerate(findings, 1))
    options = "".join(
        f'<option value="{html.escape(item)}">{html.escape(item)}</option>' for item in indicators
    )
    target = html.escape(str(scan["target"]))
    created_at = html.escape(str(scan["created_at"]))
    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>CropsSecurity — Sensitive Data Finder</title>
<style>
:root{{--bg:#06110d;--panel:#0c1d16;--line:#1d3d31;--text:#e5f2ec;--muted:#789187;--green:#42e6a4}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px Inter,Arial,sans-serif}}
header,main{{width:min(1160px,calc(100% - 36px));margin:auto}}header{{padding:42px 0 26px;border-bottom:1px solid var(--line)}}
.eyebrow{{color:var(--green);font:700 11px monospace;letter-spacing:.14em}}h1{{margin:9px 0;font-size:32px}}p{{color:var(--muted)}}
.summary{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:25px 0}}.metric,.finding{{border:1px solid var(--line);border-radius:13px;background:var(--panel)}}
.metric{{padding:17px}}.metric strong,.metric span{{display:block}}.metric strong{{font:700 24px monospace}}.metric span{{margin-top:5px;color:var(--muted);font-size:11px}}
.filters{{display:flex;gap:10px;margin:0 0 18px}}select,input{{padding:11px;border:1px solid var(--line);border-radius:8px;background:#091711;color:var(--text)}}input{{flex:1}}
.results{{display:grid;gap:12px;padding-bottom:45px}}.finding{{padding:18px}}.top{{display:flex;justify-content:space-between;gap:15px}}.badge{{padding:5px 8px;border-radius:6px;background:#26352e;text-transform:uppercase;font:700 10px monospace}}
.critical .badge{{color:#ff9199;background:#3a1a1e}}.high .badge{{color:#ffb079;background:#38251a}}.medium .badge{{color:#eed17e;background:#332e18}}.low .badge{{color:#99bfff;background:#172841}}
h2{{margin:13px 0 4px;font-size:16px}}.meta,a{{color:var(--muted);font-size:11px}}pre{{padding:13px;overflow:auto;border-radius:8px;background:#06110d;color:#b7d1c5;white-space:pre-wrap;word-break:break-word}}mark{{padding:2px 4px;border-radius:4px;background:#b92332;color:#fff;font-weight:800}}
a{{color:var(--green)}}@media(max-width:700px){{.summary{{grid-template-columns:repeat(2,1fr)}}.filters{{flex-direction:column}}}}
</style></head><body>
<header><div class="eyebrow">CROPS SECURITY / RELATÓRIO DE ANÁLISE</div><h1>Detector de Dados Sensíveis</h1>
<p><strong>Alvo:</strong> {target}<br><strong>Execução:</strong> {created_at} · {scan['pages_scanned']} recursos analisados</p></header>
<main><section class="summary">
<div class="metric"><strong>{len(findings)}</strong><span>Total</span></div>
<div class="metric"><strong>{counts['critical']}</strong><span>Críticos</span></div>
<div class="metric"><strong>{counts['high']}</strong><span>Altos</span></div>
<div class="metric"><strong>{counts['medium']}</strong><span>Médios</span></div>
<div class="metric"><strong>{counts['low']}</strong><span>Baixos</span></div></section>
<section class="filters"><select id="severity"><option value="">Todas as severidades</option><option value="critical">Crítico</option><option value="high">Alto</option><option value="medium">Médio</option><option value="low">Baixo</option><option value="informative">Informativo</option></select>
<select id="indicator"><option value="">Todos os indicadores</option>{options}</select><input id="search" placeholder="Buscar por indicador, categoria ou URL"></section>
<section class="results">{rows or '<p>Nenhum achado foi identificado.</p>'}</section></main>
<script>const cards=[...document.querySelectorAll('.finding')];function filter(){{const s=document.querySelector('#severity').value,i=document.querySelector('#indicator').value,q=document.querySelector('#search').value.toLowerCase();cards.forEach(c=>c.hidden=!!((s&&c.dataset.severity!==s)||(i&&c.dataset.indicator!==i)||(q&&!c.dataset.search.includes(q))))}}document.querySelectorAll('select,input').forEach(e=>e.addEventListener('input',filter));</script>
</body></html>"""


def _finding_card(index: int, finding: dict[str, Any]) -> str:
    severity = html.escape(str(finding["severity"]))
    indicator = html.escape(str(finding["indicator"]))
    category = html.escape(str(finding["category"]))
    url = html.escape(str(finding["url"]))
    file_name = html.escape(str(finding["file_name"]))
    snippet = _highlight_match(str(finding["snippet"]), str(finding["match_text"]))
    search = html.escape(f"{finding['indicator']} {finding['category']} {finding['url']}".lower())
    return f"""<article class="finding {severity}" data-severity="{severity}" data-indicator="{indicator}" data-search="{search}">
<div class="top"><span class="badge">{severity}</span><span class="meta">#{index} · confiança {html.escape(str(finding['confidence']))}</span></div>
<h2>{indicator}</h2><div class="meta">{category} · {file_name}:{finding['line']}</div><pre>{snippet}</pre>
<a href="{url}" target="_blank" rel="noopener noreferrer">Abrir recurso</a></article>"""


def _highlight_match(snippet: str, match_text: str) -> str:
    if not match_text:
        return html.escape(snippet)
    index = snippet.casefold().find(match_text.casefold())
    if index < 0:
        return html.escape(snippet)
    end = index + len(match_text)
    return (
        html.escape(snippet[:index])
        + f"<mark>{html.escape(snippet[index:end])}</mark>"
        + html.escape(snippet[end:])
    )
