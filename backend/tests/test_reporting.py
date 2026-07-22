import csv
import html
import io
import json

from crops_security.reporting import findings_csv, findings_html, findings_json


def test_all_exports_preserve_original_evidence() -> None:
    snippet = '\tpassword = "ProductionSecret17"\ncontexto posterior'
    match_text = 'password = "ProductionSecret17"'
    scan = {
        "target": "https://app.example.test/",
        "created_at": "2026-07-22T12:00:00+00:00",
        "pages_scanned": 1,
    }
    finding = {
        "severity": "high",
        "confidence": "high",
        "category": "Credencial",
        "indicator": "Assignment: password",
        "url": "https://app.example.test/app.js",
        "file_name": "app.js",
        "line": 1,
        "snippet": snippet,
        "match_text": match_text,
    }

    csv_finding = next(csv.DictReader(io.StringIO(findings_csv([finding]))))
    json_finding = json.loads(findings_json(scan, [finding]))["findings"][0]
    rendered_html = html.unescape(findings_html(scan, [finding])).replace("<mark>", "").replace(
        "</mark>", ""
    )

    assert csv_finding["snippet"] == snippet
    assert csv_finding["match_text"] == match_text
    assert json_finding["snippet"] == snippet
    assert json_finding["match_text"] == match_text
    assert snippet in rendered_html
