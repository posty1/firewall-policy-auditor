import html
import json
from collections import Counter
from pathlib import Path

from .models import Finding


def write_reports(findings: list[Finding], output_dir: str | Path) -> tuple[Path, Path]:
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    json_path = target / "findings.json"
    html_path = target / "report.html"
    json_path.write_text(json.dumps([f.to_dict() for f in findings], indent=2) + "\n", encoding="utf-8")
    counts = Counter(f.severity for f in findings)
    rows = "".join(
        f"<tr><td>{html.escape(f.severity.upper())}</td><td>{html.escape(f.rule)}</td>"
        f"<td>{html.escape(f.check)}</td><td>{html.escape(f.detail)}</td></tr>"
        for f in findings
    )
    html_path.write_text(
        "<!doctype html><meta charset='utf-8'><title>Firewall Audit</title>"
        "<style>body{font:15px system-ui;max-width:1100px;margin:40px auto;color:#17202a}"
        "table{border-collapse:collapse;width:100%}th,td{padding:10px;border:1px solid #ccd1d1;text-align:left}"
        "th{background:#eef2f3}</style><h1>Firewall Policy Audit</h1>"
        f"<p>Critical: {counts['critical']} · High: {counts['high']} · Medium: {counts['medium']} · Low: {counts['low']}</p>"
        f"<table><tr><th>Severity</th><th>Rule</th><th>Check</th><th>Detail</th></tr>{rows}</table>",
        encoding="utf-8",
    )
    return json_path, html_path
