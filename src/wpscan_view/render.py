import html
import json
from urllib.parse import urlsplit

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .model import clean, mapping, sequence

STYLE = """
:root{color-scheme:dark;--bg:#0b1220;--card:#131e30;--line:#29374d;--muted:#a7b5ca;--accent:#67e8c1}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#e7eef8;font:16px/1.6 system-ui,sans-serif}
main{max-width:1150px;margin:auto;padding:40px 24px}h1{font-size:36px;margin:0}h2{margin-top:32px;font-size:22px}
.eyebrow{color:var(--accent);letter-spacing:.15em;font-size:12px;font-weight:700}p{color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:26px 0}
.metric,.card,details{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin:12px 0}
.metric strong{font-size:28px;display:block}.warn{border-left:4px solid #fbbf24;padding:12px 18px;background:#292519;margin:10px 0}
.badge{color:#fda4af}.muted{color:var(--muted)}table{width:100%;border-collapse:collapse}td,th{padding:12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:12px;text-transform:uppercase}
.scroll{overflow:auto}a{color:#7dd3fc;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}summary{cursor:pointer;color:var(--accent)}footer{margin-top:36px;color:var(--muted);font-size:13px}
"""


def refs(v):
    values = []
    for kind, entries in mapping(v.get("references")).items():
        for entry in entries if isinstance(entries, list) else [entries]:
            text = clean(entry)
            if kind.lower() == "cve" and not text.upper().startswith("CVE-"):
                text = "CVE-" + text
            values.append((kind, text))
    return values


def terminal(report, console=None):
    console = console or Console(highlight=False)
    console.print(Panel(Text("WPScan View\n" + report["target"]), border_style="cyan"))
    console.print(Text("Scan: " + report["scope"]["kind"], style="bold"))
    for choice in report["scope"]["choices"]:
        console.print(Text("  " + choice["code"] + "  " + choice["label"]))
    console.print(Text(report["scope"]["evidence"], style="dim"))
    for warning in report["warnings"]:
        console.print(Panel(Text(warning), title="Coverage warning", border_style="yellow"))
    table = Table(title="Inventory • reported advisories first", expand=True)
    for col in ("Type", "Component", "Version", "Latest", "Advisories", "Evidence"):
        table.add_column(col, overflow="fold")
    for c in report["components"]:
        evidence = (c["role"] + " · " if c["role"] else "") + clean(c["evidence"].get("found_by"))
        if c["outdated"] is True:
            evidence += " · Outdated"
        count = str(len(c["vulnerabilities"])) if c["vulnerabilities"] else c["status"]
        table.add_row(*(Text(v) for v in (c["kind"], c["name"], c["version"], c["latest"], count, evidence)))
    console.print(table)
    for c in report["components"]:
        if c["vulnerabilities"]:
            console.print(Text("\n" + c["name"] + " — reported advisories", style="bold red"))
            if c["version"] == "Unknown":
                console.print(Text("Installed version unknown; applicability requires review.", style="yellow"))
            for v in c["vulnerabilities"]:
                console.print(Text("  • " + clean(v.get("title")), style="bold"))
                console.print(Text("    Fixed in: " + clean(v.get("fixed_in"))))
                if v.get("cvss"):
                    console.print(Text("    Reported CVSS: " + clean(json.dumps(v["cvss"], ensure_ascii=False))))
                for kind, value in refs(v):
                    console.print(Text("    " + kind + ": " + value))
        # Full component evidence is accessible with --details and in the HTML report.
    for key, value in report["extras"].items():
        table = Table(title=key.replace("_", " ").title(), expand=True)
        for col in ("Item", "Observation", "Source / confidence"):
            table.add_column(col, overflow="fold")
        entries = value.items() if isinstance(value, dict) else enumerate(value if isinstance(value, list) else [value], 1)
        for name, item in entries:
            if isinstance(item, dict):
                identity = item.get("url") or str(name)
                observation = item.get("to_s") or ("User ID: " + str(item["id"]) if "id" in item else "Observed")
                observation += "\n" + "\n".join(clean(x) for x in sequence(item.get("interesting_entries")))
                evidence = clean(item.get("found_by")) + " / " + clean(item.get("confidence"))
            else:
                identity, observation, evidence = str(name), clean(item), "Reported"
            table.add_row(Text(clean(identity)), Text(clean(observation).strip()), Text(clean(evidence)))
        console.print(table)
    console.print(Text("Reported advisories are WPScan observations, not proof of exploitability. None listed ≠ secure.", style="dim"))


def webpage(report):
    e = lambda x: html.escape(clean(x), quote=True)
    cards = []
    components = report["components"]
    for c in components:
        for v in c["vulnerabilities"]:
            links = []
            for kind, value in refs(v):
                try:
                    parsed = urlsplit(value)
                    is_link = parsed.scheme in ("http", "https") and bool(parsed.netloc)
                except ValueError:
                    is_link = False
                if is_link:
                    links.append(f'<a href="{e(value)}" rel="noreferrer">{e(kind)}: {e(value)}</a>')
                else:
                    links.append(e(kind) + ": " + e(value))
            uncertainty = "<p>Installed version unknown; applicability requires review.</p>" if c["version"] == "Unknown" else ""
            cards.append(f'<article class="card"><span class="eyebrow">{e(c["kind"])} · {e(c["name"])}</span>'
                f'<h3>{e(v.get("title"))}</h3><p>Observed version: {e(c["version"])} · Fixed in: {e(v.get("fixed_in"))}</p>'
                + uncertainty + "<br>".join(links) + f'<details><summary>Advisory evidence</summary><pre>{e(json.dumps(v, ensure_ascii=False, indent=2))}</pre></details></article>')
    rows = []
    for c in components:
        count = str(len(c["vulnerabilities"])) if c["vulnerabilities"] else c["status"]
        rows.append("<tr>" + "".join(f"<td>{e(x)}</td>" for x in (c["kind"], c["name"] + (" · " + c["role"] if c["role"] else ""),
            c["version"], c["latest"], "Yes" if c["outdated"] is True else ("No" if c["outdated"] is False else "Unknown"), count)) + "</tr>")
    details = "".join(f'<details><summary>{e(c["kind"])} · {e(c["name"])} — full detection evidence</summary>'
        f'<pre>{e(json.dumps(c["evidence"], ensure_ascii=False, indent=2))}</pre></details>' for c in components)
    extra_sections = []
    for key, value in report["extras"].items():
        entries = value.items() if isinstance(value, dict) else enumerate(value if isinstance(value, list) else [value], 1)
        rows_extra = []
        for name, item in entries:
            if isinstance(item, dict):
                identity = item.get("url") or str(name)
                observation = item.get("to_s") or ("User ID: " + str(item["id"]) if "id" in item else "Observed")
                observation += "\n" + "\n".join(clean(x) for x in sequence(item.get("interesting_entries")))
                evidence = clean(item.get("found_by")) + " / " + clean(item.get("confidence"))
            else:
                identity, observation, evidence = str(name), clean(item), "Reported"
            rows_extra.append("<tr>" + "".join(f"<td>{e(x)}</td>" for x in (identity, observation.strip(), evidence)) + "</tr>")
        extra_sections.append(f'<article class="card"><h3>{e(key.replace("_", " ").title())}</h3>'
            '<div class="scroll"><table><thead><tr><th>Item</th><th>Observation</th><th>Evidence / confidence</th></tr></thead><tbody>'
            + "".join(rows_extra) + f'</tbody></table></div><details><summary>Full source evidence</summary><pre>{e(json.dumps(value, ensure_ascii=False, indent=2))}</pre></details></article>')
    extras = "".join(extra_sections)
    metrics = [("Plugins observed", sum(c["kind"] == "Plugin" for c in components)),
        ("Themes observed", sum(c["kind"] == "Theme" for c in components)),
        ("Reported advisory entries", sum(len(c["vulnerabilities"]) for c in components)),
        ("Coverage warnings", len(report["warnings"]))]
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' \
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'">' \
        '<title>WPScan View</title><style>' + STYLE + '</style></head><body><main><div class="eyebrow">WORDPRESS · SCAN REVIEW</div>' \
        '<h1>WPScan View</h1><p>' + e(report["target"]) + '</p><section class="grid">' \
        + "".join(f'<div class="metric"><strong>{v}</strong>{e(k)}</div>' for k, v in metrics) + '</section>' \
        + '<h2>Scan scope</h2><div class="card"><strong>' + e(report["scope"]["kind"]) + '</strong><p>' \
        + e(", ".join(x["code"] + " — " + x["label"] for x in report["scope"]["choices"])) + '</p><p>' \
        + e(report["scope"]["evidence"]) + '</p></div>' \
        + "".join('<div class="warn">' + e(w) + '</div>' for w in report["warnings"]) \
        + '<h2>Inventory</h2><div class="scroll"><table><thead><tr><th>Type</th><th>Component</th><th>Version</th><th>Latest</th><th>Outdated</th><th>Advisories</th></tr></thead><tbody>' \
        + "".join(rows) + '</tbody></table></div><h2>Reported advisories</h2>' + ("".join(cards) or '<p>No advisory entries supplied. Review coverage warnings.</p>') \
        + '<h2>Other findings</h2>' + (extras or '<p>No other findings supplied.</p>') + '<h2>Detection evidence</h2>' + details \
        + '<details><summary>Scan statistics</summary><pre>' + e(json.dumps(report["statistics"], ensure_ascii=False, indent=2)) + '</pre></details>' \
        + '<footer>Reported advisories are WPScan observations, not proof of exploitability. No listed advisories does not establish security. Generated locally; no remote assets.</footer></main></body></html>'
