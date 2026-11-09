"""Reports: Markdown for email or tickets, HTML to open in a browser,
JSON for other tools, and a Slack message for the risky changes.
Every line shown here is redacted.
"""

from __future__ import annotations

import html
import json

from .models import DeviceReport, Severity
from .redact import redact_line

_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪"}


def _status(r: DeviceReport) -> str:
    if r.error:
        return "collection failed"
    if r.previous is None:
        return "first backup"
    if not r.changed:
        return "no changes"
    return f"{len(r.changes)} lines changed"


def markdown(reports: list[DeviceReport], date: str) -> str:
    out = [f"# Config drift report, {date}", ""]
    out += ["| Device | Vendor | Status | Highest risk |", "| --- | --- | --- | --- |"]
    for r in reports:
        risk = "" if (r.error or not r.changed) else f"{_ICON[r.max_severity.value]} {r.max_severity.value}"
        out.append(f"| {r.device} | {r.vendor} | {_status(r)} | {risk} |")
    for r in reports:
        if r.error:
            out += ["", f"## {r.device}", "", f"Could not collect the config: {r.error}"]
            continue
        if not r.changed:
            continue
        out += ["", f"## {r.summary.headline}", "", f"Compared {r.previous} with {r.current}. Summary by {r.summary.source}.", ""]
        out += [f"- {b}" for b in r.summary.bullets]
        for f in r.findings:
            out += ["", f"### {_ICON[f.severity.value]} {f.title} ({f.severity.value})", "",
                    f"**Why it matters:** {f.why}", "", f"**Check:** {f.check}", "", "```diff"]
            out += [f"{c.op} {redact_line(c.text)}" for c in f.changes]
            out.append("```")
    if any(r.redactions for r in reports):
        n = sum(r.redactions for r in reports)
        out += ["", f"_{n} secret value{'s' if n != 1 else ''} replaced with <redacted> in this report._"]
    return "\n".join(out) + "\n"


def to_json(reports: list[DeviceReport], date: str) -> str:
    data = {"date": date, "devices": [r.to_dict() for r in reports]}
    for d in data["devices"]:
        for c in d["changes"]:
            c["line"] = redact_line(c["line"])
        for f in d["findings"]:
            for c in f["changes"]:
                c["line"] = redact_line(c["line"])
    return json.dumps(data, indent=2, ensure_ascii=False)


_CSS = """
:root{--bg:#f7f7f4;--card:#fff;--ink:#16150f;--muted:#5e5c55;--line:#e3e1d9;--add:#e7f5ea;--del:#fdecea;
--high:#b3261e;--medium:#a15c00;--low:#7a6a00;--info:#5e5c55}
@media (prefers-color-scheme:dark){:root{--bg:#131209;--card:#1f1f1f;--ink:#f4f2ec;--muted:#a5a39b;--line:#313131;
--add:#173a22;--del:#3d1a17;--high:#ff8a7a;--medium:#f2b544;--low:#e0d26a;--info:#a5a39b}}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:28px;margin:0 0 4px}h2{font-size:20px;margin:0}h3{font-size:16px;margin:16px 0 4px}
.muted{color:var(--muted)}table{width:100%;border-collapse:collapse;margin:24px 0}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:500}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-top:16px}
.sev{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:0 8px;font-size:12px;font-weight:600}
.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.info{color:var(--info)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px 0;overflow-x:auto;font:13px/1.6 ui-monospace,Menlo,monospace}
pre span{display:block;padding:0 12px;white-space:pre}.add{background:var(--add)}.del{background:var(--del)}
ul{padding-left:20px}
"""


def html_report(reports: list[DeviceReport], date: str) -> str:
    e = html.escape
    rows = []
    for r in reports:
        risk = "" if (r.error or not r.changed) else f'<span class="sev {r.max_severity.value}">{r.max_severity.value}</span>'
        rows.append(f"<tr><td>{e(r.device)}</td><td>{e(r.vendor)}</td><td>{e(_status(r))}</td><td>{risk}</td></tr>")
    cards = []
    for r in reports:
        if r.error:
            cards.append(f'<section class="card"><h2>{e(r.device)}</h2><p>Could not collect the config: {e(r.error)}</p></section>')
            continue
        if not r.changed:
            continue
        parts = [f'<section class="card"><h2>{e(r.summary.headline)}</h2>',
                 f'<p class="muted">Compared {e(r.previous or "")} with {e(r.current)}. Summary by {e(r.summary.source)}.</p>',
                 "<ul>" + "".join(f"<li>{e(b)}</li>" for b in r.summary.bullets) + "</ul>"]
        for f in r.findings:
            lines = "".join(
                f'<span class="{"add" if c.op == "+" else "del"}">{e(c.op + " " + redact_line(c.text))}</span>' for c in f.changes)
            parts.append(f'<h3><span class="sev {f.severity.value}">{f.severity.value}</span> {e(f.title)}</h3>'
                         f"<p><strong>Why it matters:</strong> {e(f.why)}<br><strong>Check:</strong> {e(f.check)}</p><pre>{lines}</pre>")
        parts.append("</section>")
        cards.append("".join(parts))
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>Config drift {e(date)}</title><style>{_CSS}</style></head><body><main>"
            f'<h1>Config drift report</h1><p class="muted">{e(date)}</p>'
            f"<table><thead><tr><th>Device</th><th>Vendor</th><th>Status</th><th>Highest risk</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>{''.join(cards)}</main></body></html>\n")


def slack_payload(reports: list[DeviceReport], date: str, min_severity: Severity = Severity.medium,
                  report_url: str | None = None) -> dict | None:
    """One message listing devices whose changes reach min_severity. None if there is nothing to send."""
    hits = [r for r in reports if r.changed and not r.error and r.max_severity.rank >= min_severity.rank]
    failed = [r for r in reports if r.error]
    if not hits and not failed:
        return None
    blocks: list[dict] = [{"type": "header", "text": {"type": "plain_text", "text": f"Config changes to review, {date}"}}]
    for r in hits:
        lines = "\n".join(f"• {b}" for b in r.summary.bullets[:5])
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
                       "text": f"{_ICON[r.max_severity.value]} *{r.summary.headline}*\n{lines}"}})
    if failed:
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
                       "text": "⚠️ Could not collect: " + ", ".join(f"`{r.device}`" for r in failed)}})
    if report_url:
        blocks.append({"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": "Open full report"},
                                                         "url": report_url}]})
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": "Secrets are redacted. Verify each change before acting."}]})
    return {"text": f"Config changes to review, {date}", "blocks": blocks}
