"""Plain-English summaries of what changed.

The rule-based summary always works. A language model (any OpenAI-compatible
endpoint, including a local Ollama) can write a more natural one; it only
ever sees redacted lines, and if it fails the rule-based summary is used.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Protocol

import httpx

from .models import Change, Finding, Severity, Summary
from .redact import redact_line

log = logging.getLogger("config_drift")


def _count(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def rule_summary(device: str, changes: list[Change], findings: list[Finding]) -> Summary:
    if not changes:
        return Summary(headline=f"No changes on {device}", bullets=[])
    added = sum(c.op == "+" for c in changes)
    removed = len(changes) - added
    risky = [f for f in findings if f.severity in (Severity.high, Severity.medium)]
    top = findings[0]
    if top.severity == Severity.high:
        headline = f"{device}: {top.title.lower()}"
    elif risky:
        headline = f"{device}: {top.title.lower()}"
    else:
        headline = f"{device}: {_count(len(changes), 'line')} changed, nothing in a watched area"
    bullets = [f"{_count(added, 'line')} added, {_count(removed, 'line')} removed."]
    for f in findings:
        example = redact_line(f.changes[0].text)
        more = f" (+{len(f.changes) - 1} more)" if len(f.changes) > 1 else ""
        bullets.append(f"[{f.severity.value}] {f.title}: {f.changes[0].op} {example}{more}")
    return Summary(headline=headline[:120], bullets=bullets, source="rules")


class Explainer(Protocol):
    name: str

    def explain(self, device: str, vendor: str, changes: list[Change], findings: list[Finding]) -> Summary: ...


class RuleExplainer:
    name = "rules"

    def explain(self, device, vendor, changes, findings) -> Summary:
        return rule_summary(device, changes, findings)


_SYSTEM = """You explain network configuration changes to an IT manager who does not read router syntax.
You get the device, its vendor, the changed lines (+ added, - removed; secrets already replaced with <redacted>)
and the risk areas a rule engine matched. Reply with JSON only:
{"headline": str (max 100 chars), "bullets": [str, ...] (2-6 items, one plain sentence each)}
Rules:
- Describe only what the lines show. Do not guess who made the change or why.
- Name the concrete effect: which port, address, account or route.
- Mention the highest-risk change first.
- Never say a change is safe; say what a person should confirm.
- Plain text, no markdown."""


class LLMExplainer:
    name = "llm"

    def __init__(self, base_url: str, api_key: str, model: str, client: httpx.Client | None = None, timeout: float = 60):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.client = client or httpx.Client(timeout=timeout)

    def explain(self, device, vendor, changes, findings) -> Summary:
        if not changes:
            return rule_summary(device, changes, findings)
        payload = {
            "device": device,
            "vendor": vendor,
            "changes": [f"{c.op} {redact_line(c.text)}" for c in changes][:200],
            "risk_areas": [{"severity": f.severity.value, "title": f.title, "lines": len(f.changes)} for f in findings],
        }
        resp = self.client.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {},
            json={
                "model": self.model,
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": _SYSTEM}, {"role": "user", "content": json.dumps(payload)}],
            },
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"].strip()
        content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content)
        data = json.loads(content)
        headline = str(data["headline"]).strip()[:120]
        bullets = [str(b).strip() for b in data.get("bullets", []) if str(b).strip()][:6]
        if not headline or not bullets:
            raise ValueError("model returned an empty summary")
        # Never let a model's wording leak a secret it might have reconstructed.
        return Summary(headline=redact_line(headline), bullets=[redact_line(b) for b in bullets], source="llm")


class FallbackExplainer:
    def __init__(self, primary: Explainer):
        self.primary = primary
        self.name = f"{primary.name} with rules fallback"

    def explain(self, device, vendor, changes, findings) -> Summary:
        try:
            return self.primary.explain(device, vendor, changes, findings)
        except Exception as exc:  # noqa: BLE001 - any model failure falls back
            log.warning("model summary failed for %s: %s", device, exc)
            s = rule_summary(device, changes, findings)
            s.source = "rules (model failed)"
            return s
