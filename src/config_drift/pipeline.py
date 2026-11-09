from __future__ import annotations

import datetime as dt
import logging
import os
from dataclasses import dataclass, field

from .collect import Collector
from .explain import Explainer, FallbackExplainer, LLMExplainer, RuleExplainer
from .models import Device, DeviceReport, Summary
from .normalize import diff
from .redact import redact
from .rules import evaluate
from .store import BackupStore

log = logging.getLogger("config_drift")


@dataclass
class Settings:
    """Read from the environment when created."""

    backup_dir: str = field(default_factory=lambda: os.getenv("BACKUP_DIR", "data/backups"))
    keep_days: int = field(default_factory=lambda: int(os.getenv("KEEP_DAYS", "90")))
    llm_base_url: str | None = field(default_factory=lambda: os.getenv("LLM_BASE_URL") or None)
    llm_api_key: str = field(default_factory=lambda: os.getenv("LLM_API_KEY", ""))
    llm_model: str = field(default_factory=lambda: os.getenv("LLM_MODEL", "llama3.1:8b"))
    slack_webhook_url: str | None = field(default_factory=lambda: os.getenv("SLACK_WEBHOOK_URL") or None)
    slack_min_severity: str = field(default_factory=lambda: os.getenv("SLACK_MIN_SEVERITY", "medium"))
    report_url: str | None = field(default_factory=lambda: os.getenv("REPORT_URL") or None)


def make_explainer(s: Settings) -> Explainer:
    if s.llm_base_url:
        return FallbackExplainer(LLMExplainer(s.llm_base_url, s.llm_api_key, s.llm_model))
    return RuleExplainer()


def compare(device: str, vendor: str, old: str | None, new: str, explainer: Explainer,
            previous: str | None = None, current: str = "") -> DeviceReport:
    if old is None:
        return DeviceReport(device, vendor, None, current, [], [], Summary(f"First backup of {device}", []))
    changes = diff(vendor, old, new)
    findings = evaluate(vendor, changes)
    summary = explainer.explain(device, vendor, changes, findings)
    redactions = sum(redact(c.text)[1] for c in changes)
    return DeviceReport(device, vendor, previous, current, changes, findings, summary, redactions)


def run(devices: list[Device], collector: Collector, store: BackupStore, explainer: Explainer,
        date: str | None = None) -> list[DeviceReport]:
    """Back up every device, then compare with its previous backup."""
    date = date or dt.date.today().isoformat()
    reports = []
    for d in devices:
        try:
            text = collector.fetch(d)
            if not text.strip():
                raise ValueError("device returned an empty config")
        except Exception as exc:  # noqa: BLE001 - one device failing must not stop the others
            log.warning("collect %s failed: %s", d.name, exc)
            reports.append(DeviceReport(d.name, d.vendor, None, date, [], [], Summary(f"{d.name}: collection failed", []),
                                        error=str(exc)))
            continue
        prev = store.previous(d.name, date)
        store.save(d.name, date, text)
        old = store.read(d.name, prev) if prev else None
        reports.append(compare(d.name, d.vendor, old, text, explainer, previous=prev, current=date))
    return reports
