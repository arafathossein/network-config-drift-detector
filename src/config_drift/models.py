from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum

VENDORS = ("mikrotik_routeros", "cisco_ios", "juniper_junos")


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high"].index(self.value)


@dataclass
class Device:
    name: str
    vendor: str
    host: str | None = None
    port: int = 22
    username_env: str = "NCD_USERNAME"
    password_env: str = "NCD_PASSWORD"

    def __post_init__(self) -> None:
        if self.vendor not in VENDORS:
            raise ValueError(f"{self.name}: unknown vendor '{self.vendor}', expected one of {', '.join(VENDORS)}")


@dataclass
class Change:
    """One added or removed configuration line, with its section for context."""

    op: str  # "+" or "-"
    line: str
    section: str = ""

    @property
    def text(self) -> str:
        return f"{self.section} > {self.line}" if self.section else self.line


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    why: str
    check: str
    changes: list[Change] = field(default_factory=list)


@dataclass
class Summary:
    headline: str
    bullets: list[str]
    source: str = "rules"  # "rules", "llm" or "rules (model failed)"


@dataclass
class DeviceReport:
    device: str
    vendor: str
    previous: str | None
    current: str
    changes: list[Change]
    findings: list[Finding]
    summary: Summary
    redactions: int = 0
    error: str | None = None

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.info
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    @property
    def changed(self) -> bool:
        return bool(self.changes)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["max_severity"] = self.max_severity.value
        for f in d["findings"]:
            f["severity"] = f["severity"].value if hasattr(f["severity"], "value") else f["severity"]
        return d
