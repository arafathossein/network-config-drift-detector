"""Config backups on disk: one folder per device, one file per day.

    data/backups/edge-rtr-01/2026-11-02.cfg
    data/backups/edge-rtr-01/2026-11-03.cfg

Plain files on purpose: easy to read, easy to restore, and easy to put
under git if you want history beyond the retention window.
"""

from __future__ import annotations

import re
from pathlib import Path

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class BackupStore:
    def __init__(self, root: str | Path, keep: int = 90):
        self.root = Path(root)
        self.keep = keep

    def _dir(self, device: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", device):
            raise ValueError(f"unsafe device name: {device!r}")
        return self.root / device

    def versions(self, device: str) -> list[str]:
        d = self._dir(device)
        if not d.exists():
            return []
        return sorted(p.stem for p in d.glob("*.cfg") if _DATE.match(p.stem))

    def read(self, device: str, version: str) -> str:
        return (self._dir(device) / f"{version}.cfg").read_text(encoding="utf-8")

    def save(self, device: str, version: str, text: str) -> Path:
        if not _DATE.match(version):
            raise ValueError("version must be a date like 2026-11-03")
        d = self._dir(device)
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{version}.cfg"
        p.write_text(text, encoding="utf-8")
        p.chmod(0o600)  # backups hold secrets; keep them private to the service user
        self._prune(device)
        return p

    def previous(self, device: str, before: str) -> str | None:
        older = [v for v in self.versions(device) if v < before]
        return older[-1] if older else None

    def _prune(self, device: str) -> None:
        for v in self.versions(device)[: -self.keep]:
            (self._dir(device) / f"{v}.cfg").unlink()
