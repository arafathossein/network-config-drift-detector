"""Command line.

    config-drift run --inventory devices.yaml                 # SSH to each device
    config-drift run --inventory devices.yaml --from-folder exports/
    config-drift compare old.cfg new.cfg --vendor cisco_ios
    config-drift demo                                         # sample configs, no devices needed
"""

from __future__ import annotations

import argparse
import datetime as dt
import logging
import sys
import tempfile
from pathlib import Path

import httpx

from .collect import FileCollector, SSHCollector, load_inventory
from .models import VENDORS, Severity
from .pipeline import Settings, compare, make_explainer, run
from .report import html_report, markdown, slack_payload, to_json
from .store import BackupStore


def _write_reports(reports, date: str, out: Path) -> dict[str, Path]:
    out.mkdir(parents=True, exist_ok=True)
    paths = {
        "md": out / f"drift-{date}.md",
        "html": out / f"drift-{date}.html",
        "json": out / f"drift-{date}.json",
    }
    paths["md"].write_text(markdown(reports, date), encoding="utf-8")
    paths["html"].write_text(html_report(reports, date), encoding="utf-8")
    paths["json"].write_text(to_json(reports, date), encoding="utf-8")
    return paths


def _notify(reports, date: str, s: Settings) -> None:
    if not s.slack_webhook_url:
        return
    payload = slack_payload(reports, date, Severity(s.slack_min_severity), s.report_url)
    if payload is None:
        return
    try:
        httpx.post(s.slack_webhook_url, json=payload, timeout=15).raise_for_status()
    except httpx.HTTPError as exc:
        print(f"Slack notification failed: {exc}", file=sys.stderr)


def _exit_code(reports, fail_on: str | None) -> int:
    if any(r.error for r in reports):
        return 1
    if fail_on and any(r.changed and r.max_severity.rank >= Severity(fail_on).rank for r in reports):
        return 2
    return 0


def _summary_lines(reports) -> None:
    for r in reports:
        status = "FAILED: " + r.error if r.error else (r.summary.headline if r.changed else
                                                        ("first backup" if r.previous is None else "no changes"))
        sev = f"[{r.max_severity.value}] " if r.changed else ""
        print(f"  {r.device:<20} {sev}{status}")


def cmd_run(a: argparse.Namespace) -> int:
    s = Settings()
    devices = load_inventory(a.inventory)
    collector = FileCollector(a.from_folder) if a.from_folder else SSHCollector()
    store = BackupStore(a.backup_dir or s.backup_dir, s.keep_days)
    date = a.date or dt.date.today().isoformat()
    reports = run(devices, collector, store, make_explainer(s), date)
    paths = _write_reports(reports, date, Path(a.out))
    _summary_lines(reports)
    print(f"\nReport: {paths['html']}")
    _notify(reports, date, s)
    return _exit_code(reports, a.fail_on)


def cmd_compare(a: argparse.Namespace) -> int:
    old = Path(a.old).read_text(encoding="utf-8")
    new = Path(a.new).read_text(encoding="utf-8")
    r = compare(a.name or Path(a.new).stem, a.vendor, old, new, make_explainer(Settings()),
                previous=Path(a.old).name, current=Path(a.new).name)
    print(markdown([r], "manual comparison"))
    return _exit_code([r], a.fail_on)


def cmd_demo(a: argparse.Namespace) -> int:
    root = Path(__file__).resolve().parents[2] / "samples"
    if not root.exists():
        print("samples/ folder not found; run the demo from a clone of the repository.", file=sys.stderr)
        return 1
    devices = load_inventory(root / "devices.yaml")
    store = BackupStore(tempfile.mkdtemp(prefix="config-drift-"))
    explainer = make_explainer(Settings())
    days = sorted(p.name for p in (root / "configs").iterdir() if p.is_dir())
    reports = []
    for day in days:
        reports = run(devices, FileCollector(root / "configs" / day), store, explainer, day)
        print(f"{day}:")
        _summary_lines(reports)
    paths = _write_reports(reports, days[-1], Path(a.out))
    print(f"\nReport: {paths['html']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    p = argparse.ArgumentParser(prog="config-drift", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="Back up every device in the inventory and report changes")
    r.add_argument("--inventory", required=True)
    r.add_argument("--from-folder", help="Read <device>.cfg files from this folder instead of SSH")
    r.add_argument("--backup-dir", help="Where backups are kept (default: $BACKUP_DIR or data/backups)")
    r.add_argument("--out", default="reports")
    r.add_argument("--date", help="Backup date label, YYYY-MM-DD (default: today)")
    r.add_argument("--fail-on", choices=[s.value for s in Severity], help="Exit with code 2 if a change reaches this severity")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("compare", help="Compare two config files")
    c.add_argument("old")
    c.add_argument("new")
    c.add_argument("--vendor", required=True, choices=VENDORS)
    c.add_argument("--name")
    c.add_argument("--fail-on", choices=[s.value for s in Severity])
    c.set_defaults(func=cmd_compare)

    d = sub.add_parser("demo", help="Run on the bundled sample configs")
    d.add_argument("--out", default="reports")
    d.set_defaults(func=cmd_demo)

    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    raise SystemExit(main())
