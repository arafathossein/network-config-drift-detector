import os
import stat

import pytest

from config_drift.cli import main
from config_drift.collect import FileCollector, load_inventory
from config_drift.explain import RuleExplainer
from config_drift.models import Device
from config_drift.pipeline import run
from config_drift.store import BackupStore

from .conftest import DAY1, DAY2


def test_two_days_end_to_end(samples_dir, tmp_path):
    devices = load_inventory(samples_dir / "devices.yaml")
    store = BackupStore(tmp_path / "backups")
    first = run(devices, FileCollector(samples_dir / "configs" / DAY1), store, RuleExplainer(), DAY1)
    assert all(r.previous is None and not r.changed for r in first)
    second = run(devices, FileCollector(samples_dir / "configs" / DAY2), store, RuleExplainer(), DAY2)
    by_name = {r.device: r for r in second}
    assert by_name["branch-rtr-02"].changed is False
    assert {by_name[n].max_severity.value for n in ("edge-rtr-01", "core-sw-01", "dc-fw-01")} == {"high"}
    assert store.versions("core-sw-01") == [DAY1, DAY2]


def test_one_failing_device_does_not_stop_the_rest(samples_dir, tmp_path):
    devices = [Device("missing-01", "cisco_ios"), Device("core-sw-01", "cisco_ios")]
    reports = run(devices, FileCollector(samples_dir / "configs" / DAY1), BackupStore(tmp_path), RuleExplainer(), DAY1)
    assert reports[0].error and "missing-01" in reports[0].error
    assert reports[1].error is None


def test_empty_config_is_an_error_not_a_wipe(tmp_path):
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "sw.cfg").write_text("   \n")
    store = BackupStore(tmp_path / "b")
    reports = run([Device("sw", "cisco_ios")], FileCollector(tmp_path / "in"), store, RuleExplainer(), DAY1)
    assert reports[0].error and store.versions("sw") == []


def test_store_keeps_files_private_and_prunes(tmp_path):
    store = BackupStore(tmp_path, keep=2)
    for day in ("2026-11-01", "2026-11-02", "2026-11-03"):
        p = store.save("sw", day, "hostname sw\n")
    assert store.versions("sw") == ["2026-11-02", "2026-11-03"]
    assert store.previous("sw", "2026-11-03") == "2026-11-02"
    if os.name == "posix":
        assert stat.S_IMODE(p.stat().st_mode) == 0o600


@pytest.mark.parametrize("name", ["../etc", "a/b", ""])
def test_store_rejects_unsafe_names(tmp_path, name):
    with pytest.raises(ValueError):
        BackupStore(tmp_path).save(name, DAY1, "x")


def test_inventory_validation(tmp_path):
    bad = tmp_path / "inv.yaml"
    bad.write_text("devices:\n  - {name: a, vendor: cisco_ios}\n  - {name: a, vendor: cisco_ios}\n")
    with pytest.raises(ValueError, match="duplicate"):
        load_inventory(bad)
    bad.write_text("devices:\n  - {name: a, vendor: huawei_vrp}\n")
    with pytest.raises(ValueError, match="unknown vendor"):
        load_inventory(bad)


def test_cli_compare_exit_codes(samples_dir, capsys):
    old = samples_dir / "configs" / DAY1 / "core-sw-01.cfg"
    new = samples_dir / "configs" / DAY2 / "core-sw-01.cfg"
    assert main(["compare", str(old), str(new), "--vendor", "cisco_ios"]) == 0
    assert "permit ip any any" in capsys.readouterr().out
    assert main(["compare", str(old), str(new), "--vendor", "cisco_ios", "--fail-on", "high"]) == 2
    assert main(["compare", str(old), str(old), "--vendor", "cisco_ios", "--fail-on", "high"]) == 0


def test_cli_run_from_folder_writes_reports(samples_dir, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    inv = str(samples_dir / "devices.yaml")
    common = ["--inventory", inv, "--backup-dir", str(tmp_path / "b"), "--out", str(tmp_path / "r")]
    assert main(["run", *common, "--from-folder", str(samples_dir / "configs" / DAY1), "--date", DAY1]) == 0
    assert main(["run", *common, "--from-folder", str(samples_dir / "configs" / DAY2), "--date", DAY2, "--fail-on", "high"]) == 2
    for ext in ("md", "html", "json"):
        assert (tmp_path / "r" / f"drift-{DAY2}.{ext}").exists()


def test_cli_demo(tmp_path, monkeypatch):
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    assert main(["demo", "--out", str(tmp_path)]) == 0
    assert (tmp_path / f"drift-{DAY2}.html").exists()
