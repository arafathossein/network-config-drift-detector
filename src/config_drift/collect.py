"""Getting the running config from each device.

Two collectors:
- FileCollector reads configs that something else already saved (Oxidized,
  RANCID, a cron job, or the sample folder). No credentials needed here.
- SSHCollector logs in with Netmiko and runs a read-only show command.
  Install with: pip install "config-drift[ssh]"
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

import yaml

from .models import Device

# Read-only commands. Nothing here changes the device.
SHOW_COMMANDS = {
    # RouterOS 7 hides secrets in exports by default; "show-sensitive" is never used.
    "mikrotik_routeros": "/export terse",
    "cisco_ios": "show running-config",
    "juniper_junos": "show configuration | display set",
}


class Collector(Protocol):
    def fetch(self, device: Device) -> str: ...


class FileCollector:
    """Reads <folder>/<device name>.cfg (or .rsc / .txt)."""

    def __init__(self, folder: str | Path):
        self.folder = Path(folder)

    def fetch(self, device: Device) -> str:
        for ext in (".cfg", ".rsc", ".txt", ".conf"):
            p = self.folder / f"{device.name}{ext}"
            if p.exists():
                return p.read_text(encoding="utf-8", errors="replace")
        raise FileNotFoundError(f"no config for {device.name} in {self.folder}")


class SSHCollector:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def fetch(self, device: Device) -> str:
        try:
            from netmiko import ConnectHandler
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise RuntimeError('SSH collection needs Netmiko: pip install "config-drift[ssh]"') from exc
        username = os.environ.get(device.username_env)
        password = os.environ.get(device.password_env)
        if not username or not password:
            raise RuntimeError(f"{device.name}: set {device.username_env} and {device.password_env} in the environment")
        params = {
            "device_type": device.vendor,
            "host": device.host or device.name,
            "port": device.port,
            "username": username,
            "password": password,
            "timeout": self.timeout,
            "fast_cli": False,
        }
        with ConnectHandler(**params) as conn:  # pragma: no cover - needs a real device
            return conn.send_command(SHOW_COMMANDS[device.vendor], read_timeout=self.timeout * 4)


def load_inventory(path: str | Path) -> list[Device]:
    """devices.yaml:

    devices:
      - name: edge-rtr-01
        vendor: mikrotik_routeros
        host: 192.0.2.1
    """
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    devices = [Device(**d) for d in data.get("devices", [])]
    names = [d.name for d in devices]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        raise ValueError(f"duplicate device names in inventory: {', '.join(sorted(dupes))}")
    return devices
