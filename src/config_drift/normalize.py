"""Turn a raw config into comparable lines.

Two jobs:
1. Drop lines that change on every backup without anyone changing anything
   (timestamps, byte counts, uptime). Otherwise every day looks like drift.
2. Give each line its context. Cisco configs are indented blocks, so
   "permit ip any any" means nothing without "ip access-list extended OUTSIDE"
   above it. MikroTik terse exports and Junos set format already carry the
   full path on every line.
"""

from __future__ import annotations

import re

from .models import Change

_VOLATILE: dict[str, list[re.Pattern[str]]] = {
    "mikrotik_routeros": [
        re.compile(r"^#\s*\d{4}-\d{2}-\d{2} .* by RouterOS"),  # v7 header
        re.compile(r"^#\s*\w{3}/\d{2}/\d{4} .* by RouterOS"),  # v6 header
        re.compile(r"^#\s*software id ="),
        re.compile(r"^#\s*model ="),
        re.compile(r"^#\s*serial number ="),
    ],
    "cisco_ios": [
        re.compile(r"^Building configuration"),
        re.compile(r"^Current configuration\s*:"),
        re.compile(r"^! Last configuration change at"),
        re.compile(r"^! NVRAM config last updated at"),
        re.compile(r"^! No configuration change since last restart"),
        re.compile(r"^ntp clock-period"),
        re.compile(r"^!\s*Time:"),
    ],
    "juniper_junos": [
        re.compile(r"^## Last commit:"),
        re.compile(r"^## Last changed:"),
    ],
}


def normalize(vendor: str, text: str) -> list[tuple[str, str]]:
    """Return (section, line) pairs with noise removed."""
    patterns = _VOLATILE.get(vendor, [])
    out: list[tuple[str, str]] = []
    section = ""
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or any(p.search(stripped) for p in patterns):
            continue
        if vendor == "cisco_ios":
            if stripped == "!" or stripped == "end":
                continue
            if line[0] in " \t":
                out.append((section, stripped))
                continue
            section = stripped
            out.append(("", stripped))
        elif vendor == "mikrotik_routeros":
            if stripped.startswith("#"):
                continue
            # Non-terse exports wrap long commands with a trailing backslash.
            if out and out[-1][1].endswith("\\"):
                prev = out.pop()[1][:-1].rstrip()
                out.append(("", f"{prev} {stripped}"))
                continue
            # Non-terse exports put the menu path on its own line ("/ip firewall filter")
            # followed by "add ..." lines; terse exports repeat the path on every line.
            # Expand both to the terse form so they compare equal.
            if _MT_MENU.match(stripped):
                section = stripped
                continue
            if not stripped.startswith("/") and section:
                stripped = f"{section} {stripped}"
            out.append(("", stripped))
        else:
            if stripped.startswith("#"):
                continue
            out.append(("", stripped))
    return [x for x in out if x[1]]


_MT_MENU = re.compile(r"^/[a-z0-9][a-z0-9 -]*$")


def diff(vendor: str, old: str, new: str) -> list[Change]:
    """Added and removed lines, in config order, each with its section."""
    import difflib

    a = normalize(vendor, old)
    b = normalize(vendor, new)
    # Compare on section + line, so the same "permit ip any any" in two different ACLs stays distinct.
    sa = [f"{s}\x00{l}" for s, l in a]
    sb = [f"{s}\x00{l}" for s, l in b]
    changes: list[Change] = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=sa, b=sb, autojunk=False).get_opcodes():
        if tag in ("delete", "replace"):
            changes += [Change("-", l, s) for s, l in a[i1:i2]]
        if tag in ("insert", "replace"):
            changes += [Change("+", l, s) for s, l in b[j1:j2]]
    # A section header only appears as changed if the whole block is new or gone;
    # a changed child line keeps its unchanged parent as context instead.
    return changes
