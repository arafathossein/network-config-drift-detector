"""Remove secrets from configuration text before it is stored in a report,
sent to chat, or shown to a language model.

Backups on disk keep the original text (they are your restore point); only
what leaves the backup folder is redacted.
"""

from __future__ import annotations

import re

R = "<redacted>"

# Each pattern has a prefix group (kept) and a value group (replaced).
_PATTERNS: list[re.Pattern[str]] = [
    # MikroTik: password=..., secret=..., authentication-key=..., wpa2-pre-shared-key=..., passphrase=...
    re.compile(r"(\b(?:[\w-]*password|secret|[\w-]*-key|passphrase)=)(\"[^\"]*\"|\S+)", re.I),
    # Junos: encrypted-password "$6$...", secret "$9$...", ascii-text "$9$...", authentication-key "..."
    re.compile(r"(\b(?:encrypted-password|ascii-text|authentication-key)\s+)(\"[^\"]*\"|\S+)", re.I),
    # Cisco: enable secret 9 x / username x secret 5 x / password 7 x / key-string x
    re.compile(r"(\b(?:secret|password|key-string)\s+(?:\d\s+)?)(\"[^\"]*\"|\S+)", re.I),
    # Cisco tacacs/radius/ntp keys always carry a type digit: key 0 x / key 7 x
    re.compile(r"(\bkey\s+\d\s+)(\S+)", re.I),
    # Junos keys are quoted $9$ strings: key "$9$..."
    re.compile(r'(\bkey\s+)("\$[^"]*")', re.I),
    # SNMP communities (Cisco "snmp-server community x", Junos "snmp community x")
    re.compile(r"((?<![/\w])snmp(?:-server)? community\s+)(\S+)", re.I),
    # MikroTik SNMP: /snmp community add name=x
    re.compile(r"(/snmp community (?:add|set)\b.*?\bname=)(\S+)", re.I),
]
_DEFAULTS = {"public", "private"}
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)


def redact(text: str) -> tuple[str, int]:
    """Return the redacted text and how many secret values were replaced."""
    count = 0

    def sub(m: re.Match[str]) -> str:
        nonlocal count
        # Well-known defaults are not secrets, and hiding them would hide the finding.
        if m.group(2) == R or m.group(2).strip('"').lower() in _DEFAULTS:
            return m.group(0)
        count += 1
        return m.group(1) + R

    for pattern in _PATTERNS:
        text = pattern.sub(sub, text)
    text, n = _PRIVATE_KEY.subn(R, text)
    return text, count + n


def redact_line(line: str) -> str:
    return redact(line)[0]
