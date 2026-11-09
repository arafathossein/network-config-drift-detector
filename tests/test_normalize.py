from config_drift.normalize import diff, normalize

from .conftest import DAY1, DAY2, sample


def test_cisco_timestamps_and_byte_counts_are_not_drift():
    old = "Building configuration...\n\nCurrent configuration : 100 bytes\n! Last configuration change at 01:00 by a\nhostname x\nntp clock-period 17179\nend\n"
    new = "Building configuration...\n\nCurrent configuration : 104 bytes\n! Last configuration change at 09:30 by b\nhostname x\nntp clock-period 17188\nend\n"
    assert diff("cisco_ios", old, new) == []


def test_mikrotik_export_header_is_not_drift():
    assert diff("mikrotik_routeros", sample(DAY1, "branch-rtr-02"), sample(DAY2, "branch-rtr-02")) == []


def test_junos_commit_header_is_not_drift():
    a = "## Last commit: 2026-11-02 02:00:09 UTC by a\nset system host-name fw\n"
    b = "## Last commit: 2026-11-03 07:12:00 UTC by b\nset system host-name fw\n"
    assert diff("juniper_junos", a, b) == []


def test_mikrotik_terse_and_block_exports_compare_equal():
    terse = "/ip firewall filter add action=accept chain=input\n/ip firewall filter add action=drop chain=input\n"
    block = "/ip firewall filter\nadd action=accept chain=input\nadd action=drop \\\n    chain=input\n"
    assert normalize("mikrotik_routeros", terse) == normalize("mikrotik_routeros", block)


def test_cisco_child_lines_keep_their_section():
    lines = normalize("cisco_ios", "ip access-list extended A\n permit ip any any\n!\nhostname x\n")
    assert ("ip access-list extended A", "permit ip any any") in lines
    assert ("", "hostname x") in lines


def test_same_line_in_two_sections_is_distinct():
    old = "ip access-list extended A\n permit ip any any\nip access-list extended B\n deny ip any any\n"
    new = "ip access-list extended A\n permit ip any any\nip access-list extended B\n permit ip any any\n deny ip any any\n"
    changes = diff("cisco_ios", old, new)
    assert [(c.op, c.section, c.line) for c in changes] == [("+", "ip access-list extended B", "permit ip any any")]


def test_reordering_firewall_rules_is_reported():
    old = "/ip firewall filter add action=drop chain=input\n/ip firewall filter add action=accept chain=input protocol=icmp\n"
    new = "/ip firewall filter add action=accept chain=input protocol=icmp\n/ip firewall filter add action=drop chain=input\n"
    changes = diff("mikrotik_routeros", old, new)
    assert {c.op for c in changes} == {"+", "-"}


def test_windows_line_endings():
    assert diff("juniper_junos", "set a\r\nset b\r\n", "set a\nset b\n") == []
