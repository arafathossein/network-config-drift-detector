import pytest

from config_drift.models import Change, Severity
from config_drift.normalize import diff
from config_drift.rules import RULES, evaluate

from .conftest import DAY1, DAY2, sample

EXPECTED = {
    ("edge-rtr-01", "mikrotik_routeros"): {
        "mt-insecure-service", "mt-port-forward", "mt-input-accept-any", "mt-full-user", "mt-logging-removed", "other"},
    ("core-sw-01", "cisco_ios"): {
        "ios-acl-permit-any", "ios-insecure-mgmt", "ios-priv15-user", "ios-weak-snmp", "ios-routing",
        "ios-logging-removed", "ios-shutdown", "other"},
    ("dc-fw-01", "juniper_junos"): {
        "junos-super-user", "junos-insecure-service", "junos-untrust-any", "junos-default-route", "junos-dest-nat",
        "junos-users", "junos-policies", "other"},
}


@pytest.mark.parametrize("device, vendor", EXPECTED)
def test_sample_findings(device, vendor):
    findings = evaluate(vendor, diff(vendor, sample(DAY1, device), sample(DAY2, device)))
    assert {f.rule_id for f in findings} == EXPECTED[(device, vendor)]
    assert findings[0].severity == Severity.high
    ranks = [f.severity.rank for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_each_change_is_reported_once():
    changes = diff("cisco_ios", sample(DAY1, "core-sw-01"), sample(DAY2, "core-sw-01"))
    findings = evaluate("cisco_ios", changes)
    assert sum(len(f.changes) for f in findings) == len(changes)


def test_removing_insecure_service_is_not_high():
    findings = evaluate("mikrotik_routeros", [Change("-", "/ip service set telnet disabled=no")])
    assert findings[0].severity == Severity.info


def test_disabling_a_service_is_not_flagged_as_enabling_it():
    findings = evaluate("mikrotik_routeros", [Change("+", "/ip service set telnet disabled=yes")])
    assert all(f.rule_id != "mt-insecure-service" for f in findings)


@pytest.mark.parametrize("line, expected", [
    ("/ip firewall filter add action=accept chain=input dst-port=22 protocol=tcp", "mt-input-accept-any"),
    ("/ip firewall filter add action=accept chain=input dst-port=22 protocol=tcp src-address=10.0.0.0/24", "mt-firewall"),
    ("/ip firewall filter add action=accept chain=input src-address-list=mgmt", "mt-firewall"),
    ("/ip firewall filter add action=accept chain=input connection-state=established,related", "mt-firewall"),
])
def test_mikrotik_input_accept_needs_a_source_limit(line, expected):
    assert evaluate("mikrotik_routeros", [Change("+", line)])[0].rule_id == expected


@pytest.mark.parametrize("vendor, change, expected", [
    ("cisco_ios", Change("+", "access-list 101 permit ip any any"), "ios-acl-permit-any"),
    ("cisco_ios", Change("+", "ip http server"), "ios-insecure-mgmt"),
    ("cisco_ios", Change("+", "ip http secure-server"), "other"),
    ("cisco_ios", Change("+", "ip nat inside source static tcp 10.0.0.5 3389 interface Gi0/0 3389"), "ios-static-nat"),
    ("cisco_ios", Change("+", "ip route 0.0.0.0 0.0.0.0 192.0.2.1"), "ios-default-route"),
    ("cisco_ios", Change("-", "logging host 10.0.0.9"), "ios-logging-removed"),
    ("cisco_ios", Change("+", "logging host 10.0.0.9"), "other"),
    ("juniper_junos", Change("+", "set system services web-management http interface ge-0/0/0.0"), "junos-insecure-service"),
    ("juniper_junos", Change("+", "set system services web-management https interface ge-0/0/1.0"), "other"),
    ("juniper_junos", Change("+", "set snmp community public authorization read-only"), "junos-weak-snmp"),
    ("juniper_junos", Change("-", "set system syslog host 10.0.0.9 any info"), "junos-syslog-removed"),
    ("juniper_junos", Change("+", "set interfaces ge-0/0/3 disable"), "junos-interface-disabled"),
    ("mikrotik_routeros", Change("+", "/snmp community add name=public addresses=0.0.0.0/0"), "mt-weak-snmp"),
    ("mikrotik_routeros", Change("+", "/ip route add dst-address=0.0.0.0/0 gateway=192.0.2.1"), "mt-default-route"),
])
def test_individual_rules(vendor, change, expected):
    assert evaluate(vendor, [change])[0].rule_id == expected


def test_rule_ids_are_unique_and_vendors_known():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
    assert {r.vendor for r in RULES} == {"mikrotik_routeros", "cisco_ios", "juniper_junos"}


def test_no_changes_no_findings():
    assert evaluate("cisco_ios", []) == []
