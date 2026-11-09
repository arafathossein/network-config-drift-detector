"""Risk rules: which changes deserve a person's attention, and why.

Rules are checked in order and each changed line goes to the first rule it
matches, so specific high-risk rules come before the general ones for the
same area. Lines that match nothing are grouped as "other changes".

Rules see the raw lines (so they can tell an SNMP community of "public" from
any other); everything shown to people is redacted afterwards.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Change, Finding, Severity

H, M, L = Severity.high, Severity.medium, Severity.low


@dataclass(frozen=True)
class Rule:
    id: str
    vendor: str
    severity: Severity
    pattern: str
    title: str
    why: str
    check: str
    op: str = "any"  # "+", "-" or "any"
    exclude: str | None = None

    def matches(self, c: Change) -> bool:
        if self.op != "any" and c.op != self.op:
            return False
        if not re.search(self.pattern, c.text, re.I):
            return False
        return not (self.exclude and re.search(self.exclude, c.text, re.I))


MT, IOS, JUNOS = "mikrotik_routeros", "cisco_ios", "juniper_junos"

RULES: list[Rule] = [
    # ---------------- MikroTik RouterOS ----------------
    Rule("mt-insecure-service", MT, H, r"^/ip service set .*\b(telnet|ftp|www|api)\b", "Insecure management service enabled",
         "Telnet, FTP, plain HTTP and the unencrypted API send credentials in clear text.",
         "Confirm who enabled it and why; if it must stay on, restrict it with address= to a management network.",
         op="+", exclude=r"disabled=yes"),
    Rule("mt-port-forward", MT, H, r"^/ip firewall nat add .*action=dst-nat", "Port forward added",
         "A destination NAT rule exposes an internal host to whoever can reach the router.",
         "Check the target host and port, who requested it, and whether src-address limits who can use it.", op="+"),
    Rule("mt-input-accept-any", MT, H, r"^/ip firewall filter add .*action=accept.*chain=input|^/ip firewall filter add .*chain=input.*action=accept",
         "Router accepts new input traffic from any source",
         "An input-chain accept rule without a source limit opens the router itself to the internet.",
         "Add src-address or src-address-list, or remove the rule if it was temporary.",
         op="+", exclude=r"src-address(-list)?=|connection-state=|in-interface-list=LAN|in-interface=(bridge|ether[2-9])"),
    Rule("mt-firewall", MT, M, r"^/ip firewall (filter|raw|mangle|address-list)", "Firewall rules changed",
         "Firewall changes alter what traffic is allowed through or to the router.",
         "Match each change to a ticket; check rule order, since RouterOS uses the first matching rule."),
    Rule("mt-nat", MT, M, r"^/ip firewall nat", "NAT rules changed",
         "NAT changes alter which internal hosts are reachable or how traffic leaves the network.",
         "Confirm the change was planned and test the affected service."),
    Rule("mt-full-user", MT, H, r"^/user add .*group=full", "New user with full rights",
         "A new full-rights account can change anything on the router.",
         "Confirm the account belongs to a named person and was approved; remove it if not.", op="+"),
    Rule("mt-users", MT, M, r"^/user ", "User accounts changed",
         "Account changes affect who can log in and what they can do.",
         "Check the change against your access request records."),
    Rule("mt-default-route", MT, H, r"^/ip route .*dst-address=0\.0\.0\.0/0", "Default route changed",
         "The default route decides where all internet-bound traffic goes.",
         "Confirm the new gateway is your ISP or firewall, and check traffic is flowing normally."),
    Rule("mt-routes", MT, M, r"^/ip route|^/routing ", "Routing changed",
         "Routing changes can send traffic the wrong way or cut a site off.",
         "Check reachability of the affected networks."),
    Rule("mt-weak-snmp", MT, H, r"^/snmp community (add|set) .*name=(public|private)\b", "Default SNMP community in use",
         "Communities named public or private are the first ones attackers try.", "Use a unique community or SNMPv3.", op="+"),
    Rule("mt-snmp", MT, M, r"^/snmp", "SNMP settings changed", "SNMP can expose or change device settings.",
         "Confirm the monitoring team made this change."),
    Rule("mt-logging-removed", MT, M, r"^/system logging", "Logging configuration removed",
         "Removing log targets is a common way to hide later activity.", "Confirm logs still reach your log server.", op="-"),
    Rule("mt-interface-disabled", MT, L, r"^/interface .*disabled=yes", "Interface disabled",
         "A disabled interface may cut off a link or a site.", "Confirm the outage was planned.", op="+"),

    # ---------------- Cisco IOS ----------------
    Rule("ios-acl-permit-any", IOS, H, r"access-list.*\bpermit (ip|tcp|udp) any any\b|^access-list \d+ permit any\b",
         "Access list now permits any to any", "A permit any any line makes the access list allow everything after that point.",
         "Find who added it; narrow it to the hosts and ports that are actually needed.", op="+"),
    Rule("ios-acl", IOS, M, r"access-list", "Access lists changed",
         "Access list changes alter what traffic is allowed through the device.",
         "Match each change to a ticket and check the order of entries."),
    Rule("ios-insecure-mgmt", IOS, H, r"transport input (all|.*telnet)|^ip http server$", "Insecure management access enabled",
         "Telnet and plain HTTP send credentials in clear text.", "Use SSH only (transport input ssh) and ip http secure-server if needed.",
         op="+"),
    Rule("ios-priv15-user", IOS, H, r"^username \S+ privilege 15", "New privilege 15 user",
         "A privilege 15 account has full control of the device.", "Confirm the account belongs to a named, approved person.", op="+"),
    Rule("ios-users", IOS, M, r"^username ", "Local user accounts changed", "Account changes affect who can log in.",
         "Check the change against your access request records."),
    Rule("ios-default-route", IOS, H, r"^ip route 0\.0\.0\.0 0\.0\.0\.0", "Default route changed",
         "The default route decides where all unknown traffic goes.", "Confirm the next hop and check traffic is flowing normally."),
    Rule("ios-routing", IOS, M, r"^ip route |^router (ospf|bgp|eigrp|rip)", "Routing changed",
         "Routing changes can send traffic the wrong way or cut a site off.", "Check reachability of the affected networks."),
    Rule("ios-static-nat", IOS, H, r"^ip nat (inside|outside) source static", "Static NAT added",
         "A static NAT entry can expose an internal host to the outside.", "Check the host, the ports and the access list that protects it.",
         op="+"),
    Rule("ios-nat", IOS, M, r"^ip nat", "NAT changed", "NAT changes alter reachability.", "Confirm the change was planned."),
    Rule("ios-weak-snmp", IOS, H, r"^snmp-server community (public|private)\b", "Default SNMP community in use",
         "Communities named public or private are the first ones attackers try.", "Use a unique community with an ACL, or SNMPv3.", op="+"),
    Rule("ios-snmp", IOS, M, r"^snmp-server", "SNMP settings changed", "SNMP can expose or change device settings.",
         "Confirm the monitoring team made this change."),
    Rule("ios-logging-removed", IOS, M, r"^logging (host |\d|trap)", "Logging configuration removed",
         "Removing log targets is a common way to hide later activity.", "Confirm logs still reach your log server.", op="-"),
    Rule("ios-aaa", IOS, M, r"^(aaa |tacacs|radius)", "Authentication settings changed",
         "AAA changes affect how every administrator logs in.", "Test a login with a named account."),
    Rule("ios-shutdown", IOS, L, r"^interface .* > shutdown$", "Interface shut down", "A shut interface may cut off a link.",
         "Confirm the outage was planned.", op="+"),

    # ---------------- Juniper Junos ----------------
    Rule("junos-super-user", JUNOS, H, r"^set system login user \S+ class super-user", "New super-user account",
         "A super-user account has full control of the device.", "Confirm the account belongs to a named, approved person.", op="+"),
    Rule("junos-users", JUNOS, M, r"^set system login", "Login accounts changed", "Account changes affect who can log in.",
         "Check the change against your access request records."),
    Rule("junos-insecure-service", JUNOS, H, r"^set system services (telnet|ftp)\b|^set system services web-management http\b",
         "Insecure management service enabled", "Telnet, FTP and plain HTTP send credentials in clear text.",
         "Disable it and use SSH or HTTPS from a management network.", op="+"),
    Rule("junos-untrust-any", JUNOS, H, r"^set security policies from-zone untrust .* match (source-address|destination-address|application) any",
         "Policy from untrust matches any", "A policy from the untrust zone that matches any address or application can open the inside network.",
         "Narrow the policy to specific addresses and applications.", op="+"),
    Rule("junos-policies", JUNOS, M, r"^set security policies|^set firewall", "Security policies or filters changed",
         "Policy changes alter what traffic is allowed.", "Match each change to a ticket and check policy order."),
    Rule("junos-default-route", JUNOS, H, r"^set routing-options static route 0\.0\.0\.0/0", "Default route changed",
         "The default route decides where all unknown traffic goes.", "Confirm the next hop and check traffic is flowing normally."),
    Rule("junos-routing", JUNOS, M, r"^set routing-options|^set protocols (ospf|bgp|isis)", "Routing changed",
         "Routing changes can send traffic the wrong way or cut a site off.", "Check reachability of the affected networks."),
    Rule("junos-dest-nat", JUNOS, H, r"^set security nat destination", "Destination NAT added",
         "Destination NAT exposes an internal host to the outside.", "Check the host, the ports and the policy that protects it.", op="+"),
    Rule("junos-nat", JUNOS, M, r"^set security nat", "NAT changed", "NAT changes alter reachability.", "Confirm the change was planned."),
    Rule("junos-weak-snmp", JUNOS, H, r"^set snmp community (public|private)\b", "Default SNMP community in use",
         "Communities named public or private are the first ones attackers try.", "Use a unique community or SNMPv3.", op="+"),
    Rule("junos-snmp", JUNOS, M, r"^set snmp", "SNMP settings changed", "SNMP can expose or change device settings.",
         "Confirm the monitoring team made this change."),
    Rule("junos-syslog-removed", JUNOS, M, r"^set system syslog", "Logging configuration removed",
         "Removing log targets is a common way to hide later activity.", "Confirm logs still reach your log server.", op="-"),
    Rule("junos-interface-disabled", JUNOS, L, r"^set interfaces \S+ disable$", "Interface disabled",
         "A disabled interface may cut off a link.", "Confirm the outage was planned.", op="+"),
]


def evaluate(vendor: str, changes: list[Change]) -> list[Finding]:
    """Group changes into findings, highest severity first."""
    rules = [r for r in RULES if r.vendor == vendor]
    by_rule: dict[str, Finding] = {}
    other: list[Change] = []
    for c in changes:
        rule = next((r for r in rules if r.matches(c)), None)
        if rule is None:
            other.append(c)
            continue
        f = by_rule.setdefault(rule.id, Finding(rule.id, rule.severity, rule.title, rule.why, rule.check))
        f.changes.append(c)
    findings = sorted(by_rule.values(), key=lambda f: (-f.severity.rank, rules.index(next(r for r in rules if r.id == f.rule_id))))
    if other:
        findings.append(Finding("other", Severity.info, "Other configuration changes",
                                "Changes outside the areas the rules watch.", "Review them against planned work.", other))
    return findings
