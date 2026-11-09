import pytest

from config_drift.redact import R, redact, redact_line


@pytest.mark.parametrize(
    "line, secret",
    [
        ("/ppp secret add name=vpn password=Vendor2026! service=l2tp", "Vendor2026!"),
        ('/interface wifi security set sec1 passphrase="my wifi pass"', "my wifi pass"),
        ("/interface wireless security-profiles set default wpa2-pre-shared-key=Abc12345", "Abc12345"),
        ("/ip ipsec identity add peer=hq secret=Ipsec-Key-77", "Ipsec-Key-77"),
        ("/routing ospf interface-template add auth=md5 auth-key=ospfkey1 authentication-key=ospfkey2", "ospfkey2"),
        ("enable secret 9 $9$abcdefgh$ijklmnop", "$9$abcdefgh$ijklmnop"),
        ("username bob privilege 15 secret 5 $1$abcd$efgh", "$1$abcd$efgh"),
        ("username old password 7 0822455D0A16", "0822455D0A16"),
        (" key 7 0822455D0A16544541", "0822455D0A16544541"),
        (" key-string MyKey123", "MyKey123"),
        ("snmp-server community S3cretRO RO 10", "S3cretRO"),
        ('set system root-authentication encrypted-password "$6$salt$hash"', "$6$salt$hash"),
        ('set protocols ospf area 0 interface ge-0/0/1 authentication md5 1 key "$9$abc"', "$9$abc"),
        ('set security ike policy p1 pre-shared-key ascii-text "$9$xyz"', "$9$xyz"),
        ("set snmp community monitor-ro authorization read-only", "monitor-ro"),
        ("/snmp community add name=nms-ro-77 addresses=10.0.0.5/32", "nms-ro-77"),
    ],
)
def test_secret_values_are_removed(line, secret):
    out, n = redact(line)
    assert secret not in out
    assert R in out
    assert n >= 1


def test_default_communities_are_kept_because_they_are_the_finding():
    assert redact_line("snmp-server community public RO") == "snmp-server community public RO"
    assert redact_line("set snmp community private authorization read-write") == "set snmp community private authorization read-write"


def test_ordinary_lines_are_untouched():
    for line in [
        "crypto key generate rsa modulus 2048",
        "ip access-list extended SERVERS-IN",
        "/ip firewall filter add action=drop chain=input",
        "set system services ssh root-login deny",
    ]:
        assert redact(line) == (line, 0)


def test_private_key_block():
    text = "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----\nb"
    out, n = redact(text)
    assert "MIIEow" not in out and n == 1


def test_redaction_is_idempotent_and_counts_once():
    once, n1 = redact("enable secret 9 $9$abc")
    twice, n2 = redact(once)
    assert once == twice and n1 == 1 and n2 == 0
