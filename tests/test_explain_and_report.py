import json

import httpx
import pytest

from config_drift.explain import FallbackExplainer, LLMExplainer, RuleExplainer, rule_summary
from config_drift.models import Severity
from config_drift.pipeline import compare
from config_drift.report import html_report, markdown, slack_payload, to_json

from .conftest import DAY1, DAY2, SAMPLE_SECRETS, sample

DEVICES = [("edge-rtr-01", "mikrotik_routeros"), ("core-sw-01", "cisco_ios"), ("dc-fw-01", "juniper_junos")]


def _reports(explainer=None):
    explainer = explainer or RuleExplainer()
    return [compare(d, v, sample(DAY1, d), sample(DAY2, d), explainer, DAY1, DAY2) for d, v in DEVICES]


def _mock_llm(handler):
    return LLMExplainer("http://llm.test/v1", "k", "m", client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_rule_summary_without_changes():
    s = rule_summary("x", [], [])
    assert s.headline == "No changes on x" and s.bullets == []


def test_rule_summary_leads_with_the_highest_risk():
    r = _reports()[1]
    assert r.summary.headline == "core-sw-01: access list now permits any to any"
    assert r.summary.bullets[0] == "6 lines added, 2 lines removed."


@pytest.mark.parametrize("fmt", [markdown, to_json, html_report])
def test_no_secret_reaches_any_report(fmt):
    text = fmt(_reports(), DAY2)
    for secret in SAMPLE_SECRETS:
        assert secret not in text, secret
    assert "<redacted>" in text or "&lt;redacted&gt;" in text


def test_slack_payload_has_no_secrets_and_lists_risky_devices():
    payload = slack_payload(_reports(), DAY2)
    text = json.dumps(payload)
    assert all(s not in text for s in SAMPLE_SECRETS)
    assert "core-sw-01" in text and "dc-fw-01" in text and "edge-rtr-01" in text


def test_slack_payload_skips_low_risk_days():
    r = compare("sw", "cisco_ios", "interface Gi0/3\n no shutdown\n", "interface Gi0/3\n shutdown\n", RuleExplainer(), DAY1, DAY2)
    assert r.max_severity == Severity.low
    assert slack_payload([r], DAY2) is None
    assert slack_payload([r], DAY2, min_severity=Severity.low) is not None


def test_html_escapes_config_text():
    r = compare("sw", "cisco_ios", "hostname a\n", "hostname a\nbanner motd <script>alert(1)</script>\n", RuleExplainer(), DAY1, DAY2)
    assert "<script>" not in html_report([r], DAY2)


def test_llm_summary_used_and_only_sees_redacted_lines():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content.decode()
        content = json.dumps({"headline": "Any-to-any rule added to SERVERS-IN",
                              "bullets": ["A new line lets all traffic into the server VLAN.", "Telnet is now allowed on the VTY lines."]})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    r = compare("core-sw-01", "cisco_ios", sample(DAY1, "core-sw-01"), sample(DAY2, "core-sw-01"),
                FallbackExplainer(_mock_llm(handler)), DAY1, DAY2)
    assert r.summary.source == "llm"
    assert r.summary.headline == "Any-to-any rule added to SERVERS-IN"
    assert all(s not in seen["body"] for s in SAMPLE_SECRETS)
    assert "permit ip any any" in seen["body"]


@pytest.mark.parametrize("response", [
    httpx.Response(500, text="boom"),
    httpx.Response(200, json={"choices": [{"message": {"content": "not json"}}]}),
    httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({"headline": "x", "bullets": []})}}]}),
])
def test_llm_failures_fall_back_to_rules(response):
    r = compare("core-sw-01", "cisco_ios", sample(DAY1, "core-sw-01"), sample(DAY2, "core-sw-01"),
                FallbackExplainer(_mock_llm(lambda req: response)), DAY1, DAY2)
    assert r.summary.source == "rules (model failed)"
    assert r.summary.headline.startswith("core-sw-01:")


def test_llm_output_is_redacted_too():
    def handler(request):
        content = json.dumps({"headline": "Password changed", "bullets": ["The new line sets password=Hunter2 on the router."]})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    r = compare("sw", "cisco_ios", "hostname a\n", "hostname b\n", _mock_llm(handler), DAY1, DAY2)
    assert "Hunter2" not in " ".join(r.summary.bullets)
