"""Tests for offline Phishing URL detection, indicators, privacy boundary, and CLI integration."""
import io
import json
from pathlib import Path
import socket
import pytest

from edgeshield import cli
from edgeshield.evidence import Evidence
from edgeshield.indicators import DESCRIPTIONS, detect_url_indicators
from edgeshield.pipeline import assess_url, explain
from edgeshield.url_detector import (
    DEFAULT_URL_DETECTOR_PATH,
    MAX_URL_CHARS,
    load_url_detector,
    normalize_url,
    save_url_artifact,
)
from edgeshield.validator import build_prompt


@pytest.mark.parametrize("bad_url", [
    "",
    "   ",
    "https://example.com/" + "a" * MAX_URL_CHARS,
    None,
    123,
    "https://example.com/\u202e",
    "https://example.com/\x1b",
    "https://example.com/with space",
    "ftp://example.com/file",
    "not-a-host-only-scheme://",
])
def test_normalize_url_validation_and_no_leak(bad_url):
    with pytest.raises(ValueError) as exc:
        normalize_url(bad_url)
    if isinstance(bad_url, str) and "example.com" in bad_url:
        assert "example.com" not in str(exc.value)


@pytest.mark.parametrize("url,expected", [
    ("http://198.51.100.42:8080/login", {"IP_HOST_URL", "BRAND_SPOOF_URL"}),
    ("https://onlinesbi.sbi@evil-portal.xyz/login", {"PUNYCODE_OR_AT_URL", "SUSPICIOUS_TLD_URL", "BRAND_SPOOF_URL"}),
    ("https://xn--sbi-onlne-05a.example/login", {"PUNYCODE_OR_AT_URL", "BRAND_SPOOF_URL"}),
    ("http://bit.ly/sbi-kyc-urgent-2026", {"SHORTENER_LINK", "BRAND_SPOOF_URL"}),
    ("http://parivahan-echallan-pay.xyz/download/eChallan.apk", {"SUSPICIOUS_TLD_URL", "BRAND_SPOOF_URL", "RISKY_EXTENSION_URL"}),
    ("https://a.b.c.attacker.example/path", {"DEEP_SUBDOMAIN_URL"}),
])
def test_url_indicators_trigger_expected_cues(url, expected):
    cues = set(detect_url_indicators(url))
    assert expected.issubset(cues), (url, cues)


@pytest.mark.parametrize("benign_url", [
    "https://www.onlinesbi.sbi/sbijava/retail/html/faq.html",
    "https://www.npci.org.in/what-we-do/upi/product-overview",
    "https://github.com/login",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://uidai.gov.in/en/myaadhaar/about-your-aadhaar.html",
    "https://www.hdfcbank.com/personal/ways-to-bank/online-banking/net-banking",
    "https://en.m.wikipedia.org/wiki/Phishing",
])
def test_legitimate_deep_urls_do_not_false_trigger(benign_url):
    assert detect_url_indicators(benign_url) == ()


def test_url_detector_artifact_checksum_and_tamper_detection(tmp_path):
    assert DEFAULT_URL_DETECTOR_PATH.is_file()
    detector = load_url_detector(DEFAULT_URL_DETECTOR_PATH)
    assert getattr(detector, "artifact_sha256", None)

    raw_bytes = DEFAULT_URL_DETECTOR_PATH.read_bytes()
    copy_model = tmp_path / "url_detector_v1.json"
    copy_sha = tmp_path / "url_detector_v1.json.sha256"
    copy_model.write_bytes(raw_bytes)
    copy_sha.write_text("0" * 64 + "\n", encoding="ascii")
    with pytest.raises(ValueError, match="checksum"):
        load_url_detector(copy_model)

    save_url_artifact(copy_model, json.loads(raw_bytes))
    assert load_url_detector(copy_model).artifact_sha256 == detector.artifact_sha256


def test_url_privacy_boundary_and_no_network(monkeypatch, capsys, caplog):
    def blocked(*args, **kwargs):
        pytest.fail("Python network operation attempted")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)

    detector = load_url_detector(DEFAULT_URL_DETECTOR_PATH)
    sentinel_url = "http://sbi-kyc-PRIVATE_URL_SENTINEL.xyz/netbanking/login.php?token=SECRET99"
    result = assess_url(sentinel_url, detector)
    explanation = explain(result.evidence)
    assert explanation.source == "Template fallback"
    prompt = build_prompt(result.evidence)
    combined = repr(result) + repr(explanation) + prompt
    assert "PRIVATE_URL_SENTINEL" not in combined
    assert "SECRET99" not in combined
    assert not caplog.text
    assert not capsys.readouterr().out


def test_cli_url_mode_stdin_and_demo(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("http://hdfc-kyc-PRIVATE_SENTINEL.xyz/verify.apk\n"))
    assert cli.main(["--url-stdin", "--json"]) == 0
    out = capsys.readouterr().out
    assert "PRIVATE_SENTINEL" not in out
    events = [json.loads(line) for line in out.splitlines()]
    assert [e["event"] for e in events] == ["detection", "explanation"]
    assert events[0]["mode"] == "url"
    assert events[0]["advice"].startswith("DO: ")
    assert events[0]["evidence"]["band"] == "SCAM"

    assert cli.main(["--mode", "url", "--demo", "--json"]) == 0
    demo_events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(demo_events) == 8
    assert any(e.get("evidence", {}).get("band") == "SCAM" for e in demo_events)
    assert any(e.get("evidence", {}).get("band") == "LEGITIMATE" for e in demo_events)

    # Confirm default SMS --demo remains unchanged
    assert cli.main(["--demo", "--json"]) == 0
    sms_events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert sms_events[0]["demo_case"] == "english_legit_otp"
