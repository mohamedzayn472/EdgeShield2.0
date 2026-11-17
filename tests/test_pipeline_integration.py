"""Synthetic integration fixtures; test doubles are never reported as model inference."""
import io
import json
import socket
from pathlib import Path
import pytest
from edgeshield import cli
from edgeshield.detector import Detector
from edgeshield.pipeline import assess, explain
from edgeshield.validator import build_prompt


@pytest.fixture
def detector():
    return Detector.load(Path("models/detector.json"))


def test_local_pipeline_no_network_and_no_raw_output(detector, monkeypatch, capsys, caplog):
    def blocked(*args, **kwargs):
        pytest.fail("Python network operation attempted")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    sms = "PRIVATE_SENTINEL_9 Fiction Bank: Your OTP is 000000. Never share your OTP."
    result = assess(sms, detector)
    explanation = explain(result.evidence)
    assert explanation.source == "Template fallback"
    assert "PRIVATE_SENTINEL_9" not in repr(result) + repr(explanation) + build_prompt(result.evidence)
    assert not caplog.text
    assert not capsys.readouterr().out


def test_cli_json_has_no_sms_and_detection_first(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("PRIVATE_SENTINEL_9 urgent prize at https://fiction.example/"))
    assert cli.main(["--stdin", "--json"]) == 0
    output = capsys.readouterr().out
    assert "PRIVATE_SENTINEL_9" not in output
    assert "fiction.example" not in output
    events = [json.loads(line) for line in output.splitlines()]
    assert [event["event"] for event in events] == ["detection", "explanation"]
    assert events[0]["advice"].startswith("DO: ")
    assert events[1]["source"] == "Template fallback"
    assert events[1]["llama_ms"] is None


def test_cli_missing_model_and_oversize(monkeypatch, capsys, tmp_path):
    assert cli.main(["--detector", str(tmp_path / "missing.json"), "--stdin"]) == 2
    monkeypatch.setattr("sys.stdin", io.StringIO("SECRET" * 1000))
    assert cli.main(["--stdin"]) == 2
    assert "SECRET" not in str(capsys.readouterr())


def test_cli_missing_runtime_is_labeled(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr("sys.stdin", io.StringIO("Hello, see you tomorrow"))
    assert cli.main(["--stdin", "--runtime-config", str(tmp_path / "missing.json")]) == 0
    output = capsys.readouterr().out
    assert "configuration rejected" in output
    assert "Template fallback" in output
    assert "NOT VERIFIED" in output


def test_detector_and_advice_print_before_generation(monkeypatch, capsys, tmp_path):
    import edgeshield.advisory
    class TestAdvisor:
        def __init__(self, config):
            pass
        def generate(self, prompt):
            already_printed = capsys.readouterr().out
            assert "Threat band:" in already_printed
            assert "DO:" in already_printed
            assert "PRIVATE_SENTINEL_9" not in prompt
            return "WHY: bad output"
    monkeypatch.setattr(edgeshield.advisory, "ExecuTorchAdvisor", TestAdvisor)
    monkeypatch.setattr("sys.stdin", io.StringIO("PRIVATE_SENTINEL_9 hello"))
    assert cli.main(["--stdin", "--runtime-config", str(tmp_path / "test.json")]) == 0
    assert "Template fallback" in capsys.readouterr().out


def test_advisory_policies_and_cli(monkeypatch, capsys, tmp_path):
    from edgeshield.evidence import Evidence
    from edgeshield.pipeline import should_run_advisor
    calls = []

    class RecordingAdvisor:
        def __init__(self, config):
            pass

        def generate(self, prompt):
            calls.append(prompt)
            return "WHY: The detector is uncertain."

    advisor = RecordingAdvisor(None)
    clean_legit = Evidence("LEGITIMATE", 0.05, ())
    cued_legit = Evidence("LEGITIMATE", 0.10, ("BANK_IMPERSONATION",))
    uncertain = Evidence("UNCERTAIN", 0.50, ("URGENCY",))
    scam = Evidence("SCAM", 0.90, ("OTP_REQUEST",))

    assert should_run_advisor(clean_legit, "always") is True
    assert should_run_advisor(clean_legit, "elevated") is False
    assert should_run_advisor(cued_legit, "elevated") is True
    assert should_run_advisor(uncertain, "uncertain") is True
    assert should_run_advisor(scam, "uncertain") is False
    assert should_run_advisor(scam, "off") is False

    with pytest.raises(ValueError, match="policy"):
        should_run_advisor(clean_legit, "unknown")

    skipped = explain(clean_legit, advisor, policy="elevated")
    assert skipped.source == "Template fallback"
    assert skipped.reason == "SKIPPED_BY_POLICY"
    assert skipped.llama_ms is None
    assert not calls

    called = explain(uncertain, advisor, policy="uncertain")
    assert called.source == "Llama (validated)"
    assert len(calls) == 1

    monkeypatch.setattr("sys.stdin", io.StringIO("Hello, see you tomorrow"))
    assert cli.main(["--stdin", "--json", "--runtime-config", str(tmp_path / "missing.json"), "--advisory-policy", "off"]) == 0
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert events[1]["reason"] == "RUNTIME_NOT_CONFIGURED"
    assert events[1]["llama_ms"] is None

    import edgeshield.advisory
    monkeypatch.setattr(edgeshield.advisory, "ExecuTorchAdvisor", RecordingAdvisor)
    calls.clear()
    monkeypatch.setattr("sys.stdin", io.StringIO("Hello, see you tomorrow"))
    assert cli.main(["--stdin", "--json", "--runtime-config", str(tmp_path / "test.json"), "--advisory-policy", "elevated"]) == 0
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert events[1]["reason"] == "SKIPPED_BY_POLICY"
    assert not calls

    monkeypatch.setattr("sys.stdin", io.StringIO("Urgent: share your OTP now"))
    assert cli.main(["--stdin", "--json", "--runtime-config", str(tmp_path / "test.json"), "--advisory-policy", "off"]) == 0
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert events[1]["reason"] == "SKIPPED_BY_POLICY"
    assert not calls


def test_cli_demo_human_and_json_and_cwd_resolution(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["--demo"]) == 0
    human_out = capsys.readouterr().out
    assert "=== Demo 1/4:" in human_out
    assert "=== Demo 4/4:" in human_out
    assert "Threat band: SCAM" in human_out
    assert "Threat band: LEGITIMATE" in human_out
    assert "Indicator details:" in human_out
    assert "Total:" in human_out

    assert cli.main(["--demo", "--json"]) == 0
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(events) == 8
    assert [e["event"] for e in events] == ["detection", "explanation"] * 4
    assert len({e["demo_case"] for e in events}) == 4
    assert any(e.get("evidence", {}).get("band") == "SCAM" for e in events)
    assert any(e.get("evidence", {}).get("band") == "LEGITIMATE" for e in events)

    with pytest.raises(SystemExit):
        cli.main(["--demo", "--stdin"])
