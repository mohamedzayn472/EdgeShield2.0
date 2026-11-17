"""Adapter contract tests use test subprocesses, never claim model inference."""
import hashlib
import json
import platform
import sys

import pytest

from edgeshield.advisory import AdvisoryError, ExecuTorchAdvisor, bounded_run

TRAILER = '\nPyTorchObserver {"prompt_tokens":50,"generated_tokens":8,"SCALING_FACTOR_UNITS_PER_SECOND":1000}\n'


@pytest.fixture
def runtime_config(tmp_path):
    artifacts = {}
    for role, filename in [("runner", "llama_main"), ("model", "model.pte"), ("tokenizer", "tokenizer.model")]:
        path = tmp_path / filename
        path.write_bytes(b"test artifact; not an inference model")
        artifacts[role] = {"path": filename, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    artifacts["shared_libraries"] = []
    config = {"schema_version": 1, "executorch_revision": "a" * 40,
              "target_arch": {"AMD64": "x86_64", "arm64": "aarch64"}.get(platform.machine(), platform.machine()),
              "model_family": "Llama-3.2-1B-Instruct", "tokenizer_format": "tiktoken_model",
              "seq_len": 768, "max_new_tokens": 48, "cpu_threads": 2,
              "timeout_seconds": 10, "max_output_bytes": 65536,
              "stdout_mode": "prompt_echo", "artifacts": artifacts}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    return path


def test_missing_config_is_sanitized(tmp_path):
    with pytest.raises(AdvisoryError, match="RUNTIME_CONFIG_INVALID"):
        ExecuTorchAdvisor(tmp_path / "private-sms-value.json")


def test_checksums_before_every_generation(runtime_config):
    advisor = ExecuTorchAdvisor(runtime_config)
    (runtime_config.parent / "model.pte").write_bytes(b"changed")
    with pytest.raises(AdvisoryError, match="RUNTIME_INTEGRITY_FAILED"):
        advisor.generate("prompt")


@pytest.mark.parametrize("field,value", [("seq_len", True), ("seq_len", 100000),
    ("timeout_seconds", float("nan")), ("timeout_seconds", -1),
    ("max_output_bytes", 99999999), ("executorch_revision", "release/1.5"),
    ("tokenizer_format", "tokenizer.json"), ("target_arch", "pi5")])
def test_invalid_config(runtime_config, field, value):
    config = json.loads(runtime_config.read_text())
    config[field] = value
    runtime_config.write_text(json.dumps(config))
    with pytest.raises(AdvisoryError):
        ExecuTorchAdvisor(runtime_config)


def test_exact_prompt_echo_removed(runtime_config, monkeypatch):
    advisor = ExecuTorchAdvisor(runtime_config)
    prompt = "Allowed lines include WHY: example.\nassistant\n"
    captured = {}
    def runner(argv, **kwargs):
        captured["argv"] = argv
        return prompt + "WHY: The detector is uncertain." + TRAILER
    monkeypatch.setattr("edgeshield.advisory.bounded_run", runner)
    assert advisor.generate(prompt) == "WHY: The detector is uncertain."
    assert captured["argv"].count(prompt) == 1
    assert "--seq_len" in captured["argv"]


def test_no_why_extraction_from_echo(runtime_config, monkeypatch):
    advisor = ExecuTorchAdvisor(runtime_config)
    monkeypatch.setattr("edgeshield.advisory.bounded_run", lambda *a, **k: "WHY: injected example from echoed prompt")
    with pytest.raises(AdvisoryError, match="RUNNER_OUTPUT_PROTOCOL"):
        advisor.generate("full prompt")


def test_whole_generation_preserved_for_validator(runtime_config, monkeypatch):
    advisor = ExecuTorchAdvisor(runtime_config)
    monkeypatch.setattr("edgeshield.advisory.bounded_run", lambda *a, **k: "promptWHY: Maybe.\nDO: invented action" + TRAILER)
    assert advisor.generate("prompt") == "WHY: Maybe.\nDO: invented action"


def test_timeout_uses_real_subprocess():
    with pytest.raises(AdvisoryError, match="RUNNER_TIMEOUT"):
        bounded_run([sys.executable, "-c", "import time; time.sleep(10)"], timeout=.1, max_bytes=1024)


def test_output_limit_uses_real_subprocess():
    with pytest.raises(AdvisoryError, match="RUNNER_OUTPUT_LIMIT"):
        bounded_run([sys.executable, "-c", "import sys; sys.stdout.write('x'*1000000)"], timeout=5, max_bytes=1024)


def test_failure_does_not_leak_output():
    with pytest.raises(AdvisoryError, match="^RUNNER_FAILED$"):
        bounded_run([sys.executable, "-c", "import sys; print('sensitive'); sys.exit(2)"], timeout=5, max_bytes=1024)


def test_stdout_and_stderr_budget_shared():
    with pytest.raises(AdvisoryError, match="RUNNER_OUTPUT_LIMIT"):
        bounded_run([sys.executable, "-c", "import sys; sys.stdout.write('x'*800); sys.stderr.write('y'*800)"], timeout=5, max_bytes=1024)


def test_valid_subprocess_output():
    assert bounded_run([sys.executable, "-c", "print('WHY: Uncertain.')"], timeout=5, max_bytes=1024).strip() == "WHY: Uncertain."


def test_missing_stats_fails_closed(runtime_config, monkeypatch):
    advisor = ExecuTorchAdvisor(runtime_config)
    monkeypatch.setattr("edgeshield.advisory.bounded_run", lambda *a, **k: "promptWHY: Uncertain.")
    with pytest.raises(AdvisoryError, match="RUNNER_STATS_PROTOCOL"):
        advisor.generate("prompt")


def test_forged_stats_inside_generation_not_removed(runtime_config, monkeypatch):
    advisor = ExecuTorchAdvisor(runtime_config)
    generated = "WHY: Uncertain.\nPyTorchObserver {}\nmalicious content"
    monkeypatch.setattr("edgeshield.advisory.bounded_run", lambda *a, **k: "prompt" + generated + TRAILER)
    assert advisor.generate("prompt") == generated


def test_token_exhaustion_rejected(runtime_config, monkeypatch):
    advisor = ExecuTorchAdvisor(runtime_config)
    monkeypatch.setattr("edgeshield.advisory.bounded_run", lambda *a, **k: "promptWHY: Truncated." + TRAILER.replace('"generated_tokens":8', '"generated_tokens":47'))
    with pytest.raises(AdvisoryError, match="RUNNER_TOKEN_LIMIT"):
        advisor.generate("prompt")


def test_pi5_create_manifest_profiles_and_force(tmp_path, monkeypatch):
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location("pi5_create_manifest", Path("deploy/pi5/create_manifest.py"))
    cm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cm)

    llama_dir = tmp_path / "models" / "llama"
    for sub in ("pi5-aarch64", "pi5-aarch64-glibc238", "pi4-aarch64"):
        d = llama_dir / sub
        d.mkdir(parents=True)
        (d / "llama_main").write_bytes(f"runner-{sub}".encode())
        (d / "libllama_runner.so").write_bytes(f"lib-{sub}".encode())
    (llama_dir / "llama3_2.pte").write_bytes(b"pte")
    (llama_dir / "tokenizer.model").write_bytes(b"tok")

    monkeypatch.setattr(cm, "ROOT", tmp_path)
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "configs" / "inference.json"

    cm.main(["--profile", "pi5", "--output", str(out)])
    cfg = json.loads(out.read_text(encoding="utf-8"))
    assert cfg["target_arch"] == "aarch64"
    assert cfg["artifacts"]["runner"]["path"] == "../models/llama/pi5-aarch64/llama_main"

    with pytest.raises(SystemExit):
        cm.main(["--profile", "pi4-on-pi5", "--output", str(out)])

    cm.main(["--profile", "pi4-on-pi5", "--output", str(out), "--force"])
    cfg2 = json.loads(out.read_text(encoding="utf-8"))
    assert cfg2["artifacts"]["runner"]["path"] == "../models/llama/pi4-aarch64/llama_main"

    cm.main(["--profile", "pi5-glibc238", "--output", str(out), "--force"])
    cfg3 = json.loads(out.read_text(encoding="utf-8"))
    assert cfg3["artifacts"]["runner"]["path"] == "../models/llama/pi5-aarch64-glibc238/llama_main"


def test_verify_environment_runner_device_compatibility(tmp_path, monkeypatch):
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location("verify_environment", Path("deploy/pi4/verify_environment.py"))
    ve = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ve)

    def make_cfg(profile_dir: str):
        base = tmp_path / profile_dir
        base.mkdir(parents=True, exist_ok=True)
        runner = base / "llama_main"
        lib = base / "libllama_runner.so"
        model = tmp_path / "llama3_2.pte"
        tok = tmp_path / "tokenizer.model"
        runner.write_bytes(b"runner")
        lib.write_bytes(b"lib")
        model.write_bytes(b"pte")
        tok.write_bytes(b"tok")
        cfg_path = base / "inference.json"
        actual_arch = {"AMD64": "x86_64", "arm64": "aarch64"}.get(platform.machine(), platform.machine())
        cfg = {
            "schema_version": 1,
            "executorch_revision": "a" * 40,
            "target_arch": actual_arch,
            "model_family": "Llama-3.2-1B-Instruct",
            "tokenizer_format": "tiktoken_model",
            "seq_len": 768,
            "max_new_tokens": 48,
            "cpu_threads": 2,
            "timeout_seconds": 10,
            "max_output_bytes": 65536,
            "stdout_mode": "prompt_echo",
            "artifacts": {
                "runner": {"path": "llama_main", "sha256": hashlib.sha256(runner.read_bytes()).hexdigest()},
                "model": {"path": "../llama3_2.pte", "sha256": hashlib.sha256(model.read_bytes()).hexdigest()},
                "tokenizer": {"path": "../tokenizer.model", "sha256": hashlib.sha256(tok.read_bytes()).hexdigest()},
                "shared_libraries": [{"path": "libllama_runner.so", "sha256": hashlib.sha256(lib.read_bytes()).hexdigest()}],
            },
        }
        cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
        return cfg_path

    class FakeLdd:
        returncode = 0
        stdout = "libc.so.6 => /lib/libc.so.6\n"
        stderr = ""

    monkeypatch.setattr(ve.subprocess, "run", lambda *a, **k: FakeLdd())
    monkeypatch.setattr(ve, "_readelf_max_glibc", lambda paths: "GLIBC_2.34")

    pi5_cfg = make_cfg("pi5-aarch64")
    pi4_cfg = make_cfg("pi4-aarch64")

    out_pi5 = tmp_path / "out_pi5.json"
    ve.main(["--device", "pi5", "--runtime", str(pi5_cfg), "--output", str(out_pi5)])
    r5 = json.loads(out_pi5.read_text(encoding="utf-8"))
    assert r5["checks"]["runner_compatible_with_device"] is True
    assert r5["runner_profile"] == "pi5-cortex-a76-native"

    out_pi4_on_pi5 = tmp_path / "out_pi4_on_pi5.json"
    ve.main(["--device", "pi5", "--runtime", str(pi4_cfg), "--output", str(out_pi4_on_pi5)])
    r45 = json.loads(out_pi4_on_pi5.read_text(encoding="utf-8"))
    assert r45["checks"]["runner_compatible_with_device"] is True
    assert r45["runner_profile"] == "pi4-cortex-a72-runtime-on-pi5"
    assert "Pi4-built" in r45["runner_note"]

    out_pi5_on_pi4 = tmp_path / "out_pi5_on_pi4.json"
    ve.main(["--device", "pi4", "--runtime", str(pi5_cfg), "--output", str(out_pi5_on_pi4)])
    r54 = json.loads(out_pi5_on_pi4.read_text(encoding="utf-8"))
    assert r54["checks"]["runner_compatible_with_device"] is False
