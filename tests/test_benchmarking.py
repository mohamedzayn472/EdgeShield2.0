import pytest

from edgeshield.benchmarking import distribution, runner_and_memory_metrics, system_metrics, runtime_measurements


def test_percentiles_and_unavailable_measurements():
    assert distribution([None]) is None
    assert distribution(list(range(1, 101))) == {"n": 100, "median": 50.5, "p95": 95, "min": 1, "max": 100}
    assert set(system_metrics()) == {"python_peak_rss_bytes", "temperature_c"}
    assert set(runner_and_memory_metrics()) == {
        "runner_child_peak_rss_bytes",
        "mem_total_bytes",
        "mem_available_bytes",
        "swap_total_bytes",
        "swap_used_bytes",
    }


def test_runtime_counter_units_and_missing_values():
    assert all(x is None for x in runtime_measurements(None).values())
    assert all(x is None for x in runtime_measurements({"SCALING_FACTOR_UNITS_PER_SECOND": 1}).values())
    actual = runtime_measurements({"SCALING_FACTOR_UNITS_PER_SECOND": 1000,
        "model_load_start_ms": 10, "model_load_end_ms": 50,
        "inference_start_ms": 51, "prompt_eval_end_ms": 81, "first_token_ms": 82,
        "generated_tokens": 12, "decode_token_per_sec": 3.5})
    assert actual == {"model_load_ms": 40, "prefill_ms": 30, "time_to_first_token_ms": 31, "tokens_generated": 12, "decode_tokens_per_second": 3.5}


def test_benchmarking_main_averages_and_policy(tmp_path):
    import json
    from edgeshield.benchmarking import main as bench_main
    out = tmp_path / "bench.json"
    assert bench_main(["--repetitions", "2", "--advisory-policy", "off", "--output", str(out)]) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["repetitions"] == 2
    assert report["advisory_policy"] == "off"
    assert set(report["averages_ms"]) == {"detector_ms", "evidence_ms", "llama_ms", "validation_ms", "total_ms"}
    assert report["averages_ms"]["detector_ms"] >= 0
    assert report["averages_ms"]["llama_ms"] is None
    assert report["hardware_verified_pi5"] is False
    for key in ("runner_child_peak_rss_bytes", "min_mem_available_bytes", "max_swap_used_bytes", "temperature_c", "throttled_before", "throttled_after"):
        assert key in report


def _write_fake_runtime_cfg(tmp_path):
    import hashlib
    import json

    cfg_path = tmp_path / "runtime.json"
    cfg = {
        "schema_version": 1,
        "executorch_revision": "a" * 40,
        "target_arch": "x86_64",
        "model_family": "Llama-3.2-1B-Instruct",
        "tokenizer_format": "tiktoken_model",
        "seq_len": 768,
        "max_new_tokens": 48,
        "cpu_threads": 2,
        "timeout_seconds": 30,
        "max_output_bytes": 65536,
        "stdout_mode": "prompt_echo",
        "artifacts": {
            "runner": {"path": "llama_main", "sha256": hashlib.sha256(b"r").hexdigest()},
            "model": {"path": "m.pte", "sha256": hashlib.sha256(b"m").hexdigest()},
            "tokenizer": {"path": "tokenizer.model", "sha256": hashlib.sha256(b"t").hexdigest()},
            "shared_libraries": [{"path": "lib.so", "sha256": hashlib.sha256(b"l").hexdigest()}],
        },
    }
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    return cfg_path, cfg


def test_benchmarking_stale_stats_fix_and_accounting(tmp_path, monkeypatch):
    import json
    import edgeshield.advisory
    import edgeshield.benchmarking as bench

    cfg_path, cfg = _write_fake_runtime_cfg(tmp_path)

    class StubDetector:
        def predict(self, text):
            if "UNCERTAIN_CASE" in text:
                return {"band": "UNCERTAIN", "score": 0.5, "score_label": "uncertain", "model_version": "stub"}
            return {"band": "SCAM", "score": 0.99, "score_label": "scam", "model_version": "stub"}

    class FakeAdvisor:
        def __init__(self, path):
            self.config = cfg
            self.last_stats = None
            self.last_timing = None

        def generate(self, prompt):
            self.last_stats = {
                "SCALING_FACTOR_UNITS_PER_SECOND": 1000,
                "model_load_start_ms": 100,
                "model_load_end_ms": 120,
                "inference_start_ms": 121,
                "prompt_eval_end_ms": 151,
                "first_token_ms": 152,
                "inference_end_ms": 171,
                "generated_tokens": 8,
                "decode_token_per_sec": 10.0,
            }
            self.last_timing = {"integrity_ms": 5.0, "runner_wall_ms": 100.0}
            return "WHY: The detector is uncertain."

    monkeypatch.setattr(bench, "FIXTURES", ("UNCERTAIN_CASE text", "SCAM_CASE urgent OTP"))
    monkeypatch.setattr(bench, "load_detector", lambda _p: StubDetector())
    monkeypatch.setattr(edgeshield.advisory, "ExecuTorchAdvisor", FakeAdvisor)

    out = tmp_path / "bench.json"
    rc = bench.main([
        "--runtime-config", str(cfg_path),
        "--advisory-policy", "uncertain",
        "--repetitions", "2",
        "--run-id", "stale-check",
        "--output", str(out),
    ])
    assert rc == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["run_id"] == "stale-check"
    assert report["completed"] is True
    assert report["stop_reason"] is None
    assert report["llama_attempted_count"] == 1
    assert report["skipped_by_policy_count"] == 1
    assert report["llama_validated_count"] == 1
    assert report["reason_counts"] == {"ACCEPTED": 1, "SKIPPED_BY_POLICY": 1}
    assert sum(report["reason_counts"].values()) == report["repetitions"]
    assert report["effective_settings"]["cpu_threads"] == 2
    assert report["effective_settings"]["artifacts_sha256"]["runner"] == cfg["artifacts"]["runner"]["sha256"]

    row0, row1 = report["samples"]
    assert row0["llama_attempted"] is True
    assert row0["reason"] == "ACCEPTED"
    assert row0["runner_stats"] is not None
    assert row0["integrity_ms"] == 5.0
    assert row0["runner_wall_ms"] == 100.0
    assert row0["decode_ms"] == 20
    assert row0["runner_overhead_ms"] == 29.0

    assert row1["llama_attempted"] is False
    assert row1["reason"] == "SKIPPED_BY_POLICY"
    assert row1["runner_stats"] is None
    assert row1["integrity_ms"] is None
    assert row1["runner_wall_ms"] is None
    assert row1["decode_ms"] is None
    assert row1["runner_overhead_ms"] is None
    assert row1["model_load_ms"] is None


def test_benchmarking_cli_argv_preserves_contract(tmp_path):
    import json
    from edgeshield.benchmarking import main as bench_main

    out = tmp_path / "bench.json"
    rc = bench_main(["--duration", "0.2", "--repetitions", "2", "--advisory-policy", "off", "--output", str(out)])
    assert rc == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["repetitions"] >= 2
    assert report["duration_seconds"] >= 0.2
    assert report["fixtures"] == "five fixed synthetic cases; not detection-quality evaluation"
    assert report["scheduled_starts"] is None
    assert set(report["averages_ms"]) == {"detector_ms", "evidence_ms", "llama_ms", "validation_ms", "total_ms"}
    assert set(report["timings_ms"]) == {"detector_ms", "evidence_ms", "llama_ms", "validation_ms", "total_ms"}
    for key in (
        "schema_version", "measurement_kind", "platform", "recorded_at_utc",
        "detector_sha256", "runtime_config_sha256", "llama_validated_count",
        "template_fallback_count", "template_fallback_rate",
        "runner_child_peak_rss_bytes", "min_mem_available_bytes", "max_swap_used_bytes",
        "temperature_c", "throttled_before", "throttled_after",
    ):
        assert key in report


def test_benchmarking_sigterm_partial_report_and_stop_file(tmp_path, monkeypatch):
    import json
    import os
    import signal
    import edgeshield.advisory
    import edgeshield.benchmarking as bench

    cfg_path, cfg = _write_fake_runtime_cfg(tmp_path)

    class InterruptingAdvisor:
        def __init__(self, path):
            self.config = cfg
            self.last_stats = None
            self.last_timing = None
            self.calls = 0

        def generate(self, prompt):
            self.calls += 1
            if self.calls == 2:
                os.kill(os.getpid(), signal.SIGTERM)
            self.last_stats = {
                "SCALING_FACTOR_UNITS_PER_SECOND": 1000,
                "model_load_start_ms": 10,
                "model_load_end_ms": 20,
                "inference_start_ms": 21,
                "prompt_eval_end_ms": 31,
                "first_token_ms": 32,
                "inference_end_ms": 41,
                "generated_tokens": 5,
                "decode_token_per_sec": 10.0,
            }
            self.last_timing = {"integrity_ms": 1.0, "runner_wall_ms": 35.0}
            return "WHY: The detector estimates elevated risk."

    monkeypatch.setattr(edgeshield.advisory, "ExecuTorchAdvisor", InterruptingAdvisor)
    out = tmp_path / "sigterm.json"
    rc = bench.main([
        "--runtime-config", str(cfg_path),
        "--repetitions", "5",
        "--run-id", "sigterm-test",
        "--output", str(out),
    ])
    assert rc == 3
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["completed"] is False
    assert report["stop_reason"] == "SIGTERM"
    assert report["repetitions"] == 1
    partial_lines = (tmp_path / "sigterm.json.partial.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(partial_lines) == 1
    assert json.loads(partial_lines[0])["request_index"] == 0

    # Also test --stop-file stop path
    stop_file = tmp_path / "STOP"

    class StopTouchingAdvisor:
        def __init__(self, path):
            self.config = cfg
            self.last_stats = None
            self.last_timing = None
            self.calls = 0

        def generate(self, prompt):
            self.calls += 1
            self.last_stats = None
            self.last_timing = {"integrity_ms": 1.0, "runner_wall_ms": 10.0}
            if self.calls == 2:
                stop_file.write_text("stop\n", encoding="utf-8")
            return "WHY: The detector estimates elevated risk."

    monkeypatch.setattr(edgeshield.advisory, "ExecuTorchAdvisor", StopTouchingAdvisor)
    out2 = tmp_path / "stopfile.json"
    rc2 = bench.main([
        "--runtime-config", str(cfg_path),
        "--repetitions", "5",
        "--stop-file", str(stop_file),
        "--output", str(out2),
    ])
    assert rc2 == 3
    report2 = json.loads(out2.read_text(encoding="utf-8"))
    assert report2["completed"] is False
    assert report2["stop_reason"] == "STOP_FILE"
    assert report2["repetitions"] == 2


def test_benchmarking_paced_on_time_and_overloaded(tmp_path, monkeypatch):
    import json
    import time
    import edgeshield.advisory
    import edgeshield.benchmarking as bench

    # On-time paced run
    out_ok = tmp_path / "paced_ok.json"
    rc_ok = bench.main([
        "--interval-seconds", "0.06",
        "--repetitions", "3",
        "--advisory-policy", "off",
        "--output", str(out_ok),
    ])
    assert rc_ok == 0
    rep_ok = json.loads(out_ok.read_text(encoding="utf-8"))
    assert rep_ok["completed"] is True
    assert rep_ok["offered_interval_seconds"] == 0.06
    assert rep_ok["scheduled_starts"] == 3
    assert rep_ok["actual_starts"] == 3
    assert rep_ok["late_starts"] == 0
    assert rep_ok["arrival_to_completion_ms"]["n"] == 3
    assert rep_ok["start_delay_ms"]["n"] == 3
    for idx, row in enumerate(rep_ok["samples"]):
        assert row["scheduled_offset_s"] == pytest.approx(idx * 0.06)
        assert row["scheduled_start_utc"] is not None
        assert row["is_late_start"] is False
        assert row["arrival_to_completion_ms"] >= row["total_ms"]

    # Overloaded paced run: inference slower than offered interval
    cfg_path, cfg = _write_fake_runtime_cfg(tmp_path)

    class SlowAdvisor:
        def __init__(self, path):
            self.config = cfg
            self.last_stats = None
            self.last_timing = None

        def generate(self, prompt):
            time.sleep(0.06)
            self.last_timing = {"integrity_ms": 1.0, "runner_wall_ms": 60.0}
            return "WHY: The detector estimates elevated risk."

    monkeypatch.setattr(edgeshield.advisory, "ExecuTorchAdvisor", SlowAdvisor)
    out_late = tmp_path / "paced_late.json"
    rc_late = bench.main([
        "--runtime-config", str(cfg_path),
        "--interval-seconds", "0.02",
        "--repetitions", "4",
        "--output", str(out_late),
    ])
    assert rc_late == 0
    rep_late = json.loads(out_late.read_text(encoding="utf-8"))
    assert rep_late["scheduled_starts"] == 4
    assert rep_late["actual_starts"] == 4
    assert rep_late["late_starts"] == 3
    assert rep_late["samples"][0]["is_late_start"] is False
    assert all(row["is_late_start"] is True for row in rep_late["samples"][1:])
    assert rep_late["samples"][3]["arrival_to_completion_ms"] > rep_late["samples"][3]["total_ms"]
    assert rep_late["start_delay_ms"]["max"] > 50.0


def test_benchmarking_deterministic_holdout_fixtures(tmp_path):
    import json
    from edgeshield.benchmarking import load_fixtures, main as bench_main

    h30, _ = load_fixtures("holdout30")
    assert len(h30) == 30
    assert [fid for fid, _ in h30[:4]] == ["v2h001", "v2h031", "v2h002", "v2h032"]
    assert [fid for fid, _ in h30[-2:]] == ["v2h015", "v2h045"]

    h132, _ = load_fixtures("holdout132")
    assert len(h132) == 132
    assert [fid for fid, _ in h132] == [f"v2h{i:03d}" for i in range(1, 133)]

    out = tmp_path / "holdout.json"
    rc = bench_main([
        "--fixtures", "holdout30",
        "--repetitions", "4",
        "--advisory-policy", "off",
        "--run-id", "h30-check",
        "--output", str(out),
    ])
    assert rc == 0
    rep = json.loads(out.read_text(encoding="utf-8"))
    assert rep["fixture_set"] == "holdout30"
    assert rep["fixture_ids"] == ["v2h001", "v2h031", "v2h002", "v2h032"]
