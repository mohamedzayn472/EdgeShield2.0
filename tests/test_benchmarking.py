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
    assert report["hardware_verified_pi4"] is False
    assert report["hardware_verified_pi5"] is False
    for key in ("runner_child_peak_rss_bytes", "min_mem_available_bytes", "max_swap_used_bytes", "temperature_c", "throttled_before", "throttled_after"):
        assert key in report
