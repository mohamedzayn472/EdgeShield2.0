"""Compare EdgeShield Pi 5 thermal trials, check comparability, and evaluate §4 criteria."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re
import statistics
import sys
from typing import Any

CURRENT_BITS = {
    0: "under_voltage",
    1: "arm_freq_capped",
    2: "throttled",
    3: "soft_temp_limit",
}

STICKY_BITS = {
    16: "under_voltage",
    17: "arm_freq_capped",
    18: "throttled",
    19: "soft_temp_limit",
}

_TEMP_RE = re.compile(r"temp=([+-]?\d+(?:\.\d+)?)")
_MILLIC_RE = re.compile(r"thermal_zone0_millic=(\d+)")
_THROTTLED_RE = re.compile(r"throttled=(0x[0-9a-fA-F]+|[0-9a-fA-F]+)")
_KV_RE = re.compile(r"^(COOLING_NOTE|AMBIENT_C|GIT_COMMIT)=(.*)$")


def decode_throttled(raw: str | int | None) -> dict[str, Any]:
    """Decode Raspberry Pi vcgencmd get_throttled current (0-3) and sticky (16-19) bits."""
    empty = {
        "raw": raw,
        "value": None,
        "hex": None,
        "current_mask": None,
        "sticky_mask": None,
        "current": {},
        "sticky": {},
    }
    if raw is None:
        return empty
    value: int | None = None
    if isinstance(raw, int) and not isinstance(raw, bool):
        value = raw
    elif isinstance(raw, str):
        text = raw.strip()
        if "=" in text:
            _, _, text = text.partition("=")
        text = text.strip()
        if text:
            try:
                value = int(text, 16)
            except ValueError:
                return empty
    if value is None or value < 0:
        return empty
    return {
        "raw": raw if isinstance(raw, str) else hex(value),
        "value": value,
        "hex": hex(value),
        "current_mask": value & 0xF,
        "sticky_mask": (value >> 16) & 0xF,
        "current": {name: bool(value & (1 << bit)) for bit, name in CURRENT_BITS.items()},
        "sticky": {name: bool(value & (1 << bit)) for bit, name in STICKY_BITS.items()},
    }


def _dist(values: list[float | int | None]) -> dict[str, Any] | None:
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    return {
        "n": len(vals),
        "min": vals[0],
        "median": statistics.median(vals),
        "mean": statistics.fmean(vals),
        "p95": vals[math.ceil(0.95 * len(vals)) - 1],
        "max": vals[-1],
    }


def _read_json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    return rows


def _parse_sys_txt(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {
        "timestamp_utc": None,
        "temp_c": None,
        "throttled_raw": None,
        "cooling_note": None,
        "ambient_c": None,
        "git_commit": None,
    }
    if not path.is_file():
        return info
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if lines:
        info["timestamp_utc"] = lines[0].strip() or None
    for line in lines:
        m_temp = _TEMP_RE.search(line)
        if m_temp:
            info["temp_c"] = float(m_temp.group(1))
        elif info["temp_c"] is None:
            m_mc = _MILLIC_RE.search(line)
            if m_mc:
                info["temp_c"] = float(m_mc.group(1)) / 1000.0
        m_th = _THROTTLED_RE.search(line)
        if m_th:
            info["throttled_raw"] = f"throttled={m_th.group(1)}"
        m_kv = _KV_RE.match(line.strip())
        if m_kv:
            k, v = m_kv.group(1), m_kv.group(2).strip()
            if v and v != "unknown":
                info[k.lower()] = v
    return info


def _parse_process_resources(path: Path) -> dict[str, Any]:
    out: dict[str, Any] = {"cpu_seconds": None, "max_rss_bytes": None, "swaps": None}
    if not path.is_file():
        return out
    user_s = None
    sys_s = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if s.startswith("User time (seconds):"):
            try:
                user_s = float(s.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif s.startswith("System time (seconds):"):
            try:
                sys_s = float(s.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif s.startswith("Maximum resident set size (kbytes):"):
            try:
                out["max_rss_bytes"] = int(s.split(":", 1)[1].strip()) * 1024
            except ValueError:
                pass
        elif s.startswith("Swaps:"):
            try:
                out["swaps"] = int(s.split(":", 1)[1].strip())
            except ValueError:
                pass
    if user_s is not None and sys_s is not None:
        out["cpu_seconds"] = user_s + sys_s
    return out


def _sample_decode_ms(sample: dict[str, Any]) -> float | None:
    if sample.get("decode_ms") is not None:
        return sample["decode_ms"]
    stats = sample.get("runner_stats")
    if isinstance(stats, dict) and stats.get("SCALING_FACTOR_UNITS_PER_SECOND") == 1000:
        a, b = stats.get("prompt_eval_end_ms"), stats.get("inference_end_ms")
        if type(a) in (int, float) and type(b) in (int, float) and 0 < a <= b:
            return b - a
    return None


def _sample_outside_runner_ms(sample: dict[str, Any]) -> float | None:
    stats = sample.get("runner_stats")
    llama_ms = sample.get("llama_ms")
    if (
        isinstance(stats, dict)
        and stats.get("SCALING_FACTOR_UNITS_PER_SECOND") == 1000
        and type(llama_ms) in (int, float)
    ):
        a, b = stats.get("model_load_start_ms"), stats.get("inference_end_ms")
        if type(a) in (int, float) and type(b) in (int, float) and 0 < a <= b:
            return llama_ms - (b - a)
    return None


def _extract_artifact_hashes(bench: dict[str, Any] | None, manifest: dict[str, Any] | None) -> dict[str, Any] | None:
    if isinstance(bench, dict) and isinstance(bench.get("effective_settings"), dict):
        hashes = bench["effective_settings"].get("artifacts_sha256")
        if isinstance(hashes, dict):
            return hashes
    if isinstance(manifest, dict) and isinstance(manifest.get("artifacts"), dict):
        art = manifest["artifacts"]
        return {
            "runner": art.get("runner", {}).get("sha256") if isinstance(art.get("runner"), dict) else None,
            "model": art.get("model", {}).get("sha256") if isinstance(art.get("model"), dict) else None,
            "tokenizer": art.get("tokenizer", {}).get("sha256") if isinstance(art.get("tokenizer"), dict) else None,
            "shared_libraries": [
                item.get("sha256")
                for item in art.get("shared_libraries", [])
                if isinstance(item, dict)
            ] if isinstance(art.get("shared_libraries"), list) else [],
        }
    return None


def _reconstruct_sample_timeline(bench: dict[str, Any], samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sleep_gap_s = 0.01 if (bench.get("requested_duration_seconds") or 0) > 0 and (bench.get("offered_interval_seconds") or 0) == 0 else 0.0
    cum_s = 0.0
    timeline: list[dict[str, Any]] = []
    for idx, s in enumerate(samples):
        total_s = (s.get("total_ms") or 0.0) / 1000.0
        if s.get("completion_offset_s") is not None:
            start_s = s.get("offset_s", cum_s)
            end_s = s["completion_offset_s"]
        else:
            start_s = s.get("offset_s") if s.get("offset_s") is not None else cum_s
            end_s = start_s + total_s
            cum_s = end_s + sleep_gap_s
        timeline.append(
            {
                "index": idx,
                "start_s": start_s,
                "end_s": end_s,
                "temperature_c": s.get("temperature_c"),
                "total_ms": s.get("total_ms"),
                "source": s.get("source"),
                "reason": s.get("reason"),
                "arrival_to_completion_ms": s.get("arrival_to_completion_ms"),
            }
        )
    return timeline


def load_trial(path: Path, sustain_c: float, abort_c: float) -> dict[str, Any]:
    """Load either an instrumented trial directory or a legacy B0 directory / benchmark.json."""
    if path.is_file():
        trial_dir = path.parent
        bench_path = path
    else:
        trial_dir = path
        bench_path = trial_dir / "benchmark.json"

    bench = _read_json(bench_path)
    trial_meta = _read_json(trial_dir / "trial.json")
    thermal_summary = _read_json(trial_dir / "thermal-summary.json")
    thermal_trace = _read_jsonl(trial_dir / "thermal.jsonl")
    stop_data = _read_json(trial_dir / "stop.json")
    manifest = _read_json(trial_dir / "manifest.json")
    wait_data = _read_json(trial_dir / "wait.json")
    sys_before = _parse_sys_txt(trial_dir / "system-before.txt")
    sys_after = _parse_sys_txt(trial_dir / "system-after.txt")
    proc_res = _parse_process_resources(trial_dir / "process-resources.txt")

    cleanup_path = trial_dir / "cleanup.txt"
    cleanup_leftovers: list[str] = []
    if cleanup_path.is_file():
        cleanup_leftovers = [
            line for line in cleanup_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()
        ]

    if bench is None and trial_meta is None:
        raise FileNotFoundError(f"No benchmark.json or trial.json found at {path}")

    bench = bench if isinstance(bench, dict) else {}
    samples: list[dict[str, Any]] = bench.get("samples", []) if isinstance(bench.get("samples"), list) else []
    timeline = _reconstruct_sample_timeline(bench, samples)

    is_instrumented = isinstance(thermal_summary, dict)
    resolution = "1HZ-TRACE" if is_instrumented else "LOW-RESOLUTION"
    resolution_note = (
        "1 Hz thermal_monitor trace"
        if is_instrumented
        else "Legacy format: per-request post-completion sysfs temps only (no 1 Hz trace)"
    )

    run_id = (
        (trial_meta.get("run_id") if isinstance(trial_meta, dict) else None)
        or bench.get("run_id")
        or trial_dir.name
    )

    reps = bench.get("repetitions", len(samples))
    duration_s = bench.get("duration_seconds")
    validated_count = bench.get("llama_validated_count", sum(1 for s in samples if s.get("source") == "Llama (validated)"))
    validated_per_min = bench.get("validated_per_minute")
    if validated_per_min is None and duration_s and duration_s > 0:
        validated_per_min = validated_count / (duration_s / 60.0)

    reason_counts = bench.get("reason_counts")
    if not isinstance(reason_counts, dict):
        counts: dict[str, int] = {}
        for s in samples:
            r = s.get("reason")
            if r is not None:
                counts[r] = counts.get(r, 0) + 1
        reason_counts = dict(sorted(counts.items()))

    # Thermal fields
    if is_instrumented:
        start_temp_c = thermal_summary.get("start_temp_c")
        peak_temp_c = thermal_summary.get("peak_temp_c")
        mean_temp_c = thermal_summary.get("mean_temp_c")
        p95_temp_c = thermal_summary.get("p95_temp_c")
        end_temp_c = thermal_summary.get("end_temp_c")
        time_to_sustain_s = thermal_summary.get("time_to_sustain_s")
        time_to_abort_s = thermal_summary.get("time_to_abort_s")
        first_req_at_sustain = next(
            (i + 1 for i, s in enumerate(samples) if s.get("temperature_c") is not None and s["temperature_c"] >= sustain_c),
            None,
        )
        first_req_at_abort = next(
            (i + 1 for i, s in enumerate(samples) if s.get("temperature_c") is not None and s["temperature_c"] >= abort_c),
            None,
        )
        seconds_above_sustain = thermal_summary.get("seconds_above_sustain")
        seconds_above_abort = thermal_summary.get("seconds_above_abort")
        coverage = thermal_summary.get("coverage")
        max_gap_s = thermal_summary.get("max_gap_s")
        current_bits_seen = thermal_summary.get("current_bits_seen", [])
        sticky_at_start = thermal_summary.get("sticky_at_start")
        sticky_at_end = thermal_summary.get("sticky_at_end")
        throttled_raw_start = thermal_summary.get("throttled_raw_start") or bench.get("throttled_before")
        throttled_raw_end = thermal_summary.get("throttled_raw_end") or bench.get("throttled_after")
        last_120s_slope = thermal_summary.get("last_120s_slope_c_per_min")
        rising_at_end = thermal_summary.get("rising_at_end")
        fan_rpm_min = thermal_summary.get("fan_rpm_min")
        fan_rpm_max = thermal_summary.get("fan_rpm_max")
        arm_hz_min = thermal_summary.get("arm_hz_min")
        arm_hz_median = thermal_summary.get("arm_hz_median")
        arm_hz_max = thermal_summary.get("arm_hz_max")
        ext5v_v_min = thermal_summary.get("ext5v_v_min")
        ext5v_v_max = thermal_summary.get("ext5v_v_max")
    else:
        temp_dist = bench.get("temperature_c") if isinstance(bench.get("temperature_c"), dict) else _dist([s.get("temperature_c") for s in samples])
        sample_temps = [s.get("temperature_c") for s in samples if s.get("temperature_c") is not None]
        start_temp_c = sys_before.get("temp_c") if sys_before.get("temp_c") is not None else (sample_temps[0] if sample_temps else None)
        peak_temp_c = temp_dist.get("max") if temp_dist else None
        mean_temp_c = statistics.fmean(sample_temps) if sample_temps else None
        p95_temp_c = temp_dist.get("p95") if temp_dist else None
        end_temp_c = sys_after.get("temp_c") if sys_after.get("temp_c") is not None else (sample_temps[-1] if sample_temps else None)

        time_to_sustain_s = None
        first_req_at_sustain = None
        time_to_abort_s = None
        first_req_at_abort = None
        for row, t_item in zip(samples, timeline):
            tc = row.get("temperature_c")
            if tc is None:
                continue
            if time_to_sustain_s is None and tc >= sustain_c:
                time_to_sustain_s = t_item["end_s"]
                first_req_at_sustain = t_item["index"] + 1
            if time_to_abort_s is None and tc >= abort_c:
                time_to_abort_s = t_item["end_s"]
                first_req_at_abort = t_item["index"] + 1

        seconds_above_sustain = None
        seconds_above_abort = None
        coverage = None
        max_gap_s = None
        throttled_raw_start = bench.get("throttled_before") or sys_before.get("throttled_raw")
        throttled_raw_end = bench.get("throttled_after") or sys_after.get("throttled_raw")
        th_start = decode_throttled(throttled_raw_start)
        th_end = decode_throttled(throttled_raw_end)
        sticky_at_start = th_start["sticky"] if th_start["value"] is not None else None
        sticky_at_end = th_end["sticky"] if th_end["value"] is not None else None
        current_bits_seen = sorted(
            {
                name
                for th in (th_start, th_end)
                if th["value"] is not None
                for name, active in th["current"].items()
                if active
            }
        )
        last_120s_slope = None
        rising_at_end = None
        fan_rpm_min = None
        fan_rpm_max = None
        arm_hz_min = None
        arm_hz_median = None
        arm_hz_max = None
        ext5v_v_min = None
        ext5v_v_max = None

    mem_candidates = [bench.get("min_mem_available_bytes")]
    if is_instrumented:
        mem_candidates.append(thermal_summary.get("min_mem_available_bytes"))
    mem_vals = [m for m in mem_candidates if m is not None]
    min_mem_avail = min(mem_vals) if mem_vals else None

    swap_vals = [v for v in (bench.get("max_swap_used_bytes"), proc_res.get("swaps")) if v is not None]
    max_swap_used = max(swap_vals) if swap_vals else None

    total_dist = (bench.get("timings_ms") or {}).get("total_ms")
    llama_dist = (bench.get("timings_ms") or {}).get("llama_ms")
    decode_dist = bench.get("decode_ms") or _dist([_sample_decode_ms(s) for s in samples])
    overhead_dist = bench.get("runner_overhead_ms") or _dist([_sample_outside_runner_ms(s) for s in samples])
    det_ev_dist = _dist(
        [
            s["detector_ms"] + s["evidence_ms"]
            for s in samples
            if s.get("detector_ms") is not None and s.get("evidence_ms") is not None
        ]
    )

    fixture_set = bench.get("fixture_set")
    if fixture_set is None and str(bench.get("fixtures", "")).startswith("five fixed"):
        fixture_set = "smoke"
    fixture_ids = bench.get("fixture_ids")
    if fixture_ids is None and fixture_set == "smoke" and samples:
        fixture_ids = [f"smoke_{i % 5}" for i in range(len(samples))]

    completed = bench.get("completed")
    if completed is None:
        completed = not bool(stop_data) and reps > 0
    stop_reason = bench.get("stop_reason") or (stop_data.get("reason") if isinstance(stop_data, dict) else None)

    cpu_threads = None
    if isinstance(bench.get("effective_settings"), dict):
        cpu_threads = bench["effective_settings"].get("cpu_threads")
    elif isinstance(manifest, dict):
        cpu_threads = manifest.get("cpu_threads")

    cooling_note = (
        (trial_meta.get("cooling_note") if isinstance(trial_meta, dict) else None)
        or sys_before.get("cooling_note")
    )
    if cooling_note == "unknown":
        cooling_note = None
    ambient_c = (
        (trial_meta.get("ambient_c") if isinstance(trial_meta, dict) else None)
        or sys_before.get("ambient_c")
    )
    if ambient_c == "unknown":
        ambient_c = None

    offered_interval = bench.get("offered_interval_seconds", 0.0)
    planned_scheduled_starts = bench.get("planned_scheduled_starts")
    scheduled_starts = bench.get("scheduled_starts")
    actual_starts = bench.get("actual_starts")
    late_starts = bench.get("late_starts", 0)
    start_delay_dist = bench.get("start_delay_ms")
    arrival_to_completion_dist = bench.get("arrival_to_completion_ms")

    return {
        "run_id": run_id,
        "path": str(path),
        "trial_dir": str(trial_dir),
        "resolution": resolution,
        "resolution_note": resolution_note,
        "git_commit": (trial_meta.get("git_commit") if isinstance(trial_meta, dict) else None) or bench.get("git_commit") or sys_before.get("git_commit"),
        "cooling_note": cooling_note,
        "ambient_c": ambient_c,
        "start_below_c": (trial_meta.get("parameters", {}).get("start_below_c") if isinstance(trial_meta, dict) and isinstance(trial_meta.get("parameters"), dict) else None),
        "wait_status": wait_data.get("status") if isinstance(wait_data, dict) else None,
        "runtime_config_sha256": bench.get("runtime_config_sha256"),
        "manifest_sha256": trial_meta.get("manifest_sha256") if isinstance(trial_meta, dict) else None,
        "artifact_hashes": _extract_artifact_hashes(bench, manifest),
        "cpu_threads": cpu_threads,
        "advisory_policy": bench.get("advisory_policy"),
        "runtime_configured": bench.get("runtime_configured"),
        "fixture_set": fixture_set,
        "fixture_ids": fixture_ids,
        "repetitions": reps,
        "duration_seconds": duration_s,
        "completed": completed,
        "stop_reason": stop_reason,
        "cleanup_leftovers": cleanup_leftovers,
        "llama_attempted_count": bench.get("llama_attempted_count"),
        "skipped_by_policy_count": bench.get("skipped_by_policy_count"),
        "llama_validated_count": validated_count,
        "validated_per_minute": validated_per_min,
        "reason_counts": reason_counts,
        "offered_interval_seconds": offered_interval,
        "planned_scheduled_starts": planned_scheduled_starts,
        "scheduled_starts": scheduled_starts,
        "actual_starts": actual_starts,
        "late_starts": late_starts,
        "start_delay_ms": start_delay_dist,
        "arrival_to_completion_ms": arrival_to_completion_dist,
        "total_ms": total_dist,
        "llama_ms": llama_dist,
        "detector_plus_evidence_ms": det_ev_dist,
        "integrity_ms": bench.get("integrity_ms"),
        "runner_wall_ms": bench.get("runner_wall_ms"),
        "model_load_ms": bench.get("model_load_ms"),
        "prefill_ms": bench.get("prefill_ms"),
        "decode_ms": decode_dist,
        "runner_overhead_ms": overhead_dist,
        "child_cpu_s": bench.get("child_cpu_s"),
        "child_cpu_total_s": proc_res.get("cpu_seconds"),
        "runner_child_peak_rss_bytes": bench.get("runner_child_peak_rss_bytes") or proc_res.get("max_rss_bytes"),
        "min_mem_available_bytes": min_mem_avail,
        "max_swap_used_bytes": max_swap_used,
        "start_temp_c": start_temp_c,
        "peak_temp_c": peak_temp_c,
        "mean_temp_c": mean_temp_c,
        "p95_temp_c": p95_temp_c,
        "end_temp_c": end_temp_c,
        "time_to_sustain_s": time_to_sustain_s,
        "first_req_at_sustain": first_req_at_sustain,
        "time_to_abort_s": time_to_abort_s,
        "first_req_at_abort": first_req_at_abort,
        "seconds_above_sustain": seconds_above_sustain,
        "seconds_above_abort": seconds_above_abort,
        "coverage": coverage,
        "max_gap_s": max_gap_s,
        "current_bits_seen": current_bits_seen,
        "sticky_at_start": sticky_at_start,
        "sticky_at_end": sticky_at_end,
        "throttled_raw_start": throttled_raw_start,
        "throttled_raw_end": throttled_raw_end,
        "last_120s_slope_c_per_min": last_120s_slope,
        "rising_at_end": rising_at_end,
        "fan_rpm_min": fan_rpm_min,
        "fan_rpm_max": fan_rpm_max,
        "arm_hz_min": arm_hz_min,
        "arm_hz_median": arm_hz_median,
        "arm_hz_max": arm_hz_max,
        "ext5v_v_min": ext5v_v_min,
        "ext5v_v_max": ext5v_v_max,
        "_samples": samples,
        "_timeline": timeline,
        "_thermal_trace": thermal_trace,
    }


def check_comparability(trials: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare provenance and setup invariants across trials."""
    if len(trials) <= 1:
        return {"comparable": True, "checks": {}, "warnings": []}

    checks: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []

    # 1. Artifact hashes
    art_vals = {t["run_id"]: t["artifact_hashes"] for t in trials}
    present_art = [v for v in art_vals.values() if v is not None]
    if not present_art:
        status = "PARTIAL_MISSING"
        warn = "Artifact SHA-256 hashes missing across all trials."
    elif len(present_art) < len(trials):
        all_same_present = all(v == present_art[0] for v in present_art)
        status = "PARTIAL_MISSING" if all_same_present else "MISMATCH"
        warn = (
            "Artifact hashes missing on legacy/uninstrumented trial(s); verify manually."
            if all_same_present
            else "Artifact SHA-256 hashes differ across trials."
        )
    elif all(v == present_art[0] for v in present_art):
        status = "MATCH"
        warn = None
    else:
        status = "MISMATCH"
        warn = "Artifact SHA-256 hashes differ across trials."
    if warn:
        warnings.append(warn)
    checks["artifact_hashes"] = {"status": status, "warning": warn}

    # 2. Fixtures and order
    fsets = {t["run_id"]: t["fixture_set"] for t in trials}
    fids = {t["run_id"]: t["fixture_ids"] for t in trials if t["fixture_ids"]}
    non_null_sets = {v for v in fsets.values() if v is not None}
    order_ok = True
    if len(fids) >= 2:
        min_len = min(len(v) for v in fids.values())
        if min_len > 0:
            prefixes = {tuple(v[:min_len]) for v in fids.values()}
            if len(prefixes) > 1:
                order_ok = False
    if len(non_null_sets) > 1 or not order_ok:
        f_status = "MISMATCH"
        f_warn = "Fixture set or fixture ordering differs across trials."
    elif len(non_null_sets) == 0 or len(fids) < len(trials):
        f_status = "PARTIAL_MISSING"
        f_warn = "Fixture metadata missing on one or more trials."
    else:
        f_status = "MATCH"
        f_warn = None
    if f_warn:
        warnings.append(f_warn)
    checks["fixtures_and_order"] = {"status": f_status, "values": fsets, "warning": f_warn}

    # 3. Start gate (+/- 1.0 C)
    gates = {t["run_id"]: t["start_below_c"] for t in trials}
    present_gates = [v for v in gates.values() if v is not None]
    if len(present_gates) == len(trials):
        spread = max(present_gates) - min(present_gates)
        if spread <= 1.0 + 1e-9:
            g_status, g_warn = "MATCH", None
        else:
            g_status, g_warn = "MISMATCH", f"Start gate spread is {spread:.2f} C (> 1.0 C)."
    elif len(present_gates) == 0:
        g_status, g_warn = "PARTIAL_MISSING", "Start gate not recorded on trials."
    else:
        spread = max(present_gates) - min(present_gates)
        g_status = "MISMATCH" if spread > 1.0 + 1e-9 else "PARTIAL_MISSING"
        g_warn = "Start gate missing on one or more trials (e.g. legacy B0)."
    if g_warn:
        warnings.append(g_warn)
    checks["start_gate_c"] = {"status": g_status, "values": gates, "warning": g_warn}

    # 4. Cooling note
    cooling = {t["run_id"]: t["cooling_note"] for t in trials}
    present_cooling = [v for v in cooling.values() if v is not None]
    if not present_cooling or len(present_cooling) < len(trials):
        c_status = "MISMATCH" if len(set(present_cooling)) > 1 else "PARTIAL_MISSING"
        c_warn = "COOLING_NOTE differs." if c_status == "MISMATCH" else "COOLING_NOTE missing on one or more trials."
    elif len(set(present_cooling)) > 1:
        c_status, c_warn = "MISMATCH", f"COOLING_NOTE differs across trials: {sorted(set(present_cooling))}."
    else:
        c_status, c_warn = "MATCH", None
    if c_warn:
        warnings.append(c_warn)
    checks["cooling_note"] = {"status": c_status, "values": cooling, "warning": c_warn}

    # 5. Git commit
    commits = {t["run_id"]: t["git_commit"] for t in trials}
    present_commits = [v for v in commits.values() if v is not None]
    if not present_commits or len(present_commits) < len(trials):
        cm_status = "MISMATCH" if len(set(present_commits)) > 1 else "PARTIAL_MISSING"
        cm_warn = "Git commit differs across trials." if cm_status == "MISMATCH" else "Git commit missing on one or more trials."
    elif len(set(present_commits)) > 1:
        cm_status, cm_warn = "MISMATCH", "Git commit differs across trials."
    else:
        cm_status, cm_warn = "MATCH", None
    if cm_warn:
        warnings.append(cm_warn)
    checks["git_commit"] = {"status": cm_status, "values": commits, "warning": cm_warn}

    # 6. Offered interval
    intervals = {t["run_id"]: t["offered_interval_seconds"] for t in trials}
    if len(set(intervals.values())) == 1:
        i_status, i_warn = "MATCH", None
    else:
        i_status, i_warn = "MISMATCH", f"Offered interval differs across trials: {intervals}."
        warnings.append(i_warn)
    checks["offered_interval_seconds"] = {"status": i_status, "values": intervals, "warning": i_warn}

    comparable = all(item["status"] == "MATCH" for item in checks.values())
    return {"comparable": comparable, "checks": checks, "warnings": warnings}


def compute_matched_metrics(trials: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute matched-request N and matched-duration metrics across trials."""
    active = [t for t in trials if t["repetitions"] > 0 and t["duration_seconds"]]
    if not active:
        return {"matched_requests_n": None, "matched_duration_s": None, "per_trial": {}}

    matched_n = min(t["repetitions"] for t in active)
    matched_dur = min(t["duration_seconds"] for t in active)
    per_trial: dict[str, dict[str, Any]] = {}

    for t in trials:
        if t["repetitions"] == 0 or not t["duration_seconds"]:
            per_trial[t["run_id"]] = {}
            continue
        timeline = t["_timeline"]
        samples = t["_samples"]
        trace = t["_thermal_trace"]

        first_n_t = timeline[:matched_n]
        first_n_s = samples[:matched_n]
        n_end_s = first_n_t[-1]["end_s"] if first_n_t else 0.0
        n_validated = sum(1 for s in first_n_s if s.get("source") == "Llama (validated)")
        n_total_dist = _dist([s.get("total_ms") for s in first_n_s])

        if trace:
            trace_n = [p for p in trace if p.get("offset_s", 0.0) <= n_end_s + 1e-9 and p.get("temperature_c") is not None]
            temps_n = [p["temperature_c"] for p in trace_n]
            temp_at_n = temps_n[-1] if temps_n else first_n_s[-1].get("temperature_c")
        else:
            temps_n = [s["temperature_c"] for s in first_n_s if s.get("temperature_c") is not None]
            temp_at_n = first_n_s[-1].get("temperature_c") if first_n_s else None

        dur_items = [item for item in timeline if item["end_s"] <= matched_dur + 1e-9]
        dur_reqs = len(dur_items)
        dur_validated = sum(1 for item in dur_items if item.get("source") == "Llama (validated)")
        if trace:
            temps_dur = [
                p["temperature_c"]
                for p in trace
                if p.get("offset_s", 0.0) <= matched_dur + 1e-9 and p.get("temperature_c") is not None
            ]
        else:
            temps_dur = [item["temperature_c"] for item in dur_items if item.get("temperature_c") is not None]

        per_trial[t["run_id"]] = {
            "temp_at_matched_n_c": temp_at_n,
            "matched_n_peak_temp_c": max(temps_n) if temps_n else None,
            "matched_n_mean_temp_c": statistics.fmean(temps_n) if temps_n else None,
            "matched_n_elapsed_s": n_end_s,
            "matched_n_validated_count": n_validated,
            "matched_n_validated_per_min": (n_validated / (n_end_s / 60.0)) if n_end_s > 0 else None,
            "matched_n_p50_total_ms": n_total_dist["median"] if n_total_dist else None,
            "matched_n_p95_total_ms": n_total_dist["p95"] if n_total_dist else None,
            "matched_duration_requests": dur_reqs,
            "matched_duration_validated_count": dur_validated,
            "matched_duration_validated_per_min": (dur_validated / (matched_dur / 60.0)) if matched_dur > 0 else None,
            "matched_duration_peak_temp_c": max(temps_dur) if temps_dur else None,
            "matched_duration_mean_temp_c": statistics.fmean(temps_dur) if temps_dur else None,
        }

    return {
        "matched_requests_n": matched_n,
        "matched_duration_s": matched_dur,
        "per_trial": per_trial,
    }


def evaluate_verdict(
    trial: dict[str, Any],
    paced_p95_budget_s: float,
    saturated_min_vpm: float,
    sustain_c: float,
    abort_c: float,
) -> dict[str, Any]:
    """Evaluate plan §4 pass criteria for a trial."""
    checks: dict[str, bool | None] = {}
    is_low_res = trial["resolution"] == "LOW-RESOLUTION"

    checks["trace_coverage_ge_95"] = (trial["coverage"] is not None and trial["coverage"] >= 0.95) if not is_low_res else False
    checks["trace_max_gap_le_3s"] = (trial["max_gap_s"] is not None and trial["max_gap_s"] <= 3.0) if not is_low_res else False
    checks["no_current_throttle_bits"] = len(trial["current_bits_seen"]) == 0
    sticky_start = trial["sticky_at_start"]
    checks["sticky_bits_clear_at_start"] = (
        isinstance(sticky_start, dict) and bool(sticky_start) and all(not v for v in sticky_start.values())
    )
    checks["sticky_bits_reported_at_end"] = isinstance(trial["sticky_at_end"], dict) and bool(trial["sticky_at_end"])

    checks["thermal_p95_le_sustain"] = trial["p95_temp_c"] is not None and trial["p95_temp_c"] <= sustain_c
    checks["thermal_peak_lt_abort"] = trial["peak_temp_c"] is not None and trial["peak_temp_c"] < abort_c
    if trial["rising_at_end"] is True:
        checks["thermal_not_rising_at_end"] = False
    elif trial["rising_at_end"] is False:
        checks["thermal_not_rising_at_end"] = True
    elif not is_low_res and (trial["duration_seconds"] or 0) < 120:
        checks["thermal_not_rising_at_end"] = True
    else:
        checks["thermal_not_rising_at_end"] = False

    rc = trial["reason_counts"]
    checks["correctness_zero_runner_errors"] = (
        rc.get("RUNTIME_ERROR", 0) + rc.get("RUNNER_TIMEOUT", 0) + rc.get("RUNNER_TOKEN_LIMIT", 0)
    ) == 0

    if trial["fixture_set"] == "smoke" and trial["repetitions"] >= 5 and trial["advisory_policy"] == "always":
        first5 = trial["_samples"][:5]
        checks["correctness_smoke_5_of_5"] = len(first5) == 5 and all(
            s.get("source") == "Llama (validated)" for s in first5
        )
    else:
        checks["correctness_smoke_5_of_5"] = True

    checks["resources_zero_swap"] = trial["max_swap_used_bytes"] == 0
    checks["resources_mem_avail_ge_2gib"] = (
        trial["min_mem_available_bytes"] is not None and trial["min_mem_available_bytes"] >= 2 * (1024**3)
    )
    checks["completed"] = trial["completed"] is True
    checks["cleanup_no_leftovers"] = len(trial["cleanup_leftovers"]) == 0

    offered_interval = trial["offered_interval_seconds"] or 0.0
    if offered_interval > 0:
        arr_p95 = (
            trial["arrival_to_completion_ms"]["p95"]
            if isinstance(trial.get("arrival_to_completion_ms"), dict)
            else (trial["total_ms"]["p95"] if isinstance(trial.get("total_ms"), dict) else None)
        )
        checks["budget_paced_arrival_p95_ok"] = arr_p95 is not None and arr_p95 <= paced_p95_budget_s * 1000.0
        checks["budget_paced_no_late_starts"] = (trial["late_starts"] or 0) == 0
        sched = trial["scheduled_starts"]
        actual = trial["actual_starts"]
        checks["budget_paced_full_completion"] = (
            sched is not None and actual == sched and trial["repetitions"] == sched
        )
    else:
        vpm = trial["validated_per_minute"]
        checks["budget_saturated_vpm_ok"] = vpm is not None and vpm >= saturated_min_vpm

    failed = [name for name, ok in checks.items() if ok is not True]
    if is_low_res:
        verdict = "REFERENCE_LOW_RES"
    elif not failed:
        verdict = "PASS"
    else:
        verdict = "FAIL"
    return {"verdict": verdict, "failed_checks": failed, "checks": checks}


def _fmt(val: Any, digits: int = 2, suffix: str = "") -> str:
    if val is None:
        return "-"
    if isinstance(val, bool):
        return "yes" if val else "no"
    if isinstance(val, int):
        return f"{val}{suffix}"
    if isinstance(val, float):
        return f"{val:.{digits}f}{suffix}"
    return str(val)


def _format_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = ["# Pi 5 Thermal Trial Comparison", ""]
    comp = report["comparability"]
    lines.append(f"**Comparable:** {'YES' if comp['comparable'] else 'NO / PARTIAL'}  ")
    if comp["warnings"]:
        lines.append("**Warnings:** " + " | ".join(comp["warnings"]))
    lines.append("")

    if comp["checks"]:
        lines.extend(["## Comparability Checks", "", "| Check | Status | Details |", "|---|---|---|"])
        for k, v in comp["checks"].items():
            detail = v.get("warning") or "OK"
            lines.append(f"| `{k}` | {v['status']} | {detail} |")
        lines.append("")

    trials = report["trials"]
    lines.extend([
        "## Trial Summary & §4 Verdicts",
        "",
        "| Run ID | Resolution | Threads | Interval (s) | Reps | Completed / Stop | Peak °C | p95 °C | Time 75/78 °C (s) | E2E p50 / p95 (ms) | Val/min | Verdict |",
        "|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---|",
    ])
    for t in trials:
        v = t["verdict"]
        total = t["total_ms"] or {}
        t75 = _fmt(t["time_to_sustain_s"], 1)
        t78 = _fmt(t["time_to_abort_s"], 1)
        comp_str = "yes" if t["completed"] else f"no ({t['stop_reason'] or 'STOPPED'})"
        e2e = f"{_fmt(total.get('median'), 1)} / {_fmt(total.get('p95'), 1)}"
        lines.append(
            f"| `{t['run_id']}` | {t['resolution']} | {_fmt(t['cpu_threads'])} | "
            f"{_fmt(t['offered_interval_seconds'], 1)} | {t['repetitions']} | {comp_str} | "
            f"{_fmt(t['peak_temp_c'], 1)} | {_fmt(t['p95_temp_c'], 1)} | {t75} / {t78} | "
            f"{e2e} | {_fmt(t['validated_per_minute'], 2)} | **{v['verdict']}** |"
        )
    lines.append("")

    paced_trials = [t for t in trials if (t["offered_interval_seconds"] or 0.0) > 0]
    if paced_trials:
        lines.extend([
            "## Paced Arrival-to-Completion Metrics",
            "",
            "| Run ID | Interval (s) | Scheduled | Actual | Late | Start Delay p50/p95 (ms) | Arrival->Completion p50/p95/max (ms) | Detector+Ev p95 (ms) |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ])
        for t in paced_trials:
            sd = t["start_delay_ms"] or {}
            ac = t["arrival_to_completion_ms"] or {}
            de = t["detector_plus_evidence_ms"] or {}
            lines.append(
                f"| `{t['run_id']}` | {_fmt(t['offered_interval_seconds'], 2)} | "
                f"{_fmt(t['scheduled_starts'])} | {_fmt(t['actual_starts'])} | {_fmt(t['late_starts'])} | "
                f"{_fmt(sd.get('median'), 1)} / {_fmt(sd.get('p95'), 1)} | "
                f"{_fmt(ac.get('median'), 1)} / {_fmt(ac.get('p95'), 1)} / {_fmt(ac.get('max'), 1)} | "
                f"{_fmt(de.get('p95'), 2)} |"
            )
        lines.append("")

    matched = report["matched_interval"]
    if matched["matched_requests_n"] is not None:
        lines.extend([
            f"## Matched-Interval Comparison (N = {matched['matched_requests_n']} reqs, T = {matched['matched_duration_s']:.1f} s)",
            "",
            "| Run ID | Temp@N (°C) | Peak@N (°C) | Mean@N (°C) | Val/min@N | p95 E2E@N (ms) | Reqs@T | Val/min@T |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ])
        for t in trials:
            m = matched["per_trial"].get(t["run_id"], {})
            lines.append(
                f"| `{t['run_id']}` | {_fmt(m.get('temp_at_matched_n_c'), 1)} | "
                f"{_fmt(m.get('matched_n_peak_temp_c'), 1)} | {_fmt(m.get('matched_n_mean_temp_c'), 1)} | "
                f"{_fmt(m.get('matched_n_validated_per_min'), 2)} | {_fmt(m.get('matched_n_p95_total_ms'), 1)} | "
                f"{_fmt(m.get('matched_duration_requests'))} | {_fmt(m.get('matched_duration_validated_per_min'), 2)} |"
            )
        lines.append("")

    lines.extend(["## Failed §4 Checks by Trial", ""])
    for t in trials:
        failed = t["verdict"]["failed_checks"]
        lines.append(f"- `{t['run_id']}` ({t['verdict']['verdict']}): {', '.join(failed) if failed else 'none'}")
    lines.append("")
    return "\n".join(lines)


def _strip_ext(out_prefix: Path) -> Path:
    if out_prefix.suffix in (".md", ".json"):
        return out_prefix.with_suffix("")
    return out_prefix


def compare(
    inputs: list[Path],
    out_prefix: Path,
    paced_p95_budget_s: float = 2.0,
    saturated_min_vpm: float = 7.2,
    sustain_c: float = 75.0,
    abort_c: float = 78.0,
) -> dict[str, Any]:
    loaded = [load_trial(p, sustain_c=sustain_c, abort_c=abort_c) for p in inputs]
    comparability = check_comparability(loaded)
    matched = compute_matched_metrics(loaded)

    public_trials: list[dict[str, Any]] = []
    for t in loaded:
        verdict = evaluate_verdict(
            t,
            paced_p95_budget_s=paced_p95_budget_s,
            saturated_min_vpm=saturated_min_vpm,
            sustain_c=sustain_c,
            abort_c=abort_c,
        )
        pub = {k: v for k, v in t.items() if not k.startswith("_")}
        pub["verdict"] = verdict
        pub["matched"] = matched["per_trial"].get(t["run_id"], {})
        public_trials.append(pub)

    report = {
        "schema_version": 1,
        "thresholds": {
            "paced_p95_budget_s": paced_p95_budget_s,
            "saturated_min_vpm": saturated_min_vpm,
            "sustain_c": sustain_c,
            "abort_c": abort_c,
        },
        "comparability": comparability,
        "matched_interval": matched,
        "trials": public_trials,
    }

    prefix = _strip_ext(out_prefix)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = Path(f"{prefix}.json")
    md_path = Path(f"{prefix}.md")
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(_format_markdown(report), encoding="utf-8")
    return report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("inputs", nargs="+", type=Path, help="Trial directories or benchmark.json files")
    p.add_argument("--out", type=Path, required=True, help="Output path prefix (writes <out>.md and <out>.json)")
    p.add_argument("--paced-p95-budget-s", type=float, default=2.0, help="Paced p95 arrival-to-completion budget (s)")
    p.add_argument("--saturated-min-vpm", type=float, default=7.2, help="Saturated minimum validated/min")
    p.add_argument("--sustain-c", type=float, default=75.0)
    p.add_argument("--abort-c", type=float, default=78.0)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        compare(
            inputs=args.inputs,
            out_prefix=args.out,
            paced_p95_budget_s=args.paced_p95_budget_s,
            saturated_min_vpm=args.saturated_min_vpm,
            sustain_c=args.sustain_c,
            abort_c=args.abort_c,
        )
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
