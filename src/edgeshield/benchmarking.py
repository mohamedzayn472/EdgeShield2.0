"""Real timings on fixed synthetic fixtures, never device simulations."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time

from .model_loader import load_detector, resolve_default_detector
from .pipeline import ADVISORY_POLICIES, assess, explain

FIXTURES = (
    "Fiction Bank: your OTP is 000000. Do not share your OTP.",
    "Urgent: claim your lottery prize at https://reward.example/claim",
    "Aapka parcel kal aayega. Delivery update in the official app.",
    "Fiction Bank: KYC reminder. Visit your usual branch if you need help.",
    "Approve this UPI collect request immediately to receive your prize.",
)


class StopRequested(BaseException):
    """Raised when SIGTERM, SIGINT, or a STOP file interrupts a benchmark."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _read_temperature_c() -> float | None:
    if sys.platform != "linux":
        return None
    try:
        thermal = Path("/sys/class/thermal/thermal_zone0/temp")
        if thermal.exists():
            return float(thermal.read_text(encoding="utf-8").strip()) / 1000.0
    except (OSError, ValueError):
        pass
    return None


def _children_cpu_seconds() -> float | None:
    if sys.platform != "linux":
        return None
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        return usage.ru_utime + usage.ru_stime
    except (OSError, ValueError):
        return None


def _git_commit() -> str | None:
    repo_root = Path(__file__).resolve().parents[2]
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=2,
        )
        if proc.returncode == 0:
            value = proc.stdout.strip()
            return value or None
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def system_metrics():
    result = {"python_peak_rss_bytes": None, "temperature_c": None}
    try:
        if sys.platform == "linux":
            import resource
            result["python_peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
            result["temperature_c"] = _read_temperature_c()
        elif sys.platform == "win32":
            import ctypes
            from ctypes import wintypes
            class Counters(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                    (x, ctypes.c_size_t) for x in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                    "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.GetCurrentProcess.restype = wintypes.HANDLE
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            if psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
                result["python_peak_rss_bytes"] = counters.PeakWorkingSetSize
    except (OSError, ValueError):
        pass
    return result


def runner_and_memory_metrics():
    """Capture child runner peak RSS and system available/swap memory on Linux."""
    result = {
        "runner_child_peak_rss_bytes": None,
        "mem_total_bytes": None,
        "mem_available_bytes": None,
        "swap_total_bytes": None,
        "swap_used_bytes": None,
    }
    if sys.platform != "linux":
        return result
    try:
        import resource

        child_kib = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        if child_kib > 0:
            result["runner_child_peak_rss_bytes"] = child_kib * 1024
    except (OSError, ValueError):
        pass
    try:
        meminfo = Path("/proc/meminfo")
        if meminfo.exists():
            parsed = {}
            for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
                if ":" not in line:
                    continue
                key, rest = line.split(":", 1)
                parts = rest.strip().split()
                if parts and parts[0].isdigit():
                    parsed[key] = int(parts[0]) * 1024
            result["mem_total_bytes"] = parsed.get("MemTotal")
            result["mem_available_bytes"] = parsed.get("MemAvailable")
            swap_total = parsed.get("SwapTotal")
            swap_free = parsed.get("SwapFree")
            if swap_total is not None:
                result["swap_total_bytes"] = swap_total
                if swap_free is not None:
                    result["swap_used_bytes"] = max(0, swap_total - swap_free)
    except (OSError, ValueError):
        pass
    return result


def throttled_state():
    """Query Raspberry Pi vcgencmd get_throttled when available; otherwise None."""
    vcgencmd = shutil.which("vcgencmd")
    if not vcgencmd:
        return None
    try:
        proc = subprocess.run([vcgencmd, "get_throttled"], capture_output=True, text=True, timeout=5)
        if proc.returncode == 0:
            return proc.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def _device_model():
    model_path = Path("/proc/device-tree/model")
    if not model_path.exists():
        return None
    try:
        return model_path.read_text(encoding="utf-8", errors="replace").strip("\x00\n ")
    except OSError:
        return None


def distribution(values):
    values = sorted(v for v in values if v is not None)
    if not values:
        return None
    return {"n": len(values), "median": statistics.median(values), "p95": values[math.ceil(.95 * len(values)) - 1],
            "min": values[0], "max": values[-1]}


def runtime_measurements(stats):
    """Interpret only the pinned runner's millisecond counters; no estimates."""
    keys = ("model_load_ms", "prefill_ms", "time_to_first_token_ms", "tokens_generated", "decode_tokens_per_second")
    result = dict.fromkeys(keys)
    if not isinstance(stats, dict) or stats.get("SCALING_FACTOR_UNITS_PER_SECOND") != 1000:
        return result
    def duration(start, end):
        a, b = stats.get(start), stats.get(end)
        if type(a) not in (int, float) or type(b) not in (int, float):
            return None
        return b - a if math.isfinite(a) and math.isfinite(b) and 0 < a <= b else None
    result["model_load_ms"] = duration("model_load_start_ms", "model_load_end_ms")
    result["prefill_ms"] = duration("inference_start_ms", "prompt_eval_end_ms")
    result["time_to_first_token_ms"] = duration("inference_start_ms", "first_token_ms")
    for target, source in (("tokens_generated", "generated_tokens"), ("decode_tokens_per_second", "decode_token_per_sec")):
        value = stats.get(source)
        if type(value) in (int, float) and math.isfinite(value) and value >= 0:
            result[target] = value
    return result


def _extended_runtime_measurements(stats, runner_wall_ms) -> dict[str, float | None]:
    result: dict[str, float | None] = {"decode_ms": None, "runner_overhead_ms": None}
    if not isinstance(stats, dict) or stats.get("SCALING_FACTOR_UNITS_PER_SECOND") != 1000:
        return result

    def duration(start: str, end: str) -> float | None:
        a, b = stats.get(start), stats.get(end)
        if type(a) not in (int, float) or type(b) not in (int, float):
            return None
        return b - a if math.isfinite(a) and math.isfinite(b) and 0 < a <= b else None

    result["decode_ms"] = duration("prompt_eval_end_ms", "inference_end_ms")
    runner_internal_ms = duration("model_load_start_ms", "inference_end_ms")
    if (
        type(runner_wall_ms) in (int, float)
        and math.isfinite(runner_wall_ms)
        and runner_internal_ms is not None
    ):
        result["runner_overhead_ms"] = runner_wall_ms - runner_internal_ms
    return result


def load_fixtures(fixture_set: str) -> tuple[list[tuple[str, str]], str]:
    """Load deterministic benchmark fixtures for smoke, holdout30, or holdout132."""
    if fixture_set == "smoke":
        return (
            [(f"smoke_{i}", text) for i, text in enumerate(FIXTURES)],
            "five fixed synthetic cases; not detection-quality evaluation",
        )
    rel = Path("data/synthetic/v2_holdout.jsonl")
    holdout_path = rel if rel.is_file() else Path(__file__).resolve().parents[2] / rel
    if not holdout_path.is_file():
        raise FileNotFoundError(f"Holdout fixture dataset not found: {holdout_path}")
    records = [
        json.loads(line)
        for line in holdout_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if fixture_set == "holdout30":
        l0 = sorted((r for r in records if r.get("label") == 0), key=lambda r: r["id"])[:15]
        l1 = sorted((r for r in records if r.get("label") == 1), key=lambda r: r["id"])[:15]
        if len(l0) < 15 or len(l1) < 15:
            raise ValueError("Insufficient label-0/label-1 rows for holdout30")
        interleaved = [row for pair in zip(l0, l1) for row in pair]
        return (
            [(row["id"], row["text"]) for row in interleaved],
            "30 deterministic holdout cases (15 label-0 + 15 label-1 interleaved by id); not detection-quality evaluation",
        )
    if fixture_set == "holdout132":
        ordered = sorted(records, key=lambda r: r["id"])
        return (
            [(row["id"], row["text"]) for row in ordered],
            "132 deterministic holdout cases sorted by id; not detection-quality evaluation",
        )
    raise ValueError(f"Unsupported fixture set: {fixture_set}")


def _effective_settings(advisor) -> dict | None:
    if advisor is None:
        return None
    config = getattr(advisor, "config", None)
    if not isinstance(config, dict):
        return None
    artifacts = config.get("artifacts", {})
    if not isinstance(artifacts, dict):
        artifacts = {}
    shared = artifacts.get("shared_libraries", [])
    return {
        "cpu_threads": config.get("cpu_threads"),
        "max_new_tokens": config.get("max_new_tokens"),
        "seq_len": config.get("seq_len"),
        "timeout_seconds": config.get("timeout_seconds"),
        "artifacts_sha256": {
            "runner": artifacts.get("runner", {}).get("sha256") if isinstance(artifacts.get("runner"), dict) else None,
            "model": artifacts.get("model", {}).get("sha256") if isinstance(artifacts.get("model"), dict) else None,
            "tokenizer": artifacts.get("tokenizer", {}).get("sha256") if isinstance(artifacts.get("tokenizer"), dict) else None,
            "shared_libraries": [
                item.get("sha256") for item in shared if isinstance(item, dict)
            ] if isinstance(shared, list) else [],
        },
    }


def _interruptible_sleep(seconds: float, stop_file: Path | None) -> None:
    if stop_file is not None and stop_file.exists():
        raise StopRequested("STOP_FILE")
    if seconds <= 0:
        return
    deadline = time.perf_counter() + seconds
    while True:
        if stop_file is not None and stop_file.exists():
            raise StopRequested("STOP_FILE")
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            break
        time.sleep(min(0.1, remaining))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--detector", type=Path, default=Path("models/detector_v8.json"))
    p.add_argument("--runtime-config", type=Path)
    p.add_argument("--advisory-policy", choices=ADVISORY_POLICIES, default="always")
    p.add_argument("--repetitions", type=int, default=30)
    p.add_argument("--duration", type=float, default=0, help="Minimum seconds; 600 for sustained Pi run")
    p.add_argument("--interval-seconds", type=float, default=0.0, help="Offered start-to-start interval in seconds (0 = saturated)")
    p.add_argument("--fixtures", choices=("smoke", "holdout30", "holdout132"), default="smoke")
    p.add_argument("--run-id", type=str, default=None)
    p.add_argument("--stop-file", type=Path, default=None)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    if not 1 <= args.repetitions <= 10000 or not math.isfinite(args.duration) or not 0 <= args.duration <= 3600:
        p.error("Repetitions must be 1..10000 and duration 0..3600 seconds")
    if not math.isfinite(args.interval_seconds) or not 0 <= args.interval_seconds <= 3600:
        p.error("Interval seconds must be 0..3600")

    fixtures, fixtures_desc = load_fixtures(args.fixtures)
    detector_path = resolve_default_detector(args.detector)
    started = time.perf_counter()
    detector = load_detector(detector_path)
    load_ms = (time.perf_counter() - started) * 1000
    advisor = None
    if args.runtime_config:
        from .advisory import ExecuTorchAdvisor
        advisor = ExecuTorchAdvisor(args.runtime_config)
    # Warm up detector only, recorded separately. Real Llama remains cold per invocation.
    assess(fixtures[0][1], detector)
    throttled_before = throttled_state()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    partial_path = Path(f"{args.output}.partial.jsonl")

    rows = []
    planned_scheduled_starts = (
        (max(args.repetitions, math.ceil((args.duration - 1e-9) / args.interval_seconds))
         if args.duration > 0 else args.repetitions)
        if args.interval_seconds > 0
        else None
    )
    actual_starts = 0
    late_starts = 0
    completed = True
    stop_reason = None
    begin_utc = datetime.now(timezone.utc)
    begin, cpu_begin = time.perf_counter(), time.process_time()

    stop_signal_triggered = False
    prev_handlers = {}
    in_main_thread = threading.current_thread() is threading.main_thread()

    def _on_signal(signum, _frame):
        nonlocal stop_signal_triggered
        if stop_signal_triggered:
            return
        stop_signal_triggered = True
        raise StopRequested(signal.Signals(signum).name)

    if in_main_thread:
        for sig in (signal.SIGTERM, signal.SIGINT):
            prev_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, _on_signal)

    try:
        with partial_path.open("w", encoding="utf-8") as partial_fh:
            while True:
                if args.stop_file is not None and args.stop_file.exists():
                    raise StopRequested("STOP_FILE")

                req_idx = len(rows)
                if args.interval_seconds > 0:
                    scheduled_offset_s = req_idx * args.interval_seconds
                    target_start = begin + scheduled_offset_s
                    if req_idx >= planned_scheduled_starts:
                        if args.duration > 0:
                            remaining_dur = (begin + args.duration) - time.perf_counter()
                            if remaining_dur > 0:
                                _interruptible_sleep(remaining_dur, args.stop_file)
                        break
                    if req_idx > 0:
                        now = time.perf_counter()
                        if now > target_start:
                            is_late_start = True
                            late_starts += 1
                        else:
                            is_late_start = False
                            _interruptible_sleep(target_start - now, args.stop_file)
                    else:
                        is_late_start = False
                else:
                    if not (len(rows) < args.repetitions or time.perf_counter() - begin < args.duration):
                        break
                    scheduled_offset_s = None
                    target_start = None
                    is_late_start = False

                fixture_id, fixture_text = fixtures[req_idx % len(fixtures)]
                actual_starts += 1
                start = time.perf_counter()
                start_utc = datetime.now(timezone.utc).isoformat()
                offset_s = start - begin
                scheduled_start_utc = (
                    (begin_utc + timedelta(seconds=scheduled_offset_s)).isoformat()
                    if scheduled_offset_s is not None
                    else None
                )
                start_delay_ms = (
                    max(0.0, (start - target_start) * 1000.0)
                    if target_start is not None
                    else None
                )
                temp_before = _read_temperature_c()
                child_cpu_before = _children_cpu_seconds()

                assessment = assess(fixture_text, detector)
                if advisor is not None:
                    try:
                        advisor.last_stats = None
                    except AttributeError:
                        pass
                    try:
                        advisor.last_timing = None
                    except AttributeError:
                        pass
                explanation = explain(assessment.evidence, advisor, policy=args.advisory_policy)
                end = time.perf_counter()
                total_ms = (end - start) * 1000.0
                completion_offset_s = end - begin
                arrival_to_completion_ms = (
                    max(total_ms, (end - target_start) * 1000.0)
                    if target_start is not None
                    else None
                )
                child_cpu_after = _children_cpu_seconds()
                child_cpu_s = (
                    max(0.0, child_cpu_after - child_cpu_before)
                    if child_cpu_before is not None and child_cpu_after is not None
                    else None
                )
                llama_attempted = (
                    advisor is not None
                    and explanation.reason != "SKIPPED_BY_POLICY"
                    and explanation.llama_ms is not None
                )
                runner_stats = getattr(advisor, "last_stats", None) if llama_attempted else None
                last_timing = getattr(advisor, "last_timing", None) if llama_attempted else None
                integrity_ms = last_timing.get("integrity_ms") if isinstance(last_timing, dict) else None
                runner_wall_ms = last_timing.get("runner_wall_ms") if isinstance(last_timing, dict) else None

                row = {
                    "request_index": req_idx,
                    "fixture_id": fixture_id,
                    "start_utc": start_utc,
                    "offset_s": offset_s,
                    "scheduled_offset_s": scheduled_offset_s,
                    "scheduled_start_utc": scheduled_start_utc,
                    "actual_start_offset_s": offset_s,
                    "start_delay_ms": start_delay_ms,
                    "is_late_start": is_late_start,
                    "completion_offset_s": completion_offset_s,
                    "arrival_to_completion_ms": arrival_to_completion_ms,
                    "detector_ms": assessment.detector_ms,
                    "evidence_ms": assessment.evidence_ms,
                    "llama_ms": explanation.llama_ms,
                    "validation_ms": explanation.validation_ms,
                    "total_ms": total_ms,
                    "source": explanation.source,
                    "reason": explanation.reason,
                    "llama_attempted": llama_attempted,
                    "integrity_ms": integrity_ms,
                    "runner_wall_ms": runner_wall_ms,
                    **system_metrics(),
                    "temperature_c_before": temp_before,
                    **runner_and_memory_metrics(),
                    "child_cpu_s": child_cpu_s,
                    "runner_stats": runner_stats,
                    **runtime_measurements(runner_stats),
                    **_extended_runtime_measurements(runner_stats, runner_wall_ms),
                }
                rows.append(row)
                partial_fh.write(json.dumps(row) + "\n")
                partial_fh.flush()
                os.fsync(partial_fh.fileno())

                if len(rows) >= 100000:
                    break  # Bound sample memory even if duration is large and inference is very fast.
                if args.interval_seconds == 0 and args.duration:
                    _interruptible_sleep(0.01, args.stop_file)
    except StopRequested as exc:
        completed = False
        stop_reason = exc.reason
    finally:
        if in_main_thread:
            for sig, handler in prev_handlers.items():
                signal.signal(sig, handler)

    elapsed = time.perf_counter() - begin
    cpu_elapsed = time.process_time() - cpu_begin
    throttled_after = throttled_state()
    if args.interval_seconds == 0:
        scheduled_starts = None
    elif completed:
        scheduled_starts = planned_scheduled_starts
    else:
        scheduled_starts = max(
            actual_starts,
            min(
                planned_scheduled_starts,
                int(math.floor((elapsed + 1e-9) / args.interval_seconds)) + 1,
            ),
        )
    fallback_count = sum(r["source"] == "Template fallback" for r in rows)
    llama_validated_count = len(rows) - fallback_count
    llama_attempted_count = sum(1 for r in rows if r["llama_attempted"])
    skipped_by_policy_count = sum(1 for r in rows if r["reason"] == "SKIPPED_BY_POLICY")
    reason_counts = dict(sorted(Counter(r["reason"] for r in rows).items()))

    timing_keys = ("detector_ms", "evidence_ms", "llama_ms", "validation_ms", "total_ms")
    averages = {
        k: (statistics.fmean([r[k] for r in rows if r[k] is not None])
            if any(r[k] is not None for r in rows) else None)
        for k in timing_keys
    }
    report = {
        "schema_version": 1, "measurement_kind": "LOCAL_EXECUTION", "platform": platform.platform(),
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": args.run_id,
        "git_commit": _git_commit(),
        "detector_sha256": hashlib.sha256(detector_path.read_bytes()).hexdigest(),
        "runtime_config_sha256": hashlib.sha256(args.runtime_config.read_bytes()).hexdigest() if args.runtime_config else None,
        "effective_settings": _effective_settings(advisor),
        "machine": platform.machine(), "python": platform.python_version(), "cpu_count": os.cpu_count(),
        "device_model": _device_model(),
        "hardware_verified_pi4": False, "hardware_verified_pi5": False,
        "note": "Host or unverified results unless separately verified with device diagnostics. Python RSS/CPU exclude runner subprocess; runner_child_peak_rss_bytes tracks RUSAGE_CHILDREN peak RSS.",
        "fixtures": fixtures_desc,
        "fixture_set": args.fixtures,
        "fixture_ids": [r["fixture_id"] for r in rows],
        "repetitions": len(rows),
        "duration_seconds": elapsed, "detector_load_ms": load_ms, "detector_warmup": 1,
        "requested_duration_seconds": args.duration,
        "offered_interval_seconds": args.interval_seconds,
        "planned_scheduled_starts": planned_scheduled_starts,
        "scheduled_starts": scheduled_starts,
        "actual_starts": actual_starts,
        "late_starts": late_starts,
        "completed": completed,
        "stop_reason": stop_reason,
        "partial_jsonl_path": str(partial_path),
        "sample_cap_reached": len(rows) >= 100000,
        "python_cpu_seconds": cpu_elapsed,
        "python_cpu_percent_one_core": (cpu_elapsed / elapsed * 100) if elapsed > 0 else None,
        "runtime_configured": advisor is not None, "advisory_policy": args.advisory_policy,
        "llama_attempted_count": llama_attempted_count,
        "skipped_by_policy_count": skipped_by_policy_count,
        "llama_validated_count": llama_validated_count,
        "validated_per_minute": (llama_validated_count / (elapsed / 60.0)) if elapsed > 0 else None,
        "template_fallback_count": fallback_count,
        "template_fallback_rate": (fallback_count / len(rows)) if rows else None,
        "reason_counts": reason_counts,
        "runner_child_peak_rss_bytes": max((r["runner_child_peak_rss_bytes"] for r in rows if r["runner_child_peak_rss_bytes"] is not None), default=None),
        "min_mem_available_bytes": min((r["mem_available_bytes"] for r in rows if r["mem_available_bytes"] is not None), default=None),
        "max_swap_used_bytes": max((r["swap_used_bytes"] for r in rows if r["swap_used_bytes"] is not None), default=None),
        "temperature_c": distribution([r["temperature_c"] for r in rows]),
        "temperature_c_before": distribution([r["temperature_c_before"] for r in rows]),
        "throttled_before": throttled_before,
        "throttled_after": throttled_after,
        "runtime_counter_note": "Pinned runner counters; TTFT excludes model loading; prefill includes tokenizer work. Null without actual runtime counters.",
        **{
            k: distribution([r[k] for r in rows])
            for k in (
                "model_load_ms", "prefill_ms", "time_to_first_token_ms", "tokens_generated",
                "decode_tokens_per_second", "integrity_ms", "runner_wall_ms", "decode_ms",
                "runner_overhead_ms", "child_cpu_s", "start_delay_ms", "arrival_to_completion_ms",
            )
        },
        "timings_ms": {k: distribution([r[k] for r in rows]) for k in timing_keys},
        "averages_ms": averages,
        "samples": rows,
    }
    tmp_out = args.output.parent / f".{args.output.name}.tmp.{os.getpid()}"
    tmp_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    os.replace(tmp_out, args.output)
    print(f"Recorded {len(rows)} actual local samples to {args.output}; Llama validated: {llama_validated_count}")
    return 0 if completed else 3


if __name__ == "__main__":
    raise SystemExit(main())
