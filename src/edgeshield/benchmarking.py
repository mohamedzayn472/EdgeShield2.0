"""Real timings on fixed synthetic fixtures, never device simulations."""
import argparse
import hashlib
from datetime import datetime, timezone
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from .model_loader import load_detector, resolve_default_detector
from .pipeline import ADVISORY_POLICIES, assess, explain

FIXTURES = (
    "Fiction Bank: your OTP is 000000. Do not share your OTP.",
    "Urgent: claim your lottery prize at https://reward.example/claim",
    "Aapka parcel kal aayega. Delivery update in the official app.",
    "Fiction Bank: KYC reminder. Visit your usual branch if you need help.",
    "Approve this UPI collect request immediately to receive your prize.",
)


def system_metrics():
    result = {"python_peak_rss_bytes": None, "temperature_c": None}
    try:
        if sys.platform == "linux":
            import resource
            result["python_peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
            thermal = Path("/sys/class/thermal/thermal_zone0/temp")
            if thermal.exists():
                result["temperature_c"] = float(thermal.read_text().strip()) / 1000
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


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--detector", type=Path, default=Path("models/detector_v2.json"))
    p.add_argument("--runtime-config", type=Path)
    p.add_argument("--advisory-policy", choices=ADVISORY_POLICIES, default="always")
    p.add_argument("--repetitions", type=int, default=30)
    p.add_argument("--duration", type=float, default=0, help="Minimum seconds; 600 for sustained Pi run")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    if not 1 <= args.repetitions <= 10000 or not 0 <= args.duration <= 3600:
        p.error("Repetitions must be 1..10000 and duration 0..3600 seconds")
    detector_path = resolve_default_detector(args.detector)
    started = time.perf_counter()
    detector = load_detector(detector_path)
    load_ms = (time.perf_counter() - started) * 1000
    advisor = None
    if args.runtime_config:
        from .advisory import ExecuTorchAdvisor
        advisor = ExecuTorchAdvisor(args.runtime_config)
    # Warm up detector only, recorded separately. Real Llama remains cold per invocation.
    assess(FIXTURES[0], detector)
    throttled_before = throttled_state()
    rows = []
    begin, cpu_begin = time.perf_counter(), time.process_time()
    while len(rows) < args.repetitions or time.perf_counter() - begin < args.duration:
        start = time.perf_counter()
        assessment = assess(FIXTURES[len(rows) % len(FIXTURES)], detector)
        explanation = explain(assessment.evidence, advisor, policy=args.advisory_policy)
        runner_stats = getattr(advisor, "last_stats", None)
        rows.append({"detector_ms": assessment.detector_ms, "evidence_ms": assessment.evidence_ms,
                     "llama_ms": explanation.llama_ms, "validation_ms": explanation.validation_ms,
                     "total_ms": (time.perf_counter() - start) * 1000,
                     "source": explanation.source, "reason": explanation.reason, **system_metrics(),
                     **runner_and_memory_metrics(),
                     "runner_stats": runner_stats, **runtime_measurements(runner_stats)})
        if len(rows) >= 100000:
            break  # Bound sample memory even if duration is large and inference is very fast.
        if args.duration:
            time.sleep(.01)
    elapsed = time.perf_counter() - begin
    throttled_after = throttled_state()
    fallback_count = sum(r["source"] == "Template fallback" for r in rows)
    timing_keys = ("detector_ms", "evidence_ms", "llama_ms", "validation_ms", "total_ms")
    averages = {
        k: (statistics.fmean([r[k] for r in rows if r[k] is not None])
            if any(r[k] is not None for r in rows) else None)
        for k in timing_keys
    }
    report = {
        "schema_version": 1, "measurement_kind": "LOCAL_EXECUTION", "platform": platform.platform(),
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "detector_sha256": hashlib.sha256(detector_path.read_bytes()).hexdigest(),
        "runtime_config_sha256": hashlib.sha256(args.runtime_config.read_bytes()).hexdigest() if args.runtime_config else None,
        "machine": platform.machine(), "python": platform.python_version(), "cpu_count": os.cpu_count(),
        "device_model": _device_model(),
        "hardware_verified_pi4": False, "hardware_verified_pi5": False,
        "note": "Host or unverified results unless separately verified with device diagnostics. Python RSS/CPU exclude runner subprocess; runner_child_peak_rss_bytes tracks RUSAGE_CHILDREN peak RSS.",
        "fixtures": "five fixed synthetic cases; not detection-quality evaluation", "repetitions": len(rows),
        "duration_seconds": elapsed, "detector_load_ms": load_ms, "detector_warmup": 1,
        "requested_duration_seconds": args.duration, "sample_cap_reached": len(rows) >= 100000,
        "python_cpu_seconds": time.process_time() - cpu_begin,
        "python_cpu_percent_one_core": (time.process_time() - cpu_begin) / elapsed * 100,
        "runtime_configured": advisor is not None, "advisory_policy": args.advisory_policy,
        "llama_validated_count": len(rows) - fallback_count,
        "template_fallback_count": fallback_count, "template_fallback_rate": fallback_count / len(rows),
        "runner_child_peak_rss_bytes": max((r["runner_child_peak_rss_bytes"] for r in rows if r["runner_child_peak_rss_bytes"] is not None), default=None),
        "min_mem_available_bytes": min((r["mem_available_bytes"] for r in rows if r["mem_available_bytes"] is not None), default=None),
        "max_swap_used_bytes": max((r["swap_used_bytes"] for r in rows if r["swap_used_bytes"] is not None), default=None),
        "temperature_c": distribution([r["temperature_c"] for r in rows]),
        "throttled_before": throttled_before,
        "throttled_after": throttled_after,
        "runtime_counter_note": "Pinned runner counters; TTFT excludes model loading; prefill includes tokenizer work. Null without actual runtime counters.",
        **{k: distribution([r[k] for r in rows]) for k in ("model_load_ms", "prefill_ms", "time_to_first_token_ms", "tokens_generated", "decode_tokens_per_second")},
        "timings_ms": {k: distribution([r[k] for r in rows]) for k in timing_keys},
        "averages_ms": averages,
        "samples": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Recorded {len(rows)} actual local samples to {args.output}; Llama validated: {len(rows) - fallback_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
