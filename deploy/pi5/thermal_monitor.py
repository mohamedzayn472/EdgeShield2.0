"""1 Hz Raspberry Pi 5 thermal, clock, fan, and throttle monitor with stop rules."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import statistics
import subprocess
import sys
import time
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
_CLOCK_RE = re.compile(r"=(\d+)")
_EXT5V_RE = re.compile(r"EXT5V_V[^=]*=([+-]?\d+(?:\.\d+)?)")


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
    current = {name: bool(value & (1 << bit)) for bit, name in CURRENT_BITS.items()}
    sticky = {name: bool(value & (1 << bit)) for bit, name in STICKY_BITS.items()}
    return {
        "raw": raw if isinstance(raw, str) else hex(value),
        "value": value,
        "hex": hex(value),
        "current_mask": value & 0xF,
        "sticky_mask": (value >> 16) & 0xF,
        "current": current,
        "sticky": sticky,
    }


def _is_default_root(sysfs_root: Path) -> bool:
    return Path(os.path.abspath(str(sysfs_root))) == Path("/")


def resolve_vcgencmd(sysfs_root: Path, vcgencmd_arg: str | None) -> str | None:
    """Resolve vcgencmd binary. Disabled automatically for non-root --sysfs-root unless specified."""
    if vcgencmd_arg is not None:
        stripped = vcgencmd_arg.strip()
        return stripped if stripped else None
    if _is_default_root(sysfs_root):
        return shutil.which("vcgencmd")
    return None


def _run_vcgencmd(vcgencmd_path: str, args: list[str], timeout: float = 2.0) -> str | None:
    try:
        proc = subprocess.run(
            [vcgencmd_path, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def _read_mem_available_bytes(sysfs_root: Path) -> int | None:
    candidates = [sysfs_root / "proc" / "meminfo"]
    if not _is_default_root(sysfs_root):
        candidates.append(Path("/proc/meminfo"))
    for meminfo in candidates:
        text = _read_text(meminfo)
        if text is None:
            continue
        for line in text.splitlines():
            if line.startswith("MemAvailable:"):
                parts = line.split(":", 1)[1].strip().split()
                if parts and parts[0].isdigit():
                    return int(parts[0]) * 1024
    return None


def sample_sensors(
    sysfs_root: Path = Path("/"),
    vcgencmd_path: str | None = None,
    check_pmic: bool = True,
) -> dict[str, Any]:
    """Read temperature, ARM clock, throttle bits, fan RPM, cooling state, optional EXT5V, and MemAvailable."""
    temperature_c: float | None = None
    temp_source: str | None = None

    if vcgencmd_path:
        out = _run_vcgencmd(vcgencmd_path, ["measure_temp"])
        if out:
            match = _TEMP_RE.search(out)
            if match:
                val = float(match.group(1))
                if math.isfinite(val):
                    temperature_c = val
                    temp_source = "vcgencmd"

    if temperature_c is None:
        raw_temp = _read_text(sysfs_root / "sys" / "class" / "thermal" / "thermal_zone0" / "temp")
        if raw_temp is not None:
            try:
                val = float(raw_temp) / 1000.0
                if math.isfinite(val):
                    temperature_c = val
                    temp_source = "sysfs"
            except ValueError:
                pass

    arm_hz: int | None = None
    arm_hz_source: str | None = None
    if vcgencmd_path:
        out = _run_vcgencmd(vcgencmd_path, ["measure_clock", "arm"])
        if out:
            match = _CLOCK_RE.search(out)
            if match:
                hz = int(match.group(1))
                if hz > 0:
                    arm_hz = hz
                    arm_hz_source = "vcgencmd"

    if arm_hz is None:
        raw_khz = _read_text(
            sysfs_root / "sys" / "devices" / "system" / "cpu" / "cpu0" / "cpufreq" / "scaling_cur_freq"
        )
        if raw_khz is not None:
            try:
                khz = int(raw_khz)
                if khz > 0:
                    arm_hz = khz * 1000
                    arm_hz_source = "cpufreq"
            except ValueError:
                pass

    throttled: dict[str, Any] | None = None
    if vcgencmd_path:
        out = _run_vcgencmd(vcgencmd_path, ["get_throttled"])
        if out:
            decoded = decode_throttled(out)
            if decoded["value"] is not None:
                throttled = decoded

    fan_rpm: int | None = None
    fan_rpm_path: str | None = None
    hwmon_dir = sysfs_root / "sys" / "class" / "hwmon"
    if hwmon_dir.is_dir():
        for fan_file in sorted(hwmon_dir.glob("hwmon*/fan1_input")):
            raw_rpm = _read_text(fan_file)
            if raw_rpm is not None:
                try:
                    rpm = int(raw_rpm)
                    if rpm >= 0:
                        fan_rpm = rpm
                        fan_rpm_path = str(fan_file)
                        break
                except ValueError:
                    pass

    cooling_states: dict[str, int] = {}
    thermal_dir = sysfs_root / "sys" / "class" / "thermal"
    if thermal_dir.is_dir():
        for cur_state_file in sorted(thermal_dir.glob("cooling_device*/cur_state")):
            raw_state = _read_text(cur_state_file)
            if raw_state is not None:
                try:
                    cooling_states[cur_state_file.parent.name] = int(raw_state)
                except ValueError:
                    pass

    ext5v_v: float | None = None
    if vcgencmd_path and check_pmic:
        out = _run_vcgencmd(vcgencmd_path, ["pmic_read_adc", "EXT5V_V"])
        if out:
            match = _EXT5V_RE.search(out)
            if match:
                val = float(match.group(1))
                if math.isfinite(val):
                    ext5v_v = val

    return {
        "temperature_c": temperature_c,
        "temp_source": temp_source,
        "arm_hz": arm_hz,
        "arm_hz_source": arm_hz_source,
        "throttled": throttled,
        "fan_rpm": fan_rpm,
        "fan_rpm_path": fan_rpm_path,
        "cooling_states": cooling_states,
        "ext5v_v": ext5v_v,
        "mem_available_bytes": _read_mem_available_bytes(sysfs_root),
    }


def pgid_non_zombie_pids(pgid: int) -> list[int]:
    """Return live (non-zombie) PIDs belonging to process group pgid."""
    proc_dir = Path("/proc")
    if not proc_dir.is_dir():
        try:
            os.killpg(pgid, 0)
            return [pgid]
        except ProcessLookupError:
            return []
        except PermissionError:
            return [pgid]

    live: list[int] = []
    try:
        entries = list(proc_dir.iterdir())
    except OSError:
        return []
    for entry in entries:
        name = entry.name
        if not name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        _, sep, rest = stat.rpartition(")")
        if not sep:
            continue
        fields = rest.split()
        if len(fields) < 3:
            continue
        state = fields[0]
        try:
            pgrp = int(fields[2])
        except ValueError:
            continue
        if pgrp == pgid and state not in ("Z", "X", "x"):
            live.append(int(name))
    return sorted(live)


def _distribution(values: list[float | int]) -> dict[str, Any] | None:
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


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.tmp.{os.getpid()}"
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _sleep_until(deadline_mono: float, stop_file: Path | None = None) -> bool:
    """Sleep in short slices until deadline_mono; return True if stop_file appeared."""
    while True:
        if stop_file is not None and stop_file.exists():
            return True
        remaining = deadline_mono - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.1, remaining))


def cmd_idle(args: argparse.Namespace) -> int:
    sysfs_root = args.sysfs_root
    vcgencmd_path = resolve_vcgencmd(sysfs_root, args.vcgencmd)
    interval = args.sample_interval
    start_mono = time.monotonic()
    samples: list[dict[str, Any]] = []
    idx = 0
    while True:
        now_mono = time.monotonic()
        offset_s = now_mono - start_mono
        reading = sample_sensors(sysfs_root, vcgencmd_path)
        samples.append(
            {
                "sample_index": idx,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "offset_s": offset_s,
                **reading,
            }
        )
        idx += 1
        if offset_s >= args.seconds:
            break
        next_tick = start_mono + idx * interval
        if next_tick - start_mono > args.seconds:
            next_tick = start_mono + args.seconds
        _sleep_until(next_tick)

    temps = [s["temperature_c"] for s in samples if s["temperature_c"] is not None]
    dist = _distribution(temps)
    idle_mean = dist["mean"] if dist else None
    suggested_gate = round(idle_mean + 2.0, 2) if idle_mean is not None else None
    rpms = [s["fan_rpm"] for s in samples if s["fan_rpm"] is not None]
    report = {
        "schema_version": 1,
        "mode": "idle",
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "requested_seconds": args.seconds,
        "duration_seconds": time.monotonic() - start_mono,
        "sample_count": len(samples),
        "valid_temp_count": len(temps),
        "idle_mean_c": idle_mean,
        "idle_median_c": dist["median"] if dist else None,
        "idle_min_c": dist["min"] if dist else None,
        "idle_max_c": dist["max"] if dist else None,
        "idle_p95_c": dist["p95"] if dist else None,
        "suggested_start_gate_c": suggested_gate,
        "fan_rpm_min": min(rpms) if rpms else None,
        "fan_rpm_max": max(rpms) if rpms else None,
        "temp_sources_seen": sorted({s["temp_source"] for s in samples if s["temp_source"]}),
        "throttled_start": samples[0]["throttled"]["raw"] if samples and samples[0]["throttled"] else None,
        "throttled_end": samples[-1]["throttled"]["raw"] if samples and samples[-1]["throttled"] else None,
        "samples": samples,
    }
    _atomic_write_json(args.out, report)
    print(
        f"Idle monitor: n={len(temps)}/{len(samples)}, mean={idle_mean}, "
        f"suggested_start_gate_c={suggested_gate}"
    )
    return 0 if temps else 1


def cmd_wait(args: argparse.Namespace) -> int:
    sysfs_root = args.sysfs_root
    vcgencmd_path = resolve_vcgencmd(sysfs_root, args.vcgencmd)
    interval = args.sample_interval
    start_mono = time.monotonic()
    samples: list[dict[str, Any]] = []
    contiguous_run: list[tuple[float, float]] = []
    ready = False
    idx = 0

    while True:
        now_mono = time.monotonic()
        offset_s = now_mono - start_mono
        reading = sample_sensors(sysfs_root, vcgencmd_path, check_pmic=False)
        temp_c = reading["temperature_c"]
        samples.append(
            {
                "sample_index": idx,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "offset_s": offset_s,
                "temperature_c": temp_c,
                "temp_source": reading["temp_source"],
                "fan_rpm": reading["fan_rpm"],
            }
        )
        idx += 1

        if temp_c is not None and temp_c <= args.below:
            contiguous_run.append((offset_s, temp_c))
            if args.stable_seconds <= 0:
                ready = True
                break
            if contiguous_run[-1][0] - contiguous_run[0][0] >= args.stable_seconds - 1e-9:
                cutoff = contiguous_run[-1][0] - args.stable_seconds - 1e-9
                window = [t for ts, t in contiguous_run if ts >= cutoff]
                if len(window) >= 2 and (max(window) - min(window)) <= 2.0 * args.tolerance_c + 1e-9:
                    ready = True
                    break
        else:
            contiguous_run = []

        if offset_s >= args.max_wait:
            break
        next_tick = start_mono + idx * interval
        if next_tick - start_mono > args.max_wait:
            next_tick = start_mono + args.max_wait
        _sleep_until(next_tick)

    temps = [s["temperature_c"] for s in samples if s["temperature_c"] is not None]
    report = {
        "schema_version": 1,
        "mode": "wait",
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "READY" if ready else "TIMEOUT",
        "below_c": args.below,
        "stable_seconds": args.stable_seconds,
        "tolerance_c": args.tolerance_c,
        "max_wait_seconds": args.max_wait,
        "waited_seconds": time.monotonic() - start_mono,
        "sample_count": len(samples),
        "final_temperature_c": temps[-1] if temps else None,
        "temp_sources_seen": sorted({s["temp_source"] for s in samples if s["temp_source"]}),
    }
    _atomic_write_json(args.out, report)
    if ready:
        print(f"Start gate satisfied: {report['final_temperature_c']} C <= {args.below} C")
        return 0
    print(f"Start gate timeout after {report['waited_seconds']:.1f}s (below {args.below} C)", file=sys.stderr)
    return 4


def _compute_last_120s_slope(samples: list[dict[str, Any]]) -> float | None:
    valid = [(s["offset_s"], s["temperature_c"]) for s in samples if s["temperature_c"] is not None]
    if len(valid) < 2:
        return None
    end_t = valid[-1][0]
    window = [(t, y) for t, y in valid if t >= end_t - 120.0]
    if len(window) < 2 or (window[-1][0] - window[0][0]) < 10.0:
        return None
    mean_t = statistics.fmean(t for t, _ in window)
    mean_y = statistics.fmean(y for _, y in window)
    denom = sum((t - mean_t) ** 2 for t, _ in window)
    if denom <= 0:
        return None
    slope_per_s = sum((t - mean_t) * (y - mean_y) for t, y in window) / denom
    return slope_per_s * 60.0


def _build_thermal_summary(
    samples: list[dict[str, Any]],
    duration_seconds: float,
    sample_interval: float,
    sustain_c: float,
    abort_c: float,
    stop_triggered: bool,
    stop_reason: str | None,
) -> dict[str, Any]:
    temps = [s["temperature_c"] for s in samples if s["temperature_c"] is not None]
    valid_offsets = [s["offset_s"] for s in samples if s["temperature_c"] is not None]
    dist = _distribution(temps)

    time_to_sustain = next(
        (s["offset_s"] for s in samples if s["temperature_c"] is not None and s["temperature_c"] >= sustain_c),
        None,
    )
    time_to_abort = next(
        (s["offset_s"] for s in samples if s["temperature_c"] is not None and s["temperature_c"] >= abort_c),
        None,
    )

    seconds_above_sustain = 0.0
    seconds_above_abort = 0.0
    for i, s in enumerate(samples):
        temp = s["temperature_c"]
        if temp is None:
            continue
        if i + 1 < len(samples):
            dt = max(0.0, samples[i + 1]["offset_s"] - s["offset_s"])
        else:
            dt = min(sample_interval, max(0.0, duration_seconds - s["offset_s"]))
        if temp >= sustain_c:
            seconds_above_sustain += dt
        if temp >= abort_c:
            seconds_above_abort += dt

    if not valid_offsets:
        max_gap_s = duration_seconds
    else:
        gaps = [valid_offsets[0], max(0.0, duration_seconds - valid_offsets[-1])]
        for a, b in zip(valid_offsets, valid_offsets[1:]):
            gaps.append(max(0.0, b - a))
        max_gap_s = max(gaps)

    expected = max(len(samples), int(math.floor(duration_seconds / sample_interval)) + 1) if sample_interval > 0 else len(samples)
    coverage = min(1.0, len(temps) / expected) if expected > 0 else 0.0

    current_bits_seen = sorted(
        {
            flag
            for s in samples
            if isinstance(s.get("throttled"), dict)
            for flag, active in s["throttled"].get("current", {}).items()
            if active
        }
    )
    throttled_samples = [s["throttled"] for s in samples if isinstance(s.get("throttled"), dict)]
    slope = _compute_last_120s_slope(samples)

    rpms = [s["fan_rpm"] for s in samples if s["fan_rpm"] is not None]
    rpm_paths = sorted({s["fan_rpm_path"] for s in samples if s.get("fan_rpm_path")})
    cooling_min: dict[str, int] = {}
    cooling_max: dict[str, int] = {}
    for s in samples:
        for dev, val in s.get("cooling_states", {}).items():
            cooling_min[dev] = min(cooling_min.get(dev, val), val)
            cooling_max[dev] = max(cooling_max.get(dev, val), val)

    arm_hz_vals = [s["arm_hz"] for s in samples if s["arm_hz"] is not None]
    arm_dist = _distribution(arm_hz_vals)
    ext5v_vals = [s["ext5v_v"] for s in samples if s["ext5v_v"] is not None]
    mem_vals = [s["mem_available_bytes"] for s in samples if s["mem_available_bytes"] is not None]

    return {
        "schema_version": 1,
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": duration_seconds,
        "sample_interval_seconds": sample_interval,
        "sample_count": len(samples),
        "valid_temp_count": len(temps),
        "sensor_failures": len(samples) - len(temps),
        "temp_sources_seen": sorted({s["temp_source"] for s in samples if s["temp_source"]}),
        "sustain_c": sustain_c,
        "abort_c": abort_c,
        "start_temp_c": temps[0] if temps else None,
        "peak_temp_c": dist["max"] if dist else None,
        "end_temp_c": temps[-1] if temps else None,
        "mean_temp_c": dist["mean"] if dist else None,
        "p95_temp_c": dist["p95"] if dist else None,
        "time_to_sustain_s": time_to_sustain,
        "time_to_abort_s": time_to_abort,
        "seconds_above_sustain": round(seconds_above_sustain, 3),
        "seconds_above_abort": round(seconds_above_abort, 3),
        "coverage": coverage,
        "max_gap_s": max_gap_s,
        "current_bits_seen": current_bits_seen,
        "sticky_at_start": throttled_samples[0]["sticky"] if throttled_samples else None,
        "sticky_at_end": throttled_samples[-1]["sticky"] if throttled_samples else None,
        "throttled_raw_start": throttled_samples[0]["raw"] if throttled_samples else None,
        "throttled_raw_end": throttled_samples[-1]["raw"] if throttled_samples else None,
        "last_120s_slope_c_per_min": slope,
        "rising_at_end": (slope > 0.5) if slope is not None else None,
        "fan_rpm_min": min(rpms) if rpms else None,
        "fan_rpm_max": max(rpms) if rpms else None,
        "fan_rpm_path": rpm_paths[0] if rpm_paths else None,
        "cooling_states_min": cooling_min,
        "cooling_states_max": cooling_max,
        "arm_hz_min": arm_dist["min"] if arm_dist else None,
        "arm_hz_median": arm_dist["median"] if arm_dist else None,
        "arm_hz_max": arm_dist["max"] if arm_dist else None,
        "arm_hz_sources_seen": sorted({s["arm_hz_source"] for s in samples if s.get("arm_hz_source")}),
        "ext5v_v_min": min(ext5v_vals) if ext5v_vals else None,
        "ext5v_v_max": max(ext5v_vals) if ext5v_vals else None,
        "min_mem_available_bytes": min(mem_vals) if mem_vals else None,
        "stop_triggered": stop_triggered,
        "stop_reason": stop_reason,
    }


def _kill_process_group(pgid: int, grace_seconds: float) -> tuple[bool, bool, list[int]]:
    sigterm_sent = False
    escalated_to_sigkill = False
    try:
        os.killpg(pgid, signal.SIGTERM)
        sigterm_sent = True
    except ProcessLookupError:
        return False, False, []
    except PermissionError:
        return False, False, pgid_non_zombie_pids(pgid)

    deadline = time.monotonic() + max(0.0, grace_seconds)
    while time.monotonic() < deadline:
        if not pgid_non_zombie_pids(pgid):
            return sigterm_sent, escalated_to_sigkill, []
        time.sleep(0.05)

    remaining = pgid_non_zombie_pids(pgid)
    if remaining:
        escalated_to_sigkill = True
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        kill_deadline = time.monotonic() + 2.0
        while time.monotonic() < kill_deadline:
            if not pgid_non_zombie_pids(pgid):
                return sigterm_sent, escalated_to_sigkill, []
            time.sleep(0.05)
        remaining = pgid_non_zombie_pids(pgid)
    return sigterm_sent, escalated_to_sigkill, remaining


def cmd_watch(args: argparse.Namespace) -> int:
    sysfs_root = args.sysfs_root
    vcgencmd_path = resolve_vcgencmd(sysfs_root, args.vcgencmd)
    args.out.mkdir(parents=True, exist_ok=True)
    trace_path = args.out / "thermal.jsonl"
    summary_path = args.out / "thermal-summary.json"
    stop_path = args.out / "stop.json"

    # Wait briefly for setsid/exec transition if the caller just spawned the process group.
    wait_pgid_deadline = time.monotonic() + 1.0
    while not pgid_non_zombie_pids(args.pgid) and time.monotonic() < wait_pgid_deadline:
        stat_text = _read_text(Path(f"/proc/{args.pgid}/stat"))
        if stat_text is None:
            break
        _, sep, rest = stat_text.rpartition(")")
        fields = rest.split() if sep else []
        if not fields or fields[0] in ("Z", "X", "x"):
            break
        time.sleep(0.02)

    interval = args.sample_interval
    min_avail_bytes = int(args.min_avail_gib * (1024**3))
    start_mono = time.monotonic()
    last_valid_temp_mono = start_mono
    consecutive_abort = 0
    samples: list[dict[str, Any]] = []
    stop_triggered = False
    stop_reason: str | None = None
    idx = 0

    with trace_path.open("w", encoding="utf-8") as trace_fh:
        while True:
            live_pids = pgid_non_zombie_pids(args.pgid)
            if not live_pids:
                break

            now_mono = time.monotonic()
            offset_s = now_mono - start_mono
            reading = sample_sensors(sysfs_root, vcgencmd_path)
            sample = {
                "sample_index": idx,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "offset_s": offset_s,
                **reading,
            }
            samples.append(sample)
            trace_fh.write(json.dumps(sample) + "\n")
            trace_fh.flush()
            idx += 1

            temp_c = sample["temperature_c"]
            if temp_c is not None:
                last_valid_temp_mono = now_mono
                if temp_c >= args.abort_c:
                    consecutive_abort += 1
                else:
                    consecutive_abort = 0
            else:
                consecutive_abort = 0

            triggers: list[str] = []
            if args.stop_file is not None and args.stop_file.exists():
                triggers.append("STOP_FILE")
            if consecutive_abort >= args.abort_consecutive:
                triggers.append("TEMP_ABORT")
            throttled_info = sample["throttled"]
            if isinstance(throttled_info, dict) and throttled_info.get("current_mask"):
                triggers.append("THROTTLE_ACTIVE")
            if temp_c is None and (now_mono - last_valid_temp_mono) > args.sensor_loss_s:
                triggers.append("SENSOR_LOSS")
            mem_avail = sample["mem_available_bytes"]
            if mem_avail is not None and mem_avail < min_avail_bytes:
                triggers.append("MEM_LOW")

            if triggers:
                stop_triggered = True
                stop_reason = triggers[0]
                sigterm_sent, escalated, remaining = _kill_process_group(
                    args.pgid, args.kill_grace_seconds
                )
                stop_payload = {
                    "schema_version": 1,
                    "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
                    "pgid": args.pgid,
                    "reason": stop_reason,
                    "triggers": triggers,
                    "offset_s": offset_s,
                    "sigterm_sent": sigterm_sent,
                    "escalated_to_sigkill": escalated,
                    "kill_grace_seconds": args.kill_grace_seconds,
                    "remaining_non_zombie_pids": remaining,
                    "trigger_sample": sample,
                }
                _atomic_write_json(stop_path, stop_payload)
                break

            next_tick = start_mono + idx * interval
            while True:
                if args.stop_file is not None and args.stop_file.exists():
                    break
                if not pgid_non_zombie_pids(args.pgid):
                    break
                remaining = next_tick - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.1, remaining))

    duration_seconds = time.monotonic() - start_mono
    summary = _build_thermal_summary(
        samples=samples,
        duration_seconds=duration_seconds,
        sample_interval=interval,
        sustain_c=args.sustain_c,
        abort_c=args.abort_c,
        stop_triggered=stop_triggered,
        stop_reason=stop_reason,
    )
    _atomic_write_json(summary_path, summary)
    return 3 if stop_triggered else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="mode", required=True)

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--sysfs-root", type=Path, default=Path("/"), help="Root prefix for sysfs/procfs (tests)")
        sp.add_argument("--vcgencmd", type=str, default=None, help="Path to vcgencmd (empty string disables)")
        sp.add_argument("--sample-interval", type=float, default=1.0, help="Sampling interval in seconds")

    p_idle = sub.add_parser("idle", help="Measure idle baseline and suggest start gate")
    add_common(p_idle)
    p_idle.add_argument("--seconds", type=float, default=600.0)
    p_idle.add_argument("--out", type=Path, required=True)

    p_wait = sub.add_parser("wait", help="Wait until temperature stays <= threshold for stable window")
    add_common(p_wait)
    p_wait.add_argument("--below", type=float, required=True)
    p_wait.add_argument("--stable-seconds", type=float, default=60.0)
    p_wait.add_argument("--tolerance-c", type=float, default=0.5)
    p_wait.add_argument("--max-wait", type=float, default=1800.0)
    p_wait.add_argument("--out", type=Path, required=True)

    p_watch = sub.add_parser("watch", help="Watch a process group at 1 Hz and enforce §4 stop rules")
    add_common(p_watch)
    p_watch.add_argument("--pgid", type=int, required=True)
    p_watch.add_argument("--out", type=Path, required=True)
    p_watch.add_argument("--sustain-c", type=float, default=75.0)
    p_watch.add_argument("--abort-c", type=float, default=78.0)
    p_watch.add_argument("--abort-consecutive", type=int, default=2)
    p_watch.add_argument("--sensor-loss-s", type=float, default=5.0)
    p_watch.add_argument("--min-avail-gib", type=float, default=1.0)
    p_watch.add_argument("--stop-file", type=Path, default=None)
    p_watch.add_argument("--kill-grace-seconds", type=float, default=10.0)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.sample_interval <= 0:
        parser.error("--sample-interval must be positive")
    if args.mode == "idle":
        return cmd_idle(args)
    if args.mode == "wait":
        return cmd_wait(args)
    if args.mode == "watch":
        return cmd_watch(args)
    parser.error(f"Unknown mode: {args.mode}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
