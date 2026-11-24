"""Host unit and integration tests for Pi 5 thermal tooling (A3–A6)."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _make_fake_sysfs(
    base: Path,
    *,
    temp_millic: int | None = 60000,
    cpufreq_khz: int | None = 1500000,
    fan_rpm: int | None = 3200,
    cooling_state: int | None = 1,
    mem_available_kib: int | None = 8_000_000,
) -> Path:
    root = base / "sysfs_root"
    tz = root / "sys" / "class" / "thermal" / "thermal_zone0"
    tz.mkdir(parents=True, exist_ok=True)
    if temp_millic is not None:
        (tz / "temp").write_text(f"{temp_millic}\n", encoding="utf-8")

    cdev = root / "sys" / "class" / "thermal" / "cooling_device0"
    cdev.mkdir(parents=True, exist_ok=True)
    if cooling_state is not None:
        (cdev / "cur_state").write_text(f"{cooling_state}\n", encoding="utf-8")

    cpufreq = root / "sys" / "devices" / "system" / "cpu" / "cpu0" / "cpufreq"
    cpufreq.mkdir(parents=True, exist_ok=True)
    if cpufreq_khz is not None:
        (cpufreq / "scaling_cur_freq").write_text(f"{cpufreq_khz}\n", encoding="utf-8")

    hwmon = root / "sys" / "class" / "hwmon" / "hwmon2"
    hwmon.mkdir(parents=True, exist_ok=True)
    if fan_rpm is not None:
        (hwmon / "fan1_input").write_text(f"{fan_rpm}\n", encoding="utf-8")

    if mem_available_kib is not None:
        proc_dir = root / "proc"
        proc_dir.mkdir(parents=True, exist_ok=True)
        (proc_dir / "meminfo").write_text(
            f"MemTotal:       16000000 kB\nMemAvailable:   {mem_available_kib} kB\n",
            encoding="utf-8",
        )
    return root


def _make_fake_vcgencmd(base: Path, *, temp_c: float | None = 62.5, throttled: str = "throttled=0x0", arm_hz: int = 2400000000, fail_all: bool = False) -> Path:
    script = base / "fake_vcgencmd.py"
    code = f"""#!/usr/bin/env python3
import sys
if {fail_all!r}:
    sys.exit(1)
args = sys.argv[1:]
if args == ["measure_temp"]:
    if {temp_c!r} is None:
        sys.exit(1)
    print(f"temp={{{temp_c!r}}}'C")
elif args == ["measure_clock", "arm"]:
    print("frequency(0)={arm_hz}")
elif args == ["get_throttled"]:
    print({throttled!r})
elif args == ["pmic_read_adc", "EXT5V_V"]:
    print("   EXT5V_V volt(24)=5.091000V")
else:
    sys.exit(1)
"""
    script.write_text(code, encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def _make_synthetic_trial_assets(tmp_path: Path, *, sleep_on_call_s: float = 0.0, pid_log: Path | None = None) -> Path:
    assets_dir = tmp_path / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    runner = assets_dir / "fake_runner"
    pid_write = (
        f"open({str(pid_log)!r}, 'a').write(str(os.getpid()) + '\\n')\n"
        if pid_log is not None
        else ""
    )
    runner_src = f"""#!{sys.executable}
import argparse, json, os, re, sys, time
{pid_write}p = argparse.ArgumentParser()
p.add_argument("--model_path")
p.add_argument("--tokenizer_path")
p.add_argument("--seq_len")
p.add_argument("--max_new_tokens")
p.add_argument("--cpu_threads")
p.add_argument("--temperature")
p.add_argument("--prompt", required=True)
args = p.parse_args()
if {sleep_on_call_s!r} > 0:
    time.sleep({sleep_on_call_s!r})
targets = re.findall(r"Target line:\\n(WHY: [^\\n<]+)", args.prompt)
why_line = targets[-1] if targets else "WHY: The detector is uncertain."
stats = {{
    "prompt_tokens": 60,
    "generated_tokens": 8,
    "model_load_start_ms": 1000,
    "model_load_end_ms": 1020,
    "inference_start_ms": 1021,
    "prompt_eval_end_ms": 1051,
    "first_token_ms": 1052,
    "inference_end_ms": 1071,
    "decode_token_per_sec": 12.5,
    "SCALING_FACTOR_UNITS_PER_SECOND": 1000,
}}
sys.stdout.write(args.prompt + why_line + "\\nPyTorchObserver " + json.dumps(stats) + "\\n")
"""
    runner.write_text(runner_src, encoding="utf-8")
    runner.chmod(runner.stat().st_mode | stat.S_IEXEC)

    model = assets_dir / "llama3_2.pte"
    model.write_bytes(b"fake pte payload")
    tok = assets_dir / "tokenizer.model"
    tok.write_bytes(b"fake tok payload")

    actual_arch = {"AMD64": "x86_64", "arm64": "aarch64"}.get(platform.machine(), platform.machine())
    manifest = {
        "schema_version": 1,
        "executorch_revision": "a" * 40,
        "target_arch": actual_arch,
        "model_family": "Llama-3.2-1B-Instruct",
        "tokenizer_format": "tiktoken_model",
        "seq_len": 768,
        "max_new_tokens": 48,
        "cpu_threads": 2,
        "timeout_seconds": 30,
        "max_output_bytes": 65536,
        "stdout_mode": "prompt_echo",
        "artifacts": {
            "runner": {"path": "fake_runner", "sha256": hashlib.sha256(runner.read_bytes()).hexdigest()},
            "model": {"path": "llama3_2.pte", "sha256": hashlib.sha256(model.read_bytes()).hexdigest()},
            "tokenizer": {"path": "tokenizer.model", "sha256": hashlib.sha256(tok.read_bytes()).hexdigest()},
            "shared_libraries": [],
        },
    }
    manifest_path = assets_dir / "inference.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path


def test_decode_throttled_bits():
    tm = _load_module("thermal_monitor", "deploy/pi5/thermal_monitor.py")

    d1 = tm.decode_throttled("throttled=0xe0008")
    assert d1["value"] == 0xE0008
    assert d1["current_mask"] == 0x8
    assert d1["current"] == {
        "under_voltage": False,
        "arm_freq_capped": False,
        "throttled": False,
        "soft_temp_limit": True,
    }
    assert d1["sticky"] == {
        "under_voltage": False,
        "arm_freq_capped": True,
        "throttled": True,
        "soft_temp_limit": True,
    }

    d2 = tm.decode_throttled("0x50005")
    assert d2["current"] == {
        "under_voltage": True,
        "arm_freq_capped": False,
        "throttled": True,
        "soft_temp_limit": False,
    }
    assert d2["sticky"] == {
        "under_voltage": True,
        "arm_freq_capped": False,
        "throttled": True,
        "soft_temp_limit": False,
    }

    d3 = tm.decode_throttled("throttled=0x0")
    assert d3["current_mask"] == 0
    assert d3["sticky_mask"] == 0
    assert not any(d3["current"].values())
    assert not any(d3["sticky"].values())

    assert tm.decode_throttled(None)["value"] is None


def test_thermal_monitor_sysfs_fallback_and_wait_idle(tmp_path):
    tm = _load_module("thermal_monitor", "deploy/pi5/thermal_monitor.py")

    sysfs_root = _make_fake_sysfs(tmp_path, temp_millic=61250, cpufreq_khz=1800000, fan_rpm=4100, cooling_state=2)
    # Failing vcgencmd triggers sysfs and cpufreq fallback cleanly
    bad_vcg = _make_fake_vcgencmd(tmp_path, fail_all=True)
    sample = tm.sample_sensors(sysfs_root, str(bad_vcg))
    assert sample["temperature_c"] == pytest.approx(61.25)
    assert sample["temp_source"] == "sysfs"
    assert sample["arm_hz"] == 1800000000
    assert sample["arm_hz_source"] == "cpufreq"
    assert sample["fan_rpm"] == 4100
    assert "hwmon2/fan1_input" in sample["fan_rpm_path"]
    assert sample["cooling_states"] == {"cooling_device0": 2}

    # Good vcgencmd takes priority and collects EXT5V_V
    good_vcg = _make_fake_vcgencmd(tmp_path, temp_c=64.0, throttled="throttled=0x0", arm_hz=2400000000)
    sample2 = tm.sample_sensors(sysfs_root, str(good_vcg))
    assert sample2["temperature_c"] == pytest.approx(64.0)
    assert sample2["temp_source"] == "vcgencmd"
    assert sample2["arm_hz"] == 2400000000
    assert sample2["arm_hz_source"] == "vcgencmd"
    assert sample2["ext5v_v"] == pytest.approx(5.091)

    # Idle mode reports mean and suggested start gate = mean + 2
    idle_out = tmp_path / "idle.json"
    rc_idle = tm.main([
        "idle",
        "--sysfs-root", str(sysfs_root),
        "--sample-interval", "0.05",
        "--seconds", "0.12",
        "--out", str(idle_out),
    ])
    assert rc_idle == 0
    idle_data = json.loads(idle_out.read_text(encoding="utf-8"))
    assert idle_data["idle_mean_c"] == pytest.approx(61.25)
    assert idle_data["suggested_start_gate_c"] == pytest.approx(63.25)

    # Wait pass
    wait_ok = tmp_path / "wait_ok.json"
    rc_wait_ok = tm.main([
        "wait",
        "--sysfs-root", str(sysfs_root),
        "--below", "62.0",
        "--stable-seconds", "0.1",
        "--max-wait", "1.0",
        "--sample-interval", "0.05",
        "--out", str(wait_ok),
    ])
    assert rc_wait_ok == 0
    assert json.loads(wait_ok.read_text(encoding="utf-8"))["status"] == "READY"

    # Wait timeout -> exit 4
    wait_to = tmp_path / "wait_to.json"
    rc_wait_to = tm.main([
        "wait",
        "--sysfs-root", str(sysfs_root),
        "--below", "55.0",
        "--stable-seconds", "0.1",
        "--max-wait", "0.12",
        "--sample-interval", "0.05",
        "--out", str(wait_to),
    ])
    assert rc_wait_to == 4
    assert json.loads(wait_to.read_text(encoding="utf-8"))["status"] == "TIMEOUT"


def test_thermal_monitor_simulated_78c_cutoff_consecutive_logic_and_kill(tmp_path):
    tm = _load_module("thermal_monitor", "deploy/pi5/thermal_monitor.py")
    sysfs_root = _make_fake_sysfs(tmp_path, temp_millic=74000)

    # Deterministic temperature sequence per 1 Hz poll:
    # 74.0 -> 78.2 (1st >=78, must NOT abort) -> 76.0 (resets streak) -> 78.4 (1st) -> 78.5 (2nd -> TEMP_ABORT)
    seq_file = tmp_path / "temp_idx.txt"
    seq_file.write_text("0\n", encoding="utf-8")
    seq_vcg = tmp_path / "seq_vcgencmd.py"
    seq_vcg.write_text(
        f"""#!/usr/bin/env python3
from pathlib import Path
import sys
args = sys.argv[1:]
temps = [74.0, 78.2, 76.0, 78.4, 78.5]
idx_path = Path({str(seq_file)!r})
if args == ["measure_temp"]:
    idx = int(idx_path.read_text().strip())
    val = temps[min(idx, len(temps) - 1)]
    idx_path.write_text(str(idx + 1) + "\\n")
    print(f"temp={{val}}'C")
elif args == ["get_throttled"]:
    print("throttled=0x0")
elif args == ["measure_clock", "arm"]:
    print("frequency(0)=2400000000")
else:
    sys.exit(1)
""",
        encoding="utf-8",
    )
    seq_vcg.chmod(seq_vcg.stat().st_mode | stat.S_IEXEC)

    # Spawn a real isolated process group running a long sleep
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    out_dir = tmp_path / "watch_78c"
    try:
        rc = tm.main([
            "watch",
            "--pgid", str(proc.pid),
            "--out", str(out_dir),
            "--sysfs-root", str(sysfs_root),
            "--vcgencmd", str(seq_vcg),
            "--sample-interval", "0.05",
            "--sustain-c", "75",
            "--abort-c", "78",
            "--abort-consecutive", "2",
            "--kill-grace-seconds", "1.0",
        ])
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)

    assert rc == 3
    stop_data = json.loads((out_dir / "stop.json").read_text(encoding="utf-8"))
    assert stop_data["reason"] == "TEMP_ABORT"
    assert stop_data["sigterm_sent"] is True
    assert stop_data["remaining_non_zombie_pids"] == []
    assert stop_data["trigger_sample"]["temperature_c"] == pytest.approx(78.5)

    summary = json.loads((out_dir / "thermal-summary.json").read_text(encoding="utf-8"))
    assert summary["stop_triggered"] is True
    assert summary["stop_reason"] == "TEMP_ABORT"
    assert summary["peak_temp_c"] == pytest.approx(78.5)
    assert summary["time_to_sustain_s"] is not None
    assert summary["time_to_abort_s"] is not None
    trace_temps = [
        json.loads(line)["temperature_c"]
        for line in (out_dir / "thermal.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert trace_temps == [
        pytest.approx(74.0),
        pytest.approx(78.2),
        pytest.approx(76.0),
        pytest.approx(78.4),
        pytest.approx(78.5),
    ]


@pytest.mark.parametrize(
    "mode",
    ["SENSOR_LOSS", "THROTTLE_ACTIVE", "MEM_LOW", "STOP_FILE", "SIGKILL_ESCALATION"],
)
def test_thermal_monitor_stop_rules_and_sigkill_escalation(tmp_path, mode):
    tm = _load_module("thermal_monitor", "deploy/pi5/thermal_monitor.py")
    sysfs_root = _make_fake_sysfs(tmp_path, temp_millic=62000)
    vcg_arg = []
    stop_file = tmp_path / "STOP"
    extra_args = []

    if mode == "SENSOR_LOSS":
        (sysfs_root / "sys" / "class" / "thermal" / "thermal_zone0" / "temp").unlink()
        extra_args = ["--sensor-loss-s", "0.12"]
    elif mode == "THROTTLE_ACTIVE":
        fake_vcg = _make_fake_vcgencmd(tmp_path, temp_c=65.0, throttled="throttled=0xe0008")
        vcg_arg = ["--vcgencmd", str(fake_vcg)]
    elif mode == "MEM_LOW":
        (sysfs_root / "proc" / "meminfo").write_text("MemTotal: 16000000 kB\nMemAvailable: 500000 kB\n", encoding="utf-8")
        extra_args = ["--min-avail-gib", "1.0"]
    elif mode == "STOP_FILE":
        stop_file.write_text("halt\n", encoding="utf-8")
        extra_args = ["--stop-file", str(stop_file)]
    elif mode == "SIGKILL_ESCALATION":
        extra_args = ["--stop-file", str(stop_file), "--kill-grace-seconds", "0.15"]

    ready_file = tmp_path / "sigkill_child.ready"
    if mode == "SIGKILL_ESCALATION":
        child_cmd = [
            sys.executable,
            "-c",
            (
                "import os, pathlib, signal, time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"tmp = pathlib.Path({str(ready_file) + '.tmp'!r}); "
                "tmp.write_text(str(os.getpid()), encoding='utf-8'); "
                f"os.replace(tmp, {str(ready_file)!r}); "
                "time.sleep(30)"
            ),
        ]
    else:
        child_cmd = [sys.executable, "-c", "import time; time.sleep(30)"]

    proc = subprocess.Popen(child_cmd, start_new_session=True)
    out_dir = tmp_path / f"watch_{mode}"
    try:
        if mode == "SIGKILL_ESCALATION":
            # Synchronize SIGTERM ignore handler readiness before arming STOP_FILE.
            deadline = time.monotonic() + 5.0
            while not ready_file.exists():
                if proc.poll() is not None:
                    raise AssertionError(f"SIGKILL test child exited early with code {proc.returncode}")
                if time.monotonic() >= deadline:
                    raise AssertionError("SIGKILL test child failed to arm SIGTERM handler")
                time.sleep(0.02)
            stop_file.write_text("halt\n", encoding="utf-8")
        rc = tm.main([
            "watch",
            "--pgid", str(proc.pid),
            "--out", str(out_dir),
            "--sysfs-root", str(sysfs_root),
            "--sample-interval", "0.05",
            *vcg_arg,
            *extra_args,
        ])
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)

    assert rc == 3
    stop_data = json.loads((out_dir / "stop.json").read_text(encoding="utf-8"))
    expected_reason = "STOP_FILE" if mode == "SIGKILL_ESCALATION" else mode
    assert stop_data["reason"] == expected_reason
    assert stop_data["remaining_non_zombie_pids"] == []
    if mode == "SIGKILL_ESCALATION":
        assert stop_data["escalated_to_sigkill"] is True


def test_make_trial_manifest_preserves_artifacts_and_refuses_overwrite(tmp_path, capsys):
    mtm = _load_module("make_trial_manifest", "deploy/pi5/make_trial_manifest.py")
    base = _make_synthetic_trial_assets(tmp_path)
    base_data = json.loads(base.read_text(encoding="utf-8"))

    rc = mtm.main(["--base", str(base), "--name", "t1", "--cpu-threads", "1"])
    assert rc == 0
    out_line = capsys.readouterr().out.strip()
    out_path = base.parent / "trial-pi5-t1.json"
    assert out_path.is_file()
    expected_sha = hashlib.sha256(out_path.read_bytes()).hexdigest()
    assert out_line == f"{expected_sha}  {out_path}"

    cloned = json.loads(out_path.read_text(encoding="utf-8"))
    assert cloned["cpu_threads"] == 1
    assert cloned["artifacts"] == base_data["artifacts"]
    assert {k: v for k, v in cloned.items() if k != "cpu_threads"} == {
        k: v for k, v in base_data.items() if k != "cpu_threads"
    }

    # Refuse overwrite
    assert mtm.main(["--base", str(base), "--name", "t1", "--cpu-threads", "3"]) == 2
    assert json.loads(out_path.read_text(encoding="utf-8"))["cpu_threads"] == 1

    # Invalid cpu_threads
    with pytest.raises(SystemExit):
        mtm.main(["--base", str(base), "--name", "t5", "--cpu-threads", "5"])


def test_thermal_trial_sh_end_to_end_normal_stop_and_simulated_78c_cutoff(tmp_path):
    # 1. Normal completed trial with start gate
    manifest_ok = _make_synthetic_trial_assets(tmp_path / "ok_run", sleep_on_call_s=0.02)
    sysfs_ok = _make_fake_sysfs(tmp_path / "ok_run", temp_millic=55000, fan_rpm=3000)
    trials_root = tmp_path / "trials"

    env = {
        **os.environ,
        "COOLING_NOTE": "passive heatsink, no case",
        "AMBIENT_C": "22",
    }
    res_ok = subprocess.run(
        [
            "bash",
            str(ROOT / "deploy/pi5/thermal_trial.sh"),
            "--run-id", "host-ok-01",
            "--manifest", str(manifest_ok),
            "--out-root", str(trials_root),
            "--repetitions", "3",
            "--start-below-c", "60",
            "--stable-seconds", "0.05",
            "--sample-interval", "0.05",
            "--sysfs-root", str(sysfs_ok),
            "--python", sys.executable,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert res_ok.returncode == 0, res_ok.stderr
    trial_ok = trials_root / "host-ok-01"
    for fname in (
        "trial.json",
        "benchmark.json",
        "benchmark.json.partial.jsonl",
        "thermal.jsonl",
        "thermal-summary.json",
        "wait.json",
        "system-before.txt",
        "system-after.txt",
        "process-resources.txt",
        "cleanup.txt",
        "manifest.json",
        "manifest.sha256",
    ):
        assert (trial_ok / fname).is_file(), f"Missing {fname}"
    assert (trial_ok / "cleanup.txt").read_text(encoding="utf-8").strip() == ""
    t_ok = json.loads((trial_ok / "trial.json").read_text(encoding="utf-8"))
    assert t_ok["status"] == "COMPLETED"
    assert t_ok["cooling_note"] == "passive heatsink, no case"
    assert t_ok["llama_validated_count"] == 3

    # Refuse overwrite of existing run-id
    res_dup = subprocess.run(
        [
            "bash",
            str(ROOT / "deploy/pi5/thermal_trial.sh"),
            "--run-id", "host-ok-01",
            "--manifest", str(manifest_ok),
            "--out-root", str(trials_root),
            "--python", sys.executable,
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert res_dup.returncode == 2

    # 2. Simulated 78 C thermal cutoff during an active child runner
    pid_log_78 = tmp_path / "sim78_pids.txt"
    manifest_78 = _make_synthetic_trial_assets(tmp_path / "sim78_run", sleep_on_call_s=6.0, pid_log=pid_log_78)
    sysfs_78 = _make_fake_sysfs(tmp_path / "sim78_run", temp_millic=71000)
    temp_file_78 = sysfs_78 / "sys" / "class" / "thermal" / "thermal_zone0" / "temp"

    def _simulate_overheat():
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if pid_log_78.is_file() and pid_log_78.read_text(encoding="utf-8").strip():
                break
            time.sleep(0.05)
        temp_file_78.write_text("76200\n", encoding="utf-8")
        time.sleep(0.15)
        temp_file_78.write_text("78600\n", encoding="utf-8")

    sim_thread = threading.Thread(target=_simulate_overheat, daemon=True)
    sim_thread.start()
    res_78 = subprocess.run(
        [
            "bash",
            str(ROOT / "deploy/pi5/thermal_trial.sh"),
            "--run-id", "host-sim78-01",
            "--manifest", str(manifest_78),
            "--out-root", str(trials_root),
            "--repetitions", "5",
            "--sample-interval", "0.08",
            "--sustain-c", "75",
            "--abort-c", "78",
            "--abort-consecutive", "2",
            "--kill-grace-seconds", "2.0",
            "--sysfs-root", str(sysfs_78),
            "--python", sys.executable,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    sim_thread.join(timeout=2)
    assert res_78.returncode == 3, res_78.stderr
    trial_78 = trials_root / "host-sim78-01"
    stop_78 = json.loads((trial_78 / "stop.json").read_text(encoding="utf-8"))
    assert stop_78["reason"] == "TEMP_ABORT"
    bench_78 = json.loads((trial_78 / "benchmark.json").read_text(encoding="utf-8"))
    assert bench_78["completed"] is False
    assert bench_78["stop_reason"] == "SIGTERM"
    tsum_78 = json.loads((trial_78 / "thermal-summary.json").read_text(encoding="utf-8"))
    assert tsum_78["stop_reason"] == "TEMP_ABORT"
    assert tsum_78["peak_temp_c"] >= 78.0
    assert tsum_78["time_to_sustain_s"] is not None
    assert tsum_78["time_to_abort_s"] is not None
    assert (trial_78 / "process-resources.txt").stat().st_size > 0
    assert (trial_78 / "cleanup.txt").read_text(encoding="utf-8").strip() == ""
    for line in pid_log_78.read_text(encoding="utf-8").splitlines():
        if line.strip().isdigit():
            with pytest.raises(ProcessLookupError):
                os.kill(int(line.strip()), 0)

    # 3. STOP-file stop through thermal_trial.sh
    pid_log_stop = tmp_path / "simstop_pids.txt"
    manifest_stop = _make_synthetic_trial_assets(tmp_path / "simstop_run", sleep_on_call_s=6.0, pid_log=pid_log_stop)
    sysfs_stop = _make_fake_sysfs(tmp_path / "simstop_run", temp_millic=62000)

    def _touch_stop():
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if pid_log_stop.is_file() and pid_log_stop.read_text(encoding="utf-8").strip():
                break
            time.sleep(0.05)
        (trials_root / "host-stop-01" / "STOP").write_text("stop\n", encoding="utf-8")

    stop_thread = threading.Thread(target=_touch_stop, daemon=True)
    stop_thread.start()
    res_stop = subprocess.run(
        [
            "bash",
            str(ROOT / "deploy/pi5/thermal_trial.sh"),
            "--run-id", "host-stop-01",
            "--manifest", str(manifest_stop),
            "--out-root", str(trials_root),
            "--repetitions", "5",
            "--sample-interval", "0.08",
            "--kill-grace-seconds", "2.0",
            "--sysfs-root", str(sysfs_stop),
            "--python", sys.executable,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    stop_thread.join(timeout=2)
    assert res_stop.returncode == 3, res_stop.stderr
    trial_stop = trials_root / "host-stop-01"
    assert json.loads((trial_stop / "stop.json").read_text(encoding="utf-8"))["reason"] == "STOP_FILE"
    assert json.loads((trial_stop / "benchmark.json").read_text(encoding="utf-8"))["completed"] is False
    assert (trial_stop / "cleanup.txt").read_text(encoding="utf-8").strip() == ""


def test_compare_trials_loads_b0_legacy_and_compares_new_trials(tmp_path):
    ct = _load_module("compare_trials", "scripts/compare_trials.py")

    # Self-contained synthetic B0-format legacy fixture
    b0_dir = tmp_path / "legacy_b0"
    b0_dir.mkdir()
    (b0_dir / "system-before.txt").write_text("2026-11-18T13:11:23Z\nthermal_zone0_millic=58950\ntemp=59.3'C\nthrottled=0x0\n", encoding="utf-8")
    (b0_dir / "system-after.txt").write_text("2026-11-18T13:22:05Z\ntemp=81.2'C\nthrottled=0xe0000\n", encoding="utf-8")
    b0_samples = []
    for i, temp in enumerate([70.0, 72.5, 75.2, 77.0, 78.4, 80.1]):
        b0_samples.append({
            "detector_ms": 1.6,
            "evidence_ms": 0.1,
            "llama_ms": 6600.0,
            "validation_ms": 0.06,
            "total_ms": 6602.0,
            "source": "Llama (validated)",
            "reason": "ACCEPTED",
            "temperature_c": temp,
            "mem_available_bytes": 15_000_000_000,
            "swap_used_bytes": 0,
            "runner_stats": {
                "SCALING_FACTOR_UNITS_PER_SECOND": 1000,
                "model_load_start_ms": 1000,
                "model_load_end_ms": 2200,
                "inference_start_ms": 2201,
                "prompt_eval_end_ms": 5401,
                "first_token_ms": 5402,
                "inference_end_ms": 6601,
                "generated_tokens": 15,
                "decode_token_per_sec": 13.5,
            },
        })
    b0_bench = {
        "schema_version": 1,
        "runtime_config_sha256": "a" * 64,
        "fixtures": "five fixed synthetic cases; not detection-quality evaluation",
        "repetitions": 6,
        "duration_seconds": 39.7,
        "requested_duration_seconds": 600.0,
        "advisory_policy": "always",
        "runtime_configured": True,
        "llama_validated_count": 6,
        "min_mem_available_bytes": 15_000_000_000,
        "max_swap_used_bytes": 0,
        "temperature_c": {"n": 6, "median": 76.1, "p95": 80.1, "min": 70.0, "max": 80.1},
        "throttled_before": "throttled=0x0",
        "throttled_after": "throttled=0xe0008",
        "timings_ms": {"total_ms": {"n": 6, "median": 6602.0, "p95": 6602.0, "min": 6602.0, "max": 6602.0}},
        "samples": b0_samples,
    }
    (b0_dir / "benchmark.json").write_text(json.dumps(b0_bench), encoding="utf-8")

    # Helper for two comparable paced trials
    def write_new_trial(name: str, interval_s: float, peak_c: float, p95_c: float, arr_p95_ms: float, late: int, start_below: float):
        d = tmp_path / name
        d.mkdir()
        sticky_clean = {"under_voltage": False, "arm_freq_capped": False, "throttled": False, "soft_temp_limit": False}
        hashes = {"runner": "r1", "model": "m1", "tokenizer": "t1", "shared_libraries": []}
        samples = [
            {
                "request_index": i,
                "fixture_id": f"smoke_{i % 5}",
                "offset_s": i * interval_s,
                "completion_offset_s": i * interval_s + 1.1,
                "detector_ms": 1.5,
                "evidence_ms": 0.1,
                "total_ms": 1100.0,
                "arrival_to_completion_ms": arr_p95_ms if i == 5 else 1100.0,
                "source": "Llama (validated)",
                "reason": "ACCEPTED",
                "temperature_c": p95_c,
            }
            for i in range(6)
        ]
        bench = {
            "schema_version": 1,
            "run_id": name,
            "git_commit": "abc123",
            "effective_settings": {"cpu_threads": 1, "artifacts_sha256": hashes},
            "fixture_set": "smoke",
            "fixture_ids": [s["fixture_id"] for s in samples],
            "repetitions": 6,
            "duration_seconds": 6 * interval_s,
            "offered_interval_seconds": interval_s,
            "planned_scheduled_starts": 6,
            "scheduled_starts": 6,
            "actual_starts": 6,
            "late_starts": late,
            "completed": True,
            "stop_reason": None,
            "advisory_policy": "always",
            "runtime_configured": True,
            "llama_validated_count": 6,
            "validated_per_minute": 6 / (6 * interval_s / 60.0),
            "reason_counts": {"ACCEPTED": 6},
            "min_mem_available_bytes": 12_000_000_000,
            "max_swap_used_bytes": 0,
            "start_delay_ms": {"n": 6, "median": 0.0, "p95": 5.0 if late == 0 else 400.0, "min": 0.0, "max": 5.0 if late == 0 else 400.0},
            "arrival_to_completion_ms": {"n": 6, "median": 1100.0, "p95": arr_p95_ms, "min": 1100.0, "max": arr_p95_ms},
            "timings_ms": {"total_ms": {"n": 6, "median": 1100.0, "p95": 1100.0, "min": 1100.0, "max": 1100.0}},
            "samples": samples,
        }
        (d / "benchmark.json").write_text(json.dumps(bench), encoding="utf-8")
        (d / "trial.json").write_text(
            json.dumps({
                "run_id": name,
                "git_commit": "abc123",
                "cooling_note": "passive heatsink",
                "ambient_c": "22",
                "parameters": {"start_below_c": start_below},
            }),
            encoding="utf-8",
        )
        (d / "thermal-summary.json").write_text(
            json.dumps({
                "start_temp_c": 58.0,
                "peak_temp_c": peak_c,
                "mean_temp_c": p95_c - 2.0,
                "p95_temp_c": p95_c,
                "end_temp_c": p95_c - 1.0,
                "time_to_sustain_s": 12.0 if peak_c >= 75.0 else None,
                "time_to_abort_s": None,
                "coverage": 1.0,
                "max_gap_s": 1.0,
                "current_bits_seen": [],
                "sticky_at_start": sticky_clean,
                "sticky_at_end": sticky_clean,
                "rising_at_end": False,
                "min_mem_available_bytes": 12_000_000_000,
            }),
            encoding="utf-8",
        )
        (d / "cleanup.txt").write_text("", encoding="utf-8")
        return d

    t_pass = write_new_trial("paced-pass", interval_s=12.0, peak_c=71.0, p95_c=70.0, arr_p95_ms=1500.0, late=0, start_below=60.0)
    t_fail = write_new_trial("paced-fail", interval_s=6.0, peak_c=76.5, p95_c=75.5, arr_p95_ms=2500.0, late=2, start_below=63.0)

    out_prefix = tmp_path / "out" / "cmp"
    report = ct.compare([b0_dir, t_pass, t_fail], out_prefix)
    assert (tmp_path / "out" / "cmp.json").is_file()
    assert (tmp_path / "out" / "cmp.md").is_file()

    by_id = {t["run_id"]: t for t in report["trials"]}
    assert by_id["legacy_b0"]["resolution"] == "LOW-RESOLUTION"
    assert by_id["legacy_b0"]["first_req_at_sustain"] == 3
    assert by_id["legacy_b0"]["first_req_at_abort"] == 5
    assert by_id["legacy_b0"]["verdict"]["verdict"] == "REFERENCE_LOW_RES"

    assert by_id["paced-pass"]["verdict"]["verdict"] == "PASS"
    assert by_id["paced-pass"]["scheduled_starts"] == 6
    assert by_id["paced-pass"]["actual_starts"] == 6
    assert by_id["paced-pass"]["late_starts"] == 0
    assert by_id["paced-pass"]["arrival_to_completion_ms"]["p95"] == 1500.0
    assert by_id["paced-fail"]["verdict"]["verdict"] == "FAIL"
    assert "budget_paced_arrival_p95_ok" in by_id["paced-fail"]["verdict"]["failed_checks"]
    assert "budget_paced_no_late_starts" in by_id["paced-fail"]["verdict"]["failed_checks"]
    assert "thermal_p95_le_sustain" in by_id["paced-fail"]["verdict"]["failed_checks"]

    comp = report["comparability"]
    assert comp["comparable"] is False
    assert comp["checks"]["start_gate_c"]["status"] == "MISMATCH"
    assert comp["checks"]["offered_interval_seconds"]["status"] == "MISMATCH"
    md = (tmp_path / "out" / "cmp.md").read_text(encoding="utf-8")
    assert "LOW-RESOLUTION" in md
    assert "Paced Arrival-to-Completion Metrics" in md
