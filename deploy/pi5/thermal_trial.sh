#!/usr/bin/env bash
# Supervised Pi 5 thermal trial wrapper: start gate, 1 Hz monitor, setsid benchmark, cleanup check, trial.json.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
unset PYTHONPATH PYTHONHOME

RUN_ID=""
MANIFEST=""
REPETITIONS=30
DURATION=0
INTERVAL_SECONDS=0
FIXTURES="smoke"
START_BELOW_C=""
SUSTAIN_C=75
ABORT_C=78
OUT_ROOT="results/pi5/trials"
ADVISORY_POLICY="always"
STABLE_SECONDS=60
MAX_WAIT=1800
ABORT_CONSECUTIVE=2
SENSOR_LOSS_S=5
MIN_AVAIL_GIB=1
SAMPLE_INTERVAL=1.0
KILL_GRACE_SECONDS=10.0
SYSFS_ROOT=""
VCGENCMD_BIN=""
HAS_VCGENCMD_ARG=false
PYTHON_BIN=".venv/bin/python"

usage() {
  cat >&2 <<'EOF'
Usage: bash deploy/pi5/thermal_trial.sh --run-id ID --manifest PATH [options]
  --repetitions N           (default: 30)
  --duration S              (default: 0)
  --interval-seconds S      (default: 0)
  --fixtures SET            smoke|holdout30|holdout132 (default: smoke)
  --start-below-c C         optional start temperature gate
  --sustain-c C             (default: 75)
  --abort-c C               (default: 78)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id) RUN_ID="${2:?missing value for --run-id}"; shift 2 ;;
    --manifest) MANIFEST="${2:?missing value for --manifest}"; shift 2 ;;
    --repetitions) REPETITIONS="${2:?missing value for --repetitions}"; shift 2 ;;
    --duration) DURATION="${2:?missing value for --duration}"; shift 2 ;;
    --interval-seconds) INTERVAL_SECONDS="${2:?missing value for --interval-seconds}"; shift 2 ;;
    --fixtures) FIXTURES="${2:?missing value for --fixtures}"; shift 2 ;;
    --start-below-c) START_BELOW_C="${2:-}"; shift 2 ;;
    --sustain-c) SUSTAIN_C="${2:?missing value for --sustain-c}"; shift 2 ;;
    --abort-c) ABORT_C="${2:?missing value for --abort-c}"; shift 2 ;;
    --out-root) OUT_ROOT="${2:?missing value for --out-root}"; shift 2 ;;
    --advisory-policy) ADVISORY_POLICY="${2:?missing value for --advisory-policy}"; shift 2 ;;
    --stable-seconds) STABLE_SECONDS="${2:?missing value for --stable-seconds}"; shift 2 ;;
    --max-wait) MAX_WAIT="${2:?missing value for --max-wait}"; shift 2 ;;
    --abort-consecutive) ABORT_CONSECUTIVE="${2:?missing value for --abort-consecutive}"; shift 2 ;;
    --sensor-loss-s) SENSOR_LOSS_S="${2:?missing value for --sensor-loss-s}"; shift 2 ;;
    --min-avail-gib) MIN_AVAIL_GIB="${2:?missing value for --min-avail-gib}"; shift 2 ;;
    --sample-interval) SAMPLE_INTERVAL="${2:?missing value for --sample-interval}"; shift 2 ;;
    --kill-grace-seconds) KILL_GRACE_SECONDS="${2:?missing value for --kill-grace-seconds}"; shift 2 ;;
    --sysfs-root) SYSFS_ROOT="${2:?missing value for --sysfs-root}"; shift 2 ;;
    --vcgencmd) VCGENCMD_BIN="${2:-}"; HAS_VCGENCMD_ARG=true; shift 2 ;;
    --python) PYTHON_BIN="${2:?missing value for --python}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$RUN_ID" && -n "$MANIFEST" ]] || { usage; exit 2; }
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || {
  echo "Invalid --run-id '$RUN_ID': use [A-Za-z0-9][A-Za-z0-9._-]{0,127}" >&2
  exit 2
}
[[ -f "$MANIFEST" ]] || { echo "Manifest not found: $MANIFEST" >&2; exit 2; }
[[ -x "$PYTHON_BIN" ]] || { echo "Python interpreter not executable: $PYTHON_BIN" >&2; exit 2; }
command -v /usr/bin/time >/dev/null || { echo 'Install GNU time (sudo apt install time).' >&2; exit 2; }
command -v setsid >/dev/null || { echo 'Missing setsid utility.' >&2; exit 2; }

COOLING_NOTE="${COOLING_NOTE:-unknown}"
AMBIENT_C="${AMBIENT_C:-unknown}"
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")

mkdir -p "$OUT_ROOT"
TRIAL_DIR="$OUT_ROOT/$RUN_ID"
if ! mkdir "$TRIAL_DIR" 2>/dev/null; then
  echo "Refusing to overwrite existing trial directory: $TRIAL_DIR" >&2
  exit 2
fi

cp -p "$MANIFEST" "$TRIAL_DIR/manifest.json"
MANIFEST_SHA256=$("$PYTHON_BIN" -c 'import hashlib, sys; from pathlib import Path; print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())' "$TRIAL_DIR/manifest.json")
printf '%s  manifest.json\n' "$MANIFEST_SHA256" > "$TRIAL_DIR/manifest.sha256"

capture_sys() {
  local out="$1"
  {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
    echo "COOLING_NOTE=$COOLING_NOTE"
    echo "AMBIENT_C=$AMBIENT_C"
    echo "GIT_COMMIT=$GIT_COMMIT"
    uname -a
    uptime || true
    free -h
    grep -E '^(MemTotal|MemFree|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null || true
    swapon --show 2>/dev/null || true
    [[ -r /sys/class/thermal/thermal_zone0/temp ]] && echo "thermal_zone0_millic=$(cat /sys/class/thermal/thermal_zone0/temp)" || true
    [[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq ]] && echo "scaling_cur_freq_khz=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq)" || true
    if command -v vcgencmd >/dev/null 2>&1; then
      vcgencmd measure_temp || true
      vcgencmd get_throttled || true
      vcgencmd measure_clock arm || true
    fi
    grep -H . /sys/class/hwmon/hwmon*/name /sys/class/hwmon/hwmon*/fan1_input /sys/class/thermal/cooling_device*/cur_state 2>/dev/null || true
  } > "$out"
}

write_trial_json() {
  local status="$1"
  local bench_rc="$2"
  local monitor_rc="$3"
  local wait_rc="$4"
  local start_utc="$5"
  local end_utc="$6"
  "$PYTHON_BIN" - "$TRIAL_DIR" "$RUN_ID" "$MANIFEST" "$MANIFEST_SHA256" \
    "$REPETITIONS" "$DURATION" "$INTERVAL_SECONDS" "$FIXTURES" "$ADVISORY_POLICY" \
    "$START_BELOW_C" "$SUSTAIN_C" "$ABORT_C" "$COOLING_NOTE" "$AMBIENT_C" "$GIT_COMMIT" \
    "$status" "$bench_rc" "$monitor_rc" "$wait_rc" "$start_utc" "$end_utc" <<'PY'
import json
from pathlib import Path
import sys

(
    trial_dir_s, run_id, manifest_path, manifest_sha256,
    reps_s, dur_s, interval_s, fixtures, policy,
    start_below_s, sustain_s, abort_s, cooling_note, ambient_c, git_commit,
    status, bench_rc_s, monitor_rc_s, wait_rc_s, start_utc, end_utc,
) = sys.argv[1:]

trial_dir = Path(trial_dir_s)

def load_opt(name: str):
    p = trial_dir / name
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None

cleanup_path = trial_dir / "cleanup.txt"
cleanup_lines = []
if cleanup_path.is_file():
    cleanup_lines = [line for line in cleanup_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]

stop_data = load_opt("stop.json")
bench_data = load_opt("benchmark.json")
thermal_data = load_opt("thermal-summary.json")
wait_data = load_opt("wait.json")

payload = {
    "schema_version": 1,
    "run_id": run_id,
    "status": status,
    "start_utc": start_utc,
    "end_utc": end_utc,
    "git_commit": git_commit if git_commit != "unknown" else None,
    "manifest_source_path": manifest_path,
    "manifest_sha256": manifest_sha256,
    "cooling_note": cooling_note,
    "ambient_c": ambient_c,
    "parameters": {
        "repetitions": int(reps_s),
        "duration_seconds": float(dur_s),
        "interval_seconds": float(interval_s),
        "fixtures": fixtures,
        "advisory_policy": policy,
        "start_below_c": float(start_below_s) if start_below_s else None,
        "sustain_c": float(sustain_s),
        "abort_c": float(abort_s),
    },
    "exit_codes": {
        "wait": int(wait_rc_s) if wait_rc_s != "null" else None,
        "benchmark": int(bench_rc_s) if bench_rc_s != "null" else None,
        "monitor": int(monitor_rc_s) if monitor_rc_s != "null" else None,
    },
    "stop_triggered": bool(stop_data) or (isinstance(bench_data, dict) and bench_data.get("completed") is False),
    "stop_reason": (
        stop_data.get("reason")
        if isinstance(stop_data, dict)
        else (bench_data.get("stop_reason") if isinstance(bench_data, dict) else None)
    ),
    "cleanup_leftover_count": len(cleanup_lines),
    "cleanup_leftovers": cleanup_lines,
    "wait_status": wait_data.get("status") if isinstance(wait_data, dict) else None,
    "benchmark_repetitions_completed": bench_data.get("repetitions") if isinstance(bench_data, dict) else None,
    "llama_validated_count": bench_data.get("llama_validated_count") if isinstance(bench_data, dict) else None,
    "thermal_peak_c": thermal_data.get("peak_temp_c") if isinstance(thermal_data, dict) else None,
    "thermal_p95_c": thermal_data.get("p95_temp_c") if isinstance(thermal_data, dict) else None,
    "files_present": sorted(p.name for p in trial_dir.iterdir()),
}
(trial_dir / "trial.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
}

START_UTC=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
capture_sys "$TRIAL_DIR/system-before.txt"

MONITOR_COMMON_ARGS=(--sample-interval "$SAMPLE_INTERVAL")
if [[ -n "$SYSFS_ROOT" ]]; then
  MONITOR_COMMON_ARGS+=(--sysfs-root "$SYSFS_ROOT")
fi
if [[ "$HAS_VCGENCMD_ARG" == true ]]; then
  MONITOR_COMMON_ARGS+=(--vcgencmd "$VCGENCMD_BIN")
fi

WAIT_RC="null"
if [[ -n "$START_BELOW_C" ]]; then
  set +e
  "$PYTHON_BIN" deploy/pi5/thermal_monitor.py wait \
    "${MONITOR_COMMON_ARGS[@]}" \
    --below "$START_BELOW_C" \
    --stable-seconds "$STABLE_SECONDS" \
    --max-wait "$MAX_WAIT" \
    --out "$TRIAL_DIR/wait.json"
  WAIT_RC=$?
  set -e
  if [[ "$WAIT_RC" -ne 0 ]]; then
    END_UTC=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    capture_sys "$TRIAL_DIR/system-after.txt"
    : > "$TRIAL_DIR/cleanup.txt"
    STATUS="WAIT_TIMEOUT"
    [[ "$WAIT_RC" -eq 4 ]] || STATUS="WAIT_FAILED"
    write_trial_json "$STATUS" "null" "null" "$WAIT_RC" "$START_UTC" "$END_UTC"
    exit "$WAIT_RC"
  fi
fi

setsid bash -c 'trap "" TERM INT; exec "$@"' _ \
  /usr/bin/time -v -o "$TRIAL_DIR/process-resources.txt" \
  "$PYTHON_BIN" -m edgeshield.benchmarking \
  --runtime-config "$MANIFEST" \
  --advisory-policy "$ADVISORY_POLICY" \
  --repetitions "$REPETITIONS" \
  --duration "$DURATION" \
  --interval-seconds "$INTERVAL_SECONDS" \
  --fixtures "$FIXTURES" \
  --run-id "$RUN_ID" \
  --stop-file "$TRIAL_DIR/STOP" \
  --output "$TRIAL_DIR/benchmark.json" &
BENCH_PID=$!

# Wait briefly for setsid to establish PGID == BENCH_PID before attaching monitor.
for _ in $(seq 1 100); do
  cur_pgid=$(ps -o pgid= -p "$BENCH_PID" 2>/dev/null | tr -d ' ' || true)
  if [[ "$cur_pgid" == "$BENCH_PID" ]] || ! kill -0 "$BENCH_PID" 2>/dev/null; then
    break
  fi
  sleep 0.02
done

forward_term() {
  kill -TERM -- "-$BENCH_PID" 2>/dev/null || true
}
trap forward_term INT TERM

set +e
"$PYTHON_BIN" deploy/pi5/thermal_monitor.py watch \
  "${MONITOR_COMMON_ARGS[@]}" \
  --pgid "$BENCH_PID" \
  --out "$TRIAL_DIR" \
  --sustain-c "$SUSTAIN_C" \
  --abort-c "$ABORT_C" \
  --abort-consecutive "$ABORT_CONSECUTIVE" \
  --sensor-loss-s "$SENSOR_LOSS_S" \
  --min-avail-gib "$MIN_AVAIL_GIB" \
  --stop-file "$TRIAL_DIR/STOP" \
  --kill-grace-seconds "$KILL_GRACE_SECONDS"
MONITOR_RC=$?

wait "$BENCH_PID"
BENCH_RC=$?
set -e
trap - INT TERM

END_UTC=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
capture_sys "$TRIAL_DIR/system-after.txt"
pgrep -a llama_main > "$TRIAL_DIR/cleanup.txt" || true

STATUS="COMPLETED"
if [[ -s "$TRIAL_DIR/cleanup.txt" ]]; then
  STATUS="CLEANUP_LEFTOVER"
elif [[ "$BENCH_RC" -eq 3 || "$MONITOR_RC" -eq 3 ]]; then
  STATUS="STOPPED"
elif [[ "$BENCH_RC" -ne 0 || "$MONITOR_RC" -ne 0 ]]; then
  STATUS="ERROR"
fi

write_trial_json "$STATUS" "$BENCH_RC" "$MONITOR_RC" "$WAIT_RC" "$START_UTC" "$END_UTC"

echo "Trial $RUN_ID status=$STATUS bench_rc=$BENCH_RC monitor_rc=$MONITOR_RC dir=$TRIAL_DIR"

if [[ -s "$TRIAL_DIR/cleanup.txt" ]]; then
  echo "ERROR: Leftover llama_main processes found in $TRIAL_DIR/cleanup.txt" >&2
  exit 5
fi
if [[ "$BENCH_RC" -eq 3 || "$MONITOR_RC" -eq 3 ]]; then
  exit 3
fi
if [[ "$BENCH_RC" -ne 0 ]]; then
  exit "$BENCH_RC"
fi
exit "$MONITOR_RC"
