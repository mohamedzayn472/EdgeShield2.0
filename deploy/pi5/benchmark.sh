#!/usr/bin/env bash
# Run detector benchmark, short 5-rep Llama validation, and 600-second sustained Pi 5 test.
# Usage: bash deploy/pi5/benchmark.sh [--short-only]
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
unset PYTHONPATH PYTHONHOME

SHORT_ONLY=false
if [[ $# -gt 0 ]]; then
  if [[ $# -eq 1 && $1 == "--short-only" ]]; then
    SHORT_ONLY=true
  else
    echo "Usage: bash deploy/pi5/benchmark.sh [--short-only]" >&2
    exit 2
  fi
fi

[[ -f configs/inference.json ]] || {
  echo "Missing configs/inference.json. Create it first with .venv/bin/python deploy/pi5/create_manifest.py --profile pi5." >&2
  exit 2
}
command -v /usr/bin/time >/dev/null || { echo 'Install GNU time during provisioning (sudo apt install time).' >&2; exit 2; }

mkdir -p results/pi5
.venv/bin/python deploy/pi5/verify_environment.py --runtime configs/inference.json --output results/pi5/environment.json

capture_sys() {
  local out="$1"
  {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
    free -h
    grep -E '^(MemTotal|MemFree|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null || true
    swapon --show 2>/dev/null || true
    [[ -r /sys/class/thermal/thermal_zone0/temp ]] && echo "thermal_zone0_millic=$(cat /sys/class/thermal/thermal_zone0/temp)" || true
    command -v vcgencmd >/dev/null 2>&1 && vcgencmd measure_temp || true
    command -v vcgencmd >/dev/null 2>&1 && vcgencmd get_throttled || true
  } > "$out"
}

capture_sys results/pi5/system-before.txt

echo "1/3 Running standalone detector benchmark (100 reps)..."
.venv/bin/python -m edgeshield.benchmarking --repetitions 100 --advisory-policy off --output results/pi5/benchmark-detector.json

echo "2/3 Running short Llama benchmark (5 reps) before 600-second sustained run..."
/usr/bin/time -v -o results/pi5/process-resources-short.txt \
  .venv/bin/python -m edgeshield.benchmarking --runtime-config configs/inference.json --repetitions 5 --output results/pi5/benchmark-short.json

.venv/bin/python -c '
import json
r = json.load(open("results/pi5/benchmark-short.json", encoding="utf-8"))
assert r["llama_validated_count"] > 0, "No validated Llama output in short benchmark; aborting before 600s run."
print(
    f"Short benchmark: validated={r[\"llama_validated_count\"]}/{r[\"repetitions\"]}, "
    f"child_peak_rss_bytes={r.get(\"runner_child_peak_rss_bytes\")}, "
    f"min_mem_available_bytes={r.get(\"min_mem_available_bytes\")}, "
    f"max_swap_used_bytes={r.get(\"max_swap_used_bytes\")}"
)
'

if [[ "$SHORT_ONLY" == true ]]; then
  capture_sys results/pi5/system-after.txt
  echo "Short-only benchmark finished. Review results/pi5/benchmark-short.json before running the 600s test."
  exit 0
fi

echo "3/3 Running 600-second sustained Llama benchmark (>=30 reps)..."
/usr/bin/time -v -o results/pi5/process-resources.txt \
  .venv/bin/python -m edgeshield.benchmarking --runtime-config configs/inference.json --duration 600 --repetitions 30 --output results/pi5/benchmark.json

capture_sys results/pi5/system-after.txt
.venv/bin/python -c '
import json
r = json.load(open("results/pi5/benchmark.json", encoding="utf-8"))
print(
    f"Sustained 600s benchmark: reps={r[\"repetitions\"]}, validated={r[\"llama_validated_count\"]}, "
    f"fallback_rate={r[\"template_fallback_rate\"]:.3f}, "
    f"child_peak_rss_bytes={r.get(\"runner_child_peak_rss_bytes\")}, "
    f"min_mem_available_bytes={r.get(\"min_mem_available_bytes\")}, "
    f"max_swap_used_bytes={r.get(\"max_swap_used_bytes\")}, "
    f"throttled_before={r.get(\"throttled_before\")}, throttled_after={r.get(\"throttled_after\")}"
)
'
echo 'Inspect Llama validated count, fallback rate, child RSS, swap, and thermals; measurements alone do not prove successful Llama output.'
