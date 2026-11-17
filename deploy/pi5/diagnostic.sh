#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
unset PYTHONPATH PYTHONHOME

mkdir -p results/pi5
if [[ -f configs/inference.json ]]; then
  .venv/bin/python deploy/pi5/verify_environment.py --runtime configs/inference.json --output results/pi5/environment.json
else
  .venv/bin/python deploy/pi5/verify_environment.py --output results/pi5/environment.json
fi

{
  echo "=== Timestamp (UTC) ==="
  date -u +"%Y-%m-%dT%H:%M:%SZ"
  echo "=== Device Model ==="
  tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo "UNAVAILABLE"
  echo ""
  echo "=== OS Release ==="
  cat /etc/os-release 2>/dev/null || true
  echo "=== Kernel & Arch ==="
  uname -a
  echo "=== Python ==="
  .venv/bin/python --version 2>&1 || python3 --version 2>&1
  echo "=== GLIBC ==="
  getconf GNU_LIBC_VERSION || ldd --version | head -n 1
  echo "=== Memory & Swap ==="
  free -h
  grep -E '^(MemTotal|MemFree|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null || true
  swapon --show 2>/dev/null || true
  echo "=== Disk ==="
  df -h .
  echo "=== Thermals & Throttling ==="
  if [[ -r /sys/class/thermal/thermal_zone0/temp ]]; then
    echo "thermal_zone0_millic: $(cat /sys/class/thermal/thermal_zone0/temp)"
  fi
  if command -v vcgencmd >/dev/null 2>&1; then
    vcgencmd measure_temp || true
    vcgencmd get_throttled || true
  else
    echo "vcgencmd: unavailable"
  fi
} | tee results/pi5/diagnostics.txt
