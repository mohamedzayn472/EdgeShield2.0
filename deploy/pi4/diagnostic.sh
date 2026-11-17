#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
mkdir -p results/pi4
.venv/bin/python deploy/pi4/verify_environment.py --runtime configs/inference.json --output results/pi4/environment.json
uname -a
getconf GNU_LIBC_VERSION
command -v vcgencmd >/dev/null && vcgencmd measure_temp || true
command -v vcgencmd >/dev/null && vcgencmd get_throttled || true
