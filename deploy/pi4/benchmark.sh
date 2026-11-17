#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
mkdir -p results/pi4
.venv/bin/python deploy/pi4/verify_environment.py --runtime configs/inference.json --output results/pi4/environment.json
command -v /usr/bin/time >/dev/null || { echo 'Install GNU time during provisioning.' >&2; exit 2; }
/usr/bin/time -v -o results/pi4/process-resources.txt .venv/bin/python -m edgeshield.benchmarking --runtime-config configs/inference.json --duration 600 --repetitions 30 --output results/pi4/benchmark.json
echo 'Inspect Llama validated count and fallback rate; measurements alone do not prove successful Llama output.'
