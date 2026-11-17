#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
command -v ip >/dev/null
command -v strace >/dev/null
mkdir -p results/pi4
echo 'Run at a local console after disabling Wi-Fi and unplugging Ethernet. This script does not disconnect your session.'
ip -j address show > results/pi4/interfaces.json
ip -j route show > results/pi4/routes.json
.venv/bin/python -c 'import json; rows=json.load(open("results/pi4/interfaces.json")); assert not any(r["ifname"]!="lo" and "UP" in r.get("flags",[]) for r in rows), "Non-loopback interface is UP; disconnect before offline evidence run"'
.venv/bin/python deploy/pi4/verify_environment.py --runtime configs/inference.json --output results/pi4/offline-environment.json
# Synthetic fixtures only. strace follows runtime subprocesses; captures attempts even without connectivity.
strace -f -e trace=network -o results/pi4/network.trace .venv/bin/python -m edgeshield.benchmarking --runtime-config configs/inference.json --repetitions 5 --output results/pi4/offline-benchmark.json
.venv/bin/python -c 'import json; r=json.load(open("results/pi4/offline-benchmark.json")); assert r["llama_validated_count"] > 0, "No validated Llama generation; offline compliance NOT established"'
if grep -E 'AF_INET|AF_INET6' results/pi4/network.trace; then
  echo 'Internet-family network activity observed; review trace. Offline verification FAILED.' >&2
  exit 2
fi
echo 'No Internet-family calls seen in this traced run. Inspect logs and record actual device demonstration.'
