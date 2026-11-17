#!/usr/bin/env bash
# Lab smoke test on physical Raspberry Pi 4 after staging models/llama/ and configs/inference.json.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
[[ -f configs/inference.json ]] || {
  echo "Missing configs/inference.json. Create it first with deploy/pi4/create_manifest.py --arch aarch64." >&2
  exit 2
}
mkdir -p results/pi4
.venv/bin/python deploy/pi4/verify_environment.py --runtime configs/inference.json --output results/pi4/environment.json
exec .venv/bin/python -m edgeshield.cli --demo --runtime-config configs/inference.json "$@"
