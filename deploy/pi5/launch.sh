#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
unset PYTHONPATH PYTHONHOME
.venv/bin/python deploy/pi5/verify_environment.py --runtime configs/inference.json
exec .venv/bin/python -m edgeshield.cli --runtime-config configs/inference.json "$@"
