#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
if [[ -f BUNDLE_MANIFEST.json ]]; then
  python3 scripts/verify_bundle.py
fi
python3 deploy/pi4/verify_environment.py
bash deploy/pi4/install_dependencies.sh
echo 'Detector environment installed. Llama remains unavailable until approved artifacts and manifest are provisioned.'
echo 'Next: .venv/bin/python deploy/pi4/verify_environment.py --runtime configs/inference.json'
