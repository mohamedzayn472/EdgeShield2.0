#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
[[ $(uname -m) == aarch64 ]] || { echo 'Requires target aarch64; never copy host venv.' >&2; exit 2; }
python3 -c 'import sys; assert sys.version_info[:2] == (3,11), "Bundled wheelhouse requires CPython 3.11"'
[[ -d wheelhouse/pi4-cp311 ]] || { echo 'Offline target wheelhouse missing; provision before demo.' >&2; exit 2; }
[[ ! -e .venv/Scripts/python.exe ]] || { echo 'Windows host .venv detected. Copy deployment bundle without host environments.' >&2; exit 2; }
python3 -m venv .venv
.venv/bin/python -m pip install --no-index --find-links wheelhouse/pi4-cp311 -r requirements/pi4.txt
.venv/bin/python -m pip install --no-index --no-deps --no-build-isolation .
.venv/bin/python -m pip check
