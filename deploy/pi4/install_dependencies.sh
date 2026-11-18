#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
[[ $(uname -m) == aarch64 ]] || { echo 'Requires target aarch64; never copy host venv.' >&2; exit 2; }
PYTHON=${EDGESHIELD_PYTHON:-python3}
PY_MM=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
case "$PY_MM" in
  3.11) WHEELHOUSE="wheelhouse/pi4-cp311" ;;
  3.13) WHEELHOUSE="wheelhouse/pi5-cp313-aarch64" ;;
  *)
    echo "Bundled Pi 4 wheelhouses support CPython 3.11 (Bookworm) or 3.13 (Trixie); got $PY_MM" >&2
    exit 2
    ;;
esac
[[ -d "$WHEELHOUSE" ]] || { echo "Offline target wheelhouse missing ($WHEELHOUSE); provision before demo." >&2; exit 2; }
[[ ! -e .venv/Scripts/python.exe ]] || { echo 'Windows host .venv detected. Copy deployment bundle without host environments.' >&2; exit 2; }
"$PYTHON" -m venv .venv
.venv/bin/python -m pip install --no-index --find-links "$WHEELHOUSE" -r requirements/pi4.txt
.venv/bin/python -m pip install --no-index --no-deps --no-build-isolation .
.venv/bin/python -m pip check
