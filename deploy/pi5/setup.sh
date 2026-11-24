#!/usr/bin/env bash
# Provision EdgeShield into .venv on a Raspberry Pi 5 (64-bit aarch64 Linux, Python >=3.10,<3.14).
# Usage: bash deploy/pi5/setup.sh [--offline] [--recreate-venv] [--provision-python]
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"

OFFLINE=false
RECREATE_VENV=false
PROVISION_PYTHON=false

for arg in "$@"; do
  case "$arg" in
    --offline) OFFLINE=true ;;
    --recreate-venv) RECREATE_VENV=true ;;
    --provision-python) PROVISION_PYTHON=true ;;
    -h|--help)
      cat <<'EOF'
Usage: bash deploy/pi5/setup.sh [--offline] [--recreate-venv] [--provision-python]

Options:
  --offline           Require pre-populated wheelhouse/pi5-cp*-aarch64 cache (no network download).
  --recreate-venv     Remove an existing .venv and rebuild it cleanly.
  --provision-python  If no supported system Python (3.10-3.13) is found, install isolated Python 3.12 via uv without altering system Python.
EOF
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      echo "Usage: bash deploy/pi5/setup.sh [--offline] [--recreate-venv] [--provision-python]" >&2
      exit 2
      ;;
  esac
done

unset PYTHONPATH PYTHONHOME

is_supported_python() {
  local py="$1"
  "$py" -c 'import sys; raise SystemExit(0 if (3, 10) <= sys.version_info[:2] < (3, 14) else 1)' >/dev/null 2>&1
}

select_python() {
  if [[ -n "${EDGESHIELD_PYTHON:-}" ]]; then
    if [[ ! -x "$EDGESHIELD_PYTHON" ]] && ! command -v "$EDGESHIELD_PYTHON" >/dev/null 2>&1; then
      echo "EDGESHIELD_PYTHON='$EDGESHIELD_PYTHON' was not found or is not executable." >&2
      exit 2
    fi
    if ! is_supported_python "$EDGESHIELD_PYTHON"; then
      echo "EDGESHIELD_PYTHON='$EDGESHIELD_PYTHON' is outside supported Python >=3.10,<3.14." >&2
      exit 2
    fi
    echo "$EDGESHIELD_PYTHON"
    return 0
  fi

  local candidates=(
    python3
    python3.13
    python3.12
    python3.11
    python3.10
    "$HOME/.local/bin/python3.13"
    "$HOME/.local/bin/python3.12"
    "$HOME/.local/bin/python3.11"
    "$HOME/.local/bin/python3.10"
  )
  if [[ -d "$ROOT/.python-pi5" ]]; then
    while IFS= read -r found; do
      candidates+=("$found")
    done < <(find "$ROOT/.python-pi5" -maxdepth 4 -type f -name 'python3.*' -executable 2>/dev/null || true)
  fi

  for cand in "${candidates[@]}"; do
    if command -v "$cand" >/dev/null 2>&1 || [[ -x "$cand" ]]; then
      if is_supported_python "$cand"; then
        echo "$cand"
        return 0
      fi
    fi
  done
  return 1
}

if ! PYTHON=$(select_python); then
  if [[ "$PROVISION_PYTHON" == true ]]; then
    if [[ "$OFFLINE" == true ]]; then
      echo "Cannot run --provision-python with --offline." >&2
      exit 2
    fi
    if ! command -v uv >/dev/null 2>&1; then
      echo "No supported Python (3.10-3.13) found and 'uv' is unavailable for --provision-python." >&2
      echo "Install Python 3.11/3.12/3.13 separately or install uv, then re-run with EDGESHIELD_PYTHON=/path/to/python3.12." >&2
      exit 2
    fi
    echo "Provisioning isolated Python 3.12 under $ROOT/.python-pi5 (leaving system Python untouched)..."
    UV_PYTHON_INSTALL_DIR="$ROOT/.python-pi5" uv python install 3.12
    PYTHON=$(UV_PYTHON_INSTALL_DIR="$ROOT/.python-pi5" uv python find --managed-python 3.12)
  else
    echo "No supported Python interpreter (>=3.10,<3.14) found (default python3 may be >=3.14 or <3.10)." >&2
    echo "Provide a separate supported interpreter via EDGESHIELD_PYTHON=/path/to/python3.12, or pass --provision-python when uv is installed." >&2
    exit 2
  fi
fi

echo "Selected Python: $PYTHON ($("$PYTHON" --version 2>&1))"

if [[ -f BUNDLE_MANIFEST.json ]]; then
  "$PYTHON" scripts/verify_bundle.py
fi

"$PYTHON" deploy/pi5/verify_environment.py

[[ ! -e .venv/Scripts/python.exe ]] || {
  echo "Windows host .venv detected. Remove host environments and use a clean target extraction." >&2
  exit 2
}

if [[ -e .venv ]]; then
  if [[ "$RECREATE_VENV" == true || ! -f .venv/.edgeshield_complete ]]; then
    echo "Removing incomplete or stale .venv before clean recreation..."
    rm -rf .venv
  else
    echo "Existing complete .venv found. Reuse .venv/bin/python or pass --recreate-venv to rebuild it." >&2
    exit 2
  fi
fi

TAG=$("$PYTHON" -c 'import sys; print(f"cp{sys.version_info.major}{sys.version_info.minor}")')
WHEELS="wheelhouse/pi5-${TAG}-aarch64"

if ! "$PYTHON" -m venv .venv; then
  echo "Failed to create .venv. On Debian/Raspberry Pi OS, ensure python3-venv and python3-pip are installed via apt." >&2
  rm -rf .venv
  exit 2
fi

CACHE_VALID=false
if [[ -f "$WHEELS/SHA256SUMS" ]] && (cd "$WHEELS" && sha256sum --check SHA256SUMS >/dev/null 2>&1); then
  CACHE_VALID=true
fi

if [[ "$CACHE_VALID" == false ]]; then
  if [[ "$OFFLINE" == true ]]; then
    echo "Missing or invalid verified wheel cache at $WHEELS for --offline install." >&2
    echo "Cross-download wheels on Ubuntu with: bash scripts/download_pi5_wheels.sh ${TAG#cp}" >&2
    rm -rf .venv
    exit 2
  fi
  mkdir -p "$WHEELS"
  echo "Downloading binary-only aarch64 wheels for $TAG into $WHEELS..."
  if ! .venv/bin/python -m pip download --only-binary=:all: --dest "$WHEELS" -r requirements/pi5.txt; then
    echo "Wheel download failed for $TAG. Check network connectivity or cross-download matching wheels on Ubuntu." >&2
    rm -rf .venv
    exit 2
  fi
  (cd "$WHEELS" && sha256sum ./*.whl > SHA256SUMS)
fi

(cd "$WHEELS" && sha256sum --check SHA256SUMS)
.venv/bin/python -m pip install --no-index --find-links "$WHEELS" -r requirements/pi5.txt
.venv/bin/python -m pip install --no-index --no-deps --no-build-isolation .
.venv/bin/python -m pip check
touch .venv/.edgeshield_complete

echo "Application installed cleanly into .venv (Python $TAG)."
echo "Next:"
echo "  1. Stage models/llama/ assets and verify with: .venv/bin/python scripts/verify_bundle.py --check-runtime"
echo "  2. Create runtime manifest: .venv/bin/python deploy/pi5/create_manifest.py --profile pi5"
echo "  3. Run smoke test: bash deploy/pi5/smoke_test.sh"
