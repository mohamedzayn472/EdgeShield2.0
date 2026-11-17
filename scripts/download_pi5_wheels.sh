#!/usr/bin/env bash
# Cross-download target aarch64 binary wheels on Ubuntu without installing them on the host.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

PYTHON="$ROOT/.venv-host/bin/python"
[[ -x "$PYTHON" ]] || { echo "Missing host Python at $PYTHON" >&2; exit 2; }

if [[ $# -eq 0 ]]; then
  TARGETS=(3.13)
else
  TARGETS=("$@")
fi

for raw in "${TARGETS[@]}"; do
  case "$raw" in
    3.10|310|cp310) PYVER="310"; TAG="cp310" ;;
    3.11|311|cp311) PYVER="311"; TAG="cp311" ;;
    3.12|312|cp312) PYVER="312"; TAG="cp312" ;;
    3.13|313|cp313) PYVER="313"; TAG="cp313" ;;
    *)
      echo "Unsupported target Python version '$raw'. Supported: 3.10, 3.11, 3.12, 3.13 (>=3.10,<3.14)." >&2
      exit 2
      ;;
  esac
  DEST="$ROOT/wheelhouse/pi5-${TAG}-aarch64"
  rm -rf "$DEST"
  mkdir -p "$DEST"
  echo "Downloading aarch64 wheels for Python $PYVER ($TAG) into $DEST..."
  env -u PYTHONPATH -u PYTHONHOME "$PYTHON" -m pip download \
    --only-binary=:all: \
    --platform manylinux2014_aarch64 \
    --platform manylinux_2_27_aarch64 \
    --platform manylinux_2_28_aarch64 \
    --implementation cp \
    --python-version "$PYVER" \
    --abi "$TAG" \
    --dest "$DEST" \
    -r "$ROOT/requirements/pi5.txt"
  (cd "$DEST" && sha256sum ./*.whl > SHA256SUMS)
  echo "Verified wheel checksums written to $DEST/SHA256SUMS"
done
