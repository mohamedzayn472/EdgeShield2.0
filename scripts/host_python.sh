#!/usr/bin/env bash
# Keep shell-startup ROS packages out of the isolated application environment.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
  echo 'This launcher requires the Ubuntu x86_64 host environment.' >&2
  exit 2
}
exec env -u PYTHONPATH -u PYTHONHOME "$ROOT/.venv-host/bin/python" "$@"
