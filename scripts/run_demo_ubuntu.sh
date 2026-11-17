#!/usr/bin/env bash
# Run the built-in English & Hinglish synthetic EdgeShield demo on Ubuntu x86_64.
# Pass --llama to enable genuine host Llama-3.2-1B SpinQuant explanations.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ARGS=()
USE_LLAMA=false
for arg in "$@"; do
  if [[ "$arg" == "--llama" ]]; then
    USE_LLAMA=true
  else
    ARGS+=("$arg")
  fi
done
if [[ "$USE_LLAMA" == true ]]; then
  ARGS+=(--runtime-config "$ROOT/results/host/ubuntu/inference_host_x86_64.json")
fi
exec bash "$ROOT/scripts/host_python.sh" -m edgeshield.cli --demo "${ARGS[@]}"
