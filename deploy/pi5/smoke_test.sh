#!/usr/bin/env bash
# Lab smoke test on physical Raspberry Pi 5 after staging models/llama/ and configs/inference.json.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
unset PYTHONPATH PYTHONHOME

[[ -f configs/inference.json ]] || {
  echo "Missing configs/inference.json. Create it first with .venv/bin/python deploy/pi5/create_manifest.py --profile pi5." >&2
  exit 2
}
mkdir -p results/pi5
.venv/bin/python deploy/pi5/verify_environment.py --runtime configs/inference.json --output results/pi5/environment.json

.venv/bin/python -m edgeshield.cli --demo --runtime-config configs/inference.json "$@" | tee results/pi5/smoke_test.txt
if ! grep -q "Llama (validated)" results/pi5/smoke_test.txt; then
  echo "ERROR: No 'Llama (validated)' output observed in smoke_test.txt. Template fallback does not prove ExecuTorch Llama execution." >&2
  exit 2
fi

printf 'Cedar Bank: Your OTP is 000000. Do not share your OTP.\n' | \
  .venv/bin/python -m edgeshield.cli --stdin --json --runtime-config configs/inference.json --advisory-policy off \
  > results/pi5/fallback_smoke.jsonl
printf 'Urgent: share OTP now.\n' | \
  .venv/bin/python -m edgeshield.cli --stdin --json --runtime-config /nonexistent/missing.json \
  >> results/pi5/fallback_smoke.jsonl
.venv/bin/python -c '
import json
rows = [json.loads(line) for line in open("results/pi5/fallback_smoke.jsonl", encoding="utf-8")]
explanations = [r for r in rows if r.get("event") == "explanation"]
assert len(explanations) == 2
assert explanations[0]["source"] == "Template fallback" and explanations[0]["reason"] == "SKIPPED_BY_POLICY"
assert explanations[1]["source"] == "Template fallback" and explanations[1]["reason"] == "RUNTIME_CONFIGURATION_REJECTED"
print("Fallback verification PASSED (SKIPPED_BY_POLICY and RUNTIME_CONFIGURATION_REJECTED).")
'
echo "Smoke test PASSED: verified genuine 'Llama (validated)' output and labeled fallback behavior."
