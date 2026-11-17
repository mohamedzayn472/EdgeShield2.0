#!/usr/bin/env bash
# Run inside the separately provisioned, pinned ExecuTorch Linux checkout.
set -euo pipefail
PIN=985c1ceccc8bb8b6a32294f71aeb5d2f299562f7
[[ $(uname -s) == Linux ]] || { echo 'Linux export host required for this tested-upstream workflow.' >&2; exit 2; }
[[ $(git rev-parse HEAD) == "$PIN" ]] || { echo "Expected ExecuTorch commit $PIN" >&2; exit 2; }
[[ ${LLAMA_LICENSE_ACCEPTED:-no} == yes ]] || { echo 'Obtain approved Meta access and review the license before setting LLAMA_LICENSE_ACCEPTED=yes.' >&2; exit 2; }
: "${LLAMA_QUANTIZED_CHECKPOINT:?Set path to approved Llama-3.2-1B-Instruct SpinQuant INT4 consolidated.00.pth}"
: "${LLAMA_PARAMS:?Set path to matching params.json}"
[[ -f "$LLAMA_QUANTIZED_CHECKPOINT" && -f "$LLAMA_PARAMS" ]] || { echo 'Checkpoint or params missing.' >&2; exit 2; }
[[ ! -e llama3_2.pte ]] || { echo 'Existing output found; use a fresh export working checkout to preserve it.' >&2; exit 2; }
python -m extension.llm.export.export_llm \
  --config examples/models/llama/config/llama_xnnpack_spinquant.yaml \
  +base.model_class=llama3_2 \
  +base.checkpoint="$LLAMA_QUANTIZED_CHECKPOINT" \
  +base.params="$LLAMA_PARAMS"
test -s llama3_2.pte
sha256sum llama3_2.pte > llama3_2.pte.sha256
echo 'Export produced a file. Execute real host and Pi inference before claiming compatibility.'
