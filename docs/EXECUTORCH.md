# ExecuTorch Integration, Lawful Model Access, and Pi 5 Runtime Verification

**Status (20 November 2026):** Model export (`llama3_2.pte`), dedicated Raspberry Pi 5 Cortex-A76 `aarch64` cross-compilation (`pi5-cortex-a76-native`, `GLIBC <= 2.34`), **genuine on-device physical Raspberry Pi 5 execution** (archived B0 measured under Detector V2 `f37c3dd9...`: `4/4` smoke test, `5/5` short run, `91/91` sustained 605.4 s B0 benchmark in `results/pi5/archive/20261118-B0-full/`), and **disconnected Pi 5 `strace` offline verification** (`results/pi5/offline-20261119/`, V2 `f37c3dd9...`: `5/5` validated, zero `AF_INET`/`AF_INET6`, `eth0`/`wlan0` `DOWN`, manifest `a4f1f80b...` matching B0) are **VERIFIED**. Detector V3 (`b2b2126b...`) on-device Pi 5 verification is `PENDING_HARDWARE`. Host adapter, packaging, and safety tests pass (`261 passed` on Ubuntu x86_64).

## Verified Upstream Configuration and Provenance

- **ExecuTorch revision:** `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7` (`release/1.5`). Audited reference snapshots and upstream `LICENSE` live under `executorch/references/`. See [SOURCES_RUNTIME.md](SOURCES_RUNTIME.md).
- **Target checkpoint:** Official [Meta Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8](https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8), Hugging Face revision `b8c08c95d0476ccb6fc86e9410818d602ecca19d` (`consolidated.00.pth` SHA-256 `c14adb6bf48fd9e81fdc14ebad5ef0ea9f98d50ca3419b28f0b788149c4ef2a5`, `tokenizer.model` SHA-256 `82e9d31979e92ab929cd544440f129d9ecd797b69e327f80f17e1c50d5551b55`).
- **Export YAML:** `llama_xnnpack_spinquant.yaml` (prequantized SpinQuant, group size 32, 8-bit dynamic activations, 4-bit weights, XNNPACK extended operators, KV cache, 2048 context).
- **Exported `.pte`:** `llama3_2.pte`, `1,075,142,912` bytes (~1.00 GiB), SHA-256 `c31e4d376f349de85b4422a8c0405d88f21145709f0e17168b06d809ffe5e8a2`.
- **Dedicated Pi 5 runner (`pi5-cortex-a76-native`):** Cross-compiled with Arm GNU Toolchain `12.2.rel1` (`GLIBC <= 2.34`, Bookworm & Trixie compatible):
  - `models/llama/pi5-aarch64/llama_main` (`6,245,384` bytes, SHA-256 `e628abef24091067f4954b4ea15ce84317570d6d99e2ddc34a3786af7ad8d70c`)
  - `models/llama/pi5-aarch64/libllama_runner.so` (SHA-256 `d45f39fd3b7f53bb511190fedab971933d176a3431c73f53f9fd87ad39496731`)

## Lawful Model Acquisition and Reproduction on a Linux Export Host

Meta Llama 3.2 weights and tokenizer are gated under the **Meta Llama 3.2 Community License** and are **never** distributed in the public GitHub repository or public source archive. Reviewers reproducing genuine on-device Llama execution must:

1. Request and obtain approved access to `meta-llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8` (revision `b8c08c95d0476ccb6fc86e9410818d602ecca19d`) on Hugging Face, review the Meta Llama 3.2 License and Acceptable Use Policy, and download the original-format `consolidated.00.pth`, `params.json`, `tokenizer.model`, and Meta `LICENSE` / `NOTICE` files. Do not substitute a base/non-Instruct model or rename `tokenizer.json` to `.model`.
2. Export `llama3_2.pte` and cross-build the Pi 5 runner on a Linux x86_64 host (CMake 3.26+, git, supported Python 3.10–3.13):

```bash
git clone https://github.com/pytorch/executorch.git build/executorch
cd build/executorch
git checkout 985c1ceccc8bb8b6a32294f71aeb5d2f299562f7
git submodule update --init --recursive
python3 -m venv .venv
source .venv/bin/activate
./install_executorch.sh

export LLAMA_LICENSE_ACCEPTED=yes  # only after actual approval and license review
export LLAMA_QUANTIZED_CHECKPOINT=/absolute/approved/consolidated.00.pth
export LLAMA_PARAMS=/absolute/approved/params.json
bash /absolute/edgeshield/scripts/export_llama.sh

# Dedicated Pi 5 Cortex-A76 cross-build (use separate build tree from any host runtime):
bash examples/raspberry_pi/setup.sh pi5 --skip-env-setup
```

3. Stage `llama3_2.pte`, `tokenizer.model`, `pi5-aarch64/llama_main`, `pi5-aarch64/libllama_runner.so`, and Meta `LICENSE_AND_NOTICE.md` under `models/llama/` on the Raspberry Pi 5, then generate `configs/inference.json`:

```bash
chmod u+x models/llama/pi5-aarch64/llama_main
.venv/bin/python deploy/pi5/create_manifest.py --profile pi5
bash deploy/pi5/smoke_test.sh
```

Retain all Meta license and attribution notices (`models/llama/LICENSE_AND_NOTICE.md`) on any authorized private device deployment. Never publish gated weights or tokenizer files.

## Runner Contract and Safety

`ExecuTorchAdvisor(config_path).generate(prompt)` (`src/edgeshield/advisory.py`) receives only the already-framed evidence-only Llama 3 prompt built by `src/edgeshield/validator.py`. It never inspects raw SMS text or adds a second chat template. The pinned runner accepts `--model_path`, `--tokenizer_path`, `--max_new_tokens`, `--cpu_threads`, `--temperature`, and `--prompt`. Production Pi 5 settings use `max_new_tokens=48`, `cpu_threads=2`, and greedy decoding.

The pinned runner echoes the prompt, writes generated tokens, and emits a terminal `PyTorchObserver` JSON stats trailer. The adapter requires an exact prompt prefix and valid trailer, passing all generated text to the strict validator. Missing/changed protocol, invalid UTF-8, timeout, child failure, or excessive stdout/stderr triggers sanitized failure and an explicitly labeled `Template fallback`. No runtime stdout/stderr is written to disk by the adapter.

Manifest SHA-256 hashes are verified before every call. Shared-library loading is restricted to declared local directories and inherited preload variables (`LD_PRELOAD`, etc.) are stripped. One runner process is spawned per message, so measured Llama wall time includes per-call integrity verification, `.pte` model load (`~1.22 s` median on Pi 5), tokenization + prefill (`3.20 s` median TTFT), and decode (`13.49 tok/s` median). The detector verdict and deterministic `DO:` advice print in `<2 ms` before the advisory call finishes.

## Verified Execution Evidence (19 November 2026)

- **Physical Raspberry Pi 5 (`VERIFIED`, `results/pi5/archive/20261118-B0-full/`):**
  - Model B Rev 1.1, 16 GB, CPU-only `aarch64`, Debian 13 Trixie, Python 3.13.5, `glibc 2.41`, `pi5-cortex-a76-native` (`cpu_threads=2`).
  - `smoke_test.txt`: `4/4` `Llama (validated)`; `fallback_smoke.jsonl`: `2/2` labeled `Template fallback`.
  - `benchmark.json` (B0 sustained, 605.4 s, `n=91`): `91/91` validator-accepted advisories (`0` fallbacks), `6.81 s` p95 full response, `1.44 GB` (`1.34 GiB`) peak runner RSS, `0 B` swap, `83.7 °C` peak passive-heatsink temp with throttling (`0xe0008`).
- **Ubuntu x86_64 host (`VERIFIED`):** `261 passed` pytest (`tests/test_runtime.py` exercises child timeout, output bounding, error sanitization, and protocol parsing); `432/432` dev, `132/132` holdout, and `20/20` comparison validator acceptance on host x86_64 plus V3 `Llama (validated)` host E2E runs (`results/host/v3/e2e_host_llama_validation.txt`).

Arm-Examples LLM-Runner was reviewed as a reference only and is not used (its README pins ExecuTorch v1.4.1 and defaults to another backend).
