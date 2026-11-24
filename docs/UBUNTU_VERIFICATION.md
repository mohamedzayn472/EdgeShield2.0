# Ubuntu verification — 16–17 November 2026

This record continues the transferred project at `/home/zayn/Projects/edgeshield`.
Evidence is under `results/host/ubuntu/`; historical Windows and frozen V1/V2
results remain separate. The extracted project is not a Git repository.

## Transfer and application

- Before edits, all 130 entries in the original `BUNDLE_MANIFEST.json` passed
  SHA-256 and size verification (`bundle_audit.txt`). This is integrity evidence,
  not independent authentication of the transfer.
- Ubuntu 22.04.5 LTS, Linux x86_64, Python 3.10.12, GCC 11.4.0; approximately
  14 GiB RAM and 54 GiB free disk before provisioning. System CMake 3.22.1 is
  below the export requirement. See `prerequisites.json`.
- Separate `.venv-host` installed `requirements/host.txt` using host wheels.
  No Arm64 wheel was installed on the laptop. Dependency check passed.
- **170 passed, 1 skipped** on Ubuntu. The skip is the expected raw-corpus
  split audit: raw UCI data is excluded from the bundle. Historical Windows
  baseline remains 171 passing tests.
- Shell startup injects ROS Humble into `PYTHONPATH`; the initial pytest run
  failed loading an unrelated ROS plugin. Unsetting `PYTHONPATH` and
  `PYTHONHOME` isolates the environment. `scripts/host_python.sh` applies this
  for subsequent app/test commands.
- CLI smoke output is in `cli_smoke.jsonl`. It reports `Template fallback`,
  `RUNTIME_NOT_CONFIGURED`, and null Llama timing. It is not Llama inference.
- `benchmark.json` contains 100 actual host iterations with template fallback.
  Detector median was 0.516 ms and p95 1.008 ms in that run.
  These measurements establish neither Llama latency nor Pi performance.
- Pi preflight and installer correctly reject this x86_64/Python 3.10 host;
  their outputs are `pi_guard_check.json` and `pi_install_guard.txt`.

Reproduce the application environment from the project root:

```bash
python3 -m venv .venv-host
env -u PYTHONPATH -u PYTHONHOME .venv-host/bin/python -m pip install -r requirements/host.txt
bash scripts/host_python.sh -m pip install --no-deps --no-build-isolation -e .
bash scripts/host_python.sh -m pytest -q
bash scripts/host_python.sh -m edgeshield.cli --repeat
```

Network access is needed for initial host provisioning. The bundled
`wheelhouse/pi4-cp311` is exclusively for the target, not this environment.

## Downloaded model

Read-only inspection verified the files in
`/home/zayn/EdgeShield/models/llama-spinquant` against the public metadata of
[Meta's SpinQuant repository](https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8)
at revision `b8c08c95d0476ccb6fc86e9410818d602ecca19d`.
The official API response is retained in `upstream_model_metadata.json`.
All six downloaded files match their upstream Git blob or LFS digest and
their local Hugging Face download metadata. See `model_audit.json`.

| File | Bytes | SHA-256 |
|---|---:|---|
| consolidated.00.pth | 1621294320 | c14adb6bf48fd9e81fdc14ebad5ef0ea9f98d50ca3419b28f0b788149c4ef2a5 |
| params.json | 273 | 44ef8d02aaf4a2f071b65552c0a93ae8f79cbe50df8e545c377eee45d350b17e |
| tokenizer.model | 2183982 | 82e9d31979e92ab929cd544440f129d9ecd797b69e327f80f17e1c50d5551b55 |

Parameters specify 2048 dimensions, 16 layers, 32 attention heads, 8 KV
heads, vocabulary 128256 and quantization group size 32. The matching
tokenizer is a tiktoken BPE rank file with 128000 unique base tokens and
contiguous ranks, not a renamed tokenizer JSON or SentencePiece file.
Repository identity and hashes establish the intended Instruct/SpinQuant
artifact; successful export and generation remain separate checks.

The owner confirmed approved gated access and acceptance of the Llama 3.2
license in this chat. The local model README contains the license and
acceptable-use policy. Before distributing any Llama materials, retain the
agreement and required Notice, and display the required attribution as
specified in the [official model card](https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8).
The source preparation bundle excludes Llama weights and tokenizer.

## Export and target work

The pinned source checkout and its independent environment are in
`build/executorch` and `build/executorch/.venv` respectively.
Pin: `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7`.
The initial checkout name `executorch-export` failed the upstream CMake
basename check. The real checkout is now named `executorch`; an alias at the
old path preserves venv script paths. The failed output was retained separately.
System-wide Python and CMake were not changed.

The separate environment installed CPU PyTorch `2.14.0+cpu`, TorchAO
`0.18.0+cpu`, and CMake `3.31.10`. Native compilation is limited to two jobs,
with CUDA and OpenVINO disabled for this XNNPACK workflow. The source pin,
export YAML and Pi setup script match the transferred upstream reference copies.
`submodule_revisions.txt` records the recursive dependency revisions.

Safe checkpoint inspection used `torch.load(weights_only=True, mmap=True,
map_location="cpu")`. All 16 layer IDs are present, with 261 tensors:
114 int8, 114 float32, and 33 bfloat16. Representative linear weights range
from -8 to 7 with per-group scales shaped `[2048,64]`; embedding/output
weights are `[128256,2048]` with int8 range -128 to 127.
`checkpoint_shapes.json` records every tensor shape, dtype, and int8 range.

The pinned tokenizer implementation loads the original tokenizer successfully.
For empty and all-indicator evidence prompts across all three bands, measured
prompt sizes are 79–382 tokens; including the configured 48 generated tokens
stays below 2048. These six checks are recorded in `tokenizer_prompt_check.json`.
They verify tokenization, not generation or inference quality.

On 17 November the work completed export, native host inference verification,
prompt/validator tuning, core optimizations, and Arm cross-compilation on
Ubuntu x86_64 (`OPUS_TO_ARGON_HANDOFF.md` historical milestone note).

### Verified export, host inference, and optimizations (17 November 2026)

- **Model export (`VERIFIED`):** `scripts/export_llama.sh` generated
  `build/executorch/llama3_2.pte` (`1,075,142,912` bytes, SHA-256
  `c31e4d376f349de85b4422a8c0405d88f21145709f0e17168b06d809ffe5e8a2`, max
  activation memory `352,739,136` bytes, peak export RSS `7,355,912` KiB in
  `3m35s`; `export.log` & `export_freeze.txt`).
- **Frozen V2 reproduction (`VERIFIED`):** `scripts/reproduce_v2_evaluation.py`
  verified all 13 frozen V2 hashes and reproduced `50/60` scams detected (`26/30`
  English, `24/30` Hinglish), `1/60` false alarm, `0` band mismatches, and max
  score diff `5.55e-17` (`v2_reproduction.json`).
- **Pybind `TextLLMRunner` discovery (`VERIFIED`):** Importing `_llm_runner`
  alone fails with `Backend XnnpackBackend is not registered`
  (`llama_host_smoke_attempt1_xnnpack_unregistered.log`); importing
  `portable_lib`, `executorch.kernels.quantized`, and `custom_ops` first resolves
  shared-runtime registration (`scripts/verify_llama_host.py`).
- **Prompt & salience fix (`VERIFIED`):** Original `build_prompt()` yielded
  `48/432` (11.1%) validator acceptance (`llama_prompt_v1_development.json`) due
  to raw enum names triggering 1B safety refusals and zero-shot format drift.
  Switching to 1-shot defensive framing + salience-ordered `fallback()`
  (`src/edgeshield/validator.py`) achieved **432/432 (100%)** dev acceptance
  (`llama_prompt_v2_development.json`), **132/132 (100%)** holdout acceptance
  (`llama_prompt_v2_holdout.json`), and **3/3** smoke acceptance
  (`llama_host_smoke_v2.json`), all with `deterministic_rerun_first_case: true`.
- **Native x86_64 C++ `llama_main` & end-to-end CLI (`VERIFIED`):** Built
  `models/llama/host-x86_64/{llama_main,libllama_runner.so}` via presets
  `llm-release` and `llama-release` (`native_runner_build.log`). Verified
  `ExecuTorchAdvisor` integrity and end-to-end CLI JSON output
  (`results/host/ubuntu/inference_host_x86_64.json`, `cli_llama_smoke.jsonl`:
  `source="Llama (validated)"`, `reason="ACCEPTED"`, `llama_ms=3740.68 ms`).
- **Host benchmarks & optimizations (`VERIFIED` on Ubuntu x86_64 only):**
  `benchmark_optimized_detector.json` (100 reps: detector median `0.577 ms`,
  evidence `0.042 ms`); `benchmark_llama_threads2.json` (10/10 Llama validated,
  `llama_ms` median `3434.78 ms`, `model_load_ms` `1568.5 ms`, `prefill_ms`
  `772.0 ms`, decode `45.23 tok/s`, GNU time Max RSS `1667588 KiB`);
  `optimization_study.json` (cold CLI `509.59 ms` median / `111.46 MiB` RSS;
  `load_detector` `29.96 ms` cold vs `0.985 ms` cached; `--advisory-policy
  elevated` invokes Llama on `104/132` holdout cases; thread scaling 1/2/4
  median `llama_ms`: `4257.7` / `3408.0` / `3155.9 ms`).
- **Ubuntu unit/integration tests (`VERIFIED`):** `174 passed, 1 skipped` in
  `0.92s` (`pytest_opus.xml`) after all edits; zero frozen hash mismatches.

Physical Pi compatibility, genuine device inference, offline trace,
memory/CPU/thermal measurements, and sustained performance remain
`PENDING_HARDWARE`. Human label review and the clarity study also remain open.
The unchanged synthetic evaluation detected 50/60 scams, including 24/30
Hinglish scams, with one false alarm and ten missed scams. It is not
real-world validation.


### Exact export environment commands

The checkout basename must be `executorch`. Use a separate venv from the app:

```bash
cd /home/zayn/Projects/edgeshield/build/executorch
source .venv/bin/activate
unset PYTHONPATH PYTHONHOME
export PIP_CACHE_DIR=/tmp/edgeshield-pip-cache
export CCACHE_DIR=/tmp/edgeshield-ccache
export CMAKE_BUILD_PARALLEL_LEVEL=2
export CMAKE_ARGS="-DEXECUTORCH_BUILD_CUDA=OFF -DEXECUTORCH_BUILD_OPENVINO=OFF -DEXECUTORCH_BUILD_QNN=OFF -DEXECUTORCH_BUILD_COREML=OFF -DEXECUTORCH_BUILD_VULKAN=OFF"
git rev-parse HEAD
# Must print 985c1ceccc8bb8b6a32294f71aeb5d2f299562f7.
# For fresh provisioning:
bash install_executorch.sh
# If dependencies and tokenizers are already installed, resume its package step:
python -m pip install . --no-build-isolation -v
```

The initial installer automatically enabled a Qualcomm SDK download on Linux
x86_64. That unrelated build was stopped; explicit `EXECUTORCH_BUILD_QNN=OFF`
keeps this workflow focused on CPU/XNNPACK. Native and target output trees
must remain separate.

### Pi cross-build completion and GLIBC ABI finding

A fresh retry of `bash examples/raspberry_pi/setup.sh pi4 --skip-env-setup --force-rebuild`
succeeded (`pi4_cross_build_attempt2.log`): the full `145 MiB` Arm GNU
Toolchain `14.3.rel1` archive downloaded cleanly, passed MD5 verification
(`b82906df613ca762058e3ca39ac2e23a`), and compiled `aarch64` Cortex-A72
binaries (`-march=armv8-a -mtune=cortex-a72`) staged under
`models/llama/pi4-aarch64/{llama_main,libllama_runner.so}`.

**Important ABI finding (`pi4_binary_audit.json`):** `readelf -V` shows the `14.3.rel1`
`aarch64` binaries require `GLIBC_2.38` and `GLIBCXX_3.4.32`, which would fail on
stock Raspberry Pi OS Bookworm (`GLIBC 2.36`).

**Bookworm resolution (`VERIFIED` on host):** Using Arm GNU Toolchain `12.2.rel1`
(SHA-256 `6e8112dce0d4334d93bd3193815f16abe6a2dd5e7872697987a0b12308f876a4`)
via `arm-toolchain-pi4-bookworm.cmake` (`-march=armv8-a -mtune=cortex-a72`)
with KleidiAI and Armv8.2+/Armv9 extensions disabled (`pi4_bookworm_cross_build.log`),
Argon built Bookworm-compatible `models/llama/pi4-aarch64/{llama_main,libllama_runner.so}`
with `max_glibc_required: GLIBC_2.34`, `max_glibcxx_required: GLIBCXX_3.4.30`, and
`symbols_requiring_glibc_gt_2_36: []` (`pi4_bookworm_binary_audit.json`), and staged
`models/llama/` alongside `llama3_2.pte`, `tokenizer.model`, `LICENSE_AND_NOTICE.md`,
and `pi4-runtime-manifest.json`. The earlier `14.3.rel1` build is archived under
`models/llama/pi4-aarch64-glibc238/`. (`ARGON_COMPLETION_REPORT.md` historical milestone note)
for Argon's 20-case comparison (`20/20` accepted), `averages_ms` benchmarks, `--demo --llama`
verification, and `176 passed, 1 skipped` test suite.
