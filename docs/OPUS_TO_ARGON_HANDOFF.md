# EdgeShield — Phase 1 Handoff: Claude Opus → Gemini Argon

**Date:** 17 November 2026  
**Environment:** Ubuntu 22.04.5 LTS (`Linux-6.8.0-136-generic-x86_64-with-glibc2.35`, `x86_64`, Python 3.10.12, 12-core AMD Ryzen 5 8645HS, 14 GiB RAM)  
**Repository root:** `/home/zayn/Projects/edgeshield` (extracted archive, not a Git repository)  
**External SpinQuant checkpoint directory:** `/home/zayn/EdgeShield/models/llama-spinquant` (unmodified)

All measurements and model runs below were executed on the **Ubuntu x86_64 development host**. No Raspberry Pi 4 hardware was connected or tested. Every major item is tagged `VERIFIED`, `IMPLEMENTED BUT NOT VERIFIED`, `BLOCKED`, or `DEFERRED`.

---

## 1. Exact Original Codex Stopping Point

- `[VERIFIED]` Codex transferred the Windows V2 bundle to Ubuntu (`/home/zayn/Projects/edgeshield`), verified all 130 `BUNDLE_MANIFEST.json` entries (`results/host/ubuntu/bundle_audit.txt`), verified the 27 present frozen files (`results/host/ubuntu/frozen_audit.json`), provisioned `.venv-host` (`scripts/host_python.sh` clearing ROS Humble `PYTHONPATH`/`PYTHONHOME`), ran `170 passed, 1 skipped` tests, and ran a detector-only benchmark with template fallback (`results/host/ubuntu/benchmark.json`).
- `[VERIFIED]` Codex audited `/home/zayn/EdgeShield/models/llama-spinquant` against Hugging Face revision `b8c08c95d0476ccb6fc86e9410818d602ecca19d` (`results/host/ubuntu/model_audit.json`, `checkpoint_shapes.json`), tokenized 6 bounding prompts (`tokenizer_prompt_check.json`), cloned ExecuTorch commit `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7` into `build/executorch`, built the ExecuTorch Python package (`executorch_cpu_build.log`), and exported `build/executorch/llama3_2.pte` (`1,075,142,912` bytes, SHA-256 `c31e4d376f349de85b4422a8c0405d88f21145709f0e17168b06d809ffe5e8a2`, `results/host/ubuntu/export.log` ending 17 Nov 05:35 IST).
- `[VERIFIED]` Codex **stopped before**:
  1. Verifying genuine `.pte` model loading or inference on host (`scripts/verify_llama_host.py` existed on disk, unexecuted; native C++ `llama_main` was not built).
  2. Reproducing the frozen V2 heldout evaluation on Ubuntu (`scripts/reproduce_v2_evaluation.py` did not exist).
  3. Testing prompt acceptance against the real quantized 1B model (`validator.py` originally caused an 88.9% rejection rate on first real test).
  4. Resolving the Arm GNU `14.3.rel1` download interruption (`HTTP 503`, partial 23 MB archive left in `build/executorch/examples/raspberry_pi/gen/arm-toolchain/`), so Pi 4 cross-compilation had not completed.

---

## 2. Files Inspected

- **Status & architecture docs:** `PROJECT_STATUS.md`, `README.md`, `docs/HANDOFF.md`, `docs/WINDOWS_TO_LINUX.md`, `docs/UBUNTU_VERIFICATION.md`, `docs/EXECUTORCH.md`, `docs/PI4_DEPLOYMENT.md`, `docs/V2_RESULTS.md`, `docs/V2_FINAL_EVALUATION.md`, `docs/EVALUATION_V2.md`, `docs/ARCHITECTURE.md`, `docs/BENCHMARKS.md`, `docs/LIMITATIONS.md`, `docs/SECURITY.md`, `docs/SOURCES_RUNTIME.md`, `docs/LAB_CHECKLIST.md`, `docs/REPORT.md`, `docs/DEMO_SCRIPT.md`, `docs/MASTER_BUILD_PROMPT.md` (headings and sections 5–12), `submission/CHECKLIST.md`.
- **Source code (`src/edgeshield/`):** `cli.py`, `pipeline.py`, `advisory.py`, `model_loader.py`, `validator.py`, `detector.py`, `detector_v2.py`, `evidence.py`, `indicators.py`, `privacy.py`, `recommendations.py`, `benchmarking.py`, `datasets.py`.
- **Tests (`tests/`):** `test_safety.py`, `test_runtime.py`, `test_packaging.py`, `test_detector_v2.py`, `test_detector.py`, `test_benchmarking.py`, `test_model_loader.py`, `test_pipeline_integration.py`.
- **Scripts & deployment (`scripts/`, `deploy/pi4/`, `requirements/`):** `scripts/export_llama.sh`, `scripts/host_python.sh`, `scripts/evaluate_detector_v2.py`, `scripts/verify_llama_host.py`, `scripts/verify_bundle.py`, `scripts/package_bundle.py`, `scripts/safety_report.py`, `scripts/write_handoff.py`, `scripts/write_v2_status.py`, `deploy/pi4/setup.sh`, `deploy/pi4/install_dependencies.sh`, `deploy/pi4/verify_environment.py`, `deploy/pi4/create_manifest.py`, `deploy/pi4/launch.sh`, `deploy/pi4/benchmark.sh`, `deploy/pi4/diagnostic.sh`, `deploy/pi4/offline_verify.sh`, `deploy/pi4/runtime-manifest.example.json`, `deploy/pi4/README.md`, `deploy/pi4/TROUBLESHOOTING.md`, `requirements/host.txt`, `requirements/pi4.txt`, `pyproject.toml`.
- **Model, export, & result records:** `/home/zayn/EdgeShield/models/llama-spinquant/{params.json,config.json}`, `build/executorch/examples/models/llama/config/llama_xnnpack_spinquant.yaml`, `build/executorch/examples/models/llama/{main.cpp,CMakePresets.json,README.md}`, `build/executorch/examples/raspberry_pi/setup.sh`, `results/PROJECT_STATUS.json`, `results/pi4/STATUS.json`, `results/host/evaluation_freeze.json`, `results/host/v2/{evaluation_freeze.json,data_audit.json,heldout_evaluation.json,training_validation.json}`, `results/host/ubuntu/*`.

---

## 3. Files Modified or Created by Opus

### Modified application source files
- `src/edgeshield/validator.py` — Added `INDICATOR_PRIORITY` salience ordering for `fallback()`, updated `build_prompt()` to 1-shot defensive status-line framing without raw `IMPERSONATION`/`LURE` enum leakage, preserved `allowed_explanations()` and `validate_explanation()` unchanged. (`VERIFIED`)
- `src/edgeshield/indicators.py` — Precompiled module-level regexes (`COMPILED_PATTERNS`, `NEGATION`) and guarded `OTP_REQUEST` negation scan so `finditer` runs only when `OTP_REQUEST` matches. (`VERIFIED`)
- `src/edgeshield/model_loader.py` — Replaced eager dual-module import + double 1.95 MB JSON read/parse with single-pass JSON read, lazy v1/v2 class import, full `.sha256` verification, and SHA-256-keyed `_CACHE`. (`VERIFIED`)
- `src/edgeshield/pipeline.py` — Added `ADVISORY_POLICIES = ("always", "elevated", "uncertain", "off")`, `should_run_advisor()`, and `policy` parameter to `explain()`, emitting `Template fallback` with reason `SKIPPED_BY_POLICY` when gated out. (`VERIFIED`)
- `src/edgeshield/cli.py` — Added `--advisory-policy` CLI flag (`choices=("always", "elevated", "uncertain", "off"), default="always"`) wired into `explain()`. (`VERIFIED`)

### Modified tests
- `tests/test_safety.py` — Added `test_fallback_salience_priority` and `test_prompt_framing_avoids_raw_enums_and_uses_oneshot`. (`VERIFIED`)
- `tests/test_model_loader.py` — Added `test_loader_cache_hit_and_tamper_invalidation`. (`VERIFIED`)
- `tests/test_pipeline_integration.py` — Added `test_advisory_policies_and_cli`. (`VERIFIED`)

### Added/updated engineering & diagnostic scripts
- `scripts/reproduce_v2_evaluation.py` — Read-only reproduction script checking frozen V2 hashes and reproducing `heldout_evaluation.json` on Ubuntu without altering frozen files. (`VERIFIED`)
- `scripts/export_evidence_fixtures.py` — Exports closed-schema `Evidence` JSON (no SMS text) for real Llama host prompt studies. (`VERIFIED`)
- `scripts/verify_llama_host.py` — Updated to register `portable_lib`, `executorch.kernels.quantized`, and `custom_ops` before `TextLLMRunner`, and added `--suite evidence` with persistent runner reset & determinism check. (`VERIFIED`)
- `scripts/study_optimizations.py` — Controlled Ubuntu host benchmark for cold startup, loader cache, indicator/assess latency, policy invocation rates, child RSS, and CPU thread scaling (1/2/4 threads). (`VERIFIED`)

### Updated documentation & status records
- `docs/OPUS_TO_ARGON_HANDOFF.md` (this file), `PROJECT_STATUS.md`, `docs/HANDOFF.md`, `docs/UBUNTU_VERIFICATION.md`, `docs/EXECUTORCH.md`, `results/PROJECT_STATUS.json`. (`VERIFIED`)

### Build/runtime artifacts generated (outside bundle inclusion; frozen models untouched)
- `models/llama/host-x86_64/{llama_main,libllama_runner.so}` — Native x86_64 ExecuTorch Llama runner binaries. (`VERIFIED`)
- `models/llama/pi4-aarch64/{llama_main,libllama_runner.so}` — Cross-compiled `aarch64` Cortex-A72 binaries (`-march=armv8-a -mtune=cortex-a72`). (`VERIFIED` ELF build; `PENDING_HARDWARE` on physical Pi 4, see GLIBC 2.38 finding in Section 7 & 9)
- `results/host/ubuntu/{v2_reproduction.json,evidence_v2_development.json,evidence_v2_holdout.json,llama_host_smoke.json,llama_host_smoke_v2.json,llama_prompt_v1_development.json,llama_prompt_v2_development.json,llama_prompt_v2_holdout.json,inference_host_x86_64.json,cli_llama_smoke.jsonl,benchmark_optimized_detector.json,benchmark_llama_threads2.json,benchmark_llama_threads2_resources.txt,optimization_study.json,pi4_cross_build_attempt2.log,pi4_binary_audit.json,native_runner_build.log,pytest_opus.xml}`. (`VERIFIED`)

### Frozen files integrity check
- `[VERIFIED]` Zero modifications to any frozen file in `results/host/evaluation_freeze.json` (`0` mismatches; 4 raw UCI `data/processed/*.jsonl` files absent from transfer bundle as expected) or `results/host/v2/evaluation_freeze.json` (`0` mismatches across all 13 files).

---

## 4. Architecture Decisions

1. **V2 detector remains the sole default classifier and runs completely independently (`VERIFIED`):**
   - `models/detector_v2.json` (`edgeshield-word-char-lr-v2`) executes in `< 1 ms` median without PyTorch or ExecuTorch, prints threat band and deterministic `DO:` recommendation before Llama starts, and never uses Llama for detection verdicts. V1 stays at `models/detector.json` for audit only.
2. **Strict SMS-to-Evidence privacy firewall preserved (`VERIFIED`):**
   - Only `Evidence(band, score, indicators, schema_version=1)` crosses into `build_prompt()`, which builds a closed-schema Llama 3 instruction prompt; SMS text is never passed to Llama or written to diagnostics.
3. **Solved 1B SpinQuant validator rejection via 1-shot defensive framing + salience-ordered fallback (`VERIFIED`):**
   - **Root cause found:** Codex's original `build_prompt()` interpolated raw internal enum strings (`BANK_IMPERSONATION`, `KYC_IMPERSONATION`, `UPI_COLLECT_LURE`), triggering Llama-3.2-1B-Instruct safety refusals on benign bank/UPI cues, while zero-shot prompting caused missing `WHY: ` prefixes (`302/432`) or multi-line dumps (`82/432`) — yielding only **48/432 (11.1%)** accepted outputs on `v2_development.jsonl`.
   - **Fix:** Removed raw enum names from the prompt, added a 1-shot defensive status-line example, and ordered `fallback()` by `INDICATOR_PRIORITY` (putting `OTP_REQUEST`, `UPI_COLLECT_LURE`, `SHORTENER_LINK`, `THREAT_OF_BLOCK` ahead of `HINGLISH_CUE`). Acceptance jumped from **11.1% (48/432)** to **100.0% (432/432 dev, 132/132 holdout)** while keeping `validate_explanation()` strictness intact.
4. **Conditional hybrid policy kept opt-in (`--advisory-policy`, default `"always"`) (`VERIFIED`):**
   - Added `"always"` (default, preserves full compliance path), `"elevated"` (runs Llama only when `band in ("SCAM", "UNCERTAIN")` or `indicators` is nonempty — skips **21.2%** of holdout cases cleanly), `"uncertain"` (band `UNCERTAIN` only), and `"off"` (detector + prioritized template only).
5. **Subprocess-per-call `ExecuTorchAdvisor` kept as the verified runtime boundary (`VERIFIED`):**
   - With `llama_ms` ~3.4 s on Ubuntu host (`1.57 s` model load + `0.77 s` prefill + ~0.35 s decode) and a single `llama_main` process peaking at **1.59 GiB RSS**, spawning per-message isolates crashes/timeouts and ensures RAM returns to the OS between messages on an 8 GB Pi 4 rather than holding 1.6 GB resident continuously. Persistent server/IPC optimization remains `DEFERRED` pending physical Pi 4 latency measurements.

---

## 5. Test Commands and Results

| Check | Command | Outcome | Status |
|---|---|---|---|
| Full host test suite (after all edits) | `bash scripts/host_python.sh -m pytest -q --junitxml=results/host/ubuntu/pytest_opus.xml` | **174 passed, 1 skipped** in `0.92s` (skip: `tests/test_detector.py:71`, raw UCI corpus excluded from transfer bundle) | `VERIFIED` |
| Frozen V1 & V2 hash audit | Python SHA-256 verification against `results/host/evaluation_freeze.json` & `results/host/v2/evaluation_freeze.json` | **0 mismatches** across all present frozen files | `VERIFIED` |
| Host runtime manifest integrity | `bash scripts/host_python.sh -c 'from edgeshield.advisory import ExecuTorchAdvisor; ExecuTorchAdvisor("results/host/ubuntu/inference_host_x86_64.json")'` | Passed SHA-256 + schema verification for `runner`, `model`, `tokenizer`, `shared_libraries` | `VERIFIED` |
| End-to-end CLI with real Llama subprocess | `printf 'Urgent: share your OTP at https://bit.ly/synthetic to prevent bank account block.\n' \| bash scripts/host_python.sh -m edgeshield.cli --stdin --json --runtime-config ...` | Detection printed first (`SCAM`, `0.946`); explanation `source: "Llama (validated)"`, `reason: "ACCEPTED"`, `llama_ms: 3740.68` (`results/host/ubuntu/cli_llama_smoke.jsonl`) | `VERIFIED` |
| Real Llama 3-case smoke (`verify_llama_host.py`) | `verify_llama_host.py --suite smoke` (`llama_host_smoke_v2.json`) | **3/3 ACCEPTED**, `deterministic_rerun_first_case: true` | `VERIFIED` |
| Real Llama dev evidence sweep | `verify_llama_host.py --suite evidence` (`llama_prompt_v2_development.json`) | **148/148 distinct (432/432 weighted) ACCEPTED**, `deterministic: true` (vs `48/432` in v1) | `VERIFIED` |
| Real Llama holdout evidence sweep | `verify_llama_host.py --suite evidence` (`llama_prompt_v2_holdout.json`) | **116/116 distinct (132/132 weighted) ACCEPTED**, `deterministic: true` | `VERIFIED` |
| Bundle inclusion rule check | Python check of `scripts/package_bundle.py:included()` | `models/llama/**` & `build/**` excluded (`False`); `src/` & `docs/OPUS_TO_ARGON_HANDOFF.md` included (`True`) | `VERIFIED` |
| Pi 4 deployment & offline tests | `deploy/pi4/*.sh` | Not executable on x86_64; hardware unavailable | `PENDING_HARDWARE` / `DEFERRED` |

---

## 6. Actual Evaluation Results

Reproduced bit-for-bit on Ubuntu from frozen `models/detector_v2.json` and `data/synthetic/v2_holdout.jsonl` (`results/host/ubuntu/v2_reproduction.json`):
- `[VERIFIED]` **Frozen hashes:** All 13 entries in `results/host/v2/evaluation_freeze.json` match; `per_case_band_mismatches_vs_recorded: []`, `max_abs_score_diff_vs_recorded: 5.55e-17`.
- `[VERIFIED]` **Overall fresh synthetic holdout (120 labeled cases: 60 scams, 60 legitimate; 12 ambiguous analyzed separately):**
  - Scams detected (`SCAM`): **50/60** (`83.33%` recall)
  - Scams assigned `LEGITIMATE` (missed): **10/60** (`16.67%`; 4 English `v2h049/050/056/057`, 6 Hinglish `v2h091/100/102/106/108/118`)
  - Legitimate false alarms (`SCAM`): **1/60** (`1.67%` FPR; `v2h066` Hinglish)
  - Precision: **98.04%**, F1: **0.9009**, Abstentions (`UNCERTAIN`): **0/120** (`thresholds: low=0.25, high=0.275`)
- `[VERIFIED]` **By language:**
  - English (60 cases): **26/30** scams detected, **0/30** false alarms (`4` missed scams).
  - Hinglish (60 cases): **24/30** scams detected, **1/30** false alarms (`6` missed scams).
- `[VERIFIED]` **Holdout explanation policy coverage (over all 132 holdout cases):** `"always"` invokes Llama on `132/132` (`100%`); `"elevated"` on `104/132` (`78.8%`); `"uncertain"` on `0/132` (`0%`).
- `[BLOCKED]` **UCI test regression (`1148` rows):** `NOT_AVAILABLE` in transfer bundle (`data/processed/test.jsonl` excluded by design; historical Windows recorded `148/164` recall, `1/984` FPR).
- `[BLOCKED]` **Human label review & real-world Indian SMS validation:** Synthetic corpus is AI-assisted and not human-reviewed.

---

## 7. Model Loading, Export, and Runtime Findings

1. **Checkpoint & Tokenizer (`VERIFIED`):**
   - `/home/zayn/EdgeShield/models/llama-spinquant/consolidated.00.pth` (`1,621,294,320` bytes) matches Meta's `meta-llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8` (`b8c08c95d0476ccb6fc86e9410818d602ecca19d`): 16 layers, dim 2048, 32 heads, 8 KV heads, vocab 128256, `group_size: 32`, SpinQuant INT4 weights (`[-8, 7]`) with group scales `[2048, 64]` and int8 embeddings `[128256, 2048]`.
   - `tokenizer.model` (`2,183,982` bytes) is a genuine `TiktokenTokenizer` rank file (128,000 base tokens, BOS `128000`, EOS `128001/128009`).
2. **ExecuTorch Export (`VERIFIED`):**
   - `build/executorch/llama3_2.pte` (`1,075,142,912` bytes, SHA-256 `c31e4d376f349de85b4422a8c0405d88f21145709f0e17168b06d809ffe5e8a2`) exported under ExecuTorch commit `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7` using `llama_xnnpack_spinquant.yaml` (`preq_8da4w_out_8da8w`, `preq_group_size: 32`, `preq_embedding_quantize: 8,0`, `use_spin_quant: native`, XNNPACK extended ops, `max_seq_length: 2048`). Reported activation memory: `352,739,136` bytes (`336.4 MiB`).
3. **Pybind Runner Discovery (`VERIFIED`):**
   - Initial `TextLLMRunner` smoke test failed with `Backend XnnpackBackend is not registered` (`results/host/ubuntu/llama_host_smoke_attempt1_xnnpack_unregistered.log`) because ExecuTorch's shared-runtime wheel does not eagerly load backend/kernel `.so` initializers from `_llm_runner`. Importing `portable_lib`, `executorch.kernels.quantized`, and `custom_ops` before `TextLLMRunner` resolved it completely.
4. **Native x86_64 C++ `llama_main` Runner (`VERIFIED`):**
   - Built via `cmake --workflow --preset llm-release` and `examples/models/llama` preset `llama-release`.
   - Emits exact prompt echo + generation + `<|eot_id|>` + `\nPyTorchObserver {...}` matching `ExecuTorchAdvisor`'s strict protocol parser. End-to-end CLI and 10-rep `benchmarking.py` runs passed `10/10`.
5. **Pi 4 `aarch64` Cross-Compilation & Critical GLIBC ABI Finding (`VERIFIED` on host; `PENDING_HARDWARE` on Pi 4):**
   - Arm GNU Toolchain `14.3.rel1` (`145 MiB`) downloaded cleanly, passed MD5 `b82906df613ca762058e3ca39ac2e23a`, and cross-compiled `models/llama/pi4-aarch64/llama_main` (`7,097,336` bytes, AArch64, `-march=armv8-a -mtune=cortex-a72`) and `libllama_runner.so` (`4,374,680` bytes, AArch64) in `results/host/ubuntu/pi4_cross_build_attempt2.log`.
   - **CRITICAL COMPATIBILITY FINDING (`results/host/ubuntu/pi4_binary_audit.json`):** Both `aarch64` binaries link dynamically against **`GLIBC_2.38`** (`__isoc23_strtol`, `__isoc23_strtoul`, `__isoc23_strtoll`, `__isoc23_strtoull`, `__isoc23_sscanf`, `fmod@GLIBC_2.38`, `fmodf@GLIBC_2.38`) and **`GLIBCXX_3.4.32` / `CXXABI_1.3.15`** from Arm GNU Toolchain 14.3.rel1's sysroot. **Raspberry Pi OS Bookworm (Debian 12) ships GLIBC 2.36**, meaning these binaries will fail to load (`version 'GLIBC_2.38' not found`) on stock Bookworm unless mitigated (see Section 9 & 11).

---

## 8. Inference Benchmark Results (Ubuntu x86_64 Host Only — NOT Pi 4)

**Conditions:** Ubuntu 22.04.5 LTS x86_64, AMD Ryzen 5 8645HS (12 logical CPUs), 14 GiB RAM, Python 3.10.12, `models/detector_v2.json` (`1.95 MB`), `llama3_2.pte` (`1.00 GiB`), `max_new_tokens=48`, `temperature=0`, `seq_len=768`. **Never present these figures as Raspberry Pi 4 performance.**

| Benchmark / Metric | Result | Source Artifact | Status |
|---|---|---|---|
| Detector-only 100 reps (after optimization) | `detector_ms` median **0.577 ms** (p95 `1.094 ms`), `evidence_ms` median **0.042 ms** (down from `0.046 ms`), `total_ms` median **0.632 ms** | `results/host/ubuntu/benchmark_optimized_detector.json` | `VERIFIED` |
| Cold CLI startup (5 subprocesses: import + load + 1 `assess`) | Wall median **509.59 ms** (p95 `634.80 ms`), Peak RSS median **111.46 MiB** | `results/host/ubuntu/optimization_study.json` | `VERIFIED` |
| `load_detector` cold vs cached (with `.sha256` verify) | Cold **29.96 ms** (single JSON parse); Cached hit median **0.985 ms** | `results/host/ubuntu/optimization_study.json` | `VERIFIED` |
| `detect_indicators` / `assess` across 132 holdout messages | Indicators **0.056 ms/msg**, `assess` **0.643 ms/msg** median | `results/host/ubuntu/optimization_study.json` | `VERIFIED` |
| End-to-end `ExecuTorchAdvisor` (`cpu_threads=2`, 10 reps) | **10/10 Llama (validated)**; `llama_ms` median **3434.78 ms** (p95 `3779.40 ms`), `model_load_ms` **1568.5 ms**, `prefill_ms` / TTFT **772.0 ms**, decode **45.23 tok/s** (15–20 tokens), GNU time Max RSS **1628.5 MiB** (`1667588 KiB`) | `results/host/ubuntu/benchmark_llama_threads2.json` & `benchmark_llama_threads2_resources.txt` | `VERIFIED` |
| Single `llama_main` child RSS (`GNU time -v`) | **1627.86 MiB** (`1666932 KiB`) | `results/host/ubuntu/optimization_study.json` | `VERIFIED` |
| CPU thread scaling (1 vs 2 vs 4 threads, 5 reps each + 1 warmup) | `1 thread`: `llama_ms` **4257.7 ms**, prefill `1412 ms`, decode `37.14 tok/s`; `2 threads`: **3408.0 ms**, prefill `778 ms`, decode `44.91 tok/s`; `4 threads`: **3155.9 ms**, prefill `506 ms`, decode `48.86 tok/s` | `results/host/ubuntu/optimization_study.json` | `VERIFIED` |

---

## 9. Remaining Technical Blockers

1. **Cross-compiled `aarch64` `GLIBC_2.38` / `GLIBCXX_3.4.32` requirement vs Bookworm (`GLIBC 2.36`) (`BLOCKED` until OS choice or Pi-native/sysroot build):**
   - `models/llama/pi4-aarch64/{llama_main,libllama_runner.so}` require `GLIBC_2.38` and `GLIBCXX_3.4.32`, whereas `deploy/pi4/install_dependencies.sh` and `wheelhouse/pi4-cp311` target CPython 3.11 (Debian Bookworm's default Python, which has GLIBC 2.36). Running these specific binaries on Bookworm will fail `ldd` / `verify_environment.py --runtime` at the lab unless one of these paths is prepared:
     - **Option A (fastest at lab):** Boot Pi 4 on a `GLIBC >= 2.38` 64-bit OS (e.g., Raspberry Pi OS Trixie or Ubuntu 24.04 ARM64) OR run the C++ `llama_main` binary inside an Ubuntu 24.04 ARM64 chroot/rootfs while keeping Bookworm CPython 3.11 for EdgeShield's Python layer — or build a CPython 3.11 venv via `pyenv`/conda on the newer OS.
     - **Option B (best for stock Bookworm CPython 3.11):** Compile `llama_main` & `libllama_runner.so` **natively on the Pi 4** running Bookworm (or cross-compile using Arm GNU Toolchain 12.2.rel1 / Debian Bookworm aarch64 sysroot).
2. **Physical Raspberry Pi 4 validation (`PENDING_HARDWARE`):** Real Pi 4 execution, `model_load_ms`, decode speed, RSS, CPU utilization, thermal throttling, `strace -f -e trace=network` offline trace, and 600 s sustained run.
3. **Non-hardware submission gates (`BLOCKED`):** Human review of synthetic dataset labels, 20-case Llama-vs-template study & 5-person clarity study, demo video recording, organiser clarification on Pi 4 + SMS-only PS3 scope, and authorized GitHub/form submission.

---

## 10. Tasks Delegated to Argon (Status Updated 17 Nov 2026)

1. **Pre-lab packaging, Bookworm ABI build, 20-case study, & documentation (`VERIFIED` in [ARGON_COMPLETION_REPORT.md](ARGON_COMPLETION_REPORT.md)):**
   - Argon resolved the `GLIBC_2.38` blocker by cross-compiling Bookworm-compatible (`GLIBC <= 2.34`) `aarch64` binaries with Arm GNU `12.2.rel1`, staged `models/llama/`, ran the frozen 20-case Llama-vs-template host comparison (`20/20` accepted), added `--demo`, `averages_ms`, and CWD-independent model resolution (`176 passed, 1 skipped`), prepared `docs/CLARITY_STUDY_INSTRUMENT.md`, updated `docs/` & `submission/`, and regenerated/verified `dist/edgeshield-pi4-preparation.zip`.
2. **Remaining open items (`PENDING_HARDWARE` / `PENDING_PARTICIPANTS`):** Physical Raspberry Pi 4 lab tests, 5-person clarity study, human synthetic label review, demo video, and submission.

---

## 11. Tasks Explicitly Deferred Until the Pi 4 Lab Visit

All items below are `PENDING_HARDWARE` / `DEFERRED`:
1. Confirm Pi 4 8 GB OS (`uname -a`, `ldd --version`, `python3 --version`). Resolve the `GLIBC_2.38` binary compatibility (either via native `llama_main` build on Bookworm, Bookworm sysroot cross-build, or a `GLIBC >= 2.38` OS image with matching Python wheel provisioning).
2. Copy `build/executorch/llama3_2.pte`, `/home/zayn/EdgeShield/models/llama-spinquant/tokenizer.model` (plus Meta Llama 3.2 `LICENSE` / Notice), and compatible `aarch64` `llama_main` + `libllama_runner.so` into `models/llama/` on the Pi 4.
3. Run `bash deploy/pi4/setup.sh`, generate `configs/inference.json` via `deploy/pi4/create_manifest.py --arch aarch64`, and run `deploy/pi4/verify_environment.py --runtime configs/inference.json`.
4. Run `bash deploy/pi4/launch.sh` and verify real `Llama (validated)` output on Pi 4.
5. Run `bash deploy/pi4/diagnostic.sh`, `bash deploy/pi4/offline_verify.sh` (with Wi-Fi/Ethernet disconnected and `strace -f -e trace=network`), and `bash deploy/pi4/benchmark.sh` (600 s sustained run + thermal/memory monitoring).
6. Record real on-device demo video (`docs/DEMO_SCRIPT.md`) and run the 20-case + 5-person clarity studies.

---

## 12. Known Limitations and Risks

- **Detection coverage:** On the 120-case fresh synthetic holdout, V2 missed **10/60 scams** (assigned `LEGITIMATE`, 0 abstentions due to narrow `[0.25, 0.275]` thresholds) and produced **1/60 false alarm** (`v2h066`). Real-world Indian SMS performance is unmeasured.
- **Cold subprocess latency & RAM on Pi 4:** Even on an x86_64 Ryzen 5 8645HS, cold `llama_main` takes **3.43 s** median (`1.57 s` model load) and **1.59 GiB RSS**. On a Pi 4 Cortex-A72 with slower SD/eMMC I/O and memory bandwidth, latency could be tens of seconds per message; if so, `--advisory-policy elevated` or `uncertain` can skip Llama on clean low-risk messages while preserving V2 immediacy (since V2 verdict + `DO:` advice print before Llama starts).
- **Validator trade-off:** The 1-shot prompt achieves 100% validator acceptance on synthetic evidence, effectively steering the 1B SpinQuant model to emit one of the closed-schema `WHY:` sentences rather than open prose.
- **Unimplemented PS3 capabilities:** Independent phishing URL classification, network intrusion detection, and malware behavior analysis remain `NOT_IMPLEMENTED`.

---

## 13. Instructions to Reproduce the Current Working State

### A. Run unit, safety, integration, and V2 reproduction tests (`.venv-host`)
```bash
cd /home/zayn/Projects/edgeshield
bash scripts/host_python.sh -m pytest -q
bash scripts/host_python.sh scripts/reproduce_v2_evaluation.py --output /tmp/v2_repro_check.json
```
Expected: `174 passed, 1 skipped` and `"all_frozen_hashes_match": true`, `50/60` scams detected, `24/30` Hinglish, `1/60` false alarm, `0` mismatches.

### B. Run end-to-end CLI with genuine SpinQuant Llama on Ubuntu x86_64
```bash
cd /home/zayn/Projects/edgeshield
printf 'Urgent: share your OTP at https://bit.ly/synthetic to prevent bank account block.\n' | \
  bash scripts/host_python.sh -m edgeshield.cli --stdin --json \
  --runtime-config results/host/ubuntu/inference_host_x86_64.json
```
Expected: `detection` event (`SCAM`), followed by `explanation` event with `"source": "Llama (validated)"`, `"reason": "ACCEPTED"`, and non-null `"llama_ms"`.

### C. Run ExecuTorch pybind host smoke (`build/executorch/.venv`)
```bash
cd /home/zayn/Projects/edgeshield/build/executorch
env -u PYTHONPATH -u PYTHONHOME .venv/bin/python \
  /home/zayn/Projects/edgeshield/scripts/verify_llama_host.py \
  --model llama3_2.pte \
  --tokenizer /home/zayn/EdgeShield/models/llama-spinquant/tokenizer.model \
  --output /tmp/llama_smoke_check.json
```
Expected: `validator accepted 3/3 distinct cases (3/3 weighted); deterministic=True`.
