# EdgeShield — Phase 2 Gemini Argon Completion Report

**Date:** 17 November 2026  
**Host Environment:** Ubuntu 22.04.5 LTS (`Linux-6.8.0-136-generic-x86_64-with-glibc2.35`, `x86_64`, Python 3.10.12, AMD Ryzen 5 8645HS 12-core, 14 GiB RAM)  
**Repository Root:** `/home/zayn/Projects/edgeshield`  
**External Llama Weights:** `/home/zayn/EdgeShield/models/llama-spinquant` (unmodified)  
**Overall Phase 2 Status:** Complete on Ubuntu host (`VERIFIED`); physical Raspberry Pi 4 hardware validation remains `PENDING_HARDWARE`.

---

## 1. Opus Handoff Reviewed

- `[VERIFIED]` Reviewed `docs/OPUS_TO_ARGON_HANDOFF.md`, `PROJECT_STATUS.md`, `docs/HANDOFF.md`, `docs/PI4_DEPLOYMENT.md`, `docs/EXECUTORCH.md`, `docs/V2_RESULTS.md`, and `results/PROJECT_STATUS.json`.
- `[VERIFIED]` Confirmed Opus's verified Phase 1 outcomes:
  - Frozen V2 synthetic evaluation reproduced bit-for-bit on Ubuntu (`50/60` scams detected, `24/30` Hinglish, `1/60` false alarm, `10` missed scams, max score delta `5.55e-17`).
  - `Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8` exported to `build/executorch/llama3_2.pte` (`1,075,142,912` bytes, SHA-256 `c31e4d376f349de85b4422a8c0405d88f21145709f0e17168b06d809ffe5e8a2`).
  - 1-shot defensive prompt + `INDICATOR_PRIORITY` fallback raised 1B SpinQuant validator acceptance from `48/432` (`11.1%`) to `432/432` (`100%` dev) and `132/132` (`100%` holdout).
  - Native x86_64 `llama_main` end-to-end CLI and `ExecuTorchAdvisor` benchmarks passed (`10/10` validated).
  - Identified blocker left by Opus: `14.3.rel1` Pi 4 `aarch64` binaries required `GLIBC_2.38` / `GLIBCXX_3.4.32`, incompatible with stock Raspberry Pi OS Bookworm (`GLIBC 2.36`).

---

## 2. Argon Tasks Completed

- **Task A — Stabilization & small fixes (`VERIFIED`):**
  - Added CWD-independent `resolve_default_detector()` in `src/edgeshield/model_loader.py` (used by both `cli.py` and `benchmarking.py`) so invoking EdgeShield from outside the repo root finds `models/detector_v2.json` automatically while explicit missing `--detector` paths still fail cleanly.
  - Inserted `src/` onto `sys.path` in `deploy/pi4/verify_environment.py` before importing `edgeshield.advisory` so preflight runtime checks run without needing manual `PYTHONPATH`.
  - Added regression tests covering CWD-independent resolution, `--demo` CLI output, `--advisory-policy`, and `benchmarking.main` report schema.
- **Task B — Benchmark & comparison tooling (`VERIFIED` on Ubuntu host):**
  - Enhanced `src/edgeshield/benchmarking.py` with `--advisory-policy` and `averages_ms` (mean latency across valid samples) while keeping `distribution()` (`n`, `median`, `p95`, `min`, `max`) intact.
  - Created and executed `scripts/run_twenty_case_comparison.py` (`results/host/ubuntu/twenty_case_llama_vs_template.json`): **20/20** cases accepted by validator (`0/20` rejected, `0/20` runtime errors, `0/20` fallback).
  - Executed updated 100-rep detector benchmark (`benchmark_argon_detector.json`) and 5-rep Llama benchmark (`benchmark_argon_llama.json`).
- **Task C — Pi 4 deployment readiness (`VERIFIED` on host; `PENDING_HARDWARE` on Pi 4):**
  - Resolved Opus's `GLIBC_2.38` blocker! Downloaded & SHA-256 verified Arm GNU Toolchain `12.2.rel1` (`6e8112dce0d4334d93bd3193815f16abe6a2dd5e7872697987a0b12308f876a4`), created `build/executorch/arm-toolchain-pi4-bookworm.cmake` (`-march=armv8-a -mtune=cortex-a72`), and cross-compiled ExecuTorch + `llama_main` with KleidiAI and Armv8.2+/Armv9 extensions disabled (`pi4_bookworm_cross_build.log`).
  - Audited Bookworm binaries (`pi4_bookworm_binary_audit.json`): `max_glibc_required: GLIBC_2.34`, `max_glibcxx_required: GLIBCXX_3.4.30`, `symbols_requiring_glibc_gt_2_36: []` (compatible with stock Raspberry Pi OS Bookworm `GLIBC 2.36`).
  - Staged transfer-ready `models/llama/` (`llama_main`, `libllama_runner.so`, `llama3_2.pte`, `tokenizer.model`, `LICENSE_AND_NOTICE.md`, `pi4-runtime-manifest.json`), preserved `14.3.rel1` binaries under `models/llama/pi4-aarch64-glibc238/`, and created `deploy/pi4/smoke_test.sh`.
  - Regenerated and verified `dist/edgeshield-pi4-preparation.zip`, `BUNDLE_MANIFEST.json`, and `dist/ARTIFACT_INVENTORY.json`.
- **Task D — User-facing demo polish (`VERIFIED`):**
  - Added `--demo` mode to `src/edgeshield/cli.py` with 4 built-in English & Hinglish synthetic examples, human-readable indicator descriptions (`Indicator details: ...`), and total latency (`Total: ... ms`) in terminal output.
  - Created `scripts/run_demo_ubuntu.sh` (`--llama` flag supported) and verified genuine 4-case demo execution (`results/host/ubuntu/demo_ubuntu_llama.txt`).
- **Task E — Documentation, clarity instrument, & submission alignment (`VERIFIED`):**
  - Created `docs/CLARITY_STUDY_INSTRUMENT.md` (`PENDING_PARTICIPANTS`, 0 fabricated scores).
  - Updated `README.md`, `docs/PI4_DEPLOYMENT.md`, `docs/LAB_CHECKLIST.md`, `docs/EXECUTORCH.md`, `docs/SOURCES_RUNTIME.md`, `docs/BENCHMARKS.md`, `docs/LIMITATIONS.md`, `docs/REPORT.md`, `docs/DEMO_SCRIPT.md`, `submission/*`, `PROJECT_STATUS.md`, `docs/HANDOFF.md`, `docs/UBUNTU_VERIFICATION.md`, `docs/OPUS_TO_ARGON_HANDOFF.md`, `results/PROJECT_STATUS.json`, and this report.
- **Task F — Final Ubuntu quality gate (`VERIFIED`):**
  - Validated `bash -n` on all `.sh` scripts, ran `scripts/package_bundle.py` & `scripts/verify_bundle.py`, verified zero frozen hash mismatches, and ran the full pytest suite (`176 passed, 1 skipped`).

---

## 3. Files Changed

### Source & deployment scripts
- `src/edgeshield/model_loader.py` — Added `DEFAULT_DETECTOR_PATH` and `resolve_default_detector()`.
- `src/edgeshield/cli.py` — Added `DEMO_CASES`, `--demo`, `Indicator details:` display, `Total: ... ms` timing display, and CWD-independent default detector resolution.
- `src/edgeshield/benchmarking.py` — Added `--advisory-policy`, `averages_ms` summary dict, and CWD-independent default detector resolution.
- `deploy/pi4/verify_environment.py` — Added repo `src/` to `sys.path` before importing `edgeshield.advisory`.
- `deploy/pi4/smoke_test.sh` — New Pi 4 lab smoke-test wrapper (`verify_environment.py --runtime` + `cli --demo`).
- `scripts/run_demo_ubuntu.sh` — New Ubuntu host demo wrapper (`--llama` option).
- `scripts/run_twenty_case_comparison.py` — New frozen 20-case Llama-vs-template comparison runner.
- `build/executorch/arm-toolchain-pi4-bookworm.cmake` — CMake toolchain targeting `arm-gnu-toolchain-12.2.rel1` (`-march=armv8-a -mtune=cortex-a72`).

### Tests
- `tests/test_pipeline_integration.py` — Added `test_cli_demo_human_and_json_and_cwd_resolution`.
- `tests/test_benchmarking.py` — Added `test_benchmarking_main_averages_and_policy`.

### Staged binaries & evaluation/build records (host only; frozen files untouched)
- `models/llama/{llama_main,libllama_runner.so,llama3_2.pte,tokenizer.model,LICENSE_AND_NOTICE.md,pi4-runtime-manifest.json}`
- `models/llama/pi4-aarch64/{llama_main,libllama_runner.so}` (Bookworm `GLIBC <= 2.34`)
- `models/llama/pi4-aarch64-glibc238/{llama_main,libllama_runner.so}` (archived `14.3.rel1` `GLIBC_2.38` build)
- `results/host/ubuntu/{arm_toolchain_12_2.sha256asc,pi4_bookworm_cross_build.log,pi4_bookworm_binary_audit.json,twenty_case_llama_vs_template.json,benchmark_argon_detector.json,benchmark_argon_llama.json,demo_ubuntu_llama.txt,pytest_argon.xml}`

### Documentation, submission, & packaging
- `docs/ARGON_COMPLETION_REPORT.md` (this file), `docs/CLARITY_STUDY_INSTRUMENT.md`
- `README.md`, `PROJECT_STATUS.md`, `docs/HANDOFF.md`, `docs/UBUNTU_VERIFICATION.md`, `docs/OPUS_TO_ARGON_HANDOFF.md`, `docs/PI4_DEPLOYMENT.md`, `docs/LAB_CHECKLIST.md`, `docs/EXECUTORCH.md`, `docs/SOURCES_RUNTIME.md`, `docs/BENCHMARKS.md`, `docs/LIMITATIONS.md`, `docs/REPORT.md`, `docs/DEMO_SCRIPT.md`, `results/PROJECT_STATUS.json`
- `submission/{CHECKLIST.md,SLIDE_CONTENT.md,PITCH.md,JUDGE_QA.md,VIDEO_SCRIPT.md}`
- `dist/{edgeshield-pi4-preparation.zip,ARTIFACT_INVENTORY.json}`, `BUNDLE_MANIFEST.json`

---

## 4. Commands Executed (Key Verification Commands)

```bash
# 1. Bookworm-compatible Pi 4 aarch64 cross-build (Arm GNU 12.2.rel1, KleidiAI/Armv8.2+ disabled)
cmake --preset llm -B cmake-out-pi4-bookworm -DCMAKE_TOOLCHAIN_FILE="$PWD/arm-toolchain-pi4-bookworm.cmake" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PWD/cmake-out-pi4-bookworm" \
  -DEXECUTORCH_BUILD_EXTENSION_MODULE=ON -DEXECUTORCH_XNNPACK_ENABLE_KLEIDI=OFF \
  -DXNNPACK_ENABLE_KLEIDIAI=OFF -DXNNPACK_ENABLE_ARM_BF16=OFF -DXNNPACK_ENABLE_ARM_I8MM=OFF \
  -DXNNPACK_ENABLE_ARM_SME=OFF -DXNNPACK_ENABLE_ARM_SME2=OFF
cmake --build cmake-out-pi4-bookworm -j"$(nproc)" --target install --config Release
cmake -DCMAKE_TOOLCHAIN_FILE="$PWD/arm-toolchain-pi4-bookworm.cmake" -DCMAKE_INSTALL_PREFIX="$PWD/cmake-out-pi4-bookworm" \
  -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release -B cmake-out-pi4-bookworm/examples/models/llama examples/models/llama
cmake --build cmake-out-pi4-bookworm/examples/models/llama -j"$(nproc)" --config Release

# 2. 20-case Llama-vs-template host comparison & Argon benchmarks
bash scripts/host_python.sh scripts/run_twenty_case_comparison.py \
  --runtime-config results/host/ubuntu/inference_host_x86_64.json \
  --output results/host/ubuntu/twenty_case_llama_vs_template.json
bash scripts/host_python.sh -m edgeshield.benchmarking --repetitions 100 --output results/host/ubuntu/benchmark_argon_detector.json
bash scripts/host_python.sh -m edgeshield.benchmarking --runtime-config results/host/ubuntu/inference_host_x86_64.json --repetitions 5 --output results/host/ubuntu/benchmark_argon_llama.json
bash scripts/run_demo_ubuntu.sh --llama > results/host/ubuntu/demo_ubuntu_llama.txt

# 3. Bundle packaging & final Ubuntu quality gate
bash scripts/host_python.sh scripts/package_bundle.py
bash scripts/host_python.sh scripts/verify_bundle.py
bash -n scripts/*.sh deploy/pi4/*.sh
bash scripts/host_python.sh -m pytest -q --junitxml=results/host/ubuntu/pytest_argon.xml
```

---

## 5. Test Results

- **Pytest suite (Ubuntu x86_64):** **176 passed, 1 skipped** (`tests/test_detector.py:71` expected skip because raw UCI corpus is excluded from transfer bundle; `results/host/ubuntu/pytest_argon.xml`).
- **Frozen artifact integrity:** **0 mismatches** in `results/host/evaluation_freeze.json` and `results/host/v2/evaluation_freeze.json`.
- **Bundle manifest verification:** `scripts/verify_bundle.py` passed (`BUNDLE_MANIFEST.json` matches `dist/edgeshield-pi4-preparation.zip`).
- **Shell script syntax check:** `bash -n scripts/*.sh deploy/pi4/*.sh` exited 0.
- **20-case Llama-vs-template host comparison:** **20/20** `Llama (validated)` accepted (`0/20` rejected, `0/20` runtime errors, `0/20` fallback; `16/20` exact match with template — on 4 Hinglish items Llama suppressed the noisy `HINGLISH_CUE` suffix in favor of the clean lower-risk prefix).
- **V2 synthetic evaluation (reproduced on Ubuntu in `v2_reproduction.json`):** `50/60` scams detected (`26/30` English, `24/30` Hinglish), `1/60` false alarm, `10` missed scams, `0` abstentions.

---

## 6. Benchmark Results (Ubuntu x86_64 Host Only — NOT Pi 4)

*Measured on Ubuntu 22.04.5 LTS x86_64, AMD Ryzen 5 8645HS 12-core, 14 GiB RAM, Python 3.10.12. Physical Pi 4 benchmarks are `PENDING_HARDWARE`.*

| Run | Metric | Mean | Median | p95 | Memory / Notes |
|---|---|---:|---:|---:|---|
| Detector-only 100 reps (`benchmark_argon_detector.json`) | `detector_ms` | `0.625 ms` | `0.554 ms` | `0.989 ms` | Python peak RSS `121.6 MiB` (per-sample `system_metrics`) |
| Detector-only 100 reps (`benchmark_argon_detector.json`) | `total_ms` | `0.684 ms` | `0.615 ms` | `1.066 ms` | `evidence_ms` mean `0.047 ms`, median `0.043 ms` |
| Cold CLI startup (5 procs, `optimization_study.json`) | Cold import + load + assess | — | `509.59 ms` | `634.80 ms` | Python peak RSS median `111.46 MiB` |
| `ExecuTorchAdvisor` 5 reps (`benchmark_argon_llama.json`, `cpu_threads=2`) | `llama_ms` | `3482.29 ms` | `3477.71 ms` | `3571.48 ms` | `5/5` validated; `model_load_ms` med `1619 ms`, prefill `763 ms`, decode `47.47 tok/s` |
| `ExecuTorchAdvisor` 10 reps (`benchmark_llama_threads2.json`, `cpu_threads=2`) | `llama_ms` | — | `3434.78 ms` | `3779.40 ms` | `10/10` validated; `GNU time` Max RSS `1628.5 MiB` (`1667588 KiB`) |
| 20-case comparison (`twenty_case_llama_vs_template.json`) | `llama_ms` | — | `3379.38 ms` | `3712.02 ms` | `20/20` validated |

---

## 7. Demo Status

- **`VERIFIED` on Ubuntu x86_64 (`results/host/ubuntu/demo_ubuntu_llama.txt`):**
  - `bash scripts/run_demo_ubuntu.sh` runs all 4 built-in English & Hinglish synthetic examples immediately using template fallback (`< 1 ms` per message).
  - `bash scripts/run_demo_ubuntu.sh --llama` runs all 4 cases end-to-end with genuine `Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8` through `ExecuTorchAdvisor`:
    1. English legitimate OTP notice (`LEGITIMATE`, `0.002`) → `Llama (validated)` (`3525.55 ms`)
    2. English KYC/account-block scam (`SCAM`, `0.863`) → `Llama (validated)` (`3760.44 ms`)
    3. Hinglish legitimate delivery update (`LEGITIMATE`, `0.001`) → `Llama (validated)` (`3469.38 ms`)
    4. Hinglish UPI collect/prize scam (`SCAM`, `0.995`) → `Llama (validated)` (`3422.24 ms`)
- **Offline connectivity status:** Application makes no network calls in inference; formal `strace -f -e trace=network` proof on a disconnected Raspberry Pi 4 remains `PENDING_HARDWARE`.

---

## 8. Pi 4 Deployment Readiness

- **`VERIFIED` host cross-build & staging:**
  - `dist/edgeshield-pi4-preparation.zip` includes updated source, `wheelhouse/pi4-cp311/`, `deploy/pi4/*` (including `smoke_test.sh`), docs, and submission files.
  - `models/llama/` holds all required target runtime assets outside the zip:
    - `llama_main` (`2dff99fe178ef105a178fd2b9e0fac84706181917b21ef18207cb5fcadc1dbd8`, `6,245,400` B, AArch64, `max GLIBC_2.34`)
    - `libllama_runner.so` (`b4c1c42f3bcafd8d01cbc01bb4ef378279a2634c5f83e9b92a9c10654336c996`, `4,467,072` B, AArch64, `max GLIBC_2.34`)
    - `llama3_2.pte` (`c31e4d376f349de85b4422a8c0405d88f21145709f0e17168b06d809ffe5e8a2`, `1,075,142,912` B)
    - `tokenizer.model` (`82e9d31979e92ab929cd544440f129d9ecd797b69e327f80f17e1c50d5551b55`, `2,183,982` B)
    - `LICENSE_AND_NOTICE.md` (Meta Llama 3.2 license & notice)
    - `pi4-runtime-manifest.json` (reference hashes)
- **`PENDING_HARDWARE` on physical Pi 4:** Actual `aarch64` kernel execution, `ldd`, memory footprint, CPU utilization, thermal throttling, offline `strace` verification, and 600 s benchmark.

---

## 9. Outstanding Issues

1. **Physical Raspberry Pi 4 hardware verification (`PENDING_HARDWARE`):** All target OS, runtime, offline, and benchmark checks await the lab visit.
2. **Human evaluations (`PENDING_PARTICIPANTS` / `BLOCKED`):** 5-person clarity study (`docs/CLARITY_STUDY_INSTRUMENT.md`) and team review of synthetic V2 labels remain open.
3. **Detection & PS3 scope gaps:** V2 missed `10/60` synthetic holdout scams (`LEGITIMATE`); independent phishing URL reputation, network intrusion monitoring, and malware behavior analysis remain `NOT_IMPLEMENTED`; Pi 4 + SMS-only scope needs organiser confirmation.
4. **Submission artifacts:** Final on-device demo video, slide deck population with Pi 4 measurements, authorized GitHub push, and submission-form receipt remain pending after the lab visit.

---

## 10. Lab-Visit Checklist

1. Bring Pi 4 Model B 8 GB, official 5V/3A PSU, fast storage, cooling, local keyboard/monitor (for disconnected offline `strace`), `dist/edgeshield-pi4-preparation.zip`, `models/llama/`, and `docs/CLARITY_STUDY_INSTRUMENT.md`.
2. Verify 64-bit Raspberry Pi OS Bookworm (`CPython 3.11`, `GLIBC >= 2.34`, `>= 6 GiB` RAM, `>= 3 GiB` free disk).
3. Install system prerequisites (`python3-venv python3-pip time strace iproute2`), extract the zip, copy `models/llama/` into the project root.
4. Run setup, manifest generation, smoke test, offline trace, diagnostic, and 600 s benchmark (commands below).
5. Capture genuine device demo video (`docs/DEMO_SCRIPT.md`), complete 5-person clarity study, update `docs/REPORT.md` & `submission/SLIDE_CONTENT.md` with actual Pi 4 numbers, and submit.

---

## 11. Exact Next Commands to Run on Raspberry Pi 4

```bash
# From extracted edgeshield directory on Pi 4 (with models/llama/ copied in):
python3 scripts/verify_bundle.py
bash deploy/pi4/setup.sh

chmod u+x models/llama/llama_main
.venv/bin/python deploy/pi4/create_manifest.py \
  --runner models/llama/llama_main \
  --model models/llama/llama3_2.pte \
  --tokenizer models/llama/tokenizer.model \
  --library models/llama/libllama_runner.so \
  --arch aarch64 \
  --output configs/inference.json

bash deploy/pi4/smoke_test.sh
bash deploy/pi4/launch.sh --repeat

# After disconnecting Wi-Fi and Ethernet at a local console:
bash deploy/pi4/offline_verify.sh
bash deploy/pi4/diagnostic.sh
bash deploy/pi4/benchmark.sh
```
