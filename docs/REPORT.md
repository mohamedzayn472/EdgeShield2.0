# EdgeShield technical report

**Report state:** Evidence-linked Phase 2 engineering & deployment-preparation draft (17 November 2026). Read alongside `PROJECT_STATUS.md`, `docs/ARGON_COMPLETION_REPORT.md`, and `docs/OPUS_TO_ARGON_HANDOFF.md`. **Physical Raspberry Pi 4 measurements remain `PENDING_HARDWARE`.**

**Verified detector & software test state:**
- **Tests:** `176 passed, 1 skipped` on Ubuntu x86_64 (`results/host/ubuntu/pytest_argon.xml`; expected skip: excluded raw UCI corpus split audit; historical Windows baseline passed `171` tests).
- **V2 fresh synthetic holdout (reproduced bit-for-bit on Ubuntu in `results/host/ubuntu/v2_reproduction.json`):** `50/60` scams detected (`83.33%` recall; `26/30` English, `24/30` Hinglish), `1/60` false alarm (`1.67%` FPR; `v2h066`), `10/60` scams assigned `LEGITIMATE`, precision `98.04%`, F1 `0.9009`, `0` abstentions. Provisional synthetic checks passed; human label review and real-world evaluation remain pending.
- **Preserved V1 baseline failure:** `1/12` synthetic scams (`0/6` Hinglish) detected (`docs/DETECTOR_FINDINGS.md`). Both freezes (`results/host/evaluation_freeze.json` and `results/host/v2/evaluation_freeze.json`) retain exact SHA-256 parity.

**Verified Ubuntu x86_64 ExecuTorch + Llama integration:**
- **Checkpoint & export:** Meta `Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8` (rev `b8c08c95d0476ccb6fc86e9410818d602ecca19d`, `TiktokenTokenizer`) exported with pinned ExecuTorch `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7` into `build/executorch/llama3_2.pte` (`1,075,142,912` bytes, SHA-256 `c31e4d376f349de85b4422a8c0405d88f21145709f0e17168b06d809ffe5e8a2`).
- **Prompt & validator reliability:** Replacing raw internal enum interpolation and zero-shot prompting with 1-shot defensive status-line framing + `INDICATOR_PRIORITY` salience ordering (`src/edgeshield/validator.py`) raised genuine 1B SpinQuant validator acceptance from `48/432` (`11.1%`) to `432/432` (`100%` dev), `132/132` (`100%` holdout), and `20/20` (`100%` 20-case comparison, `results/host/ubuntu/twenty_case_llama_vs_template.json`).
- **Host measurements (Ubuntu x86_64 only, NOT Pi 4):** Detector-only 100 reps: mean `0.625 ms`, median `0.554 ms`, p95 `0.989 ms` (`benchmark_argon_detector.json`). End-to-end `ExecuTorchAdvisor` (`cpu_threads=2`): `10/10` validated (`benchmark_llama_threads2.json`, median `3434.78 ms`, `model_load_ms` `1568.5 ms`, `prefill_ms` `772.0 ms`, `45.23 tok/s`, GNU time peak RSS `1628.5 MiB`) and `5/5` validated (`benchmark_argon_llama.json`, mean `3482.29 ms`, median `3477.71 ms`, `47.47 tok/s`).

## Problem and contribution

EdgeShield helps a non-expert inspect a user-selected SMS locally. It separates independent detection from language generation: a statistical detector supplies a score/band and precompiled deterministic rules supply observable cues; Llama is restricted to explaining structured `Evidence` across a strict privacy firewall, and application code owns every `DO:` recommendation. Conditional `--advisory-policy {always,elevated,uncertain,off}` supports skipping Llama on clean low-risk messages (`elevated` skips `21.2%` of holdout cases) while preserving `always` as the default.

## Implementation

See [ARCHITECTURE.md](ARCHITECTURE.md) for component boundaries, [DATASET.md](DATASET.md) for provenance, [EVALUATION_V2.md](EVALUATION_V2.md) for development/holdout protocols, and [EXECUTORCH.md](EXECUTORCH.md) for export/runner details.

## Hardware mapping

Target: Raspberry Pi 4 Model B, 8 GB RAM, 64-bit Raspberry Pi OS Bookworm (CPython 3.11, `GLIBC 2.36`). Host cross-compilation with Arm GNU Toolchain `12.2.rel1` (`-march=armv8-a -mtune=cortex-a72`, KleidiAI & Armv8.2+/Armv9 extensions disabled) produced Bookworm-compatible `aarch64` binaries (`max_glibc_required: GLIBC_2.34`, `max_glibcxx_required: GLIBCXX_3.4.30`, zero `GLIBC > 2.36` symbols; `results/host/ubuntu/pi4_bookworm_binary_audit.json`), staged with `llama3_2.pte`, `tokenizer.model`, and Meta notices under `models/llama/`.

**Device validation: `PENDING_HARDWARE`.** No laptop result is a Pi result.

## Evaluation evidence

Use generated files under `results/host/v2/` and `results/host/ubuntu/` as the numerical source of truth. The 20-case Llama-vs-template study is recorded in `results/host/ubuntu/twenty_case_llama_vs_template.json` (`20/20` accepted). The 5-person clarity study instrument is prepared in `docs/CLARITY_STUDY_INSTRUMENT.md` (`PENDING_PARTICIPANTS`).

## Security and responsible-use limitations

[SECURITY.md](SECURITY.md) and [LIMITATIONS.md](LIMITATIONS.md) document prompt injection isolation, artifact SHA-256 verification, bounded child execution, and residual host/domain-shift risks.

## Compliance assessment

Phase 1 implements the local SMS workflow end-to-end on Ubuntu x86_64. Independent phishing URL detection, network intrusion monitoring, and malware behavior analysis remain `NOT_IMPLEMENTED` against the broader PS3 description. Pi 4 acceptance remains an interpretation of "Arm-based Linux devices" pending organiser confirmation.

## Evidence still required at the lab visit before submission

- Physical Pi 4 setup, runtime execution (`deploy/pi4/smoke_test.sh`), `vcgencmd` diagnostics, 600 s sustained benchmark, and `strace -f -e trace=network` offline proof (`deploy/pi4/offline_verify.sh`).
- 5-person clarity study completion (`docs/CLARITY_STUDY_INSTRUMENT.md`) and team review of synthetic dataset labels.
- Real on-device demo video, final report update with Pi 4 numbers, authorized GitHub publication, and submission-form receipt.
