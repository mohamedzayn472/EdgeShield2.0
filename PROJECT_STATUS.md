# EdgeShield status — 17 November 2026

> Target update: owner now has a **Raspberry Pi 5, 4 GB**. A separate
> `deploy/pi5/` path supports provisioning for installed Python 3.10–3.13
> using matching native wheels. See [Pi5 deployment](docs/PI5_DEPLOYMENT.md).
> Pi5 inference, memory, ABI, offline and performance tests remain
> `PENDING_HARDWARE`. Earlier Pi4 records below retain their original scope.

Phase 1 (Opus) and Phase 2 (Argon) Ubuntu engineering, Bookworm `aarch64` cross-compilation, and Pi 4 deployment preparation are complete. **Physical Raspberry Pi 4 hardware validation, human clarity study, and final submission remain pending the lab visit.**

- `PASSED`: **176 software tests passed, 1 skipped** on Ubuntu x86_64 (`results/host/ubuntu/pytest_argon.xml`; expected skip is raw UCI corpus split audit excluded from the transfer bundle; historical Windows baseline passed 171).
- `PASSED`: Read-only Ubuntu reproduction of frozen V2 fresh synthetic checks (`results/host/ubuntu/v2_reproduction.json`): **50/60 scams detected** (English 26/30, Hinglish 24/30), **1/60 false alarm**, **10 scams assigned `LEGITIMATE`**, `0` abstentions, max score delta vs Windows `5.55e-17`.
- `VERIFIED (UBUNTU HOST)`: Real `Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8` exported (`build/executorch/llama3_2.pte`, `1,075,142,912` bytes, SHA-256 `c31e4d376f349de85b4422a8c0405d88f21145709f0e17168b06d809ffe5e8a2`), native x86_64 `llama_main` verified end-to-end (`cli_llama_smoke.jsonl`, `demo_ubuntu_llama.txt`), `100%` validator acceptance (`432/432` dev, `132/132` holdout, `20/20` comparison in `twenty_case_llama_vs_template.json`), and `10/10` + `5/5` host benchmarks (`benchmark_llama_threads2.json`, `benchmark_argon_llama.json`, median `llama_ms` `3.43–3.48 s`, child peak RSS `1628.5 MiB` on Ubuntu x86_64 — NOT Pi 4 numbers).
- `VERIFIED (BOOKWORM CROSS-BUILD)`: Bookworm-compatible `aarch64` Cortex-A72 `llama_main` (`2dff99fe...`) and `libllama_runner.so` (`b4c1c42f...`) cross-compiled with Arm GNU Toolchain `12.2.rel1` (`max GLIBC_2.34`, `max GLIBCXX_3.4.30`, `symbols_requiring_glibc_gt_2_36: []`, `pi4_bookworm_binary_audit.json`) and staged in `models/llama/` alongside `llama3_2.pte`, `tokenizer.model`, `LICENSE_AND_NOTICE.md`, and `pi4-runtime-manifest.json`.
- `VERIFIED (PACKAGING)`: Refreshed `dist/edgeshield-pi4-preparation.zip`, `BUNDLE_MANIFEST.json`, and `dist/ARTIFACT_INVENTORY.json` (`scripts/verify_bundle.py` passed).
- `PENDING_HARDWARE`: Pi 4 installation, `ldd`/ABI check on target, genuine Arm inference, offline `strace` trace, device latency, memory, CPU, thermals, and 600 s sustained testing.
- `PENDING_PARTICIPANTS` / `BLOCKED`: 5-person clarity study (`docs/CLARITY_STUDY_INSTRUMENT.md`), human label review, on-device demo video, scope clarification, and submission.
- `NOT_IMPLEMENTED`: Independent URL, network, and malware detectors; representative real-world evaluation.
- `FAILED` (archived): V1 Indian/Hinglish challenge (`models/detector.json`, preserved for audit).

The default detector remains `models/detector_v2.json`. All frozen files in `results/host/evaluation_freeze.json` and `results/host/v2/evaluation_freeze.json` retain their exact recorded SHA-256 hashes.

Read [Argon Completion Report](docs/ARGON_COMPLETION_REPORT.md), [Opus → Argon Handoff](docs/OPUS_TO_ARGON_HANDOFF.md), [Pi 4 Deployment](docs/PI4_DEPLOYMENT.md), and [Lab Checklist](docs/LAB_CHECKLIST.md).
