> **Phase 2 Update (17 November 2026):** Argon stabilization, Bookworm-compatible (`GLIBC <= 2.34`) Pi 4 `aarch64` cross-compilation, 20-case Llama-vs-template host comparison (`20/20` accepted), `--demo` polish, updated docs/submission assets, and bundle verification are complete. Read [ARGON_COMPLETION_REPORT.md](ARGON_COMPLETION_REPORT.md) and [OPUS_TO_ARGON_HANDOFF.md](OPUS_TO_ARGON_HANDOFF.md). Physical Pi 4 hardware tests remain `PENDING_HARDWARE`. Historical Windows results below remain unchanged.

# Current technical handoff — v2

## Windows work done (historical baseline)

The default detector now combines word and character TF-IDF features. Training used UCI development partitions and a new family-split synthetic development corpus. Six preregistered candidates were compared on validation only. Calibration, thresholds and model weights were frozen before a separately authored fresh synthetic test.

**171 software tests passed on Windows.** The app supports hidden input, repeated analysis and JSON output; detector verdict and fixed advice appear before the explanation. The evidence firewall, strict explanation validator, labeled fallback and bounded local runtime adapter remain in place. V1 stays intact for audit.

Fresh synthetic result: precision 98.04%, recall 83.33%, F1 0.9009; one false alarm among 60 legitimate cases, ten of 60 scams assigned LEGITIMATE. Hinglish recall: 24/30. No cases abstained. The predefined synthetic gates passed; human review and real-world validation have not happened. See [V2_RESULTS.md](V2_RESULTS.md).

Host benchmark on Windows: 100 real iterations, detector median 0.443 ms and p95 0.699 ms. All explanations used fallback. No Llama timing or Pi performance is claimed. Results live under `results/host/v2/`.

## Ubuntu Linux work completed (16–17 November 2026)

- **Environment & V2 reproduction (`VERIFIED`):** `176 passed, 1 skipped` on Ubuntu (`results/host/ubuntu/pytest_argon.xml`, raw UCI corpus excluded), and frozen V2 synthetic holdout reproduced bit-for-bit (`results/host/ubuntu/v2_reproduction.json`, `50/60` scams, `24/30` Hinglish, `1/60` false alarm, max score diff `5.55e-17`, 0 mismatches).
- **Llama SpinQuant export & host inference (`VERIFIED`):** Verified `/home/zayn/EdgeShield/models/llama-spinquant` (`b8c08c95d0476ccb6fc86e9410818d602ecca19d`), exported `build/executorch/llama3_2.pte` (`1,075,142,912` bytes, ExecuTorch `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7`), built native x86_64 `llama_main` (`models/llama/host-x86_64/`), and verified `Llama (validated)` generation across CLI (`cli_llama_smoke.jsonl`), `--demo --llama` (`demo_ubuntu_llama.txt`), `benchmark_llama_threads2.json` (`10/10`), `benchmark_argon_llama.json` (`5/5`, mean `llama_ms` `3482.29 ms`, median `3477.71 ms`), and the 20-case comparison (`twenty_case_llama_vs_template.json`, `20/20` accepted).
- **Prompt, optimizations, & Argon stabilization (`VERIFIED`):** Updated `validator.py` (1-shot defensive framing + `INDICATOR_PRIORITY` fallback, raising 1B acceptance from `11.1%` to `100%` across `432/432` dev and `132/132` holdout), `indicators.py` (precompiled regexes), `model_loader.py` (single-pass JSON/SHA-256 cache + CWD-independent `resolve_default_detector`), `pipeline.py` (`--advisory-policy`), `benchmarking.py` (`averages_ms`), `cli.py` (`--demo`, indicator details, total ms), `deploy/pi4/verify_environment.py` (`src/` path fix), and `deploy/pi4/smoke_test.sh`.
- **Bookworm-compatible Pi 4 cross-build (`VERIFIED` on host, `PENDING_HARDWARE` on Pi 4):** Cross-compiled `models/llama/pi4-aarch64/{llama_main,libllama_runner.so}` using Arm GNU Toolchain `12.2.rel1` with KleidiAI and Armv8.2+/Armv9 extensions disabled (`pi4_bookworm_binary_audit.json`: `max_glibc_required: GLIBC_2.34`, `max_glibcxx_required: GLIBCXX_3.4.30`, `symbols_requiring_glibc_gt_2_36: []`) and staged `models/llama/` with `llama3_2.pte`, `tokenizer.model`, `LICENSE_AND_NOTICE.md`, and `pi4-runtime-manifest.json`. (Earlier `14.3.rel1` `GLIBC_2.38` binaries archived in `models/llama/pi4-aarch64-glibc238/`.)

## Transfer and Pi work

`dist/edgeshield-pi4-preparation.zip` is regenerated and verified against `BUNDLE_MANIFEST.json` (`scripts/verify_bundle.py`), and `models/llama/` is staged separately for transfer.

The Pi4 is available, with setup deferred to the lab visit. Follow [ARGON_COMPLETION_REPORT.md](ARGON_COMPLETION_REPORT.md), [PI4_DEPLOYMENT.md](PI4_DEPLOYMENT.md), and [LAB_CHECKLIST.md](LAB_CHECKLIST.md). On the prepared Pi, run:

```bash
python3 scripts/verify_bundle.py
bash deploy/pi4/setup.sh
```

After generating `configs/inference.json` via `deploy/pi4/create_manifest.py --arch aarch64`, run `bash deploy/pi4/smoke_test.sh`, `launch.sh --repeat`, `offline_verify.sh`, `diagnostic.sh`, and `benchmark.sh`.

## Submission gates still open

- Physical Pi 4 lab execution, offline `strace` trace, `vcgencmd` diagnostics, and 600 s benchmark (`PENDING_HARDWARE`).
- 5-person clarity study (`docs/CLARITY_STUDY_INSTRUMENT.md`, `PENDING_PARTICIPANTS`), human synthetic label review, demo video recording, organiser scope clarification, and authorized submission (`BLOCKED` / `DEFERRED`).
