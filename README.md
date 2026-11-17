# EdgeShield

**Private intelligence. Safer decisions.** A terminal-first SMS risk assistant for the Bharat AI-SoC Challenge 2026–27 PS3.

An independent TF-IDF/logistic-regression detector assesses user-selected text. Fixed indicator IDs cross a strict privacy boundary; a local Llama model through ExecuTorch may choose a short explanation from approved, evidence-supported sentences. Invalid or unavailable generation produces an explicitly labeled template fallback. Application code supplies every recommendation.

**Ubuntu engineering & Pi 4 deployment preparation complete; physical Pi 4 hardware validation remains `PENDING_HARDWARE`.**
- **Detector V2:** Passes its preregistered fresh synthetic checks (`50/60` scams detected, including `24/30` Hinglish scams, with `1/60` false alarm; `10` scams assigned `LEGITIMATE`, `0` abstentions). Reproduced bit-for-bit on Ubuntu (`results/host/ubuntu/v2_reproduction.json`). Synthetic checks are not real-world validation; human label review remains pending. The failed V1 baseline is preserved for audit.
- **ExecuTorch SpinQuant Llama on Ubuntu x86_64 (`VERIFIED`):** Exported `Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8` to `llama3_2.pte` (`1,075,142,912` bytes) under ExecuTorch `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7`, built native `llama_main`, achieved `100%` validator acceptance (`432/432` dev, `132/132` holdout, `20/20` comparison cases), and verified end-to-end CLI `Llama (validated)` generation (`~3.43 s` median total subprocess time on Ubuntu x86_64).
- **Pi 4 `aarch64` preparation (`VERIFIED` on host; `PENDING_HARDWARE` on Pi 4):** Cross-compiled Bookworm-compatible (`GLIBC <= 2.34`, `GLIBCXX <= 3.4.30`) `aarch64` `llama_main` and `libllama_runner.so` with Arm GNU Toolchain `12.2.rel1` (`-march=armv8-a -mtune=cortex-a72`) and staged `models/llama/` for lab transfer.

See [docs/ARGON_COMPLETION_REPORT.md](docs/ARGON_COMPLETION_REPORT.md), [docs/OPUS_TO_ARGON_HANDOFF.md](docs/OPUS_TO_ARGON_HANDOFF.md), [docs/V2_RESULTS.md](docs/V2_RESULTS.md), and [PROJECT_STATUS.md](PROJECT_STATUS.md).

## Run on Ubuntu Linux (Current Development Host)

From `/home/zayn/Projects/edgeshield` (using `scripts/host_python.sh` to keep unrelated shell `PYTHONPATH` packages isolated):

```bash
# Built-in 4-case English & Hinglish synthetic demo (template explanations)
bash scripts/run_demo_ubuntu.sh

# Built-in 4-case synthetic demo with genuine host Llama-3.2-1B SpinQuant explanations
bash scripts/run_demo_ubuntu.sh --llama

# Interactive hidden SMS entry
bash scripts/host_python.sh -m edgeshield.cli --repeat

# Conditional hybrid policy (always | elevated | uncertain | off)
printf 'Cedar Bank: Your OTP is 000000. Do not share your OTP.\n' | \
  bash scripts/host_python.sh -m edgeshield.cli --stdin --json \
  --runtime-config results/host/ubuntu/inference_host_x86_64.json \
  --advisory-policy elevated
```

## Run on Windows (Historical Host Environment)

```powershell
.venv\Scripts\python.exe -m edgeshield.cli --repeat
```

Input is hidden to keep SMS out of terminal output. Empty input exits. No inbox access, message history, cloud inference, automatic clicking, sending, or deletion is implemented. Do not put private SMS directly into shell commands: the shell may save history even though EdgeShield does not.

## Fresh host installation

Use Python 3.10–3.13 (`requirements/host.txt`).

```bash
python3 -m venv .venv-host
env -u PYTHONPATH -u PYTHONHOME .venv-host/bin/python -m pip install -r requirements/host.txt
bash scripts/host_python.sh -m pip install --no-deps --no-build-isolation -e .
bash scripts/host_python.sh -m pytest -q
```

## How to interpret output

- `SCAM`, `UNCERTAIN`, and `LEGITIMATE` are decision bands around a binary spam-derived score. They are not three trained ground-truth classes.
- V2 combines historical UCI spam data and synthetic training examples; its score is not a calibrated real-world Indian scam probability. V1 remains available with `--detector models/detector.json`.
- Indicator names such as `BANK_IMPERSONATION` are legacy IDs for bank-related wording. They do not prove impersonation. A link cue is not an independent URL classification.
- `--advisory-policy` (`always`, `elevated`, `uncertain`, `off`; default `always`) controls whether Llama runs on clean low-risk messages (`elevated` runs only on `SCAM`, `UNCERTAIN`, or indicator matches).
- “Llama (validated)” means a real configured runner returned an allowed explanation. “Template fallback” means Llama did not provide the displayed explanation (either unavailable, rejected, or skipped by policy).
- Low estimated risk does not authenticate the sender or prove a message is safe.

## Tests and measured artifacts

```bash
bash scripts/host_python.sh -m pytest -q --junitxml=results/host/ubuntu/pytest_argon.xml
bash scripts/host_python.sh scripts/safety_report.py
bash scripts/host_python.sh -m edgeshield.benchmarking --repetitions 100 --output results/host/ubuntu/benchmark_argon_detector.json
bash scripts/host_python.sh scripts/package_bundle.py
bash scripts/host_python.sh scripts/verify_bundle.py
```

Current Ubuntu host test result: **176 passed, 1 skipped** (the expected skip is raw UCI corpus split audit excluded from the transfer bundle; historical Windows baseline passed 171 tests). Benchmarks use fixed synthetic fixtures and actual local clocks. Host timings must never be described as Pi timings.

## Raspberry Pi preparation

Copy/extract `dist/edgeshield-pi4-preparation.zip` plus the staged `models/llama/` directory (`llama3_2.pte`, `tokenizer.model`, Bookworm-compatible `aarch64` `llama_main` & `libllama_runner.so`, `LICENSE_AND_NOTICE.md`) to the Pi 4 Model B 8 GB (`aarch64` Linux, Bookworm CPython 3.11), then follow [deploy/pi4/README.md](deploy/pi4/README.md) and [docs/PI4_DEPLOYMENT.md](docs/PI4_DEPLOYMENT.md).

## Documentation and submission

- [Argon completion report](docs/ARGON_COMPLETION_REPORT.md), [Opus → Argon handoff](docs/OPUS_TO_ARGON_HANDOFF.md), [Ubuntu verification](docs/UBUNTU_VERIFICATION.md).
- [Architecture](docs/ARCHITECTURE.md), [security/privacy](docs/SECURITY.md), [verified sources](docs/SOURCES.md).
- [Benchmark protocol](docs/BENCHMARKS.md), [clarity study instrument](docs/CLARITY_STUDY_INSTRUMENT.md), [limitations](docs/LIMITATIONS.md), [technical report](docs/REPORT.md).
- [Demo procedure](docs/DEMO_SCRIPT.md), [submission checklist](submission/CHECKLIST.md), [slide content](submission/SLIDE_CONTENT.md), [pitch](submission/PITCH.md), [judge Q&A](submission/JUDGE_QA.md).

The official challenge deadline is **23 November 2026**; the team's internal target is **22 November**. Independent phishing URL classification, network intrusion detection, and malware analysis remain unimplemented. Pi 4 eligibility under “Arm-based Linux devices” and SMS-only Phase 1 acceptance need organiser confirmation. No GitHub publication or competition submission has been performed.
