# EdgeShield

**Private intelligence. Safer decisions.** A local, terminal-first SMS scam assistant for the Bharat AI-SoC Challenge 2026–27 (PS3 Open Qualifying), verified on a physical CPU-only **Raspberry Pi 5**. **Built with Llama.**

EdgeShield separates independent statistical risk detection from on-device language explanation across a strict privacy boundary:

1. **Local detector:** A frozen word + character TF-IDF logistic-regression classifier with numeric/banking canonicalization (`models/detector_v8.json`, SHA-256 `4d3481555460d2bf5dfaf5e28fc107786f38ea34400358e4637b5bd9b0afd365`, thresholds `[0.55, 0.675]`) scores pasted SMS text locally and clause-level rules (`src/edgeshield/indicators.py`) extract enumerated cue IDs without overriding statistical scores.
2. **Privacy boundary:** Only a typed `Evidence` payload (risk band, score, and enumerated cue IDs) crosses to the LLM prompt. Raw SMS text, sender info, and URLs are never sent to Llama.
3. **On-device Llama advisory via ExecuTorch:** Meta `Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8` runs locally through ExecuTorch (`985c1ceccc8bb8b6a32294f71aeb5d2f299562f7`, XNNPACK CPU backend, `pi5-cortex-a76-native`, 2 CPU threads) to generate a concise `WHY:` explanation.
4. **Validation & deterministic advice:** `src/edgeshield/validator.py` verifies every explanation against allowed evidence-supported statements. Invalid, unavailable, or policy-skipped calls fall back to an explicitly labeled `Template fallback`. Application code owns every `DO:` recommendation.

## Verified Raspberry Pi 5 status (24 November 2026)

- **Physical Arm target (`VERIFIED`):** Raspberry Pi 5 Model B Rev 1.1, **16 GB RAM**, CPU-only `aarch64`, Debian GNU/Linux 13 (Trixie), Python 3.13.5, `glibc 2.41`, using the dedicated `pi5-cortex-a76-native` runner (`cpu_threads=2`).
- **Detector V8 + ExecuTorch Llama on Pi 5 — Offline Verified (`VERIFIED`):** Audited in [results/pi5/v8-device-20261124/](results/pi5/v8-device-20261124/) (`SHA256SUMS` `8/8 OK`, recorded `2026-11-24T05:27:28Z`, `runtime_config_sha256: a4f1f80b...`): `eth0`/`wlan0` `DOWN` (`lo` only), empty `offline_routes.json` (`[]`), **0 `AF_INET`/`AF_INET6` matches** in `v8_offline_network.trace`, single CLI SCAM check `Llama (validated)` (`7.76 s`), and offline 5-request benchmark (`48.18 s`) achieving **5/5 `Llama (validated)`** (**0 fallbacks**), **6.51 s** median / **6.85 s** p95 full response (`1.80 ms` med detector, `1.21 s` med load, `3.17 s` med TTFT, `13.25 tok/s` med decode), **1.44 GB** (`1.34 GiB`) peak RSS, **0 B** swap, **72.7 °C** max (`throttled=0x0`).
- **Detector V8 on Pi 5 — Offline Detector Batch & Test Suite (`VERIFIED`, Template fallback):** Audited in [results/pi5/v8-offline-20261124/](results/pi5/v8-offline-20261124/): `361 passed, 1 skipped` (`tests/test_detector.py:71` corpus-excluded skip) in `52.35 s`, `50` repeated batch detections (`5` runs of `10` synthetic messages: `25 SCAM`, `20 LEGITIMATE`, `5 UNCERTAIN`; **2.4321 ms** avg, `2.2172 ms` min, `5.0981 ms` max), `63.7 °C`, `throttled=0x0`.
- **Archived Pi 5 Llama smoke & fallback (Detector V2 `f37c3dd9...`, `VERIFIED`):** `4/4` built-in English and Hinglish synthetic demo cases produced `Source: Llama (validated) | Status: ACCEPTED` on the physical Pi 5 (`results/pi5/archive/20261118-B0-full/smoke_test.txt`), and `2/2` fallback cases produced labeled `Template fallback` (`fallback_smoke.jsonl`).
- **Archived sustained Pi 5 B0 benchmark (Detector V2 `f37c3dd9...`, `VERIFIED`):** Over **605.4 s** (`91` back-to-back requests, passive heatsink, open board, `results/pi5/archive/20261118-B0-full/benchmark.json`):
  - **91/91** advisories passed the explanation validator (**0 fallbacks**). *(Explanation validation metric, not detector accuracy.)*
  - Full-response latency: **6.70 s** median, **6.81 s** p95 (`model_load_ms` median 1.22 s, runtime TTFT median **3.20 s**, decode median **13.49 tokens/s**).
  - Peak runner RSS: **1.44 GB** (decimal; **1.34 GiB**, `1,443,217,408` bytes), **0 bytes** swap used.
  - Thermals: **83.7 °C** peak sampled temperature with thermal throttling (`throttled_after=0xe0008`) under continuous passive load.
- **Archived Pi 5 detector-only speed (Detector V2 `f37c3dd9...`, `VERIFIED`):** **0.92 ms** p95 (`0.89 ms` median) over `100` detector-only samples (`results/pi5/archive/20261118-B0-full/benchmark-detector.json`).
- **Detector V8 synthetic evaluation (`VERIFIED`, host):**
  - On `v8_holdout` (`240` labeled synthetic messages; `24` ambiguous excluded): V8 achieves **99.17%** accuracy (`[[119, 0, 1], [0, 1, 119]]`, **99.17%** recall, **0.83%** FPR, **0.42%** abstentions, **0.99993** ROC-AUC, **0.00857** Brier).
  - On `v3_holdout` (`160`), `v2_holdout` (`120`), and `uci_test` (`1,148`): V8 achieves **99.38%**, **96.67%**, and **98.17%** (`0.00%` FPR, `88.41%` recall) respectively (`results/host/v8/v3_v5_v6_v7_v8_evaluation.json`).
  - See [V8 Evaluation Protocol](docs/V8_EVALUATION_PROTOCOL.md) and `results/host/v8/`. Synthetic checks do not establish real-world accuracy; human label review and real-world calibration remain pending.
- **Archived disconnected Pi 5 offline verification (Detector V2 `f37c3dd9...`, `VERIFIED`):** Audited in `results/pi5/offline-20261119/` (`SHA256SUMS` 6/6 `OK`, recorded `2026-11-19T12:15:54Z`): `eth0` and `wlan0` `DOWN` (`lo` only), empty routing table (`[]`), `5/5` `Llama (validated)` explanations (`0` fallbacks, `6.80 s` p95, `1.44 GB` / `1.34 GiB` RSS, `0 B` swap, `73.25 °C` max, `throttled=0x0`), **zero `AF_INET`/`AF_INET6` calls** in `network.trace`, and `inference.json` SHA-256 `a4f1f80b...` matching B0.
- **Demo video (`MISSING`):** Disconnected on-device Pi 5 recording showing `eth0`/`wlan0` `DOWN` and at least one `Llama (validated)` response is pending capture.

## Phase 1 scope

Per the official challenge brief and PS3 mentoring slides 03 and 11 (recommending one complete, testable on-device security workflow and naming scam SMS as a valid primary scenario), EdgeShield Phase 1 focuses on pasted scam SMS analysis. Independent phishing URL classification, network intrusion detection, and malware analysis are future work.

## Run on Raspberry Pi 5 (Primary Target)

See [docs/PI5_DEPLOYMENT.md](docs/PI5_DEPLOYMENT.md) and [deploy/pi5/README.md](deploy/pi5/README.md) for full provisioning, lawful model acquisition/export, and offline verification steps.

```bash
# 1. Provision isolated Python environment (Python 3.10–3.13)
bash deploy/pi5/setup.sh

# 2. After staging lawfully obtained Llama assets in models/llama/ (see docs/EXECUTORCH.md):
.venv/bin/python deploy/pi5/create_manifest.py --profile pi5

# 3. Verify environment and run 4-case smoke test with genuine Llama
bash deploy/pi5/smoke_test.sh

# 4. Launch interactive hidden-input CLI
bash deploy/pi5/launch.sh --repeat

# 5. Disconnected offline verification (local console, Wi-Fi off & Ethernet unplugged)
bash deploy/pi5/offline_verify.sh
```

## Run on a Linux host (CLI & tests without gated Llama weights)

Public source bundles exclude Meta Llama weights and compiled `aarch64` runtime binaries. Without a configured runtime, the CLI runs the frozen V8 default detector (`models/detector_v8.json`, SHA-256 verified via `models/detector_v8.json.sha256`) and returns explicitly labeled `Template fallback` explanations.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements/host.txt
.venv/bin/python -m pip install --no-deps .
.venv/bin/python -m pytest -q

# Single message JSON check (labeled Template fallback without runtime assets)
printf '%s\n' 'Cedar Bank test: Your OTP is 000000. Do not share it with anyone.' | \
  .venv/bin/python -m edgeshield.cli --stdin --json

# Interactive hidden SMS entry (empty input exits)
.venv/bin/python -m edgeshield.cli --repeat
```

In this development workspace (to isolate shell `PYTHONPATH`), prefix commands with `bash scripts/host_python.sh` (for example `bash scripts/host_python.sh -m pytest -q` or `bash scripts/run_demo_ubuntu.sh --llama` when host runtime assets are staged).

Input is hidden in interactive mode so SMS text is not echoed to terminal output. No inbox access, message history, cloud inference, automatic clicking, sending, or deletion is implemented. Do not pass private SMS via command-line arguments or shell history.

## How to interpret output

- `SCAM`, `UNCERTAIN`, and `LEGITIMATE` are decision bands around a binary spam-derived score (V8 default `thresholds: [0.55, 0.675]`; V2 `thresholds: [0.25, 0.275]` via `--detector models/detector_v2.json`). They are not three trained ground-truth classes.
- Detector V8 combines historical UCI spam data and synthetic Indian/Hinglish banking examples with canonicalized amounts, dates, OTP/short-number separation, and account masks; its score is not a calibrated real-world Indian scam probability. Earlier versions (`models/detector_v2.json`..`v7`) and the preserved failed V1 baseline (`models/detector.json`) remain inspectable via `--detector`.
- Indicator names such as `BANK_IMPERSONATION` and `KYC_IMPERSONATION` are observable lexical cues (`src/edgeshield/indicators.py`), never proof of sender identity or impersonation. A `LINK_PRESENT` cue is not an independent URL classification.
- `--advisory-policy` (`always`, `elevated`, `uncertain`, `off`; default `always`) controls when Llama runs (`elevated` runs only on `SCAM`, `UNCERTAIN`, or indicator matches).
- `Llama (validated)` means a configured ExecuTorch runner returned a validator-accepted explanation. `Template fallback` means Llama did not supply the displayed explanation (unconfigured, rejected, failed, or skipped by policy).
- Low estimated risk does not authenticate the sender or prove a message is safe.

## Obtaining Meta Llama 3.2 & ExecuTorch runtime assets

Meta Llama 3.2 weights and tokenizer are gated under the Meta Llama 3.2 Community License and are never distributed in the public source repository. Reviewers reproducing on-device Llama inference must:

1. Request and obtain lawful access to `meta-llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8` (revision `b8c08c95d0476ccb6fc86e9410818d602ecca19d`) from Hugging Face and retain Meta's `LICENSE` and `USE_POLICY` / `NOTICE` files.
2. Export `llama3_2.pte` and cross-build the `aarch64` ExecuTorch runner from pinned ExecuTorch commit `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7` following [docs/EXECUTORCH.md](docs/EXECUTORCH.md) and `scripts/export_llama.sh`.
3. Stage `llama3_2.pte`, `tokenizer.model`, `pi5-aarch64/llama_main`, `pi5-aarch64/libllama_runner.so`, and `LICENSE_AND_NOTICE.md` under `models/llama/`, then run `deploy/pi5/create_manifest.py --profile pi5`.

## Licensing and Attribution

**Built with Llama.**

- **EdgeShield original source code & original V8 detector:** [MIT License](LICENSE) (assuming all contributors approve and subject to ownership confirmation).
- **Meta Llama 3.2 1B Instruct model and tokenizer:** Licensed under the **Meta Llama 3.2 Community License** (NOT MIT). Meta's full license agreement and attribution notice are preserved in `models/llama/LICENSE_AND_NOTICE.md`. Gated model weights and tokenizer files are excluded from this public repository.
- **ExecuTorch:** Licensed under the **BSD License** (see `executorch/references/LICENSE` and [Runtime Sources](docs/SOURCES_RUNTIME.md)).

## Documentation and submission artifacts

- **Core technical & deployment docs:** [Technical Report](docs/REPORT.md), [V8 Evaluation Protocol](docs/V8_EVALUATION_PROTOCOL.md), [V3 Evaluation Report](docs/V3_EVALUATION_REPORT.md), [Architecture](docs/ARCHITECTURE.md), [Pi 5 Deployment](docs/PI5_DEPLOYMENT.md), [ExecuTorch & Model Setup](docs/EXECUTORCH.md), [V2 Results](docs/V2_RESULTS.md), [Security & Privacy](docs/SECURITY.md), [Limitations](docs/LIMITATIONS.md), [Sources](docs/SOURCES.md), [Runtime Sources](docs/SOURCES_RUNTIME.md), [Data Sources](docs/SOURCES_DATA.md).
- **Submission materials:** [Slide Draft](submission/SLIDE_CONTENT.md), [Submission Checklist](submission/CHECKLIST.md), [Pitch](submission/PITCH.md), [Demo Script](docs/DEMO_SCRIPT.md), [Video Script](submission/VIDEO_SCRIPT.md), [Judge Q&A](submission/JUDGE_QA.md).
- **Verified evidence:** [Pi 5 V8 Offline Detector Archive](results/pi5/v8-offline-20261124/), [Pi 5 B0 Archive (V2)](results/pi5/archive/20261118-B0-full/), [Pi 5 Offline Archive (V2)](results/pi5/offline-20261119/), [Pi 5 Status](results/pi5/STATUS.json), [V8 Evaluation](results/host/v8/v3_v5_v6_v7_v8_evaluation.json), [Project Status](PROJECT_STATUS.md).

Recorded Phase 1 deadline: **23 November 2026**. Historical Raspberry Pi 4 cross-compilation scripts remain under `deploy/pi4/` for reference; primary verified deployment is **Raspberry Pi 5**.
