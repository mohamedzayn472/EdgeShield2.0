# Model artifacts

## Frozen detectors

The default SMS detector is [V8](detector_v8.json). Its [evaluation protocol](../docs/V8_EVALUATION_PROTOCOL.md) and [physical Pi 5 results](../results/pi5/v8-device-20261124/) identify the frozen configuration. The separate [URL model](url_detector_v1.json) powers the experimental phishing mode. V1–V7 are retained for reproducibility and regression comparisons.

- **`models/detector_v3.json`** (historical, SHA-256 `b2b2126b872c43eb02ccdef41a7f5040cf86cfd0dc1bfb31f98ef13733d50910`, verified via `models/detector_v3.json.sha256`): non-executable JSON word + character TF-IDF logistic-regression detector (`edgeshield-word-char-lr-v3`) with numeric/banking token canonicalization (`thresholds: [0.65, 0.75]`). Read [docs/V3_EVALUATION_REPORT.md](../docs/V3_EVALUATION_REPORT.md) and [docs/REPORT.md](../docs/REPORT.md); physical Pi 5 device verification of V3 is `PENDING_HARDWARE`, and synthetic checks do not establish real-world scam accuracy.
- **`models/detector_v2.json`** (archived Pi 5 measured baseline, SHA-256 `f37c3dd9060b89ead7ea6bbf1c393b22fff7cfc18ed5d85126e977e03daea6a6`, verified via `models/detector_v2.json.sha256`): frozen V2 classifier (`thresholds: [0.25, 0.275]`) used in the physical Pi 5 B0 & offline archives (`results/pi5/archive/20261118-B0-full/`, `results/pi5/offline-20261119/`), inspectable via `--detector models/detector_v2.json`. Read [docs/V2_RESULTS.md](../docs/V2_RESULTS.md).
- **`models/detector.json`** (SHA-256 `9163c20783d76eb1c3cea637dea844e4d1c7d61bec976cd64cb0b69a20cd4c72`): original V1 baseline retained untouched for audit (`FAILED` Indian/Hinglish synthetic check).

## Excluded from public source: gated Meta Llama 3.2 & ExecuTorch runtime

Meta Llama 3.2 weights, tokenizer, exported `.pte`, and compiled `aarch64` runner binaries are **excluded** from the public GitHub repository and public release archive in compliance with the Meta Llama 3.2 Community License.

To reproduce physical Raspberry Pi 5 Llama execution:
1. Obtain lawful gated access to `meta-llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8` (revision `b8c08c95d0476ccb6fc86e9410818d602ecca19d`) on Hugging Face and retain Meta's `LICENSE` and `NOTICE` files (`models/llama/LICENSE_AND_NOTICE.md`).
2. Export `llama3_2.pte` and cross-build `pi5-aarch64/llama_main` and `pi5-aarch64/libllama_runner.so` from pinned ExecuTorch commit `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7` per [docs/EXECUTORCH.md](../docs/EXECUTORCH.md) and [docs/PI5_DEPLOYMENT.md](../docs/PI5_DEPLOYMENT.md).
3. Stage the verified files under `models/llama/` and run `.venv/bin/python deploy/pi5/create_manifest.py --profile pi5`.

Without staged Llama assets, the EdgeShield CLI runs Detector V8 (`models/detector_v8.json`) locally and emits explicitly labeled `Template fallback` explanations. Never substitute dummy weights.
