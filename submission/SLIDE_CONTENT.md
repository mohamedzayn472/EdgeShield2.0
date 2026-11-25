# EdgeShield Phase 1 submission draft

**Bharat AI-SoC Challenge 2026–27 · PS3 · Open Qualifying**

The submission includes the source code, runnable application, demonstration video, and technical report. Host the project on GitHub and submit through the official challenge form by **23 November 2026**. The PS3 mentoring slides 03 and 11 recommend one complete, testable on-device security workflow. EdgeShield focuses on scam SMS. [Official challenge brief and PS3 mentoring session](https://arm-education.github.io/Arm-Developer-Labs/Bharat_AI_SoC_2026_27.html)

## 1. EdgeShield

A local SMS scam assistant for a CPU-only Raspberry Pi 5. It flags risk, explains the evidence in plain language, and recommends a safe next action.

Add the team name, member names and roles, institution, and faculty mentor before export.

## 2. The user problem

Legitimate OTPs, bank alerts, payment notices, and delivery messages can share cues with scams. The assistant needs to catch dangerous requests while limiting false alarms on everyday messages. When evidence is ambiguous, it can show an `UNCERTAIN` verdict and suggest independent verification.

## 3. Phase 1 scope

The user pastes an SMS and receives a risk verdict, observable cues, a Llama explanation when available, and a recommended action. The workflow runs locally on the Pi. The standalone URL detector is experimental. Network traffic analysis is planned for Phase 2.

## 4. On-device architecture

1. The local detector scores the SMS using word and character TF-IDF and logistic regression. Validation-selected thresholds produce `LEGITIMATE`, `UNCERTAIN`, or `SCAM`.
2. The detector provides the risk band, score, and enumerated cue IDs. The application selects the next action.
3. Llama runs through ExecuTorch on the Pi CPU and generates an explanation using the structured evidence. The validator checks the explanation against the detected risk and cues. The CLI labels a template fallback when it uses one.

Use the [architecture diagram](../docs/ARCHITECTURE.md) to show the evidence boundary and the two paths.

## 5. Detector evaluation

Use these identical-row synthetic holdout figures (`results/host/v8/v3_v5_v6_v7_v8_evaluation.json`), noting clearly that **archived Pi 5 B0 & offline Llama tests measured V2 (`f37c3dd9...`)**, **V8 (`4d348155...`)** is verified offline on Pi 5 in detector-only mode (`results/pi5/v8-offline-20261124/`), and **V8 + Llama on Pi 5** produced five validated explanations in the [device run](../results/pi5/v8-device-20261124/):

| Synthetic holdout (`V8 [0.55, 0.675]`) | Version | Scams detected | Legitimate messages flagged | Abstentions |
|---|---|---:|---:|---:|
| **`v8_holdout` (`240` labeled; `24` ambiguous excl.)** | **V8 (`4d348155...`)** | **119/120 (99.17% recall)** | **1/120 (0.83% FPR)** | **1** |
| **`v3_holdout` (`160`: 80 legit, 80 scam)** | **V8 (`4d348155...`)** | **79/80 (98.75% recall)** | **0/80 (0.00% FPR)** | **0** |
| **`v2_holdout` (`120` labeled; `12` ambiguous excl.)** | **V8 (`4d348155...`)** | **57/60 (95.00% recall)** | **1/60 (1.67% FPR)** | **2** |
| **`uci_test` (`1,148`: 984 legit, 164 scam)** | **V8 (`4d348155...`)** | **145/164 (88.41% recall)** | **0/984 (0.00% FPR)** | **2** |

On `v8_holdout`, V8 achieved **99.17% accuracy**, **99.17% precision**, **0.9917 F1**, **0.99993 ROC-AUC**, and **0.00857 Brier score** (`[[119, 0, 1], [0, 1, 119]]`), using OTP/short-number separation (`src/edgeshield/detector_v8.py`) alongside repaired clause-level cue rules (`src/edgeshield/indicators.py`). State clearly that synthetic data does not measure real-world accuracy. [V8 Evaluation Protocol](../docs/V8_EVALUATION_PROTOCOL.md) · [V3 Evaluation Report](../docs/V3_EVALUATION_REPORT.md) · [V2 Results](../docs/V2_RESULTS.md)

## 6. Privacy and user safeguards

- The detector processes the SMS locally. The Llama prompt receives structured detector evidence and omits the raw SMS, sender, and URL.
- The application selects the recommended action. Show a recommendation to verify through a trusted channel and explain that the user decides what to do next.
- Use fictional examples in the video. Use consented, anonymized examples for any future real-message evaluation. Describe controlled offline model updates as future work.

## 7. Verified Arm deployment

- **Target:** Physical Raspberry Pi 5 Model B Rev 1.1, 16 GB, CPU-only, `aarch64`, Debian 13 (Trixie), Python 3.13.5, glibc 2.41.
- **Model and runtime:** Llama 3.2 1B Instruct, SpinQuant INT4 EO8, approximately 1.00 GiB `.pte`. ExecuTorch revision `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7`, XNNPACK CPU backend, `pi5-cortex-a76-native` runner, two CPU threads.
- **Device evidence:** The Pi 5 smoke run produced validated Llama explanations. The runtime manifest and export notes record model identity, quantization, backend, and artifact hashes. [Pi 5 environment](../results/pi5/archive/20261118-B0-full/environment.json) · [Pi 5 smoke test](../results/pi5/archive/20261118-B0-full/smoke_test.txt) · [Runtime sources](../docs/SOURCES_RUNTIME.md)

## 8. Measured Pi 5 results

| Metric | Result |
|---|---:|
| Detector inference p95 | **0.92 ms** over 100 detector-only samples |
| Full response p95 | **6.81 s** over 91 sustained requests |
| Runtime time to first token, median | **3.20 s** |
| Decode rate, median | **13.49 tokens/s** |
| Sustained runtime output | **91/91** passed the explanation validator, with zero fallbacks in 605 s |
| Peak runner RSS and maximum swap used | **1.44 GB** (**1.34 GiB**) RSS and **0 bytes** swap used |
| Passive heatsink, open board | **83.7 °C** peak sampled temperature, with throttling (`0xe0008`) under continuous load |

The detector figure measures model inference in a detector-only run (`benchmark-detector.json`). The full-response figure measures the benchmark pipeline, including the advisory (`benchmark.json`). The 91/91 result measures explanation validation. Use slide 5 for detection accuracy. Document the fixture set, timing boundaries, and cooling setup in the report. [Detector-only run](../results/pi5/archive/20261118-B0-full/benchmark-detector.json) · [Sustained run](../results/pi5/archive/20261118-B0-full/benchmark.json)

## 9. Offline demo and limitations

**Offline verification on physical Pi 5 (`VERIFIED`):**
- **V8 + ExecuTorch Llama (`results/pi5/v8-device-20261124/`, `8/8 OK`):** `eth0`/`wlan0` `DOWN`, empty `offline_routes.json`, **zero `AF_INET`/`AF_INET6` matches** in `v8_offline_network.trace`, **5/5 `Llama (validated)`** (`6.51 s` med / `6.85 s` p95 full response, `1.44 GB` / `1.34 GiB` RSS, `0 B` swap, `72.7 °C` max, `throttled=0x0`).
- **V8 detector-only batch & suite (`results/pi5/v8-offline-20261124/`):** `361 passed / 1 skipped` (`52.35 s`), `50` repeated batch detections (`5` runs × `10` messages: `2.4321 ms` avg), `63.7 °C`, `throttled=0x0`.
- **Archived V2 sustained B0 (`results/pi5/archive/20261118-B0-full/`):** `91/91` `Llama (validated)` over `605.4 s` (`6.81 s` p95, `83.7 °C` peak, `throttled=0xe0008`).

**Demo video (`MISSING`):** Record the disconnected physical Pi 5 running V8 (`4d348155...`) analyzing a fictional scam SMS and a legitimate transactional SMS, visibly showing `eth0`/`wlan0` `DOWN`, risk verdict, at least one `Llama (validated)` explanation, and suggested `DO:` action.

The five-request V8 run measures short-burst latency. The 605.4-second passive-cooling run used V2 and reached 83.7 °C. Synthetic holdout scores do not establish real-world SMS accuracy.

## 10. Final submission checklist

- [x] Archive disconnected Pi 5 V8 detector-only offline tests (`results/pi5/v8-offline-20261124/`: `361/362` pytest, `50` repeated batch runs `2.4321 ms` avg) and V2 Llama offline proof (`results/pi5/offline-20261119/`: `6/6 OK`, `5/5` validated, zero `AF_INET`/`AF_INET6`).
- [ ] Verify the final demo link and its playback from a judge-accessible account.
- [ ] Export the reconciled technical report as PDF/DOCX (`<= 10 MB`), add root `LICENSE`, push clean public GitHub repo (including final report), submit portal form, and save `submission/RECEIPT.md`.
- [ ] Approve project root `LICENSE`, confirm team/mentor details on Slide 1, and review the curated release deliverables before upload.
- [ ] Publish the reviewed project on GitHub with team authorization and verify public reviewer access.
- [ ] Confirm the submission form's fields, format, and upload limits, submit by **23 November 2026**, and save the receipt.
