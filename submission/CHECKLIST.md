# Phase 1 Submission Gates (Updated 24 November 2026)

Refer to `PROJECT_STATUS.md`, `docs/REPORT.md`, and `results/pi5/STATUS.json` for evidence paths. Unchecked items are still pending completion/verification.

## Mandatory engineering evidence

- [x] **Detector V8 release candidate & multi-version regression (`VERIFIED` on host):** Default CLI/benchmark/bundle artifact `models/detector_v8.json` (`4d3481555460d2bf5dfaf5e28fc107786f38ea34400358e4637b5bd9b0afd365`, thresholds `[0.55, 0.675]`): `v8_holdout` (`240`) `99.17%` acc (`99.17%` P, `99.17%` R, `0.83%` FPR, `0.99993` ROC-AUC, `[[119, 0, 1], [0, 1, 119]]`); `v7_holdout` (`240`) `97.08%`; `v6_holdout` (`240`) `100.00%`; `v5_holdout` (`240`) `100.00%`; `v4_holdout` (`240`) `97.08%`; `v3_holdout` (`160`) `99.38%`; `v2_holdout` (`120`) `96.67%`; `uci_test` (`1,148`) `98.17%` (`0.00%` FPR, `88.41%` R); `indian_sms` test (`24`) `95.83%` (`results/host/v8/v3_v5_v6_v7_v8_evaluation.json`). *(Synthetic holdout only; human label review & real-world calibration remain pending.)*
- [x] **Host automated test suite, Llama E2E & shell checks (`VERIFIED`):** Host `pytest -q` passes (`0` failures), `3/3` host Llama smoke & `264/264` weighted (`221/221` distinct) evidence validation (`results/host/v8/`), clean bundle verification (`results/host/v8/p4_clean_bundle_verification.txt`), and `7/7` Pi 5 deployment shell scripts (`deploy/pi5/*.sh`) pass `bash -n`.
- [x] **Detector provenance, leakage checks, and frozen hashes (`VERIFIED`):** `results/host/v8/{training_validation,evaluation_freeze}.json` (`4d348155...`), plus preserved `v2`–`v7` freeze records.
- [x] **Lawful Llama checkpoint & ExecuTorch export (`VERIFIED`):** Meta `Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8` (rev `b8c08c95d0476ccb6fc86e9410818d602ecca19d`) exported via ExecuTorch `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7` to `llama3_2.pte` (SHA-256 `c31e4d37...`), notices retained in `models/llama/LICENSE_AND_NOTICE.md`, excluded from public source archives.
- [x] **Physical Pi 5 V8 detector-only offline verification (`VERIFIED`):** `results/pi5/v8-offline-20261124/` (`OFFLINE_COMPETITION_REPORT/full_report.txt`, `test_logs/final_summary.json`): Pi 5 Rev 1.1 (`16 GB`, Debian 13 Trixie, Python 3.13.5, `eth0`/`wlan0` `DOWN`, `63.7 °C`, `throttled=0x0`), V8 checksum verified, `pip check` clean, `361 passed, 1 skipped` (`52.35 s`), `50` repeated batch detections (`2.4321 ms` avg). *(Llama runtime not configured in this run; `Template fallback`.)*
- [x] **Archived Pi 5 Llama smoke, B0 benchmark & offline proof — Detector V2 (`f37c3dd9...` ONLY, `VERIFIED`):** Physical Pi 5 Rev 1.1 (`pi5-cortex-a76-native`, 2 threads): `4/4` `Llama (validated)`, `2/2` fallback, `0.92 ms` detector p95, sustained `91/91` (`605.4 s`, `6.81 s` p95, `1.44 GB`/`1.34 GiB` RSS, `0 B` swap, `83.7 °C` `0xe0008`), offline `5/5` (`eth0`/`wlan0` `DOWN`, `0` `AF_INET`/`AF_INET6` syscalls, `results/pi5/offline-20261119/` `6/6 OK`).
- [x] **Detector V8 (`4d348155...`) + ExecuTorch Llama on-device & offline Pi 5 verification (`VERIFIED`):** Audited in `results/pi5/v8-device-20261124/` (`SHA256SUMS` `8/8 OK`): `eth0`/`wlan0` `DOWN`, empty `offline_routes.json`, `0 AF_INET/AF_INET6` matches in `v8_offline_network.trace`, single CLI `Llama (validated)`, and `5/5` `Llama (validated)` offline benchmark (`6.51 s` med / `6.85 s` p95, `1.44 GB` / `1.34 GiB` RSS, `0 B` swap, `72.7 °C` max, `throttled=0x0`). *(Note: `offline_competition_test.sh` and clean-folder `setup.sh --offline` log remain optional/pending.)*
- [x] **Evidence firewall, validator, clause-level indicators, and deterministic advice (`VERIFIED`):** `src/edgeshield/evidence.py`, `indicators.py`, `validator.py`, `pipeline.py`, `recommendations.py`, `tests/test_safety.py`.

## Scope and interpretation

- [x] **Target hardware eligibility (`VERIFIED`):** Raspberry Pi 5 (CPU-only Arm Linux) is explicitly listed on the official Bharat AI-SoC Challenge page (`docs/SOURCES.md`).
- [x] The SMS detector is the default. Standalone phishing URL inspection is available as an experimental mode. Network traffic analysis is a Phase 2 design.
- [x] **Evaluation limits, misses, and throttling disclosed (`VERIFIED`):** Synthetic/spam-proxy limits, non-calibrated scores, and B0 passive thermal throttling (`83.7 °C`, `0xe0008`) documented.
- [ ] **Optional/residual research items (disclosed as limitations):** Independent human label review of synthetic corpus and 5-person clarity study (`docs/CLARITY_STUDY_INSTRUMENT.md`, `PENDING_PARTICIPANTS`).

## Deliverables and submission

- [x] **Project root `LICENSE` & "Built with Llama" attribution added (`PENDING_CONTRIBUTOR_SIGNOFF`):** Root `LICENSE` sets MIT for EdgeShield original source code & original V8 detector (subject to contributor/ownership confirmation), preserves Meta Llama 3.2 Community License (`models/llama/LICENSE_AND_NOTICE.md`) and ExecuTorch BSD license, and adds "Built with Llama" attribution in `README.md` and `docs/REPORT.md`.
- [ ] Verify the final demo link and its playback from a judge-accessible account.
- [ ] **Final Report PDF/DOCX (≤ 10 MB) & team details (`PENDING — TEAMMATE 2`):** Populate team/mentor details, incorporate V8 + Pi 5 results, export PDF/DOCX (≤ 10 MB) for upload, and commit final report into public GitHub repo.
- [ ] **Public GitHub publication & official form submission (`PENDING — TEAMMATE 2`):** Verify the final repository link and public artifacts, submit through official challenge form, and save receipt to `submission/RECEIPT.md`.
