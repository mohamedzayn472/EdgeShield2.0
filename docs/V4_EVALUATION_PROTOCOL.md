# EdgeShield V4 Pre-Registered Evaluation Protocol & Promotion Criteria

**Registered before edits to `indicators.py`, V4 training data, calibration, or model thresholds.**  
**Date:** 20 November 2026

---

## 1. Baseline vs. Candidate Architecture

- **Frozen Baseline:** `models/detector_v3.json` (`edgeshield-word-char-lr-v3`, `format: 3`, SHA-256 `b2b2126b872c43eb02ccdef41a7f5040cf86cfd0dc1bfb31f98ef13733d50910`, thresholds `[0.65, 0.75]`, calibration `[1.370512, 0.383100]`) paired with baseline `src/edgeshield/indicators.py` (`239b39e6...`).
- **Candidate under test:**
  1. Repaired clause-level cue detection in `src/edgeshield/indicators.py` (preserving exact 12 closed indicator IDs without modifying statistical verdicts).
  2. Candidate classifier `models/detector_v4.json` (`edgeshield-word-char-lr-v4`, `format: 4`, `src/edgeshield/detector_v4.py`) trained on `data/synthetic/v4_development.jsonl` + local UCI `data/processed/{train,calibration,validation}.jsonl`, calibrated strictly on `calibration`, and thresholded strictly on `validation`.
- **Default preservation:** `models/detector_v3.json` (`b2b2126b...`), `models/detector_v2.json` (`f37c3dd9...`), `models/detector.json` (`9163c207...`), archived Pi 5 runs (`results/pi5/archive/20261118-B0-full/`, `results/pi5/offline-20261119/`), and `DEFAULT_DETECTOR_PATH` remain untouched while V4 is evaluated as an explicit `--detector models/detector_v4.json` candidate.

---

## 2. Partition Isolation & Evaluation Sets

1. **Development-only splits (NEVER used for final scoring):**
   - `data/synthetic/v4_development.jsonl` (`train` / `calibration` / `validation`), family-separated across splits and zero-overlap audited (`char 3–5 cosine < 0.85`) against all holdout/regression sets and reproduced cases.
   - `data/processed/{train,calibration,validation}.jsonl` (local UCI splits).
2. **Held-out & regression sets (evaluated strictly ONCE after freezing V4 artifacts):**
   - `reproduced_failures_and_controls`: The reproduced observed failures and paired controls (`16` labeled EN/HI cases, never placed in training, calibration, or validation).
   - **`data/synthetic/v4_holdout.jsonl`** (SHA-256 `9f5e1a9f247ebe44011393898653f8afaec02aa644aea0015d3cbcbe2b5551b9`; *fresh independent synthetic evaluation set; AI-assisted fictional messages, NOT real-world prevalence*):
     - Development counterpart `data/synthetic/v4_development.jsonl` (`74fd6928ed1158e9eb490310e56397881815c3611df6f759147274b139c9151c`, `738` total: `491` train / `89` cal / `158` val).
     - `240` labeled messages (`120` English, `120` Hinglish; `60` benign + `60` scam per language) spanning 10 benign categories, 10 scam categories, and tagged paired controls (`pair_id`).
     - `24` ambiguous messages (`label: null`, `12` English, `12` Hinglish) covering unknown-sender callbacks, unexpected payment reminders, and insufficient-context links — reported **strictly separately outside binary accuracy**.
   - **Existing regression suites:** `data/synthetic/v3_holdout.jsonl` (`160`), `data/synthetic/v2_holdout.jsonl` (`120` labeled + `12` ambiguous separate), `data/processed/test.jsonl` (`1,148` UCI test), and `data/synthetic/indian_sms.jsonl` (`24` test + `8` dev + `4` ambiguous separate).

---

## 3. Required Metrics (Per Dataset & Per Language)

For every evaluation set and language partition (`overall`, `english`, `hinglish` where applicable):
- Complete **2×3 truth-by-verdict confusion matrix**: rows `[Legitimate (0), Scam (1)]`, columns `[LEGITIMATE, UNCERTAIN, SCAM]`.
- Exact counts and denominators:
  - False-positive rate: `FP / N_neg` (report `"0/N on this set"` if `FP == 0`).
  - Scam recall: `TP / N_pos`.
  - Scams labeled `LEGITIMATE`: `FN / N_pos`.
  - Benign messages labeled `UNCERTAIN`: `U0 / N_neg`.
  - Total coverage: `(N - U0 - U1) / N` (and abstention rate `(U0 + U1) / N`).
  - Precision, F1, ROC-AUC, PR-AUC, Brier score, log-loss, and 10-bin ECE.
  - **95% Wilson score confidence intervals** on `v4_holdout.jsonl` for FPR, scam recall, scams-as-`LEGITIMATE`, benign-as-`UNCERTAIN`, and coverage.

---

## 4. Pre-Declared Promotion Criteria (`PROMOTE` vs. `HOLD CANDIDATE`)

A candidate is promoted **only if ALL gates P1–P5 pass without post-hoc threshold tuning after viewing any holdout**:

- **P1 (Reproduced failures & paired controls):**
  - `0` false `SCAM` verdicts and `0` false `BANK_IMPERSONATION` / `THREAT_OF_BLOCK` / `KYC_IMPERSONATION` / `UPI_COLLECT_LURE` cues across all benign reproduced messages (`1_antifraud_notice_en`, `1b_antifraud_bank_only`, `2_user_card_block_en`, `2b_card_block_hi`, `3_kyc_branch_appt_en`, `3b_kyc_completed_en`, `4_statement_link_en`, `7a_ctrl_genuine_otp`, `7d_paired_refund_legit`).
  - `0` scams labeled `LEGITIMATE` across active scam controls (`5_family_imp_en`, `5b_family_hi`, `6_hinglish_read_aloud`, `6c_hinglish_read_aloud_uncertain`, `7b_ctrl_active_otp_req`, `7c_ctrl_warn_then_req`, `7e_paired_refund_scam`).
- **P2 (Fresh `v4_holdout.jsonl`, `n=240` labeled):**
  - Overall FPR `<= 3.0%` (`<= 3/120`) AND strictly lower than V3 baseline FPR on `v4_holdout`.
  - Overall scam recall `>= 90.0%` (`>= 108/120`); English recall `>= 86.0%`; Hinglish recall `>= 86.0%`.
  - Scams labeled `LEGITIMATE` `<= 5.0%` (`<= 6/120`).
  - Benign messages labeled `UNCERTAIN` `<= 6.0%` (`<= 7/120`).
  - Total coverage `>= 90.0%` (`>= 216/240`).
  - Overall ROC-AUC `>= V3 ROC-AUC` AND overall Brier score `<= V3 Brier score` (verifying genuine discrimination improvement rather than mere abstention inflation).
- **P3 (Existing regression suites):**
  - `v3_holdout` (`160`): FPR `<= 2.5%` (`<= 2/80`), scam recall `>= 95.0%` (`>= 76/80`).
  - `v2_holdout` (`120` labeled): FPR `<= 3.33%` (`<= 2/60`), scam recall `>= 88.3%` (`>= 53/60`), scams labeled `LEGITIMATE` `<= 5/60`.
  - `uci_test` (`1,148`): FPR `<= 0.5%` (`<= 5/984`), scam recall `>= 85.8%` (within `2.0 pp` of V3).
- **P4 (Product & packaging):** Full host `pytest -q` passes (`0` failures), isolated archive clean-extract + fresh-venv launch passes with matching SHA-256, and host ExecuTorch Llama validation passes.
- **P5 (Hardware device gate):** Disconnected physical Raspberry Pi 5 smoke/offline verification on the **exact candidate release** (`VERIFIED`). If authorized Pi 5 hardware is unavailable from this host, status MUST be **`HOLD CANDIDATE`** (`PENDING_HARDWARE`), preserving V2 (`f37c3dd9...`) Pi 5 archives separately.
