# EdgeShield V3 Detector & Indicator Evaluation Report

**Date:** 20 November 2026  
**Objective:** Resolve legitimate banking false positives and overly broad `BANK_IMPERSONATION` indicator triggers discovered during preliminary Raspberry Pi 5 evaluation, while preserving strong scam detection, strict privacy isolation, and verified local ExecuTorch Llama inference.

---

## 1. Root Cause Investigation

Preliminary Raspberry Pi 5 testing on 6 legitimate SMS messages (plus 1 distinct earlier bank credit notification scoring `0.624`) revealed a `33.3%` false-positive rate (`2/6`: bank debit `0.442`, banking OTP `0.591`) and an inconsistent `BANK_IMPERSONATION` indicator on a benign bank statement (`score = 0.023`). Feature-weight attribution on frozen `models/detector_v2.json` and inspection of `src/edgeshield/indicators.py` confirmed three root causes:

1. **Problem A — `BANK_IMPERSONATION` triggered on bare keywords (`src/edgeshield/indicators.py`):**
   - Previously, `PATTERNS["BANK_IMPERSONATION"] = r"\b(?:bank|banking|banker)\b"` with description `"Bank-related wording appears."` fired on *any* SMS containing the word `"bank"` (including benign OTP notices and e-statements), while missing banking SMS phrased with `A/c`, `card`, or bank abbreviations (`SBI`, `HDFC`, `ICICI`).
2. **Problem B — Legitimate banking SMS scored as `SCAM` in Detector V2:**
   - **Token collision with 2012 UK UCI spam:** Raw Indian banking amounts (`5,000.00`, `2,500.50`), dates (`20-Nov-26`), and masked account IDs (`XX1234`) split into tokens (`500`, `00`, `50`, `20`, `your`, `been`, `statement`, `balance`, `valid`, `mins`, `alert`) that carry heavy positive spam weights from the historical UK UCI SMS Spam Collection.
   - **Sparse banking templates in V2 development data:** `v2_development.jsonl` lacked realistic Indian bank credit, debit, e-statement, OTP, UPI, and balance alert formatting (`A/c XX1234`, `INR`/`Rs.`, `Avl Bal`, `NEFT`/`IMPS`, `Valid for 10 mins`, `If not done by you call...`).
   - **Overly narrow validation thresholds (`[0.25, 0.275]`):** V2's validation threshold search picked `high = 0.275` with an `0.025`-wide uncertainty band, aggressively pushing borderline legitimate messages into `SCAM` and producing `0` abstentions.
3. **Problem C — Indicator vs. classifier inconsistency:**
   - Because `BANK_IMPERSONATION` fired on the literal word `"bank"`, a legitimate bank statement with score `0.023` still displayed `BANK_IMPERSONATION`, whereas a bank debit notice using `A/c XX...` did not.

---

## 2. Summary of Source-Code Changes

All frozen V1 (`models/detector.json`) and V2 (`models/detector_v2.json`, `src/edgeshield/detector_v2.py`, `data/synthetic/v2_*.jsonl`) files remain untouched (`13/13` V2 freeze SHA-256 parity verified), and the deployed Pi 5 ExecuTorch model (`llama3_2.pte`) and runtime manifest (`pi5-runtime-manifest.json`) remain untouched.

| File | Change & Rationale |
|---|---|
| `src/edgeshield/indicators.py` | Replaced bare `\b(?:bank\|banking\|banker)\b` with clause-level cue analysis preserving all 12 closed indicator IDs without overriding statistical scores. Suppresses false `BANK_IMPERSONATION`/`THREAT_OF_BLOCK`/`KYC_IMPERSONATION` on completed user-initiated card blocks, completed or scheduled-branch KYC notices, educational anti-fraud advisories, and generic statement links (`LINK_PRESENT` only), while preserving later malicious clauses after a benign sentence and supporting read-code-aloud, Hinglish OV word order, EN/Hinglish pre/post negation (`mat`, `na`, `nahi`), Unicode, and abbreviations (`ac`, `a/c`, `acct`, `pwd`, `mpin`, `tpin`). |
| `src/edgeshield/detector_v3.py` | Added `DetectorV3` (`format: 3`, `edgeshield-word-char-lr-v3`, SHA-256 verified non-executable JSON). Adds deterministic `canonicalize_features()` before word (1–2) + char (3–5) TF-IDF vectorization to normalize currency amounts (`inramount` vs. `foreignamount`), masked account/card IDs (`bankacctmask`, `acctmask`), dates/times (`datetoken`, `timetoken`), reference IDs (`txrefnum`), toll-free numbers (`tollfreenum`), and URL/shortener cues (`urltoken`, `shortenerurl`). Preserves sub-millisecond median CPU inference (`0.77 ms` median on host). |
| `src/edgeshield/model_loader.py` | Extended `load_detector()` to support `format in (1, 2, 3)` and updated `DEFAULT_DETECTOR_PATH` to `models/detector_v3.json` after passing all validation gates (V1 and V2 remain loadable via `--detector`). |
| `src/edgeshield/cli.py`, `src/edgeshield/benchmarking.py` | Updated default `--detector` argument to `models/detector_v3.json` after validation passed. |
| `scripts/create_v3_datasets.py` | Deterministically generates family-separated `data/synthetic/v3_development.jsonl` (`642` rows: `432` train [`216` legit / `216` scam], `72` calibration, `138` validation) and strictly separate `data/synthetic/v3_holdout.jsonl` (`160` rows: `80` legit / `80` scam across English & Hinglish). Enforces `check_leakage` and `char 3–5 cosine >= 0.90` zero-overlap audit against UCI, V2 holdout, and V3 dev (`0` overlaps). |
| `scripts/train_detector_v3.py` | Trains V3 on UCI + V3 synthetic `train` split only (`2,770` UCI + `432` synthetic), fits balanced sigmoid calibration on `calibration` (`543` UCI + `72` synthetic), and selects `(C=4, synthetic_weight=2)` and thresholds **`[0.65, 0.75]`** strictly on `validation` (`1,113` UCI + `138` synthetic) using low-FPR, high-recall, macro-F1, and validation log-loss criteria. Produces `models/detector_v3.json` (`1,924,125` bytes, SHA-256 `b2b2126b872c43eb02ccdef41a7f5040cf86cfd0dc1bfb31f98ef13733d50910`). |
| `scripts/evaluate_detector_v3.py` | Freezes V3 hashes (`results/host/v3/evaluation_freeze.json`) and evaluates V2 vs. V3 across `v3_holdout_160`, `v2_holdout_120`, `uci_test_1148`, and the 12-case diagnostic banking suite (`results/host/v3/v2_vs_v3_comparison.json`). |
| `tests/test_safety.py`, `tests/test_model_loader.py`, `tests/test_detector_v3.py` | Added positive/negative `BANK_IMPERSONATION` unit tests, V3 artifact/canonicalization/tamper/consistency tests, and V1/V2/V3 loader tests. |

---

## 3. Before-and-After Evaluation Results

Source: `results/host/v3/v2_vs_v3_comparison.json`.  
Thresholds: **V2 `[0.25, 0.275]`** vs. **V3 `[0.65, 0.75]`** (validation-selected).

### 3.1 Held-Out Test Benchmarks (Strictly Unseen During Training & Selection)

| Dataset | Version | Accuracy | Precision | Recall | F1 | FPR | FNR | Abstention | 2×3 Confusion Matrix `[[TN, U, FP], [FN, U, TP]]` | Legit `BANK_IMPERSONATION` False Triggers |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|---:|
| **V3 Banking/Scam Holdout (`n=160`: 80 legit, 80 scam)** | **V2 (Before)** | 85.00% | 79.79% | 93.75% | 0.8621 | 23.75% | 6.25% | 0.00% | `[[61, 0, 19], [5, 0, 75]]` | 25 |
| **V3 Banking/Scam Holdout (`n=160`: 80 legit, 80 scam)** | **V3 (After)** | **98.75%** | **100.00%** | **98.75%** | **0.9937** | **0.00%** | **1.25%** | 0.63% | **`[[79, 1, 0], [1, 0, 79]]`** | **0** |
| **Frozen V2 Holdout (`n=120`: 60 legit, 60 scam)** | **V2 (Before)** | 90.83% | 98.04% | 83.33% | 0.9009 | 1.67% | 16.67% | 0.00% | `[[59, 0, 1], [10, 0, 50]]` | 14 |
| **Frozen V2 Holdout (`n=120`: 60 legit, 60 scam)** | **V3 (After)** | **91.67%** | 96.49% | **91.67%** | **0.9402** | 3.33% | **8.33%** | 4.17% | **`[[55, 3, 2], [3, 2, 55]]`** | **2** |
| **UCI SMS Test (`n=1,148`: 984 ham, 164 spam)** | **V2 (Before)** | 98.52% | 99.33% | 90.24% | 0.9457 | 0.10% | 9.76% | 0.00% | `[[983, 0, 1], [16, 0, 148]]` | 2 |
| **UCI SMS Test (`n=1,148`: 984 ham, 164 spam)** | **V3 (After)** | 98.26% | **100.00%** | 87.80% | 0.9351 | **0.00%** | 12.20% | 0.44% | **`[[984, 0, 0], [15, 5, 144]]`** | **0** |

### 3.2 V3 Holdout Breakdown by Language (`n = 160`)

| Language | Version | Accuracy | Precision | Recall | F1 | FPR | FNR | 2×3 Matrix | Legit `BANK_IMPERSONATION` FP |
|---|---|---:|---:|---:|---:|---:|---:|---|---:|
| **English (`n=80`)** | V2 Before | 78.75% | 70.91% | 97.50% | 0.8211 | 40.00% | 2.50% | `[[24, 0, 16], [1, 0, 39]]` | 14 |
| **English (`n=80`)** | **V3 After** | **100.00%** | **100.00%** | **100.00%** | **1.0000** | **0.00%** | **0.00%** | **`[[40, 0, 0], [0, 0, 40]]`** | **0** |
| **Hinglish (`n=80`)** | V2 Before | 91.25% | 92.31% | 90.00% | 0.9114 | 7.50% | 10.00% | `[[37, 0, 3], [4, 0, 36]]` | 11 |
| **Hinglish (`n=80`)** | **V3 After** | **97.50%** | **100.00%** | **97.50%** | **0.9873** | **0.00%** | **2.50%** | **`[[39, 1, 0], [1, 0, 39]]`** | **0** |

### 3.3 V3 Holdout Breakdown by Message Category (`n = 160`)

| Category | n | True Label | V2 Before `[[TN,U,FP],[FN,U,TP]]` | V3 After `[[TN,U,FP],[FN,U,TP]]` | `BANK_IMPERSONATION` (Old → New) |
|---|---:|---|---|---|---|
| `bank_credit` | 14 | Legit | `[[11, 0, 3], [0, 0, 0]]` | `[[14, 0, 0], [0, 0, 0]]` | 6 FP → **0 FP** |
| `bank_debit` | 14 | Legit | `[[11, 0, 3], [0, 0, 0]]` | `[[14, 0, 0], [0, 0, 0]]` | 2 FP → **0 FP** |
| `bank_statement` | 12 | Legit | `[[9, 0, 3], [0, 0, 0]]` | `[[12, 0, 0], [0, 0, 0]]` | 7 FP → **0 FP** |
| `banking_otp` | 14 | Legit | `[[8, 0, 6], [0, 0, 0]]` | `[[13, 1, 0], [0, 0, 0]]` | 8 FP → **0 FP** |
| `upi_confirmation` | 10 | Legit | `[[9, 0, 1], [0, 0, 0]]` | `[[10, 0, 0], [0, 0, 0]]` | 0 FP → **0 FP** |
| `balance_notification` | 8 | Legit | `[[5, 0, 3], [0, 0, 0]]` | `[[8, 0, 0], [0, 0, 0]]` | 2 FP → **0 FP** |
| `institutional_notice` | 8 | Legit | `[[8, 0, 0], [0, 0, 0]]` | `[[8, 0, 0], [0, 0, 0]]` | 0 FP → **0 FP** |
| `scam_account_block` | 16 | Scam | `[[0, 0, 0], [2, 0, 14]]` | `[[0, 0, 0], [0, 0, 16]]` | 13 TP → **16 TP** |
| `scam_otp_pin` | 16 | Scam | `[[0, 0, 0], [1, 0, 15]]` | `[[0, 0, 0], [1, 0, 15]]` | 11 TP → 9 TP |
| `scam_fake_kyc` | 16 | Scam | `[[0, 0, 0], [1, 0, 15]]` | `[[0, 0, 0], [0, 0, 16]]` | 14 TP → **16 TP** |
| `scam_bank_link` | 16 | Scam | `[[0, 0, 0], [0, 0, 16]]` | `[[0, 0, 0], [0, 0, 16]]` | 15 TP → **16 TP** |
| `scam_credentials` | 16 | Scam | `[[0, 0, 0], [1, 0, 15]]` | `[[0, 0, 0], [0, 0, 16]]` | 12 TP → 12 TP |

### 3.4 Diagnostic Banking Suite (Before vs. After)

Unseen realistic messages covering all 6 original Pi 5 legitimate test categories + the 1 earlier bank credit case + 5 paired genuine bank scams (never trained on, never hardcoded):

| Case | Label | V2 Score / Band (Old `BANK_IMPERSONATION`) | V3 Score / Band (New Indicators) |
|---|---|---|---|
| 1. Bank credit notification | Legit | `0.553` `SCAM` (False) | **`0.025` `LEGITIMATE`** (`none`) |
| 2. Bank debit notification | Legit | `0.312` `SCAM` (False) | **`0.057` `LEGITIMATE`** (`none`) |
| 3. Banking OTP | Legit | `0.292` `SCAM` (**True**) | **`0.091` `LEGITIMATE`** (`none`) |
| 4. UPI payment confirmation | Legit | `0.016` `LEGITIMATE` (False) | **`0.015` `LEGITIMATE`** (`none`) |
| 5. College announcement | Legit | `0.002` `LEGITIMATE` (False) | **`0.036` `LEGITIMATE`** (`none`) |
| 6. Bank statement notification | Legit | `0.819` `SCAM` (**True**) | **`0.193` `LEGITIMATE`** (`none`) |
| 7. Earlier bank credit alert | Legit | `0.790` `SCAM` (False) | **`0.010` `LEGITIMATE`** (`none`) |
| Scam 1: Fake account block | Scam | `0.936` `SCAM` (True) | **`1.000` `SCAM`** (`URGENCY`, `THREAT_OF_BLOCK`, `LINK_PRESENT`, `SHORTENER_LINK`, **`BANK_IMPERSONATION`**, `KYC_IMPERSONATION`) |
| Scam 2: OTP sharing ask | Scam | `0.781` `SCAM` (True) | **`0.992` `SCAM`** (`URGENCY`, `OTP_REQUEST`, **`BANK_IMPERSONATION`**, `KYC_IMPERSONATION`) |
| Scam 3: Fake KYC update | Scam | `0.994` `SCAM` (True) | **`0.991` `SCAM`** (`THREAT_OF_BLOCK`, `LINK_PRESENT`, **`BANK_IMPERSONATION`**, `KYC_IMPERSONATION`) |
| Scam 4: Suspicious bank link | Scam | `0.998` `SCAM` (True) | **`1.000` `SCAM`** (`URGENCY`, `LINK_PRESENT`, `SHORTENER_LINK`, **`BANK_IMPERSONATION`**) |
| Scam 5: Credential request | Scam | `0.998` `SCAM` (True) | **`1.000` `SCAM`** (`LINK_PRESENT`, **`BANK_IMPERSONATION`**) |

*(Note: Re-test your exact 6 original Pi SMS strings on the Pi 5 after updating `src/edgeshield/` and `models/detector_v3.json{,.sha256}` since those exact verbatim strings were not stored in the workspace.)*

---

## 4. Regression Tests, Privacy & ExecuTorch Compatibility

- **Automated test suite & full V2-vs-V3 regression audit:** `results/host/v3/full_v2_v3_regression_audit.json` (generated by `scripts/audit_v2_v3_regression.py`) audits V3 split/family separation (`0` overlaps), calibration reliability (Brier/log-loss/ECE), identical-row V2 vs. V3 confusion matrices across `v2_holdout` (`120` labeled + `12` ambiguous excluded from binary accuracy), `v3_holdout` (`160`), `uci_test` (`1,148`), and `indian_sms` (`24` test + `8` dev + `4` ambiguous), plus separate fresh edge-case diagnostics.
- **Frozen artifact parity:** `results/host/v2/evaluation_freeze.json` (`13/13 OK`), `results/pi5/archive/20261118-B0-full/SHA256SUMS` (`12/12 OK`, V2 `f37c3dd9...`), `results/pi5/offline-20261119/SHA256SUMS` (`6/6 OK`, V2 `f37c3dd9...`).
- **Host ExecuTorch Llama 3.2 1B verification:** Recorded in `results/host/v3/host_llama_v3_final.txt` and `results/host/v3/e2e_host_llama_validation.txt` (including advisory policy skip checks, legitimate/scam `Llama (validated)` runs, and analysis of false detector verdicts paired with validator-accepted `WHY:` explanations).
- **V3 inference latency (Ubuntu host, 100 reps):** `0.77 ms` median, `1.18 ms` p95 (`results/host/v3/benchmark_v3_detector.json`).
- **Residual statistical limitations & future V4 requirements:** Zero `antifraud_advisory` or `family_impersonation` families exist in `v3_development.jsonl`, causing false alarms on educational anti-fraud warnings (`0.928` `SCAM` EN, `0.711` `UNCERTAIN` HI) and false reassurance on family impersonation (`0.344`–`0.397` `LEGITIMATE`). Future **V4** development must freeze a separate version trained with independently authored family-separated legitimate banking, anti-fraud notices, and difficult scams, fit probability calibration on calibration only, select thresholds on validation only, and justify promotion on an unseen independent holdout. Physical Pi 5 device verification of V3 (`b2b2126b...`) remains **`PENDING_HARDWARE`**.

---

## 5. Safe Pi 5 Deployment Update Steps (Preserving Working ExecuTorch Runtime)

Do **not** touch `models/llama/` or `configs/inference.json` on the Pi 5. Copy only the updated Python modules and V3 detector artifact onto the Pi:

1. Copy `src/edgeshield/{indicators.py,detector_v3.py,model_loader.py,cli.py,benchmarking.py}` and `models/detector_v3.json` + `models/detector_v3.json.sha256` to `~/edgeshield/` on the Pi 5.
2. Reinstall package in-place inside the existing Pi `.venv` (zero internet needed):
   ```bash
   cd ~/edgeshield
   .venv/bin/python -m pip install --no-deps --no-build-isolation .
   ```
3. Verify on the Pi 5:
   ```bash
   bash deploy/pi5/smoke_test.sh
   bash deploy/pi5/launch.sh --repeat   # Re-test your original 6 legitimate SMS + scam SMS
   ```
4. If you ever need to compare against V2 on the Pi 5, pass `--detector models/detector_v2.json`.
