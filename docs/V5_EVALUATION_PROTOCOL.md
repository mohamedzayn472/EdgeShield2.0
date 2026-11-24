# EdgeShield V5 Pre-Registered Evaluation Protocol & Promotion Criteria

**Registered before edits to `src/edgeshield/indicators.py`, V5 dataset creation, calibration, or model thresholds.**  
**Date:** 20 November 2026

---

## 1. Baseline, Held Reference, and Candidate Architecture

- **Current Default Baseline:** `models/detector_v3.json` (`edgeshield-word-char-lr-v3`, `format: 3`, SHA-256 `b2b2126b872c43eb02ccdef41a7f5040cf86cfd0dc1bfb31f98ef13733d50910`, thresholds `[0.65, 0.75]`).
- **Held Reference Candidate:** `models/detector_v4.json` (`edgeshield-word-char-lr-v4`, `format: 4`, SHA-256 `b6f54fab1cc4b70b4d3e1f98cd5e71e865f10ce25e6680d7a7567e40198d2f6a`, thresholds `[0.15, 0.2]`), held due to `sigmoid_equalized` intercept shift (`-1.5635`) pushing thresholds to `[0.15, 0.20]` and yielding `14/120` (`11.67%`) FPR + `11/120` benign indicator edge-case errors on `v4_holdout.jsonl`.
- **Candidate Under Test (`V5`):**
  1. Clause-level indicator repairs in `src/edgeshield/indicators.py` (fixing passive Hinglish `bheja`, benign self-entry OTP with literal codes, advisory/reporting negation & long-gap Hinglish obligation negation, quoted conditional third-party attack warnings, multi-word self-initiated card pause/disable, and completed/scheduled/routine branch KYC wording — preserving all 12 closed indicator IDs without altering statistical predictions).
  2. Candidate classifier `models/detector_v5.json` (`edgeshield-word-char-lr-v5`, `format: 5`, `src/edgeshield/detector_v5.py`) with improved canonicalization (dropping non-shortener fictional hostnames, normalizing unmasked `account ending <digits>` + `txrefnum`/`refidtoken`), 5-fold `GroupKFold` validation by family, 4-quadrant/domain-balanced calibration (`temperature_scaled` vs `sigmoid_quadrant_balanced` vs `sigmoid_synthetic_balanced`), and safety-margin-maximizing validation thresholds (`low in [0.30, 0.55]`, `high in [0.45, 0.75]`).
- **Preserved Artifacts:** `models/detector.json`, `models/detector_v2.json`, `models/detector_v3.json`, `models/detector_v4.json`, `models/llama/*`, and archived Pi 5 runs (`results/pi5/archive/20261118-B0-full/`, `results/pi5/offline-20261119/`) remain untouched.

---

## 2. Partition Isolation & Evaluation Sets

1. **Development-Only Splits (NEVER used for final scoring):**
   - `data/synthetic/v5_development.jsonl` (`train` / `calibration` / `validation`, SHA-256 recorded immediately upon generation before training): strictly family-separated across splits and zero-overlap audited (`char 3–5 cosine < 0.85`) against all holdout sets and `REPRODUCED_BLACKLIST_TEXTS`.
   - `data/processed/{train,calibration,validation}.jsonl` (local UCI splits).
2. **One-Time Unseen Fresh Evaluation Set (opened strictly ONCE after freezing `models/detector_v5.json` and `src/edgeshield/indicators.py`):**
   - `data/synthetic/v5_holdout.jsonl` (SHA-256 recorded immediately upon generation before training): `264` AI-assisted/fictional synthetic SMS (`240` labeled: `60 EN benign`, `60 EN scam`, `60 HI benign`, `60 HI scam`; plus `24` ambiguous `label: null`: `12 EN`, `12 HI` reported strictly outside binary accuracy; plus `pair_id` paired controls) using 100% unseen fictional Indian entities absent from V1–V5 development and V2–V4 holdouts.
3. **Inspected Regression Suites:**
   - `reproduced_failures_and_controls` (`17`: `10` benign, `7` scam)
   - `data/synthetic/v4_holdout.jsonl` (`240` labeled + `24` ambiguous separate; `9f5e1a9f247ebe44011393898653f8afaec02aa644aea0015d3cbcbe2b5551b9`)
   - `data/synthetic/v3_holdout.jsonl` (`160` labeled; `a127660629cfc78e763b5017b4363f7b0eaae66119a10035fb052135a1de9f85`)
   - `data/synthetic/v2_holdout.jsonl` (`120` labeled + `12` ambiguous separate; `a2eb49623715b7cf3b84c6d2afda29c6f50fe07b65a4820ad52753ea1681ff1e`)
   - `data/processed/test.jsonl` (`1,148` UCI test)
   - `data/synthetic/indian_sms.jsonl` (`24` test + `8` dev + `4` ambiguous separate)

### Recorded Dataset SHA-256 Hashes (Frozen Before V5 Training)

- `data/synthetic/v5_development.jsonl`: `e32f3ace4ef918ed2903d0ff566e2a8b9da458d9571315dda25214fecdae834b` (`900` rows: `train=589` [309 leg / 280 scam; 334 EN / 255 HI], `calibration=119` [61/58; 60 EN / 59 HI], `validation=192` [103/89; 106 EN / 86 HI])
- `data/synthetic/v5_holdout.jsonl`: `873bc9dc74ec049970f95bad7061bba5cd5f0bbd9fbafa85efdfdd57915ae1fd` (`264` rows: `240` labeled [60/60 EN, 60/60 HI] + `24` ambiguous [12 EN, 12 HI]; `0` cross-partition near-duplicates `>= 0.85` cosine)

---

## 3. Pre-Declared Host Promotion Gates (`P1`–`P4`) & Hardware Gate (`P5`)

Candidate V5 is promoted on host **only if ALL host gates `P1`–`P4` pass on the single frozen evaluation run without post-hoc threshold or rule tuning**:

- **P1 (`reproduced_failures_and_controls`, `17`):**
  - `0/10` false `SCAM` verdicts and `0/10` benign impersonation/request cues (`BANK_IMPERSONATION`, `THREAT_OF_BLOCK`, `KYC_IMPERSONATION`, `OTP_REQUEST`, `UPI_COLLECT_LURE`).
  - `0/7` scams labeled `LEGITIMATE` and `7/7` scams labeled `SCAM`.
- **P2 (Fresh Unseen `v5_holdout`, `240` labeled — strictly ONE evaluation):**
  - Overall FPR `<= 3.0%` (`<= 3/120`) AND strictly `< V3` FPR on `v5_holdout`.
  - Overall scam recall `>= 90.0%` (`>= 108/120`), English recall `>= 86.0%`, Hinglish recall `>= 86.0%`.
  - Scams labeled `LEGITIMATE` `<= 5.0%` (`<= 6/120`).
  - Benign messages labeled `UNCERTAIN` `<= 6.0%` (`<= 7/120`).
  - Total coverage `>= 90.0%` (`>= 216/240`).
  - Overall ROC-AUC `>= V3` AND overall Brier score `<= V3`.
  - Benign impersonation/request cue errors `<= 3/120` (`<= 2.5%`).
- **P3 (Existing Regression Suites):**
  - `v4_holdout` (`240` labeled): FPR `<= 4.17%` (`<= 5/120`), scam recall `>= 90.0%` (`>= 108/120`), scams→`LEGITIMATE` `<= 5.0%` (`<= 6/120`), benign impersonation/request cue errors `<= 2/120`.
  - `v3_holdout` (`160`): FPR `<= 2.5%` (`<= 2/80`), scam recall `>= 95.0%` (`>= 76/80`).
  - `v2_holdout` (`120` labeled): FPR `<= 3.33%` (`<= 2/60`), scam recall `>= 90.0%` (`>= 54/60`), scams→`LEGITIMATE` `<= 5/60`.
  - `uci_test` (`1,148`): FPR `<= 0.5%` (`<= 5/984`), scam recall `>= 86.0%`.
- **P4 (Host Product, ExecuTorch Llama & Clean Transfer Bundle):**
  - Full host `pytest -q` passes (`0` failures).
  - Host ExecuTorch Llama E2E validation passes (`exit 0`, including false-reassurance audit on any remaining missed scam, policy fallback, error handling, and tampered checksum rejection).
  - Clean-extract bundle `scripts/verify_bundle.py` passes (`0` `models/llama/` files), fresh `.venv` installs and passes `pytest -q`, and CLI launch from clean `.venv` proves exact V5 `detector_sha256`.
- **P5 (Physical Raspberry Pi 5 Verification):**
  - `PENDING_HARDWARE` on host; if `P1`–`P4` pass, V5 is promoted as default and packaged in `dist/edgeshield-v5-pi5-handoff/edgeshield-pi5-preparation.zip` for disconnected Pi 5 smoke/offline verification by the hardware teammate.
