# EdgeShield V7 Pre-Registered Evaluation Protocol & Promotion Criteria

**Registered before edits to `src/edgeshield/indicators.py`, V7 dataset generation, calibration, or model thresholds.**  
**Date:** 23 November 2026

---

## 1. Preserved References and V7 Architecture

- **Frozen V3 Reference:** `models/detector_v3.json` (`edgeshield-word-char-lr-v3`, `format: 3`, SHA-256 `b2b2126b872c43eb02ccdef41a7f5040cf86cfd0dc1bfb31f98ef13733d50910`, thresholds `[0.65, 0.75]`).
- **Held V4 Reference:** `models/detector_v4.json` (`edgeshield-word-char-lr-v4`, `format: 4`, SHA-256 `b6f54fab1cc4b70b4d3e1f98cd5e71e865f10ce25e6680d7a7567e40198d2f6a`, thresholds `[0.15, 0.2]`).
- **Current Default Reference (prior to V7 evaluation):** `models/detector_v5.json` (`edgeshield-word-char-lr-v5`, `format: 5`, SHA-256 `bc98c0d961aec7c1a03e1f0e517b970765ee818f42c938152719c7b84951908b`, thresholds `[0.5, 0.75]`).
- **Held V6 Reference:** `models/detector_v6.json` (`edgeshield-word-char-lr-v6`, `format: 6`, SHA-256 `a7e6fe59ed622f89171ee97d8dc47d5454915af0e5db68e399e2540b982210d3`, thresholds `[0.425, 0.65]`). Passed `P1` (`17/17`), `P3` (`15/15`, including UCI test `88.41%` recall & `v5_holdout` `120/120` / `0` FP / `0` cues), and `P4` host verification; held only on `P2` (`v6_holdout` FPR `5/120 = 4.17% > 3.0%` and benign cues `6/120 > 3/120`).
- **Candidate Under Test (`V7`):**
  1. **Four general clause-level indicator repairs** in `src/edgeshield/indicators.py` resolving the unseen `v6_holdout` benign indicator patterns (`digital hygiene alert` & defensive link warnings with active-demand fail-closed guard, optional `your` after explicit manual/self-initiated qualifiers in `USER_REPORTED_BLOCK`, completed branch/counter verification phrasings in `KYC_COMPLETED_RE`, and Hinglish necessity post-negations like `zaroori nahi` in `POST_NEGATION`), keeping all 12 closed indicator IDs and never overriding statistical scores.
  2. **Candidate classifier `models/detector_v7.json`** (`edgeshield-word-char-lr-v7`, `format: 7`, `src/edgeshield/detector_v7.py`) separating literal OTP/passcode numeric tokens (`otpnum`) from generic 4–6 digit shortcodes (`shortnum`) before `_SHORT_NUM_RE`, trained with 5-fold `GroupKFold` by `family`, 4-quadrant calibration comparison (`temperature_scaled`, `sigmoid_quadrant_balanced`, `sigmoid_synthetic_balanced`), balanced validation threshold search (`low in [0.325, 0.55]`, `high in [0.55, 0.725]`, `gap in [0.10, 0.25]`) requiring simultaneous `syn_fpr <= 0.012`, `uci_fpr <= 0.008`, `syn_rec >= 0.96`, `uci_rec >= 0.91`, `syn_fn <= 0.02`, `uci_fn <= 0.06`, `syn_abs <= 0.06`, `syn_benign_unc <= 0.045`, `uci_abs <= 0.05`, and a hard guard refusing to save unless `validation_quality_gate == "PASSED"`.
- **Preserved Artifacts:** `models/detector.json`, `detector_v2.json`, `detector_v3.json`, `detector_v4.json`, `detector_v5.json`, `detector_v6.json`, `models/llama/*`, prior `results/host/v3..v6/`, `dist/edgeshield-v5-pi5-handoff/`, and archived Pi 5 runs (`results/pi5/archive/20261118-B0-full/`, `results/pi5/offline-20261119/`) remain untouched.

---

## 2. Partition Isolation & Evaluation Sets

1. **Development-Only Splits (NEVER used for final scoring):**
   - `data/synthetic/v7_development.jsonl` (`train` / `calibration` / `validation`, built on `v6_development.jsonl` + family-separated additions covering benign EN self-entry passcode/OTP notices, EN fraud-caution & digital-hygiene advisories, EN concise OD/credit-headroom/standby-line alerts, HI bill/profile OTP notices with non-sharing caveats, HI awareness with collect-not-needed & hangup cues, and EN/HI scam counters including URL-less hold+CVV scams, scams embedding fake numeric codes alongside links/demands, and contrast-pivot scams — strictly using dev brands only).
   - `data/processed/{train,calibration,validation}.jsonl` (local UCI splits).
2. **One-Time Unseen Fresh Evaluation Set (opened strictly ONCE after freezing `models/detector_v7.json` and `src/edgeshield/indicators.py`):**
   - `data/synthetic/v7_holdout.jsonl`: `264` AI-assisted/fictional synthetic SMS (`240` labeled: `60 EN benign`, `60 EN scam`, `60 HI benign`, `60 HI scam`; plus `24` ambiguous `label: null`: `12 EN`, `12 HI` reported strictly outside binary accuracy; plus paired controls `ctrl7_otp_1`, `ctrl7_block_1`, `ctrl7_refund_1`, `ctrl7_hi_otp_1`, `ctrl7_hi_block_1`, `ctrl7_hi_refund_1`) using 100% unseen fictional Indian entities (`Chilika Bank`, `Vaitarna Trust`, `Tapti Pay`, `Hampi Card`, `Mysuru Mart`, `Saryu Express`, `Koyna Power`, `Bhima Water`, `Puri Rail`, `Ladakh Telecom`, `Zuari Fin`, `Rishikesh Hospital`).
3. **Existing Regression Suites:**
   - `reproduced_failures_and_controls` (`17`: `10` benign, `7` scam)
   - `data/synthetic/v6_holdout.jsonl` (`240` labeled + `24` ambiguous separate; `27257205980a0fca20c0bb44852559c3f5205db2f5320295427d8ac89a3e9f24`)
   - `data/synthetic/v5_holdout.jsonl` (`240` labeled + `24` ambiguous separate; `873bc9dc74ec049970f95bad7061bba5cd5f0bbd9fbafa85efdfdd57915ae1fd`)
   - `data/synthetic/v4_holdout.jsonl` (`240` labeled + `24` ambiguous separate; `9f5e1a9f247ebe44011393898653f8afaec02aa644aea0015d3cbcbe2b5551b9`)
   - `data/synthetic/v3_holdout.jsonl` (`160` labeled; `a127660629cfc78e763b5017b4363f7b0eaae66119a10035fb052135a1de9f85`)
   - `data/synthetic/v2_holdout.jsonl` (`120` labeled + `12` ambiguous separate; `a2eb49623715b7cf3b84c6d2afda29c6f50fe07b65a4820ad52753ea1681ff1e`)
   - `data/processed/test.jsonl` (`1,148` UCI test)
   - `data/synthetic/indian_sms.jsonl` (`24` test + `8` dev + `4` ambiguous separate)

### Recorded V7 Dataset SHA-256 Hashes (Populated Immediately Upon Dataset Generation Before Training)

- `data/synthetic/v7_development.jsonl`: `c72f2e472c7105f61fe08afb39dc5a9bdd9214a964ebbe4c49a50b2621bb4525` (`1,018` rows: `train=661` [356 leg / 305 scam; 381 EN / 280 HI], `calibration=139` [74/65; 72 EN / 67 HI], `validation=218` [121/97; 121 EN / 97 HI])
- `data/synthetic/v7_holdout.jsonl`: `5c8e7d1825861cfbcb505ff54781a00ddfb563755323045491c7f7d90593f6c7` (`264` rows: `240` labeled [60/60 EN, 60/60 HI] + `24` ambiguous [12 EN, 12 HI]; `0` cross-partition near-duplicates `>= 0.85` cosine)

---

## 3. Pre-Declared Host Promotion Gates (`P1`–`P4`) & Hardware Gate (`P5`)

Candidate V7 is promoted as workspace default and packaged into `dist/edgeshield-v7-pi5-handoff/` **only if ALL host gates `P1`–`P4` pass on the single frozen evaluation run without post-hoc weight, threshold, or rule tuning**:

- **P1 (`reproduced_failures_and_controls`, `17`):**
  - `0/10` false `SCAM` verdicts and `0/10` benign impersonation/request cues (`BANK_IMPERSONATION`, `THREAT_OF_BLOCK`, `KYC_IMPERSONATION`, `OTP_REQUEST`, `UPI_COLLECT_LURE`).
  - `0/7` scams labeled `LEGITIMATE` and `7/7` scams labeled `SCAM`.
- **P2 (Fresh Unseen `v7_holdout`, `240` labeled — strictly ONE evaluation):**
  - Overall FPR `<= 3.0%` (`<= 3/120`) AND strictly `< V3` FPR on `v7_holdout`.
  - Overall scam recall `>= 90.0%` (`>= 108/120`), English recall `>= 86.0%`, Hinglish recall `>= 86.0%`.
  - Scams labeled `LEGITIMATE` `<= 5.0%` (`<= 6/120`).
  - Benign messages labeled `UNCERTAIN` `<= 6.0%` (`<= 7/120`).
  - Total coverage `>= 90.0%` (`>= 216/240`).
  - Overall ROC-AUC `>= V3` AND overall Brier score `<= V3`.
  - Benign impersonation/request cue errors `<= 3/120` (`<= 2.5%`).
- **P3 (Existing Regression Suites):**
  - `v6_holdout` (`240` labeled): FPR `<= 3.0%` (`<= 3/120`), scam recall `>= 90.0%`, scams→`LEGITIMATE` `<= 5.0%`, benign cue errors `<= 2/120`.
  - `v5_holdout` (`240` labeled): FPR `<= 3.0%` (`<= 3/120`), scam recall `>= 90.0%`, scams→`LEGITIMATE` `<= 5.0%`, benign cue errors `<= 2/120`.
  - `v4_holdout` (`240` labeled): FPR `<= 4.17%` (`<= 5/120`), scam recall `>= 90.0%`, scams→`LEGITIMATE` `<= 5.0%`, benign cue errors `<= 2/120`.
  - `v3_holdout` (`160`): FPR `<= 2.5%` (`<= 2/80`), scam recall `>= 95.0%` (`>= 76/80`).
  - `v2_holdout` (`120` labeled): FPR `<= 3.33%` (`<= 2/60`), scam recall `>= 90.0%`, scams→`LEGITIMATE` `<= 5/60`.
  - `uci_test` (`1,148`): FPR `<= 0.5%` (`<= 5/984`), scam recall `>= 86.0%` (`>= 142/164`).
- **P4 (Host Product, Genuine ExecuTorch Llama & Clean Release Package):**
  - Full host `pytest -q` passes (`0` failures).
  - `scripts/verify_llama_host.py --suite smoke` and `--suite evidence` (on exported `v7_holdout` evidence) exit `0` with retained JSON logs under `results/host/v7/`.
  - Real CLI + host `llama_main` E2E (`results/host/v7/e2e_v7_host_llama.txt`) passes including default V7 resolution (if promoted), `v7_holdout` / borderline `UNCERTAIN` case, UCI false-reassurance audit, `--advisory-policy off` (`SKIPPED_BY_POLICY`), rejected runtime (`RUNTIME_CONFIGURATION_REJECTED`), invalid SMS (`exit 2`), and tampered checksum (`exit 2`).
  - Release bundle built in `dist/edgeshield-v7-pi5-handoff/` (if `P1`–`P3` pass), extracted into `/tmp/edgeshield-v7-clean`, verified with `scripts/verify_bundle.py` (`0` `models/llama/*` files), installed in fresh `.venv` (`pytest` `0` failures), and CLI launched from `/tmp` & bundle root proving exact V7 SHA-256, with transcript saved in `results/host/v7/p4_clean_bundle_verification.txt`.
- **P5 (Physical Raspberry Pi 5 Verification):**
  - `PENDING_HARDWARE` on host until physical Raspberry Pi 5 runs complete on V7 (`VERIFIED`).
