# EdgeShield V8 Pre-Registered Evaluation Protocol & Promotion Criteria

**Registered before edits to `src/edgeshield/indicators.py`, V8 dataset generation, calibration, or model thresholds.**  
**Date:** 24 November 2026

---

## 1. Preserved References and V8 Architecture

- **Frozen V3 Reference:** `models/detector_v3.json` (`edgeshield-word-char-lr-v3`, `format: 3`, SHA-256 `b2b2126b872c43eb02ccdef41a7f5040cf86cfd0dc1bfb31f98ef13733d50910`, thresholds `[0.65, 0.75]`).
- **Held V4 Reference:** `models/detector_v4.json` (`edgeshield-word-char-lr-v4`, `format: 4`, SHA-256 `b6f54fab1cc4b70b4d3e1f98cd5e71e865f10ce25e6680d7a7567e40198d2f6a`, thresholds `[0.15, 0.2]`).
- **Current Default Reference (prior to V8 evaluation):** `models/detector_v5.json` (`edgeshield-word-char-lr-v5`, `format: 5`, SHA-256 `bc98c0d961aec7c1a03e1f0e517b970765ee818f42c938152719c7b84951908b`, thresholds `[0.5, 0.75]`).
- **Held V6 Reference:** `models/detector_v6.json` (`edgeshield-word-char-lr-v6`, `format: 6`, SHA-256 `a7e6fe59ed622f89171ee97d8dc47d5454915af0e5db68e399e2540b982210d3`, thresholds `[0.425, 0.65]`).
- **Held V7 Reference:** `models/detector_v7.json` (`edgeshield-word-char-lr-v7`, `format: 7`, SHA-256 `3958bebfc4c791fea10f2d861acfe8998355ea7e481212aef109657ffb79daa4`, thresholds `[0.55, 0.675]`). Passed `P1` (`17/17`), all 10 numerical classifier checks in `P2` (`v7_holdout` FPR `0.83%`, recall `96.67%`, coverage `98.75%`, ROC-AUC `0.99861`, Brier `0.01851`), all 19 regression checks in `P3` (`240/240` on `v6_holdout` and `v5_holdout`, `88.41%` recall / `0` FP on `uci_test`), and `P4` host verification; held only on `P2` `benign_imp_cues_le_3` (`7/120` unseen lexical cue paraphrases).
- **Candidate Under Test (`V8`):**
  1. **General clause-level indicator repairs** in `src/edgeshield/indicators.py`: (a) `cleared` completion phrasings + reverse-order `(?:cleared|passed|completed|finished)\b[^.!?;]{0,65}\bkyc` + `verify(?:\s+aur\s+approv(?:e|ed))?\s+ho\s+(?:chuk[ei]|gay[aei])` + `poorn\s+ho(?:kar|\s+kar|\s+chuk[ei]|\s+gay[aei])` in `KYC_COMPLETED_RE`; (b) `(?:appointment|meeting|slot|visit)` and `(?:fix(?:ed|\s+hui|\s+hua)?|scheduled|booked|confirmed|reserved|tay\s+hai)` + `shakh?a` in `KYC_SCHEDULED_APPT_RE` / `_BRANCH_VISIT_CTX_RE`; (c) optional `(?:kabhi(?:\s+bhi)?|bilkul|hargiz)\s+` before necessity/negation in `POST_NEGATION`; (d) `aapk[ei]\s+(?:request|anurodh|complaint|nirdesh)\s+(?:par|se|ke\s+anusar)` in `USER_REPORTED_BLOCK`; (e) `(?:digital|cyber)\s+(?:hygiene|suraksha)` and `(?:khol(?:ne|\s*kar)?|click\s+kar(?:ne|ke)?|verify\s+karne)(?:\s+ke\s+lalach)?\s+se\s+bachein` in `EDUCATIONAL_ADVISORY_RE`; and (f) `suna(?:o|\s+do|\s+dein|\s+dijiye)?` / `bata(?:o|iye|\s+do|\s+dein|\s+dijiye)?` in `_OTP_FWD_VERB`, `_OTP_REV_VERB`, and `OTP_READ_ALOUD_GENERIC_CODE_RE`.
  2. **Candidate classifier `models/detector_v8.json`** (`edgeshield-word-char-lr-v8`, `format: 8`, `src/edgeshield/detector_v8.py`) retaining the V7 feature canonicalization (`otpnum` separation from `shortnum`, `urlkw_*`, banking token normalization) and 5-fold `GroupKFold` + 4-quadrant calibration + balanced validation threshold selection (`low in [0.325, 0.55]`, `high in [0.55, 0.725]`, `gap in [0.10, 0.25]`, hard `validation_quality_gate == "PASSED"` guard).
- **Preserved Artifacts:** `models/detector.json`, `detector_v2.json`, `detector_v3.json`, `detector_v4.json`, `detector_v5.json`, `detector_v6.json`, `detector_v7.json`, `models/llama/*`, prior `results/host/v3..v7/`, `dist/edgeshield-v5-pi5-handoff/`, and archived Pi 5 runs (`results/pi5/archive/20261118-B0-full/`, `results/pi5/offline-20261119/`) remain untouched.

---

## 2. Partition Isolation & Evaluation Sets

1. **Development-Only Splits (NEVER used for final scoring):**
   - `data/synthetic/v8_development.jsonl` (`train` / `calibration` / `validation`, built on `v7_development.jsonl` + family-separated Hinglish & English dev additions covering benign HI screen-share + cashback PIN warnings, scam HI URL-less online KYC freeze threats, scam HI contrast-pivot read-aloud OTP requests, and scam HI utility cut + remote screen-share app + phone token demands — strictly using dev brands only).
   - `data/processed/{train,calibration,validation}.jsonl` (local UCI splits).
2. **One-Time Unseen Fresh Evaluation Set (opened strictly ONCE after freezing `models/detector_v8.json` and `src/edgeshield/indicators.py`):**
   - `data/synthetic/v8_holdout.jsonl`: `264` AI-assisted/fictional synthetic SMS (`240` labeled: `60 EN benign`, `60 EN scam`, `60 HI benign`, `60 HI scam`; plus `24` ambiguous `label: null`: `12 EN`, `12 HI` reported strictly outside binary accuracy; plus paired controls `ctrl8_otp_1`, `ctrl8_block_1`, `ctrl8_refund_1`, `ctrl8_hi_otp_1`, `ctrl8_hi_block_1`, `ctrl8_hi_refund_1`) using 100% unseen fictional Indian entities (`Pench Bank`, `Hemavati Trust`, `Sharavathi Pay`, `Ellora Card`, `Udupi Mart`, `Betwa Express`, `Idukki Power`, `Teesta Water`, `Dwaraka Rail`, `Spiti Telecom`, `Netravati Fin`, `Kasauli Hospital`).
3. **Existing Regression Suites:**
   - `reproduced_failures_and_controls` (`17`: `10` benign, `7` scam)
   - `data/synthetic/v7_holdout.jsonl` (`240` labeled + `24` ambiguous separate; `5c8e7d1825861cfbcb505ff54781a00ddfb563755323045491c7f7d90593f6c7`)
   - `data/synthetic/v6_holdout.jsonl` (`240` labeled + `24` ambiguous separate; `27257205980a0fca20c0bb44852559c3f5205db2f5320295427d8ac89a3e9f24`)
   - `data/synthetic/v5_holdout.jsonl` (`240` labeled + `24` ambiguous separate; `873bc9dc74ec049970f95bad7061bba5cd5f0bbd9fbafa85efdfdd57915ae1fd`)
   - `data/synthetic/v4_holdout.jsonl` (`240` labeled + `24` ambiguous separate; `9f5e1a9f247ebe44011393898653f8afaec02aa644aea0015d3cbcbe2b5551b9`)
   - `data/synthetic/v3_holdout.jsonl` (`160` labeled; `a127660629cfc78e763b5017b4363f7b0eaae66119a10035fb052135a1de9f85`)
   - `data/synthetic/v2_holdout.jsonl` (`120` labeled + `12` ambiguous separate; `a2eb49623715b7cf3b84c6d2afda29c6f50fe07b65a4820ad52753ea1681ff1e`)
   - `data/processed/test.jsonl` (`1,148` UCI test)
   - `data/synthetic/indian_sms.jsonl` (`24` test + `8` dev + `4` ambiguous separate)

### Recorded V8 Dataset SHA-256 Hashes (Populated Immediately Upon Dataset Generation Before Training)

- `data/synthetic/v8_development.jsonl`: `c72f2e472c7105f61fe08afb39dc5a9bdd9214a964ebbe4c49a50b2621bb4525` (`1,018` rows: `train=661` [356 leg / 305 scam; 381 EN / 280 HI], `calibration=139` [74/65; 72 EN / 67 HI], `validation=218` [121/97; 121 EN / 97 HI])
- `data/synthetic/v8_holdout.jsonl`: `08d77843e32a4b3c7625d57d04222de37592eea9783d14a33d531cbd10d123c9` (`264` rows: `240` labeled [60/60 EN, 60/60 HI] + `24` ambiguous [12 EN, 12 HI]; `0` cross-partition near-duplicates `>= 0.85` cosine)

---

## 3. Pre-Declared Host Promotion Gates (`P1`–`P4`) & Hardware Gate (`P5`)

Candidate V8 is promoted as workspace default and packaged into `dist/edgeshield-v8-pi5-handoff/` **only if ALL host gates `P1`–`P4` pass on the single frozen evaluation run without post-hoc weight, threshold, or rule tuning**:

- **P1 (`reproduced_failures_and_controls`, `17`):**
  - `0/10` false `SCAM` verdicts and `0/10` benign impersonation/request cues (`BANK_IMPERSONATION`, `THREAT_OF_BLOCK`, `KYC_IMPERSONATION`, `OTP_REQUEST`, `UPI_COLLECT_LURE`).
  - `0/7` scams labeled `LEGITIMATE` and `7/7` scams labeled `SCAM`.
- **P2 (Fresh Unseen `v8_holdout`, `240` labeled — strictly ONE evaluation):**
  - Overall FPR `<= 3.0%` (`<= 3/120`) AND strictly `< V3` FPR on `v8_holdout`.
  - Overall scam recall `>= 90.0%` (`>= 108/120`), English recall `>= 86.0%`, Hinglish recall `>= 86.0%`.
  - Scams labeled `LEGITIMATE` `<= 5.0%` (`<= 6/120`).
  - Benign messages labeled `UNCERTAIN` `<= 6.0%` (`<= 7/120`).
  - Total coverage `>= 90.0%` (`>= 216/240`).
  - Overall ROC-AUC `>= V3` AND overall Brier score `<= V3`.
  - Benign impersonation/request cue errors `<= 3/120` (`<= 2.5%`).
- **P3 (Existing Regression Suites):**
  - `v7_holdout` (`240` labeled): FPR `<= 3.0%` (`<= 3/120`), scam recall `>= 90.0%`, scams→`LEGITIMATE` `<= 5.0%`, benign cue errors `<= 2/120`.
  - `v6_holdout` (`240` labeled): FPR `<= 3.0%` (`<= 3/120`), scam recall `>= 90.0%`, scams→`LEGITIMATE` `<= 5.0%`, benign cue errors `<= 2/120`.
  - `v5_holdout` (`240` labeled): FPR `<= 3.0%` (`<= 3/120`), scam recall `>= 90.0%`, scams→`LEGITIMATE` `<= 5.0%`, benign cue errors `<= 2/120`.
  - `v4_holdout` (`240` labeled): FPR `<= 4.17%` (`<= 5/120`), scam recall `>= 90.0%`, scams→`LEGITIMATE` `<= 5.0%`, benign cue errors `<= 2/120`.
  - `v3_holdout` (`160`): FPR `<= 2.5%` (`<= 2/80`), scam recall `>= 95.0%` (`>= 76/80`).
  - `v2_holdout` (`120` labeled): FPR `<= 3.33%` (`<= 2/60`), scam recall `>= 90.0%`, scams→`LEGITIMATE` `<= 5/60`.
  - `uci_test` (`1,148`): FPR `<= 0.5%` (`<= 5/984`), scam recall `>= 86.0%` (`>= 142/164`).
- **P4 (Host Product, Genuine ExecuTorch Llama & Clean Release Package):**
  - Full host `pytest -q` passes (`0` failures).
  - `scripts/verify_llama_host.py --suite smoke` and `--suite evidence` (on exported `v8_holdout` evidence) exit `0` with retained JSON logs under `results/host/v8/`.
  - Real CLI + host `llama_main` E2E (`results/host/v8/e2e_v8_host_llama.txt`) passes including default V8 resolution (if promoted), `UNCERTAIN` case, UCI false-reassurance audit, `--advisory-policy off` (`SKIPPED_BY_POLICY`), rejected runtime (`RUNTIME_CONFIGURATION_REJECTED`), invalid SMS (`exit 2`), and tampered checksum (`exit 2`).
  - Release bundle built in `dist/edgeshield-v8-pi5-handoff/` (if `P1`–`P3` pass), extracted into `/tmp/edgeshield-v8-clean`, verified with `scripts/verify_bundle.py` (`0` `models/llama/*` files), installed in fresh `.venv` (`pytest` `0` failures), and CLI launched from `/tmp` & bundle root proving exact V8 SHA-256, with transcript saved in `results/host/v8/p4_clean_bundle_verification.txt`.
- **P5 (Physical Raspberry Pi 5 Verification):**
  - `PENDING_HARDWARE` on host until physical Raspberry Pi 5 runs complete on V8 (`VERIFIED`).
