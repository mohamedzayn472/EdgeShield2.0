# EdgeShield V6 Pre-Registered Evaluation Protocol & Promotion Criteria

**Registered before edits to `src/edgeshield/indicators.py`, V6 dataset generation, calibration, or model thresholds.**  
**Date:** 23 November 2026

---

## 1. Baseline, Prior Candidates, and V6 Architecture

- **Frozen V3 Reference:** `models/detector_v3.json` (`edgeshield-word-char-lr-v3`, `format: 3`, SHA-256 `b2b2126b872c43eb02ccdef41a7f5040cf86cfd0dc1bfb31f98ef13733d50910`, thresholds `[0.65, 0.75]`).
- **Held V4 Reference:** `models/detector_v4.json` (`edgeshield-word-char-lr-v4`, `format: 4`, SHA-256 `b6f54fab1cc4b70b4d3e1f98cd5e71e865f10ce25e6680d7a7567e40198d2f6a`, thresholds `[0.15, 0.2]`).
- **V5 Reference (current default in workspace prior to V6):** `models/detector_v5.json` (`edgeshield-word-char-lr-v5`, `format: 5`, SHA-256 `bc98c0d961aec7c1a03e1f0e517b970765ee818f42c938152719c7b84951908b`, thresholds `[0.5, 0.75]`). Failed V5 gate checks: `P1` (`7c_ctrl_warn_then_req` scored `0.7048` `UNCERTAIN`), `P2` cue sub-gate (`8/120` unseen benign cue errors on `v5_holdout`), `P3` UCI test recall (`138/164 = 84.15%` < `86.0%`), and `P4` host ExecuTorch smoke/evidence suites & clean-extract transcript.
- **Candidate Under Test (`V6`):**
  1. Clause-level linguistic repairs in `src/edgeshield/indicators.py` resolving the 8 unseen benign indicator patterns from `v5_holdout` while keeping all 12 closed indicator IDs and never overriding statistical scores.
  2. Candidate classifier `models/detector_v6.json` (`edgeshield-word-char-lr-v6`, `format: 6`, `src/edgeshield/detector_v6.py`) with URL structural/risk keyword extraction (`urlkw_*`) without fictional hostnames, 5-fold `GroupKFold` validation by family, 4-quadrant/domain-balanced calibration (`temperature_scaled` vs `sigmoid_quadrant_balanced` vs `sigmoid_synthetic_balanced`), capped upper threshold search (`low in [0.30, 0.50]`, `high in [0.475, 0.675]`) requiring simultaneous `val_uci recall >= 91%` and `val_syn recall >= 95%`, and a hard failure guard refusing to save unless `validation_quality_gate == "PASSED"`.
- **Preserved Artifacts:** `models/detector.json`, `models/detector_v2.json`, `models/detector_v3.json`, `models/detector_v4.json`, `models/detector_v5.json`, `models/llama/*`, prior `results/host/v3..v5/`, and archived Pi 5 runs (`results/pi5/archive/20261118-B0-full/`, `results/pi5/offline-20261119/`) remain untouched.

---

## 2. Partition Isolation & Evaluation Sets

1. **Development-Only Splits (NEVER used for final scoring):**
   - `data/synthetic/v6_development.jsonl` (`train` / `calibration` / `validation`, built on `v5_development.jsonl` + new family-separated EN/HI contrast-pivot scams, telecom recharge alerts, self-entry passcodes, and duplicate POS reversals using strictly dev brands).
   - `data/processed/{train,calibration,validation}.jsonl` (local UCI splits).
2. **One-Time Unseen Fresh Evaluation Set (opened strictly ONCE after freezing `models/detector_v6.json` and `src/edgeshield/indicators.py`):**
   - `data/synthetic/v6_holdout.jsonl`: `264` AI-assisted/fictional synthetic SMS (`240` labeled: `60 EN benign`, `60 EN scam`, `60 HI benign`, `60 HI scam`; plus `24` ambiguous `label: null`: `12 EN`, `12 HI` reported strictly outside binary accuracy; plus `pair_id` paired controls) using 100% unseen fictional Indian entities (`Tungabhadra Bank`, `Sabarmati Trust`, `Periyar Pay`, `Konark Card`, `Vellore Mart`, `Gomti Express`, `Sutlej Power`, `Beas Water`, `Nilachal Rail`, `Zanskar Telecom`, `Mandovi Fin`, `Shivalik Hospital`).
3. **Existing Regression Suites:**
   - `reproduced_failures_and_controls` (`17`: `10` benign, `7` scam)
   - `data/synthetic/v5_holdout.jsonl` (`240` labeled + `24` ambiguous separate; `873bc9dc74ec049970f95bad7061bba5cd5f0bbd9fbafa85efdfdd57915ae1fd`)
   - `data/synthetic/v4_holdout.jsonl` (`240` labeled + `24` ambiguous separate; `9f5e1a9f247ebe44011393898653f8afaec02aa644aea0015d3cbcbe2b5551b9`)
   - `data/synthetic/v3_holdout.jsonl` (`160` labeled; `a127660629cfc78e763b5017b4363f7b0eaae66119a10035fb052135a1de9f85`)
   - `data/synthetic/v2_holdout.jsonl` (`120` labeled + `12` ambiguous separate; `a2eb49623715b7cf3b84c6d2afda29c6f50fe07b65a4820ad52753ea1681ff1e`)
   - `data/processed/test.jsonl` (`1,148` UCI test)
   - `data/synthetic/indian_sms.jsonl` (`24` test + `8` dev + `4` ambiguous separate)

### Recorded Dataset SHA-256 Hashes (Frozen Before V6 Training)

- `data/synthetic/v6_development.jsonl`: `d165160c28da233e5165b018cff99bc16aee923d29b15139b802a5532113b17a` (`934` rows: `train=609` [319 leg / 290 scam; 345 EN / 264 HI], `calibration=126` [65/61; 64 EN / 62 HI], `validation=199` [107/92; 110 EN / 89 HI])
- `data/synthetic/v6_holdout.jsonl`: `27257205980a0fca20c0bb44852559c3f5205db2f5320295427d8ac89a3e9f24` (`264` rows: `240` labeled [60/60 EN, 60/60 HI] + `24` ambiguous [12 EN, 12 HI]; `0` cross-partition near-duplicates `>= 0.85` cosine)

---

## 3. Pre-Declared Host Promotion Gates (`P1`–`P4`) & Hardware Gate (`P5`)

Candidate V6 is promoted on host **only if ALL host gates `P1`–`P4` pass on the single frozen evaluation run without post-hoc threshold or rule tuning**:

- **P1 (`reproduced_failures_and_controls`, `17`):**
  - `0/10` false `SCAM` verdicts and `0/10` benign impersonation/request cues (`BANK_IMPERSONATION`, `THREAT_OF_BLOCK`, `KYC_IMPERSONATION`, `OTP_REQUEST`, `UPI_COLLECT_LURE`).
  - `0/7` scams labeled `LEGITIMATE` and `7/7` scams labeled `SCAM`.
- **P2 (Fresh Unseen `v6_holdout`, `240` labeled — strictly ONE evaluation):**
  - Overall FPR `<= 3.0%` (`<= 3/120`) AND strictly `< V3` FPR on `v6_holdout`.
  - Overall scam recall `>= 90.0%` (`>= 108/120`), English recall `>= 86.0%`, Hinglish recall `>= 86.0%`.
  - Scams labeled `LEGITIMATE` `<= 5.0%` (`<= 6/120`).
  - Benign messages labeled `UNCERTAIN` `<= 6.0%` (`<= 7/120`).
  - Total coverage `>= 90.0%` (`>= 216/240`).
  - Overall ROC-AUC `>= V3` AND overall Brier score `<= V3`.
  - Benign impersonation/request cue errors `<= 3/120` (`<= 2.5%`).
- **P3 (Existing Regression Suites):**
  - `v5_holdout` (`240` labeled): FPR `<= 3.0%` (`<= 3/120`), scam recall `>= 90.0%` (`>= 108/120`), scams→`LEGITIMATE` `<= 5.0%` (`<= 6/120`), benign cue errors `<= 2/120`.
  - `v4_holdout` (`240` labeled): FPR `<= 4.17%` (`<= 5/120`), scam recall `>= 90.0%` (`>= 108/120`), scams→`LEGITIMATE` `<= 5.0%` (`<= 6/120`), benign cue errors `<= 2/120`.
  - `v3_holdout` (`160`): FPR `<= 2.5%` (`<= 2/80`), scam recall `>= 95.0%` (`>= 76/80`).
  - `v2_holdout` (`120` labeled): FPR `<= 3.33%` (`<= 2/60`), scam recall `>= 90.0%` (`>= 54/60`), scams→`LEGITIMATE` `<= 5/60`.
  - `uci_test` (`1,148`): FPR `<= 0.5%` (`<= 5/984`), scam recall `>= 86.0%` (`>= 142/164`).
- **P4 (Host Product, Genuine ExecuTorch Llama & Clean Release Package):**
  - Full host `pytest -q` passes (`0` failures).
  - `scripts/verify_llama_host.py --suite smoke` and `--suite evidence` (on exported `v6_holdout` evidence) exit `0` with retained JSON logs.
  - Real CLI + host `llama_main` E2E (`results/host/v6/e2e_v6_host_llama.txt`) passes including false-reassurance audit, `--advisory-policy off` (`SKIPPED_BY_POLICY`), rejected runtime (`RUNTIME_CONFIGURATION_REJECTED`), invalid SMS (`exit 2`), and tampered checksum (`exit 2`).
  - Release bundle built in `dist/edgeshield-v6-pi5-handoff/`, extracted into clean `/tmp/edgeshield-v6-clean`, verified with `scripts/verify_bundle.py` (`0` `models/llama/*` files), installed in fresh `.venv` (`pytest` `0` failures), and CLI launched from `/tmp` & bundle root proving exact V6 SHA-256, with transcript saved in `results/host/v6/p4_clean_bundle_verification.txt`.
- **P5 (Physical Raspberry Pi 5 Verification):**
  - `PENDING_HARDWARE` on host until physical Raspberry Pi 5 runs complete on V6 (`VERIFIED`).
