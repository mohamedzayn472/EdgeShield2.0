# EdgeShield Standalone Phishing URL Detection (`url_detector_v1`)

**Branch:** `feat/phishing-url` (local experimental branch; `main` V8 SMS submission remains untouched)  
**Model:** `edgeshield-url-char-lexical-lr-v1` (`models/url_detector_v1.json`, `1,125,655` bytes, SHA-256 `6e68120417050c7f4647be6373fe086dec7a7a685c0c3f3188e13eb0daf23217`, thresholds `[0.30, 0.70]`)

---

## 1. Architecture & Offline Privacy Firewall

The `--mode url` / `--url-stdin` workflow mirrors EdgeShield's privacy-first SMS architecture with zero DNS lookups, zero WHOIS queries, and zero HTTP connections:

```text
User URL (stdin / hidden prompt, <= 2,048 chars)
   │
   ▼
[normalize_url + UrlDetectorV1 + detect_url_indicators]  ──►  Immediate verdict (SCAM / UNCERTAIN / LEGITIMATE)
   │                                                          + Deterministic URL_ADVICE (app-owned DO:)
   │  Typed Evidence ONLY (band, score, enumerated cue IDs; NO raw URL/host/query)
   ▼
[ExecuTorchAdvisor subprocess]   ──►  Llama 3.2 1B SpinQuant INT4 EO8 on CPU (XNNPACK)
   │
   ▼
[Strict Explanation Validator]   ──►  ACCEPTED  ──►  WHY: ... [Source: Llama (validated)]
```

### Features & Closed Cue Vocabulary
- **23 structural features** (`src/edgeshield/url_detector.py`): normalized host/path/query lengths, excess subdomain depth (`max(0, non_www_subdomains - 1)`), hyphen count, host/path digit and special-character ratios, host Shannon entropy, `http://` indicator, IP literal host, `@`/punycode (`xn--`), non-standard port, URL shortener match, suspicious TLD, risky executable/archive extension, brand-in-subdomain/path mismatch, auth-lure keyword presence, longest label length, query parameter count, and trusted Indian `.gov.in` / `.nic.in` / `.ac.in` / `.sbi` / `.rbi.org.in` / `.npci.org.in` suffix.
- **Word + host character TF-IDF (`format: 101`):** `word` 1–2-grams (`1,942` terms) over tokenized host/path/markers + `char` 3–5-grams (`19,827` terms) over host only (`char_host`), L2-normalized alongside `/5.0`-scaled standardized structural features and Platt-calibrated Logistic Regression (`C=2.0`, calibration `[1.806247, 0.357556]`).
- **6 new URL cue IDs** in `src/edgeshield/indicators.py` (`detect_url_indicators`, keeping SMS `detect_indicators` unchanged): `IP_HOST_URL`, `PUNYCODE_OR_AT_URL`, `SUSPICIOUS_TLD_URL`, `DEEP_SUBDOMAIN_URL`, `BRAND_SPOOF_URL`, `RISKY_EXTENSION_URL` (plus reused `SHORTENER_LINK`).

---

## 2. Time-Aware, Domain-Disjoint Dataset (`results/host/url_v1/dataset_manifest.json`)

- **Phishing URLs:** 30 timestamped snapshots of `openphish/public_feed` (cutoff `2026-11-17T00:00:08Z`):
  - Earlier snapshots (`< 2026-11-17T00:00:08Z`, grouped by registrable domain) → `url_train.jsonl`, `url_calibration.jsonl`, `url_validation.jsonl`.
  - **Strictly future snapshots (`>= 2026-11-17T00:00:08Z`, zero domain overlap with earlier splits)** → `url_test_temporal.jsonl`.
- **Benign URLs:** Sampled `7,500` domain-unique sites across `tranco-list.eu` top-100k (excluding `URL_SHORTENERS`, OpenPhish domains, dev, and holdout domains) paired with diverse procedural deep paths, numeric slugs, and neutral subdomains (`~35%` 1-subdomain, `~35%` `www.`, `~30%` bare domain) + curated Indian banking/government benign URLs.
- **Partition Counts (`0` registrable-domain overlap across dev, `test_temporal`, and `url_holdout`):**
  - `url_train`: `9,502` (`5,345` phish / `4,157` benign)
  - `url_calibration`: `1,598` (`473` phish / `1,125` benign)
  - `url_validation`: `1,673` (`773` phish / `900` benign)
  - `url_test_temporal`: `1,827` (`477` future phish / `1,350` unseen benign)
  - `data/synthetic/url_holdout.jsonl`: `200` (`100` unseen Indian + global phish / `100` unseen Indian + global benign)

---

## 3. Measured Evaluation (`results/host/url_v1/evaluation_report.json`)

| Evaluation Set | n (Benign / Phish) | Acc | Prec | Rec (`SCAM`) | `SCAM+UNC` Catch | FPR | ROC-AUC | Brier | Median Latency | Confusion `[[TN,U,FP],[FN,U,TP]]` |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| **`url_validation`** (`C=2.0`, `[0.30, 0.70]`) | `1,673` (`900` / `773`) | 91.21% | 98.07% | 85.51% | 95.47% | **1.44%** | 0.99128 | 0.03862 | — | — |
| **`test_temporal`** (Future OpenPhish + Tranco) | `1,827` (`1,350` / `477`) | 91.46% | 94.72% | 79.04% | **91.40%** (`436/477`) | **1.56%** | **0.98624** | 0.04054 | **0.464 ms** | `[[1294, 35, 21], [41, 59, 377]]` |
| **`url_holdout_200`** (Unseen Indian + Global) | `200` (`100` / `100`) | **99.00%** | 98.04% | **100.00%** | **100.00%** | **2.00%** | **0.99990** | 0.01034 | **0.464 ms** | `[[98, 0, 2], [0, 0, 100]]` |
| **`url_holdout_indian_subset`** | `75` (`25` / `50`) | **98.67%** | 98.04% | **100.00%** | **100.00%** | 4.00% (`1/25`) | **1.00000** | 0.01187 | **0.474 ms** | `[[24, 0, 1], [0, 0, 50]]` |

Host ExecuTorch Llama E2E verification (`--mode url --demo` and `--url-stdin --json`) is recorded in `results/host/url_v1/e2e_url_host_llama.txt`.

---

## 4. Usage

```bash
# Built-in 4-case synthetic URL demo (offline template fallback or --runtime-config for Llama)
bash scripts/host_python.sh -m edgeshield.cli --mode url --demo

# Single URL JSON inspection via stdin (raw URL never logged or echoed in JSON)
printf '%s\n' 'http://sbi.kyc-verify-account.xyz/netbanking/login.php' | \
  bash scripts/host_python.sh -m edgeshield.cli --url-stdin --json

# Interactive URL inspection loop
bash scripts/host_python.sh -m edgeshield.cli --mode url --repeat
```

---

## 5. Limitations

1. **Compromised legitimate domains:** Because EdgeShield inspects URL strings strictly offline (zero DNS/WHOIS/HTML fetching), compromised benign-looking websites (e.g., hacked small-business domains) without phishing keywords or structural anomalies account for the ~8.6% misses (`41/477`) in `test_temporal`.
2. **Non-calibrated probability:** Scores are derived from OpenPhish + Tranco + curated Indian URLs (`EXPERIMENTAL_TIME_SPLIT_URL_MODEL`) and are not calibrated against real-world mobile click prevalence.
3. **Host-verified only:** `--mode url` has been verified on Linux x86_64 host (including genuine ExecuTorch Llama E2E); on-device Raspberry Pi 5 verification remains pending before merging into `main`.
