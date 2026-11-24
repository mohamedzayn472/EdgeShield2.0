# EdgeShield Standalone Phishing URL Detection (`url_detector_v1`)

**Branch:** `feat/phishing-url` (local experimental branch; `main` V8 SMS submission remains untouched)  
**Model:** `edgeshield-url-char-lexical-lr-v1` (`models/url_detector_v1.json`, `1,083,468` bytes, SHA-256 `e8726e42bb5023bca3952945ad5abc086a94cabac14eccfee63f4301ea711728`, thresholds `[0.30, 0.70]`)

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
- **23 structural features** (`src/edgeshield/url_detector.py`): normalized host/path/query lengths, excess subdomain depth (`max(0, non_www_subdomains - 2)`), hyphen count, host/path digit and special-character ratios, host Shannon entropy, `http://` indicator, IP literal host, `@`/mixed-script homoglyph punycode (`has_homoglyph_punycode`), non-standard port, URL shortener match, suspicious TLD, risky executable/archive extension, brand-in-subdomain/path mismatch, suspicious-host-conditioned auth context (`has_suspicious_auth_context`), longest label length, query parameter count, and trusted Indian `.gov.in` / `.nic.in` / `.ac.in` / `.sbi` / `.rbi.org.in` / `.npci.org.in` suffix.
- **Word + host character TF-IDF (`format: 101`):** `word` 1–2-grams (`1,239` terms, stripping non-suspicious TLD noise and official-brand tokens on verified domains) + `char` 3–5-grams (`20,000` terms) over host only (`char_host`), L2-normalized alongside `/5.0`-scaled standardized structural features and Platt-calibrated Logistic Regression (`C=4.0`, calibration `[1.808126, 0.411545]`).
- **6 new URL cue IDs** in `src/edgeshield/indicators.py` (`detect_url_indicators`, keeping SMS `detect_indicators` unchanged): `IP_HOST_URL`, `PUNYCODE_OR_AT_URL`, `SUSPICIOUS_TLD_URL`, `DEEP_SUBDOMAIN_URL`, `BRAND_SPOOF_URL`, `RISKY_EXTENSION_URL` (plus reused `SHORTENER_LINK`).

---

## 2. Time-Aware, Domain-Disjoint Dataset (`results/host/url_v1/dataset_manifest.json`)

- **Phishing URLs:** 30 timestamped snapshots of `openphish/public_feed` (cutoff `2026-11-17T00:00:08Z`):
  - Earlier snapshots (`< 2026-11-17T00:00:08Z`, grouped by registrable domain) → `url_train.jsonl`, `url_calibration.jsonl`, `url_validation.jsonl`.
  - **Strictly future snapshots (`>= 2026-11-17T00:00:08Z`, zero domain overlap with earlier splits)** → `url_test_temporal.jsonl`.
- **Benign URLs:** Sampled `7,500` domain-unique sites across `tranco-list.eu` top-100k (excluding `URL_SHORTENERS`, `ABUSED_HOSTING_SUFFIXES`, OpenPhish domains, dev, and holdout domains) paired with diverse procedural deep paths, numeric IDs, and neutral 1- and 2-level subdomains + curated Indian banking/government benign URLs.
- **Partition Counts (`0` registrable-domain overlap across dev, `test_temporal`, and `url_holdout`):**
  - `url_train`: `9,506` (`5,349` phish / `4,157` benign)
  - `url_calibration`: `1,598` (`473` phish / `1,125` benign)
  - `url_validation`: `1,673` (`773` phish / `900` benign)
  - `url_test_temporal`: `1,827` (`477` future phish / `1,350` unseen benign)
  - `data/synthetic/url_holdout.jsonl`: `200` (`100` unseen Indian + global phish / `100` unseen Indian + global benign)

---

## 3. Measured Evaluation (`results/host/url_v1/evaluation_report.json`)

| Evaluation Set | n (Benign / Phish) | Acc | Prec | Rec (`SCAM`) | `SCAM+UNC` Catch | FPR | ROC-AUC | Brier | Median Latency | Confusion `[[TN,U,FP],[FN,U,TP]]` |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| **`url_validation`** (`C=4.0`, `[0.30, 0.70]`) | `1,673` (`900` / `773`) | 90.85% | 98.25% | 87.19% | 95.21% | **1.33%** | 0.99055 | 0.04015 | — | — |
| **`test_temporal`** (Future OpenPhish + Tranco) | `1,827` (`1,350` / `477`) | 90.26% | 92.18% | 79.04% | **93.08%** (`444/477`) | **2.37%** | **0.98600** | 0.04303 | **0.495 ms** | `[[1272, 46, 32], [33, 67, 377]]` |
| **`url_holdout_200`** (Unseen Indian + Global) | `200` (`100` / `100`) | **94.50%** | 98.04% | **100.00%** | **100.00%** | **2.00%** | **1.00000** | 0.02028 | **0.488 ms** | `[[89, 9, 2], [0, 0, 100]]` |
| **`url_holdout_indian_subset`** | `75` (`25` / `50`) | **98.67%** | **100.00%** | **100.00%** | **100.00%** | **0.00%** (`0/25`) | **1.00000** | 0.00749 | **0.492 ms** | `[[24, 1, 0], [0, 0, 50]]` |

---

## 4. Extensive Stress-Test Suite (`results/host/url_v1/stress_test_report.json`)

Executed `129` targeted benign & adversarial phishing URLs plus `14` malformed/dangerous schemes and `3` prompt-injection sentinel checks (`0.497 ms` median / `0.585 ms` p95 latency):

- **Hard Benign URLs (`79` total — `65` `LEGITIMATE`, `10` `UNCERTAIN`, `4` `SCAM` = `5.06%` FPR):**
  - `indian_banking_logins` (`14/14` `LEGITIMATE`, **0 FP**, **0 `UNCERTAIN`** — includes HDFC, SBI, ICICI, Axis, Kotak, IndusInd, Yes Bank, Canara, BoB, PNB, Federal, IDFC First, Union Bank)
  - `indian_gov_upi_telecom` (`18/18`: `15` `LEGITIMATE`, `3` `UNCERTAIN`, **0 FP**)
  - `kyc_phishing_edu_news` (`12/12`: `11` `LEGITIMATE`, `1` `UNCERTAIN`, **0 FP** — RBI KYC FAQ, Times of India KYC rules, The Hindu UPI fraud article, StackOverflow OTP Q&A, OWASP/Wikipedia/Cloudflare)
  - `global_auth_login` (`8`: `5` `LEGITIMATE`, **3 FP**: `github.com/login` `0.9233`, `login.microsoftonline.com/...` `0.9220`, `appleid.apple.com/sign-in` `0.9251`)
  - `deep_tech_cloud_commerce` (`27`: `20` `LEGITIMATE`, `6` `UNCERTAIN`, **1 FP**: `huggingface.co/meta-llama/Llama-3.2-1B-Instruct` `0.9081`)
- **Hard Adversarial Phishing URLs (`50/50` = `100.0%` `SCAM` recall, `0` `UNCERTAIN`, `0` misses):**
  - `indian_bank_kyc_upi_gov`: `19/19` `SCAM`
  - `ip_obfuscation` (IPv4, IPv6, hex IP, integer IP): `5/5` `SCAM`
  - `at_and_punycode` (`@` credential tricks & mixed-script `xn--` homoglyphs): `4/4` `SCAM`
  - `shorteners_subdomains_extensions` (`bit.ly`, `tinyurl.com`, `is.gd`, `rb.gy`, `cutt.ly`, `rebrand.ly`, deep subdomains, `.apk`, `.pdf.exe`): `10/10` `SCAM`
  - `abused_hosting_and_evasion` (`.web.app`, `.firebaseapp.com`, `.pages.dev`, `.ngrok-free.app`, `.vercel.app`, uppercase, NFKC fullwidth Unicode, missing scheme): `12/12` `SCAM`
- **Security & Fuzz Checks:** `14/14` malformed/unsafe inputs rejected (`javascript:`, `data:`, `file://`, null byte, bidi override, newlines, spaces, oversize, empty), `0` prompt-injection sentinel leaks, `0` socket/DNS calls attempted.
- **Host ExecuTorch Llama E2E (`results/host/url_v1/e2e_url_host_llama.txt`):** `4/4` `--mode url --demo` cases + `--url-stdin --json` passed `Source: Llama (validated) | Status: ACCEPTED`.

---

## 5. Usage

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

## 6. Limitations

1. **Compromised legitimate domains:** Because EdgeShield inspects URL strings strictly offline (zero DNS/WHOIS/HTML fetching), compromised benign-looking websites without phishing keywords or structural anomalies account for the ~6.9% (`33/477`) `LEGITIMATE` misses in `test_temporal`.
2. **Global-brand host char-ngram false alarms without an allowlist:** Because OpenPhish contains heavy abuse of `github.io`, `apple`, `microsoft`, and `meta` strings while offline URL scoring intentionally avoids hardcoding a global domain allowlist, `github.com/login`, `login.microsoftonline.com`, `appleid.apple.com`, and `huggingface.co/meta-llama` scored as false positives in stress testing.
3. **Non-calibrated probability & host-only status:** Scores (`EXPERIMENTAL_TIME_SPLIT_URL_MODEL`) are not calibrated against real-world mobile click prevalence, and Raspberry Pi 5 hardware verification for `--mode url` remains pending before merging into `main`.
