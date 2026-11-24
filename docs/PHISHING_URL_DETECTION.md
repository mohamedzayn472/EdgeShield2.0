# EdgeShield Standalone Phishing URL Detection (`url_detector_v1`)

**Status:** In-progress experimental prototype included on `main` (`--mode url`, `models/url_detector_v1.json`) for judge reference; primary Phase 1 SMS default (`--mode sms`, `models/detector_v8.json`) remains completely unchanged.  
**Model:** `edgeshield-url-char-lexical-lr-v1` (`format: 102`, `models/url_detector_v1.json`, `1,736,915` bytes, SHA-256 `779cf74fd2ac1ac8c634649a468c7dea57eeb66d15d5c20574bf5072faa1f4a0`, thresholds `[0.30, 0.65]`)

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

### Features, Typosquat Detection & Closed Cue Vocabulary
- **25 structural features (`format: 102`, `src/edgeshield/url_detector.py`):** normalized host/path/query lengths, excess subdomain depth (`max(0, non_www_subdomains - 2)`), hyphen count, host/path digit and special-character ratios, host Shannon entropy, `http://` indicator, IP literal host, `@`/mixed-script homoglyph punycode (`has_homoglyph_punycode`), non-standard port, URL shortener match, suspicious TLD, risky executable/archive extension, brand-in-subdomain/path mismatch, suspicious-host-conditioned auth context (`has_suspicious_auth_context`), longest label length, query parameter count, trusted Indian `.gov.in`/`.nic.in`/`.ac.in`/`.sbi`/`.rbi.org.in`/`.npci.org.in` suffix, offline `has_brand_typosquat`, and `is_abused_hosting`. The 12 continuous features use z-score clipping `[-3.0, +3.0]` (`STRUCTURAL_Z_CLIP`) to prevent numeric-ID paths from spiking structural logits while leaving all 13 binary indicators unclipped (`scale_structural_matrix` scaled `/ 5.0`).
- **Offline typosquat & leetspeak detection (`detect_brand_typosquat` in `src/edgeshield/indicators.py`):** normalizes leetspeak (`0->o`, `1->l/i`, `3->e`, `4->a`, `5->s`, `7->t`, `8->b`), visually confusable digraphs (`rn->m`, `vv->w`), compound brand+lure tokens (`coinbasewallet`, `paypalsecure`), and Damerau-Levenshtein edit distance `<= 1` against major Indian & global brand stems (guarded by `_TYPOSQUAT_COLLISION_ALLOWLIST`; triggers `BRAND_SPOOF_URL`, with `4 / 7,832 = 0.051%` false-trigger rate across real benign URLs).
- **Word + clean host character TF-IDF:** `word` 1–2-grams (`4,847` terms, `min_df=2`, stripping non-suspicious TLD noise, official-brand tokens on verified domains, mismatched host-brand tokens, and matched abused-hosting suffixes) + `char` 3–5-grams (`28,696` terms, `min_df=2`) over non-suffix host (`char_surface` strips matched `ABUSED_HOSTING_SUFFIXES` so `.github.io`/`.vercel.app` abuse never poisons `github.com`/`apple.com` weights), Platt-calibrated Logistic Regression (`C=1.0`, `class_weight=None`, calibration `[1.48602, 0.570101]`).
- **Auditable 8-precondition verified-domain policy (`is_verified_official_domain`):** caps scores on explicit `https://` URLs whose exact registrable domain matches `VERIFIED_OFFICIAL_DOMAINS` (`BRAND_OFFICIAL_DOMAINS` union) AND passes all checks (no IP, no `@`, no mixed-script punycode, port `None` or `443`, not abused hosting/shortener, no risky extension, no embedded `http://`/`https://` open-redirect parameter, zero triggered cues).
- **6 URL cue IDs** in `src/edgeshield/indicators.py` (`detect_url_indicators`, keeping SMS `detect_indicators` unchanged): `IP_HOST_URL`, `PUNYCODE_OR_AT_URL`, `SUSPICIOUS_TLD_URL`, `DEEP_SUBDOMAIN_URL`, `BRAND_SPOOF_URL`, `RISKY_EXTENSION_URL` (plus reused `SHORTENER_LINK`).

---

## 2. Time-Aware, Domain-Disjoint Real-URL Dataset (`results/host/url_v1/dataset_manifest.json`)

- **Phishing URLs:** 30 timestamped snapshots of `openphish/public_feed` (cutoff `2026-11-17T00:00:08Z`):
  - Earlier snapshots (`< 2026-11-17T00:00:08Z`, grouped by registrable domain, capped `<= 50/reg_domain` in train) → `url_train.jsonl`, `url_calibration.jsonl`, `url_validation.jsonl`.
  - **Strictly future snapshots (`>= 2026-11-17T00:00:08Z`, zero domain overlap with earlier splits)** → `url_test_temporal.jsonl`.
- **Real Benign URLs (zero procedurally fabricated paths or subdomains):**
  - `5,400` domain-unique real crawled benign full URLs (`90%` HTTPS, `10%` HTTP, non-empty real path/query) from `ealvaradob/phishing-dataset` (`urls.json`, Apache-2.0, `label=0`), + `2,400` domain-disjoint real root URLs (`90%` HTTPS) from `tranco-list.eu` top-100k, + `32` curated Indian banking/gov benign URLs + `40` Indian KYC/UPI/APK/typosquat synthetic dev phishing URLs (`url_indian_dev.jsonl`).
- **Partition Counts (`0` registrable-domain overlap across dev, `test_temporal`, and `url_holdout`):**
  - `url_train`: `6,896` (`2,574` phish / `4,322` benign)
  - `url_calibration`: `1,643` (`473` phish / `1,170` benign)
  - `url_validation`: `1,709` (`773` phish / `936` benign) — `88.94%` acc, `97.89%` prec, `83.96%` `SCAM` recall (`90.39%` F1), `1.50%` FPR (`14/936`), `0.97346` ROC-AUC, `0.05686` Brier
  - `url_test_temporal`: `1,881` (`477` future OpenPhish / `1,404` unseen real benign)
  - `data/synthetic/url_holdout.jsonl`: `200` (`100` unseen Indian + global phish / `100` unseen Indian + global benign)

---

## 3. Measured Evaluation (`results/host/url_v1/evaluation_report.json`)

On an apples-to-apples real-world `test_temporal` comparison (`1,404` unseen real `ealvaradob` + Tranco root benign URLs vs `477` future OpenPhish URLs), the earlier synthetic-path model (`c3621d1`) scored **`0.83934` ROC-AUC with `29.9%` FPR (`420/1,404` false alarms)**, whereas training format `102` on real crawled benign URLs raises `test_temporal` ROC-AUC to **`0.93168` (+9.23 pp)** and cuts FPR **22× to `1.35%` (`19/1,404`)**:

| Evaluation Set | Policy Mode | n (Benign / Phish) | Acc | Prec | Rec (`SCAM`) | `SCAM+UNC` Catch | FPR | ROC-AUC | Brier | Median Latency | Confusion `[[TN,U,FP],[FN,U,TP]]` |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| **`test_temporal`** | Verified Policy | `1,881` (`1,404` / `477`) | 83.47% | 93.36% | 55.97% | **79.66%** (`380/477`) | **1.35%** | **0.93168** | 0.07891 | **0.562 ms** | `[[1303, 82, 19], [97, 113, 267]]` |
| **`test_temporal`** | Raw ML Only | `1,881` (`1,404` / `477`) | 83.47% | 93.36% | 55.97% | **79.66%** (`380/477`) | **1.35%** | **0.93168** | 0.07891 | **0.551 ms** | `[[1303, 82, 19], [97, 113, 267]]` |
| **`url_holdout_200`** | Verified Policy | `200` (`100` / `100`) | **99.50%** | **100.00%** | **100.00%** | **100.00%** | **0.00%** | **1.00000** | 0.00286 | **0.568 ms** | `[[99, 1, 0], [0, 0, 100]]` |
| **`url_holdout_200`** | Raw ML Only | `200` (`100` / `100`) | **99.50%** | **100.00%** | **100.00%** | **100.00%** | **0.00%** | **1.00000** | 0.00286 | **0.555 ms** | `[[99, 1, 0], [0, 0, 100]]` |
| **`url_holdout_indian_subset`** | Both Modes | `75` (`25` / `50`) | **100.00%** | **100.00%** | **100.00%** | **100.00%** | **0.00%** | **1.00000** | 0.00068 | **0.595 ms** | `[[25, 0, 0], [0, 0, 50]]` |

---

## 4. Extensive Stress-Test Suite (`results/host/url_v1/stress_test_report.json`)

Executed `139` targeted benign & adversarial phishing URLs plus `14` malformed/dangerous schemes, `11` verified-domain policy bypass checks, and `3` prompt-injection sentinel checks (`0.605 ms` median / `0.736 ms` p95 latency):

- **Hard Benign URLs (`79` total — `77` `LEGITIMATE`, `2` `UNCERTAIN`, `0` (`0.00%`) `SCAM` false positives):**
  - `indian_banking_logins`: `14/14` `LEGITIMATE`, **0 FP**
  - `indian_gov_upi_telecom`: `18/18` `LEGITIMATE`, **0 FP**
  - `global_auth_login`: `8/8` `LEGITIMATE`, **0 FP** (`github.com/login`, `appleid.apple.com/sign-in`, and `huggingface.co/meta-llama/Llama-3.2-1B-Instruct` all dropped from `>0.90` to `<0.025` purely in Raw ML; `login.microsoftonline.com` dropped from `0.9220` to `0.3686` Raw ML / `0.1500` with Verified Policy)
  - `kyc_phishing_edu_news`: `12/12` `LEGITIMATE`, **0 FP**
  - `deep_tech_cloud_commerce`: `25/27` `LEGITIMATE`, `2` `UNCERTAIN` (`zoom.us/j/98765432100` `0.4321`, `localhost:8000` `0.5712`), **0 FP**
- **Hard Adversarial Phishing URLs (`60/60` = `100.0%` `SCAM` recall, `0` `UNCERTAIN`, `0` misses):**
  - `indian_bank_kyc_upi_gov`: `19/19` `SCAM`
  - `ip_obfuscation` (IPv4, IPv6, hex IP, integer IP): `5/5` `SCAM`
  - `at_and_punycode` (`@` credential tricks & mixed-script `xn--` homoglyphs): `4/4` `SCAM`
  - `shorteners_subdomains_extensions`: `10/10` `SCAM`
  - `abused_hosting_and_evasion`: `12/12` `SCAM`
  - `typosquat_and_leetspeak` (`web-coinbese.com`, `api-google-docs.com`, `on1inesbi-kyc.com`, `hdfcbnak-verify.com`, `paypa1-secure.com`, `g00gle-docs-share.com`, `rnicrosoft-auth.com`, `arnazon-india-order.com`, `icic1bank-kyc.com`, `paytrn-wallet-refund.com`): `10/10` `SCAM`
- **Security & Fuzz Checks:** `14/14` malformed/unsafe inputs rejected, `11/11` verified-policy bypass checks passed (`http://`, `@`, `.apk`, `.github.io`, subdomain spoof, open-redirect `next=http://`, non-443 port, punycode), `0` prompt-injection sentinel leaks, `0` socket/DNS calls attempted.
- **Host ExecuTorch Llama E2E (`results/host/url_v1/e2e_url_host_llama.txt`):** `4/4` `--mode url --demo` cases + `2/2` `--url-stdin --json` cases (`sbi.kyc-verify-account.xyz` and typosquat `web-coinbese.com` at `0.9719` `SCAM`) passed offline `x86_64` ExecuTorch Llama 3.2 1B SpinQuant INT4 with `Source: Llama (validated) | Status: ACCEPTED`.

---

## 5. Physical Raspberry Pi 5 (8 GB) Prototype Handover & Controlled Network Checks

In addition to the Ubuntu `x86_64` host benchmarks in Sections 3–4 (`results/host/url_v1/`), the format-102 URL prototype was evaluated on a **physical Raspberry Pi 5 Model B Rev 1.1 (8 GB RAM, AArch64, Debian GNU/Linux 13 Trixie, kernel `6.18.50+rpt-rpi-2712`, GLIBC `2.41`, Python `3.13.5`)**, with raw device logs and packet captures archived on the Pi 5 handover USB (`edgeshield_url_transfer/`, `url-v1-device/SHA256SUMS`: `12/12 OK`, `network-traffic/SHA256SUMS`: `8/8 OK`):

- **Unit & Stress Tests:** `82/82` URL unit tests passed (`0` failed, `1.35 s`); `139`-URL stress suite scored `77/79` benign `LEGITIMATE`, `2` benign `UNCERTAIN` (`zoom.us`, `localhost:8000`), **`0/79` benign `SCAM` FP**, **`60/60` (`100%`)** phishing `SCAM`, `14/14` malformed rejected, `11/11` policy-bypass verified, `0` sentinel leaks, `0` network calls attempted (`1.1098 ms` med / `1.3329 ms` p95 / `3.2401 ms` max latency).
- **Temporal & Separate Holdouts:**
  - **Temporal (`1,881`: `1,404` neg / `477` pos):** `83.47%` acc, `93.36%` prec, **`55.97%` `SCAM` recall** (+`113` `UNCERTAIN`, `97` missed as `LEGITIMATE`), `1.35%` FPR, `69.99%` F1, `10.37%` abstention, `0.93168` ROC-AUC, `0.07891` Brier, confusion `[[1303, 82, 19], [97, 113, 267]]`, latency `1.0983 ms` med / `1.2618 ms` p95 / `2.1916 ms` max.
  - **General Holdout (`200`, separate slice):** `99.50%` acc, `100%` prec, `100%` recall, `0%` FPR, `0.50%` abstention, `1.000` ROC-AUC, `0.00286` Brier, `1.1019 ms` med / `1.3278 ms` p95 / `3.4057 ms` max.
  - **Indian Holdout (`75`, separate slice):** `100%` acc, `100%` prec, `100%` recall, `0%` FPR, `1.000` ROC-AUC, `0.00068` Brier, `1.1501 ms` med / `1.3762 ms` p95 / `1.4396 ms` max.
- **ExecuTorch Llama Integration & Resources:** `4/4` URL demo cases returned `Validated / ACCEPTED` (~`2.20 ms` avg detector, ~`6.286 s` avg Llama; `ACCEPTED` confirms validator acceptance only, never URL safety). Standalone check (`http://sbi.kyc-verify-account.xyz/netbanking/login.php?session=9281`) scored `SCAM` (`0.9999996`, `3.1838 ms` detector, `0.1566 ms` evidence, `6,652.0643 ms` Llama `ACCEPTED`, `0.5261 ms` validation). Measured resources: User CPU `40.89 s`, System `1.98 s`, Elapsed `27.04 s` (`158%` CPU), Max RSS **`1,409,328 KB` (~`1.34 GiB`)**, `0` swap, `0` socket messages, `~52–66 °C` later checks, final **`throttled=0x0`**.
- **Controlled Network Checks (`tcpdump 4.99.5` + `strace -f -e trace=network`, `wlan0` `192.168.137.45`):** Baseline/background runs (`baseline.pcap` `334` pkts, `edgeshield_run.pcap` `609` pkts, `edgeshield_isolated.pcap` `315` pkts) contained background browser/OS traffic (`chatgpt.com`, etc.); after terminating Chromium, a **`45 s` controlled capture during the full `4/4` Llama demo (`edgeshield_no_chromium.pcap`) recorded `0` packets (`0` dropped)**, while a control ping capture (`capture_control.pcap`, `5` pkts) confirmed `tcpdump` operation and `strace` (`edgeshield_process_network.trace`) matched **`0`** `socket()`, `connect()`, `sendto()`, or `recvfrom()` calls.

---

## 6. Usage

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

## 7. Limitations

1. **Moderate temporal recall (`55.97%`):** On the `1,881`-URL time-split temporal set, `97/477` (`20.34%`) positive URLs scored `LEGITIMATE` (primarily compromised generic domains lacking brand/auth/TLD/structural anomalies, with zero `abused_hosting` overlap) and `113/477` scored `UNCERTAIN`. Do **not** report temporal evaluation as 100% phishing detection; General Holdout (`200`) and Indian Holdout (`75`) are separate benchmark sets and do not prove universal accuracy.
2. **Offline string-only & typosquat scope:** Zero DNS, WHOIS, TLS cert, or HTML retrieval is performed; typosquatting uses Damerau-Levenshtein `<= 1` (plus leetspeak/digraph normalization and compound brand+lure splitting) over distinctive `>= 5`-character brand stems only (excluding short 3-character names such as `sbi`, `bob`, `pnb`), and `2/79` benign stress URLs (`zoom.us`, `localhost:8000`) scored `UNCERTAIN`.
3. **Scoped network evidence & prototype status:** The controlled `45 s` no-Chromium `tcpdump` (`0` pkts) and `strace` (`0` monitored `socket`/`connect`/`sendto`/`recvfrom` matches) establish zero observed traffic/calls in those specific runs rather than universal network-inability proof; scores (`EXPERIMENTAL_TIME_SPLIT_URL_MODEL`) are not real-world prevalence-calibrated probabilities; and raw Pi 5 (8 GB) handover files live on the USB archive (`edgeshield_url_transfer/`) while prototype code, model, and host benchmarks are included on `main` for judge reference.
