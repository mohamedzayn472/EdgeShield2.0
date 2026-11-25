# Limitations Across All Three PS3 Pillars (24 November 2026)

A verified prototype is not the same as a production-ready security system. EdgeShield deliberately separates completed offline hardware verification from in-progress prototyping, unimplemented Phase 2 plans, and open submission gates.

---

## 1. Pillar 1 — Scam SMS / Smishing (`DetectorV8`, Phase 1 Complete & Verified)

### Hardware, Latency & Thermal Limits (`Pi 5 16 GB`)
- **Passive-heatsink thermal throttling (`VERIFIED`):** Under `605.4 s` of continuous back-to-back B0 inference (`results/pi5/archive/20261118-B0-full/`, archived Detector V2) on an open **Raspberry Pi 5 Model B (16 GB)** with a passive heatsink, SoC temperature rose from `59.3 °C` to **`83.7 °C`** and triggered thermal throttling (`throttled_after=0xe0008`). Short 5-request offline bursts remained cooler with zero throttling (`<= 72.7 °C` max on V8 offline `results/pi5/v8-device-20261124/` and `69.95 °C` on B0 short burst, `throttled=0x0`). Active cooling is recommended for sustained continuous LLM workloads; sustained continuous thermal characterization on V8 remains pending.
- **Cold-load subprocess latency:** Each `ExecuTorchAdvisor` call spawns an isolated `llama_main` process, verifies SHA-256 digests, loads the ~`1.00 GiB` `.pte` file (~`1.21 s` median), runs prefill (`3.17 s` median TTFT), and decodes (`13.25 tok/s` median), giving **`6.51 s` median / `6.85 s` p95** full response latency (`1.44 GB` / `1.34 GiB` peak RSS, `0 B` swap). Statistical risk verdicts and `DO:` advice appear immediately in `1.80 ms` median before Llama runs.

### Detection, Evaluation & Privacy Limits
- **Synthetic & spam-proxy evaluation:** `DetectorV8` (`99.17%` synthetic holdout accuracy, `0.83%` FPR, `[[119, 0, 1], [0, 1, 119]]`) was developed and tested on UCI SMS Spam Collection proxies plus AI-assisted synthetic Indian/Hinglish banking, OTP, UPI, delivery, and KYC templates. Synthetic holdouts do **not** establish real-world Indian SMS fraud accuracy, and scores are **not** calibrated real-world probabilities.
- **Pending human studies:** Independent human review of synthetic labels, representative consented real-message calibration, and the 5-person explanation clarity study (`docs/CLARITY_STUDY_INSTRUMENT.md`) remain pending.
- **Lexical cues & non-authentication:** Clause-level cue IDs (`BANK_IMPERSONATION`, `KYC_IMPERSONATION`, `OTP_REQUEST`, `LINK_PRESENT`, etc.) match observable wording only and never authenticate sender identity or inspect destination URLs on `main`; a low risk score never proves a message is safe.
- **Validator scope & OS trust boundary:** Validator acceptance (`5/5` on V8 offline Pi 5; `91/91` in archived B0) proves strict template compliance against structured `Evidence`, never whether the detector's underlying risk verdict is true. Application no-history guarantees do not extend to terminal scrollback, shell history, swap, or OS crash dumps, and SHA-256 checks detect manifest mismatch against a trusted manifest rather than a compromised OS.

---

## 2. Pillar 2 — Phishing URL Detection (`UrlDetectorV1`, In Progress Prototype on Pi 5 8 GB)

The standalone phishing URL prototype (`--mode url`, [docs/PHISHING_URL_DETECTION.md](PHISHING_URL_DETECTION.md)) is included on `main` as an **in-progress experimental capability** for judge reference (keeping `--mode sms` and `models/detector_v8.json` unchanged as the Phase 1 default) and was benchmarked on a physical **Raspberry Pi 5 Model B Rev 1.1 (8 GB RAM, Debian 13 Trixie, `6.18.50+rpt-rpi-2712`, `glibc 2.41`, Python 3.13.5)**, with raw artifacts archived on the Pi 5 handover USB (`edgeshield_url_transfer/`, `12/12 OK` URL files + `8/8 OK` network-traffic files):

- **Moderate temporal recall (`55.97%`):** On the `1,881`-URL time-split temporal evaluation (`1,404` negative / `477` positive, confusion `[[1303, 82, 19], [97, 113, 267]]`, `83.47%` accuracy, `1.35%` FPR, `0.93168` ROC-AUC), `97/477` (`20.34%`) positive URLs were misclassified as `LEGITIMATE` and `113/477` as `UNCERTAIN`. Do **not** report temporal evaluation as 100% phishing detection.
- **Separate holdout sets:** General Holdout (`200`: `99.50%` acc, `100%` recall, `0%` FPR) and Indian Holdout (`75`: `100%` acc) are separate synthetic/curated evaluation slices and must not be merged with temporal results or cited as proof of universal real-world detection.
- **Benign abstentions:** `2/79` benign stress-test URLs (`zoom.us` and `localhost:8000`) fell into `UNCERTAIN` (still `0/79` `SCAM` false positives).
- **Offline lexical-only boundary:** Without DNS, WHOIS, TLS certificate inspection, or HTML retrieval, compromised legitimate websites lacking structural/brand anomalies are inherently difficult to distinguish, and offline typosquat checks intentionally inspect distinctive `>= 5`-character brand stems only (excluding 3-character stems such as `sbi`, `bob`, `pnb` to avoid everyday word false positives).
- **Scoped offline/network-traffic evidence:** While `4/4` URL + Llama runs completed (`ACCEPTED`, `1,409,328 KB` / ~`1.34 GiB` max RSS, `0` swap, `throttled=0x0`), the `45 s` Chromium-terminated `tcpdump` capture (`0` packets in `edgeshield_no_chromium.pcap`), `capture_control.pcap` (`5` packets verifying capture), and `strace` check (`0` `socket()`, `connect()`, `sendto()`, `recvfrom()` matches) show no observed packets or monitored calls in those specific runs—they do **not** establish global network disablement or prove every execution path is permanently incapable of network access.

---

## 3. Pillar 3 — Network Traffic Anomaly & Intrusion Detection (`NetDetectorV1`, Phase 2 Plan)

Per project scope, Network Traffic Anomaly & Intrusion Detection (`--mode net`) is **designed as a Phase 2 blueprint (`NOT_IMPLEMENTED`)** documented in [docs/NETWORK_TRAFFIC_PLAN.md](NETWORK_TRAFFIC_PLAN.md):

- **Zero code implemented in Phase 1:** `NetDetectorV1`, `libpcap`/`NFStream` C-ring capture, and `models/net_detector_v1.json` do not exist on `main`. All throughput, `< 0.5 ms` per-flow latency, `< 0.5%` LAN FPR, and `M1–M4` items are **planned design targets**, not measured Phase 1 results.
- **No Deep Packet Inspection (DPI) / TLS decryption:** By privacy-first design (`snaplen=96`, L3/L4 bidirectional flow headers only), the planned detector cannot inspect encrypted HTTP/QUIC application payloads.
- **Placement & privilege prerequisites:** Live multi-device LAN monitoring requires router/switch port-mirroring and `CAP_NET_RAW` / `root` capability (offline `.pcap` audit mode runs unprivileged).
- **Human-in-the-loop containment only:** Autonomous `iptables` blocking is excluded to prevent attackers with spoofed source IPs from causing self-DoS lockouts.
- **Pending local calibration:** Threshold tuning against Indian broadband/CGNAT (`100.64.0.0/10`), UPI polling, WebRTC calls, and mDNS/SSDP traffic awaits a consented Indian lab VLAN collection campaign.
