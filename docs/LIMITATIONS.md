# Limitations and Open Release Blockers (20 November 2026)

## Open Phase 1 release gates

- **`PENDING_HARDWARE` (V3 Pi 5 device verification):** Archived Pi 5 B0 and offline runs measured frozen **V2** (`f37c3dd9060b89ead7ea6bbf1c393b22fff7cfc18ed5d85126e977e03daea6a6`). An authorized offline Pi 5 smoke/demo capture running **V3** (`b2b2126b872c43eb02ccdef41a7f5040cf86cfd0dc1bfb31f98ef13733d50910`) into a new results directory is still required before recommending submission.
- **`MISSING` (On-device demo video):** No actual disconnected Raspberry Pi 5 video recording is present in the workspace. A laptop or template-fallback capture cannot substitute for showing at least one genuine `Llama (validated)` response on the disconnected Pi 5 running the V3 release candidate.
- **`BLOCKED` (Team/portal items):** Root `LICENSE` approval, team/mentor details, account-gated submission form field/limit verification, authorized GitHub publication, and final form submission by **23 November 2026**.

## Hardware and thermal limits (Verified Pi 5 B0)

- **Passive-heatsink thermal throttling (`VERIFIED`):** During the 605.4 s continuous back-to-back B0 benchmark on an open **Raspberry Pi 5 Model B (16 GB, passive heatsink)**, SoC temperature peaked at **83.7 °C** and triggered throttling (`throttled_after=0xe0008`). By contrast, a 5-request burst (`benchmark-short.json`) peaked at `69.95 °C` (`throttled=0x0`). Active cooling is recommended for sustained continuous loads.
- **Cold-load subprocess latency:** Each `ExecuTorchAdvisor` invocation launches `llama_main`, verifies SHA-256 hashes, loads the ~1.00 GiB `.pte` (`~1.22 s` median), runs prefill (`3.20 s` median TTFT), and decodes (`13.49 tok/s` median), producing **6.81 s p95** full-response latency (`1.44 GB` / `1.34 GiB` peak runner RSS, `0 B` swap). Detector verdict and `DO:` advice appear immediately in `<2 ms`. Reaching an internal 2-second latency goal and persistent-runner designs remain ongoing engineering work.

## Detection and evaluation limits

- **Preserved V1 failure (`FAILED`, archived):** V1 (`models/detector.json`, `9163c207...`) detected only `1/12` synthetic scams and `0/6` Hinglish scams (`docs/DETECTOR_FINDINGS.md`).
- **Archived V2 limits (`VERIFIED`, `f37c3dd9...`):** On `120` labeled fresh synthetic messages (`12` ambiguous excluded; `results/host/v2/heldout_evaluation.json`), V2 detected `50/60` scams (`83.33%` recall; `26/30` English, `24/30` Hinglish) with `1/60` false positive (`1.67%` FPR; `1/30` Hinglish `v2h066`), assigned **`LEGITIMATE` to 10/60 scams** (`4` English, `6` Hinglish) with **0 abstentions** (`thresholds: [0.25, 0.275]`), and produced `19/80` false positives (`23.75%` FPR) on `v3_holdout`.
- **Current V3 statistical & coverage limits (`b2b2126b...`, `thresholds: [0.65, 0.75]`):** Across identical-row audits (`results/host/v3/full_v2_v3_regression_audit.json`), V3 introduces `4` regressions vs. V2 on `v2_holdout` (`v2h001`/`v2h017` `UNCERTAIN`; `v2h018`/`v2h079` `SCAM`), `8` on `uci_test` (`3` missed, `5` abstained), and `2` on `indian_sms` test (`24` labeled). In fresh diagnostics, V3 shows false alarms on educational anti-fraud advisories (`0.928` `SCAM` EN, `0.711` `UNCERTAIN` HI) and false reassurance on family-impersonation scams (`0.344`–`0.397` `LEGITIMATE`) and some read-aloud/Hinglish-OV requests (`0.284`–`0.563`) because zero anti-fraud or family-impersonation families exist in `v3_development.jsonl`. Addressing those statistically requires a separate, independently authored **V4** development/calibration/validation/fresh-holdout round.
- **Domain shift & proxy labels:** UCI spam/ham and AI-assisted synthetic Indian/Hinglish messages do not establish real-world Indian SMS fraud accuracy. Scores are not calibrated real-world fraud probabilities.
- **Pending human studies:** Independent human label review of synthetic examples, representative consented real-message evaluation, and the 5-person clarity study (`docs/CLARITY_STUDY_INSTRUMENT.md`, `PENDING_PARTICIPANTS`) remain unfinished.
- **Keyword cues:** Clause-level indicators (`BANK_IMPERSONATION`, `KYC_IMPERSONATION`, `OTP_REQUEST`, `LINK_PRESENT`, etc.) are lexical cues only, never proof of sender identity, fraud, or malicious URL destinations, and never override statistical verdicts.

## Explanation and privacy limits

- **Controlled grammar:** The validator (`src/edgeshield/validator.py`) enforces exact approved band prefixes plus at most one supported cue sentence. Validator acceptance (`91/91` on Pi 5 B0) proves wording compliance against structured `Evidence`, not truth of the detector's underlying risk verdict.
- **OS trust boundary:** SHA-256 manifests verify integrity against a trusted manifest, not source authenticity on a compromised host. EdgeShield's no-history policy applies to application storage; OS swap, shell history, terminal scrollback, and crash dumps remain outside application guarantees.

## Deferred PS3 capabilities (Future scope)

- Aligned with PS3 mentoring slides 03 and 11 (one complete scam SMS workflow for Phase 1), independent phishing URL classification, network intrusion detection, malware behavior analysis, call filtering, automatic inbox integration, and a GUI dashboard remain future scope (`NOT_IMPLEMENTED`).
