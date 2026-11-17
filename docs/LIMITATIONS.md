# Limitations and release blockers

## Mandatory external dependencies

- **`PENDING_HARDWARE` (Raspberry Pi 4):** Physical Pi 4 hardware is not yet connected. Arm on-device execution, Cortex-A72 runtime latency, peak device memory, sustained thermals, and disconnected `strace` offline proof cannot be certified on the x86_64 Ubuntu host. *(Bookworm-compatible `GLIBC <= 2.34` `aarch64` runner binaries, `.pte`, and `tokenizer.model` are now built and staged under `models/llama/` on Ubuntu.)*
- **`PENDING_PARTICIPANTS` / `BLOCKED` (Human reviews & studies):** Independent human label review of the synthetic V2 corpus and the 5-person clarity study (`docs/CLARITY_STUDY_INSTRUMENT.md`) remain unexecuted.
- **`UNVERIFIED` (Scope & eligibility):** Organiser confirmation of Raspberry Pi 4 eligibility under "Arm-based Linux devices" and SMS-only Phase 1 scope against the full PS3 capability description remains unresolved.

## Detection limits

- **Preserved V1 failure (`FAILED`, archived):** V1 detected only `1/12` synthetic scams and `0/6` Hinglish scams (`docs/DETECTOR_FINDINGS.md`).
- **V2 synthetic holdout limits (`VERIFIED`):** On the 120-case fresh synthetic test (`results/host/v2/heldout_evaluation.json`, reproduced bit-for-bit on Ubuntu in `results/host/ubuntu/v2_reproduction.json`), V2 caught `50/60` scams (`26/30` English, `24/30` Hinglish) with `1/60` false alarm (`v2h066`), but assigned **`LEGITIMATE` to 10/60 scams** with `0` abstentions (`thresholds: [0.25, 0.275]`).
- **Domain shift & proxy labels:** UCI spam/ham and AI-assisted synthetic Indian/Hinglish messages do not establish real-world Indian SMS fraud accuracy. Scores are not calibrated real-world probabilities.
- **Keyword cues:** Indicators are lexical cues (`BANK_IMPERSONATION`, `KYC_IMPERSONATION`, `LINK_PRESENT`, etc.), never proof of sender identity, fraud, or malicious URL destinations.

## Explanation & runtime limits

- **Narrow controlled grammar:** The validator accepts only exact band prefixes plus at most one supported indicator sentence (`validator.py`). The 1-shot prompt achieves `100%` acceptance on synthetic evidence (`432/432` dev, `132/132` holdout, `20/20` comparison) by steering the 1B SpinQuant model to emit an approved `WHY:` line rather than open-ended prose. Passing validation proves wording compliance, not truth of the detector's verdict.
- **Subprocess memory & cold load latency:** Each `ExecuTorchAdvisor` call spawns `llama_main`, hashing artifacts and loading the `1.07 GB` `.pte` (`~1.6 s` load, `~3.43 s` median total wall time, `~1.59 GiB` child peak RSS on Ubuntu x86_64). Pi 4 latency could be substantially higher; `--advisory-policy elevated` can skip Llama on clean low-risk messages while `always` preserves full Llama coverage.

## Deployment and privacy limits

- SHA-256 manifests verify file integrity against a trusted manifest, not source authenticity against a compromised host.
- The no-history policy applies to EdgeShield application storage; OS swap, shell history, terminal scrollback, and crash dumps remain outside application guarantees.
- Normal inference makes no network calls by design, but formal `strace -f -e trace=network` offline certification must execute on the disconnected Pi 4.

## Deferred capabilities

- Independent phishing URL classification, network intrusion detection, malware behavior analysis, call filtering, automatic inbox integration, and a GUI dashboard remain `NOT_IMPLEMENTED`.

## Readiness gate

- Do not claim competition readiness while physical Pi 4 execution, offline device trace, demo video, clarity study, and human label review remain open. Use `submission/CHECKLIST.md` and `docs/ARGON_COMPLETION_REPORT.md` as the factual status gate.
