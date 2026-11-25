# Source register

Last verified: **19 November 2026**, Asia/Calcutta (initial capture 15 November 2026). A source being available does not prove that EdgeShield implements it. Runtime and dataset findings are maintained in [SOURCES_RUNTIME.md](SOURCES_RUNTIME.md) and [SOURCES_DATA.md](SOURCES_DATA.md); read these alongside this register.

## Official competition source and mentoring guidance

- **Public challenge portal:** [Bharat AI-SoC Challenge 2026–27](https://arm-education.github.io/Arm-Developer-Labs/Bharat_AI_SoC_2026_27.html), re-verified on **19 November 2026**.
  - **VERIFIED:** Phase 1 (Open Qualifying) submission deadline is **23 November 2026** (Phase 2 PoC deadline 5 February 2027; Finals 15–16 February 2027). The team's 22 November target is an internal buffer.
  - **VERIFIED:** Deliverables include source code, a working application, a demonstration video, and a technical report; hosting on GitHub and submission through the official challenge form are required.
  - **VERIFIED:** PS3 requires on-device Llama-family advisory/reasoning through ExecuTorch on Arm without cloud dependency. Listed hardware explicitly includes Arm Linux devices and **Raspberry Pi 5** (CPU-only Pi 5 is covered).
  - **VERIFIED:** The broad written PS3 description mentions network anomaly/intrusion analysis, phishing URLs, scam communications, explanations, recommendations, and local processing.
- **Supplied PS3 mentoring guidance (slides 03 and 11):**
  - **VERIFIED (team-supplied mentoring slides 03 and 11):** Recommend delivering one complete, testable on-device security workflow and explicitly name **scam SMS** as a valid primary Phase 1 scenario. Standalone phishing URL classification, network intrusion detection, and malware analysis are accordingly scoped as future work.
- **Account-only / form-specific checks (`UNVERIFIED — TEAM LEAD ACTION`):**
  - Exact submission form field names, character limits, allowed report file format (Markdown vs. PDF), video length/hosting/upload limits, repository/video visibility rules, judging weights, and team/college nomination/faculty mentor form fields require portal inspection by the team lead. Do not invent them.

## Evidence labels

- **VERIFIED:** directly inspected source or executed measurement, with its evidence path.
- **OPERATOR-REPORTED:** observed on device by the team/Pi operator (e.g., console output) before raw artifact files are copied into the workspace and audited.
- **REASONED:** engineering decision or inference; validation still required where applicable.
- **UNVERIFIED / MISSING:** missing source, permission, artifact, or experiment.

For execution status use `PASSED`, `VERIFIED`, `OPERATOR-REPORTED`, `MISSING`, `FAILED`, `PENDING_PARTICIPANTS`, `BLOCKED`, or `NOT_IMPLEMENTED`. A documented command is not evidence that it executed. A host test is not a Pi test. Checksum identity checks integrity, not source authenticity.
