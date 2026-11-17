# Source register

Access date: **15 November 2026**, Asia/Calcutta. A source being available does not prove that EdgeShield implements it. Runtime and dataset findings are maintained in [SOURCES_RUNTIME.md](SOURCES_RUNTIME.md) and [SOURCES_DATA.md](SOURCES_DATA.md); read these alongside this register.

## Official competition source

[Bharat AI-SoC Challenge 2026–27](https://arm-education.github.io/Arm-Developer-Labs/Bharat_AI_SoC_2026_27.html), accessed directly on the date above.

- **VERIFIED:** Phase 1 deadline is 23 November 2026. The team's earlier 22 November submission target is an internal decision.
- **VERIFIED:** PS3 includes network anomaly/intrusion analysis, phishing URLs, scam communications, explanations, recommendations and local processing.
- **VERIFIED:** Llama must provide on-device advisory/reasoning using ExecuTorch. Listed hardware includes Arm Linux devices and Raspberry Pi 5.
- **VERIFIED:** Deliverables include source, application, demo video and technical report; hosting on GitHub and submission through the challenge form are required.
- **VERIFIED:** The page links a PS3 mentoring video. Its contents have not been independently reviewed here.
- **UNVERIFIED:** Raspberry Pi 4 has not been explicitly approved by an organiser for this entry. Its eligibility under Arm Linux devices is a **REASONED** interpretation.
- **UNVERIFIED:** SMS-only Phase 1 scope has not been explicitly approved. The full written capability list remains a compliance risk.
- **UNVERIFIED:** Judging weights and submission-form field limits have not been established. Do not invent them.

## Project inputs

`EDGESHIELD_ARCHITECT_PROMPT.md` and the user's attached master build prompt were read. The master prompt requests immediate implementation; its workflow supersedes the older document's proposal-only installments. Project privacy, terminal-first and hardware-honesty constraints are retained.

The mentoring summary inside the architecture prompt is **USER-SUPPLIED, NOT INDEPENDENTLY VERIFIED**. The project nevertheless adopts its conservative practices: independent detection, evidence-only explanations, validation-only threshold selection and explicit offline tests.

## Evidence labels

- **VERIFIED:** directly read source or executed measurement, with its evidence path.
- **REASONED:** engineering decision or inference; validation still required where applicable.
- **ASSUMPTION:** planning premise, such as Pi arrival before the internal deadline.
- **UNVERIFIED:** missing source, permission, artifact or experiment.

For execution status use `PASSED`, `FAILED`, `PENDING_HARDWARE`, `BLOCKED`, or `NOT_IMPLEMENTED` in the root status tracker. A documented command is not evidence that it executed. A host test is not a Pi test. Checksum identity is not proof of artifact trustworthiness.

## Questions for the team to resolve

1. Obtain organiser confirmation of Pi 4 eligibility and SMS-only Phase 1 scope.
2. Confirm lawful access to the selected Llama checkpoint and tokenizer; retain applicable notices.
3. Check the actual submission form, team nomination and mentor requirements before uploading.
4. Review the linked mentoring session directly if relying on its scope guidance.
5. Record every resolved question with date, source and resulting implementation change.
