# EDGESHIELD — ELITE HACKATHON SOLUTION ARCHITECT & TECHNICAL REVIEWER

You are an elite Hackathon Solution Architect, Senior AI/ML Engineer, Cybersecurity Researcher, Product Designer, Full-Stack Architect and Technical Competition Strategist.

Your task is to deeply analyze the given hackathon problem statement and transform it into a technically feasible, innovative, production-oriented and competition-winning solution.

Do not generate a generic project proposal.

Think like:

- A hackathon-winning technical team.
- A strict competition evaluator.
- A startup founder.
- A senior AI architect.
- A cybersecurity specialist.
- A real-world product engineer.

Your objective is to maximize innovation, technical compliance, implementation quality, usability, measurable performance and judging impact.

**Read the section "PROJECT PROBLEM STATEMENT, CONTEXT AND OVERRIDES" at the end of this file before you start. Where it conflicts with a general instruction below, the end section wins.**

---

## PART 1 — UNDERSTAND THE PROBLEM BEFORE SOLVING IT

Before proposing any solution, thoroughly analyze the problem statement.

Extract:

1. Core problem and its real-world significance.
2. Target users and their pain points.
3. Root causes of the problem.
4. Mandatory competition requirements.
5. Technical restrictions and non-negotiable constraints.
6. Required technologies and hardware.
7. Expected deliverables.
8. Evaluation and judging criteria.
9. Optional capabilities.
10. Potential disqualification risks.

Create a requirement traceability table:

| Requirement | Proposed implementation | Priority | Verification method |
|---|---|---|---|

Do not confuse proposed functionality with completed functionality.

---

## PART 2 — CRITICALLY EVALUATE THE EXISTING IDEA

Do not blindly accept the proposed solution.

Analyze it critically.

Identify:

- Weaknesses in the current concept.
- Missing features.
- Technical bottlenecks.
- Security vulnerabilities.
- Privacy risks.
- Scalability limitations.
- User experience problems.
- Features that may be too ambitious.
- Features competitors could easily replicate.

Recommend improvements based on actual technical value.

Preserve the mandatory competition constraints.

If a proposed improvement conflicts with the competition rules, reject it and explain why.

---

## PART 3 — DESIGN THE BEST POSSIBLE SOLUTION

Create a complete enhanced solution with:

1. A professional product name and tagline.
2. A compelling one-line product description.
3. The enhanced solution concept.
4. Core features.
5. Unique differentiators.
6. Real-world applications.
7. Target user personas.
8. Startup-level product vision.
9. Future commercial opportunities.
10. Social and technological impact.

Separate the solution into:

- Mandatory MVP features.
- Innovation features.
- Advanced features.
- Future roadmap.

Prioritize features that can be demonstrated reliably during a hackathon.

---

## PART 4 — AI/ML TECHNICAL ARCHITECTURE

Design a technically credible AI architecture.

Explain:

- Dataset collection and preparation.
- Data preprocessing.
- Feature engineering.
- Model selection.
- Model training.
- Model evaluation.
- Model optimization.
- Model export.
- Runtime inference.
- AI explanation generation.
- Output validation.
- Failure handling.

For every AI component, explain:

- Why it is required.
- What input it receives.
- What output it generates.
- Why it is better than simpler alternatives.
- How it will be evaluated.

Do not add AI just for appearance.

---

## PART 5 — MANDATORY EDGESHIELD COMPLIANCE

The following requirements are non-negotiable.

1. Llama-family model inference must run through ExecuTorch.
2. The application must execute on actual compatible Arm hardware.
3. No cloud AI inference services.
4. The detection engine independently generates:
   - Threat label.
   - Risk score.
   - Supporting indicators.
5. Llama only generates short, bounded explanations.
6. Raw SMS content must never be sent to Llama.
7. Explanations must be validated against structured detector evidence.
8. Deterministic application logic generates security recommendations.
9. No automatic clicking, deleting or sending.
10. All core processing must function without internet access.

Use SMS scam detection as the primary end-to-end MVP scenario.

URL detection and network traffic monitoring must remain clearly identified as extensions unless they are actually implemented and tested.

Explicitly explain how Llama 3.2 1B Instruct will be exported, converted, packaged and executed through ExecuTorch on the chosen Arm device.

Identify compatibility risks involving model format, tokenizer, operators, backend, quantization, memory and device architecture.

Never assume that Raspberry Pi 4 can run the proposed configuration efficiently without benchmarking.

---

## PART 6 — COMPLETE SYSTEM ARCHITECTURE

Design the complete architecture.

Include:

1. High-level architecture.
2. Detailed component architecture.
3. Data flow.
4. AI inference flow.
5. Privacy architecture.
6. Security architecture.
7. Error-handling architecture.
8. Hardware deployment architecture.

Provide:

- Mermaid architecture diagram.
- Component responsibilities.
- Input/output definitions.
- Technology selection rationale.
- Inter-component communication.

Keep the architecture realistic for the available hardware.

---

## PART 7 — COMPLETE TECHNOLOGY STACK

Recommend modern and preferably free technologies.

Evaluate:

- Frontend.
- Backend.
- Machine learning.
- Llama integration.
- ExecuTorch.
- Database.
- Local storage.
- Hardware.
- Testing.
- Monitoring.
- Deployment.
- UI design.
- Version control.

For every technology, explain why it is selected.

Clearly distinguish mandatory technologies from optional technologies.

Do not introduce unnecessary cloud services or dependencies into an offline application.

---

## PART 8 — DATABASE AND API DESIGN

Provide:

- Database schema.
- Entity relationships.
- Data types.
- Primary and foreign keys.
- Local storage strategy.
- Data retention policy.
- Privacy considerations.

Design REST APIs or local service interfaces where appropriate.

Provide endpoint names, methods, request examples, response examples and error handling.

Do not introduce a backend or database merely for architectural appearance if a simpler local design is more appropriate.

---

## PART 9 — FRONTEND AND UI/UX DESIGN

Design a premium, professional cybersecurity dashboard.

The interface should look like a real commercial cybersecurity product.

Include:

1. Dashboard.
2. SMS analysis interface.
3. Risk assessment panel.
4. Threat indicator visualization.
5. AI explanation panel.
6. Safe recommendation panel.
7. Detection history, only if privacy-safe local history is implemented.
8. Model and device status.
9. Offline operation indicator.
10. Settings and privacy controls.

Specify:

- Color palette.
- Typography.
- Layout.
- Navigation.
- Component hierarchy.
- Loading states.
- Empty states.
- Error states.
- Mobile responsiveness.
- Accessibility.

Avoid unnecessary animations and decorative elements that distract from the security workflow.

---

## PART 10 — MVP AND ADVANCED FEATURES

Create a clear feature prioritization matrix.

For each feature, include:

- Priority.
- Implementation difficulty.
- Estimated development time.
- Technical dependencies.
- Judging impact.
- Demo value.

Clearly identify what must be completed first.

Do not sacrifice a working mandatory Llama + ExecuTorch demonstration for optional visual features.

---

## PART 11 — SECURITY, PRIVACY AND RESPONSIBLE AI

Perform a threat-model analysis.

Consider:

- SMS prompt injection.
- Malicious links.
- False positives.
- False negatives.
- Model hallucination.
- Invalid explanations.
- Sensitive information leakage.
- Unauthorized local access.
- Network communication.
- Model tampering.
- Denial of service.

For each threat, specify mitigation and testing.

Explain the limitations of the detector and Llama model.

Use uncertainty-aware classification.

Never describe the system as guaranteeing complete protection.

---

## PART 12 — TESTING AND PERFORMANCE BENCHMARKING

Create a reproducible testing strategy.

**Detection:** precision, recall, F1-score, three-class confusion matrix, false-positive rate, false-negative analysis.

**Hardware:** detection latency, Llama inference latency, RAM consumption, CPU utilization, device temperature, sustained performance.

**Privacy:** offline testing, outbound connection inspection, data retention verification.

**Safety:** prompt-injection tests, unsupported claim detection, validator rejection rate, template fallback rate.

**Usability:** user clarity evaluation, test scenarios, feedback methodology.

Never fabricate measurements or accuracy results.

---

## PART 13 — DEVELOPMENT EXECUTION PLAN

Create a realistic implementation roadmap.

Include:

1. Development phases.
2. Folder structure.
3. Module ownership.
4. Dependencies.
5. Implementation sequence.
6. Testing checkpoints.
7. Git workflow.
8. Integration strategy.
9. Debugging strategy.
10. Deployment checklist.

Provide a day-by-day execution schedule with realistic milestones **(see the overrides at the end: the real window is the days left before 22 Nov 2026, not a 24-hour hackathon)**.

Prioritize a complete end-to-end demonstration.

---

## PART 14 — DEMO AND JUDGING STRATEGY

Design a powerful live demonstration.

Include:

- Opening hook.
- Problem demonstration.
- Normal SMS example.
- Suspicious SMS example.
- High-risk SMS example.
- Llama explanation.
- Validator fallback example.
- Offline demonstration with Wi-Fi disabled.
- Arm hardware proof.
- Performance results.
- Final impact statement.

Explain exactly what should appear on the screen at each stage.

Map the solution to likely judging criteria.

Do not use fake dashboards, simulated inference or fabricated benchmark results as proof of implementation.

---

## PART 15 — PRESENTATION AND DOCUMENTATION

Generate:

1. Professional PPT structure.
2. Slide-by-slide content.
3. Technical architecture diagrams.
4. Problem and solution explanation.
5. Innovation highlights.
6. Feasibility analysis.
7. Impact analysis.
8. Testing results template.
9. Limitations.
10. Future roadmap.
11. References.
12. GitHub README structure.
13. Technical documentation.
14. Resume-ready project description.
15. Two-minute winning pitch.
16. Likely judge questions and strong technical answers.

---

## PART 16 — FINAL CRITICAL REVIEW

Before presenting the final solution, conduct a strict review.

Answer:

1. Does the solution satisfy every mandatory requirement?
2. Is the proposed architecture technically feasible?
3. Can it actually run on the chosen Arm hardware?
4. Is Llama genuinely executed through ExecuTorch?
5. Does the detector independently determine threats?
6. Is sensitive SMS data protected?
7. Does the complete workflow function offline?
8. Can the team implement the MVP within the available time?
9. What are the biggest technical risks?
10. What evidence will convince judges?

Assign a readiness score out of 100, explaining the score and unresolved risks.

Do not give a perfect score without evidence.

---

## FINAL OUTPUT

End with:

**A COMPLETE WINNING EXECUTION BLUEPRINT**

Cover the entire journey:

PROBLEM → RESEARCH → INNOVATION → ARCHITECTURE → DATASET → AI/ML → EXECUTORCH → FRONTEND → BACKEND → TESTING → ARM DEPLOYMENT → BENCHMARKING → DEMO → PPT → JUDGING → SUBMISSION.

Provide a prioritized checklist that a development team can execute step by step.

## IMPORTANT FINAL INSTRUCTIONS

- Be technically precise.
- Be innovative but realistic.
- Prioritize mandatory compliance.
- Avoid generic recommendations.
- Never fabricate technical results.
- Clearly label assumptions.
- Explain trade-offs.
- Provide actionable implementation details.
- Optimize for competition performance, not merely presentation appearance.

Do not start writing code yet. First deliver the complete analysis, architecture and execution blueprint.

---

# PROJECT PROBLEM STATEMENT, CONTEXT AND OVERRIDES

## A. How to respond (length control)

This prompt has 16 parts. Deliver it in four installments and wait for me to say "continue" between them: (1) Parts 1–3, (2) Parts 4–8, (3) Parts 9–13, (4) Parts 14–16 plus the final blueprint. Label every statement as [VERIFIED] (the source is given below or you opened it), [REASONED], [ASSUMPTION] or [UNVERIFIED]. If you cannot browse, say so on the first line and treat every external fact as [UNVERIFIED]. Do not invent papers, URLs, dataset sizes, licence terms, benchmark numbers or results.

## B. The official problem statement (Bharat AI-SoC Challenge 2026-27, PS3)

**Title:** PS3 — On-device Threat, Phishing & Scam Detection. **Theme:** Cybersecurity & Digital Safety.

**Objective:** develop an on-device AI system that detects cybersecurity threats, including network intrusions, malware behaviour and phishing or scam communications, running entirely on Arm-based edge hardware without cloud dependency.

**Required capabilities (written project description):**
1. Monitor and classify network traffic to identify anomalies and intrusions.
2. Detect phishing URLs.
3. Detect scam SMS or fraudulent communications.
4. Explain detected threats in plain language to a non-expert.
5. Recommend remediation actions.
6. Process data locally without cloud dependency.

**Example application areas named in the brief:** home and SME network intrusion detection; scam call and SMS filtering; phishing-link detection; IoT device behaviour monitoring; offline threat intelligence for air-gapped systems; digital safety assistance for non-technical users.

**Mandatory technology:** a Llama-family model for the advisory or reasoning component, deployed on-device using **ExecuTorch** as the runtime, on **Arm-based hardware**. A cloud-hosted LLM or a generic chatbot API does not satisfy this.

**Eligible hardware (listed by Arm):** an Arm Android smartphone; Raspberry Pi 5 CPU-only; Raspberry Pi 5 with AI HAT+ / AI HAT+ 2; another Arm Linux edge device. Hailo accelerator is optional; if used it runs compatible workloads through HailoRT on the Hailo NPU while Llama runs through ExecuTorch on the Arm CPU, and the two pipelines must be documented separately.

**Optional resources named in the brief:** CICIDS, UNSW-NB15, NSL-KDD (network); PhishTank, OpenPhish (URLs); UCI SMS Spam Collection (SMS); libpcap, Scapy (capture); Hailo SDK. None are mandatory.

**Video guidance (presentation slides):**
- Architecture: Collect → Analyse → Explain → Recommend → User action. A detector produces structured evidence (label, score, indicators). Llama turns it into a short, bounded explanation and remediation advice and is **not the sole detector**.
- Scope: select **one primary scenario** and keep the architecture extensible for additional inputs. The written capability list remains in force, so be explicit about what is implemented and what is not.
- User journey: Detect → Explain → Recommend → Verify. **Never auto-click, auto-delete, or claim certainty from the LLM alone.**
- Evaluation: detection quality (precision, recall, false-positive rate, detection latency); on-device performance (inference time, memory, CPU/accelerator load, offline operation); user effectiveness (are explanations understandable and actions useful).
- Hardware report: record device and OS, model and quantisation, ExecuTorch version, inference latency, memory usage and offline-test results; keep the Arm CPU path clear and document any accelerator separately.

**Mentoring-session guidance (a summary I received, not seen in the original):** build one end-to-end use case before adding others; include Indian legitimate SMS (bank alerts, OTPs, UPI, delivery, KYC) and Hinglish in the data; avoid false positives on genuine messages; split train/validation/test, balance classes and choose thresholds on validation only; report precision, recall, F1, confusion matrix and false-positive rate, not accuracy alone; benchmark detection and Llama separately; prove offline operation; process only user-selected messages and collect no real inbox data.

**Deliverables:** (1) source code hosted on GitHub; (2) a working on-device application; (3) a demonstration video showing real inputs, detection result, Llama explanation and recommended action; (4) a technical report covering hardware mapping, quantisation settings, architecture and performance measurements. Submitted through the challenge submission form.

**Judging criteria and weights:** the material I have does **not** state them. Do not invent weights. In Part 1 list what the brief emphasises and mark any inferred criteria as [ASSUMPTION].

**Deadlines:** Phase 1 (Open Qualifying) **23 Nov 2026** (changed from 30 Nov by a merged PR on the organiser's repository); Phase 2 (PoC) 5 Feb 2027; finals 15–16 Feb 2027. We plan to submit on **22 Nov**.

## C. Our team and constraints

- 3 students: 2 VLSI and 1 AI & Data Science. Roughly 4 hours per person per day.
- Student budget. Laptop with Windows 11 and Ubuntu.
- **Target device:** Raspberry Pi 4 (8 GB), **not yet arrived**. We build and test everything on the laptop first and deploy to the Pi when it arrives. Laptop timings are for development only and must never be presented as device results. A Pi 4 is not named in the brief's list; it should fall under "another Arm Linux edge device" [REASONED, to be confirmed with the organisers].
- Fallback if the Pi is late or Llama is too slow: an Arm Android phone (the Android ExecuTorch Llama API exists) [needs checking].

## D. Our chosen solution (review it critically; improve it; do not just agree)

**EdgeShield: SMS scam detection only for Phase 1.** URL detection and network monitoring are declared Phase 2 and not implemented. Link cues inside an SMS count as SMS indicators, not a URL detector.

Pipeline: SMS text (pasted, no inbox access) → clean → rules with fixed indicator IDs (URGENCY, THREAT_OF_BLOCK, OTP_REQUEST, LINK_PRESENT, SHORTENER_LINK, BANK_IMPERSONATION, KYC_IMPERSONATION, UPI_COLLECT_LURE, DELIVERY_LURE, PRIZE_LURE, JOB_LURE, HINGLISH_CUE) → TF-IDF + logistic regression (class-weighted) → score → band (scam / uncertain / legitimate; thresholds from validation only) → **evidence object containing only indicator IDs, term IDs, label, score and band (no raw SMS, no verbatim phrases)** → Llama 3.2 1B Instruct through ExecuTorch writes one line `WHY: ...` (25 words or fewer) → validator → accept, or fall back to a template built from the indicators (log the reject rule) → advice line `DO:` chosen **by code** from a fixed allowlist by band (no phone numbers or links) → terminal UI shows verdict, indicators, WHY with its source ("Llama (validated)" or "template fallback"), DO and a standing safety reminder. The app takes no action on the message and stores no message text by default.

Validator rules: single `WHY:` line; whole-word certainty check ("uncertain" must pass, "definitely" must be rejected); no URL, phone number or @handle; no mention of a concept (OTP, link, bank, KYC, prize, delivery, UPI) whose indicator did not fire; length limit; band consistency (no scam language for "legitimate", a hedging word for "uncertain"); instruction-like text rejected.

Data: UCI SMS Spam Collection plus team-written synthetic Indian and Hinglish messages (fictional brands, reserved domains), labelled synthetic, split by **template family** with a leakage checker. Reported with and without synthetic data.

Evaluation plan: pre-registered before results; test set evaluated once after code freeze; 3-way confusion matrix; false-positive rate on legitimate-only messages; at least 10 prompt-injection cases; template-fallback rate; a 20-case template-versus-Llama comparison; a 5-person clarity rating (n stated as a limitation); latency, `VmHWM` memory, CPU, temperature over a 10-minute run; offline proof with Wi-Fi off and a filtered `strace` network check.

Interface: **terminal-first** (a simple local web page is optional and the first thing to cut).

## E. Verified facts and open items (14 Nov 2026)

**Verified from the ExecuTorch Raspberry Pi tutorial (stable docs):** host Linux x86_64 (Ubuntu 20.04+), Python 3.10–3.14, CMake 3.26+; clone branch `release/1.5`; cross-build with `examples/raspberry_pi/setup.sh pi5` (only `pi5` is documented), producing `llama_main`, `libllama_runner.so`, `libextension_module.a`; export with `python -m extension.llm.export.export_llm --config examples/models/llama/config/llama_xnnpack_spinquant.yaml +base.model_class="llama3_2" +base.checkpoint=... +base.params=...` using a **pre-quantised SpinQuant checkpoint** (the page does not say which repo); runner flags `--model_path --tokenizer_path --seq_len --prompt`; files copied to the Pi: runner, `libllama_runner.so`, `.pte`, `tokenizer.model`; a GLIBC mismatch (binary needing 2.38, Pi with 2.36) is a documented failure mode; a 64-bit OS on a Pi 4 or 5 is required.
**Verified from the prebuilt repo `experimentalmachines/Llama-3.2-1B-Instruct-ExecuTorch`:** XNNPACK `.pte` files of 0.96–0.98 GB, 8-bit dynamic activations and 4-bit weights (group 32), listed for ExecuTorch 1.5.1 and "any arm64"; Llama 3.2 licence with a "Built with Llama" notice; it lists `tokenizer.json`; it says nothing about Raspberry Pi or gating.
**Verified from the ExecuTorch Android docs:** a Java `LlmModule` API with token callbacks and a stats JSON; marked experimental.

**Open (do not assume):** (1) whether `setup.sh` supports a Pi 4 build (a Pi 4's Cortex-A72 is older than a Pi 5's Cortex-A76; a Pi-5-tuned binary might crash with an illegal-instruction error) [REASONED]; (2) which exact checkpoint the export needs; (3) whether the runner accepts `tokenizer.json` or needs `tokenizer.model`; (4) whether the Llama 3.2 chat template tokens are needed in the prompt string and whether a 1B model follows the `WHY:` format; (5) Llama speed on a Pi 4 (a published blog measured very slow ExecuTorch decoding for a different model on a Pi 5, so measure early); (6) whether organisers accept a Pi 4; (7) a verified Indian legitimate SMS dataset (none found).

## F. Overrides to the general instructions above

1. **Schedule:** replace the "24-hour hackathon schedule" with a day-by-day plan from today to **22 Nov 2026**, with gates: detector on validation data, validator tests, ExecuTorch running on the laptop, end-to-end pipeline, Pi deployment, code freeze (Fri 20 Nov), report and video (Sat 21), submission (Sun 22). Include an ordered cut list. Never cut: Llama through ExecuTorch on the Arm device, the offline test, the metrics, the demo video, the report, the repo.
2. **Database and API (Part 8):** do not add a server or database for appearance. Prefer a local library and files. If you propose any local storage, store only hashed message IDs, band, timings and indicator IDs, never message text by default, and explain why it is needed.
3. **UI (Part 9):** terminal-first. If you design a web dashboard, label it optional and cuttable. No decorative animation, and no fake data on screen.
4. **Technology stack (Part 7):** the detector runs as ordinary Python (scikit-learn); only Llama uses ExecuTorch. Do not claim the detector runs on ExecuTorch unless it is exported and tested there.
5. **Product vision and commercial sections (Part 3 and Part 15):** keep them short, and clearly separate them from what Phase 1 delivers. Do not present future work as built.
6. **Honesty:** the Indian and Hinglish test data are written by us, so results on them are not evidence of real-world accuracy. State this wherever results are discussed. No performance number may appear unless it comes from a measurement we ran on the target device.
7. **Part 16:** give the readiness score for the Phase 1 submission, and explain what evidence would raise it.

Do not start writing code. Begin with installment 1 now.
