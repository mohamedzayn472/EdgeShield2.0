# Demo video script

Target duration: approximately three minutes, adjusted to the actual form's limit once verified. This is a script, not evidence that the described recording exists.

**0:00–0:20 — Problem and scope.** “EdgeShield helps people inspect suspicious SMS locally. Our Phase 1 prototype focuses on pasted SMS. Independent URL, network and malware detection are not implemented.” Show title and actual terminal.

**0:20–0:40 — Device and runtime.** Show the physical Arm device, diagnostics and runtime manifest. Say “Llama runs through ExecuTorch on the Arm CPU” only after actual successful execution. Identify detector runtime separately. If this is only a laptop recording, say that explicitly and disclose the missing compliance gate.

**0:40–1:25 — Real inputs and detection.** Run `bash deploy/pi4/smoke_test.sh` (or `bash scripts/run_demo_ubuntu.sh --llama` if recording a clearly labelled host preview) and/or paste fictional normal and scam examples. Show actual bands, score meaning, indicator descriptions, and cue IDs. Leave misclassifications visible. Explain that indicators are cues and the score is not proof of fraud or authenticity.

**1:25–1:55 — Privacy and explanation.** Show the evidence structure without private content. Point out the validated WHY provenance and deterministic DO advice. “The advisory model receives fixed evidence IDs, not the SMS. Unaccepted responses use a labelled fallback.” Do not rename template output as Llama.

**1:55–2:25 — Offline evidence.** Show disconnected interfaces and the real traced inference. Explain that connectivity state and attempted network calls were checked separately. Display actual trace conclusions only after review.

**2:25–2:45 — Measurements.** Present actual device median/p95 timing, memory and sustained-run result, with repetitions and hardware labels. Omit unavailable numbers; do not substitute host results.

**2:45–3:00 — Limits and next step.** “Our baseline uses spam data and authored Indian/Hinglish tests, so it does not establish real-world fraud accuracy. Our next step is representative evaluation and broader threat inputs.” End with the reviewed source location.
