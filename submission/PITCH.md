# Two-minute pitch

Use the bracketed delivery note to choose truthful wording for the actual demo state; do not read it aloud.

“A message says your account will be blocked. Another contains a routine one-time password. Both mention banking, but the right response may be very different.

EdgeShield is our SMS-first safety assistant. A person pastes the message they want to inspect. An independent detector produces a score, a decision band, and observable indicators in under a millisecond on our host machine. If the evidence is unclear, the system can abstain.

Our design separates detection from explanation. The advisory model never receives the raw message. It receives only approved structured evidence, such as a decision band and fixed indicator IDs. By framing the 1-billion-parameter SpinQuant Llama model defensively and prioritizing high-salience cues, we raised strict validator acceptance from 11 percent to 100 percent across 564 synthetic evidence configurations and a 20-case comparison study on our Linux host. Any unaccepted output falls back to a clearly labelled template, and security advice always comes from fixed application logic.

[If Pi 4 lab tests are verified:] In this demonstration, Llama runs through ExecuTorch on the Raspberry Pi 4 Arm CPU. We show the actual device, measured performance, and a disconnected run with network-call inspection.

[If still host-only before the lab visit:] On our Ubuntu Linux host, genuine ExecuTorch SpinQuant inference, Bookworm-compatible `aarch64` cross-compilation, and 176 automated tests are verified end-to-end. Physical Raspberry Pi 4 execution, offline device tracing, and sustained hardware benchmarks are scheduled for our lab visit and remain open compliance gates.

Our evaluation separates public spam data from authored Indian and Hinglish examples. The first baseline failed, and we preserved that result. V2 passed its synthetic checks: fifty of sixty scams detected, including twenty-four of thirty Hinglish scams, with one false alarm. Ten scams were still assigned lower risk, and independent human label review remains open. Independent URL, network, and malware detection are outside this Phase 1 implementation.

EdgeShield's contribution is a clear boundary between detection, explanation, and action, with local processing and visible uncertainty.”
