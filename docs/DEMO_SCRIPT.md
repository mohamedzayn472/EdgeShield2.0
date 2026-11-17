# Demonstration procedure

Use this as a rehearsal checklist. Do not record a successful Arm/Llama claim until that path has actually passed. Commands and device prerequisites are in [PI4_DEPLOYMENT.md](PI4_DEPLOYMENT.md) and `deploy/pi4/README.md`.

## Before recording

Freeze the code and record artifact hashes. Use synthetic inputs only. Close private windows and notifications. Show the actual device, hardware/OS diagnostics and matched runtime manifest. Check that the application reports real backend status and that the terminal font is readable. Prepare the final metrics from generated result files, not copied slide placeholders. Interactive SMS entry is hidden for privacy; show the fictional example in a separate prepared caption before pasting it, and state that the application does not echo raw SMS.

## Quick launch commands

- **On Ubuntu host (development demonstration, clearly labeled HOST TEST):**
  - `bash scripts/run_demo_ubuntu.sh --llama` runs all 4 built-in English & Hinglish synthetic demo cases end-to-end with genuine `Llama (validated)` explanations (`results/host/ubuntu/demo_ubuntu_llama.txt`).
  - `bash scripts/host_python.sh -m edgeshield.cli --repeat` runs interactive hidden SMS input.
- **On physical Raspberry Pi 4 (lab demonstration):**
  - `bash deploy/pi4/smoke_test.sh` runs preflight verification and the 4-case `--demo` suite with the Pi 4 `aarch64` runner.
  - `bash deploy/pi4/launch.sh --repeat` launches interactive hidden SMS input.

## Live sequence

1. Introduce EdgeShield as an SMS-first prototype. State that network intrusion, malware and independent URL detection are not implemented.
2. Show the Pi 4, 64-bit OS and process startup. Explain that Llama uses ExecuTorch on the Arm CPU while the detector uses Python.
3. Paste a fictional normal OTP notification: `Cedar Bank: Your OTP is 123456. Do not share it with anyone.` Discuss the result actually produced; do not promise a particular band. OTP wording alone does not prove fraud.
4. Paste a fictional pressure message: `Cedar Bank account will be blocked today. Update KYC immediately at https://verify.example/kyc.` Show the actual score, band and cue IDs. Explain that a link cue does not classify the destination.
5. Paste a Hinglish example: `Aapka reward ready hai. Prize lene ke liye abhi processing fee bhejo.` Show limitations honestly if the detector misses it or abstains.
6. Show that verdict and deterministic recommendation appear before the advisory finishes. Show the accepted `WHY:` and its actual provenance. A template response must remain labelled template.
7. Demonstrate validator rejection using a clearly labelled test fixture through the test suite. Do not present a fixture as real model output. Explain the runtime-error fallback without editing displayed results.
8. Disable connectivity and show the interface state. Start the traced offline run, demonstrate genuine ExecuTorch generation and inspect the trace for attempted networking.
9. Show measured device timings, memory and sustained-run evidence. State unavailable metrics explicitly.
10. Close with remaining risks: spam/scam domain shift, synthetic Indian data, incomplete PS3 scope and the need for independent verification of unusual requests.

If Pi or model assets are absent, record only a clearly labelled laptop development demo and disclose the compliance gap. It is not a substitute for the mandatory Arm demonstration.
