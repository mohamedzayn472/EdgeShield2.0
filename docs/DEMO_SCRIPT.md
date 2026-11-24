# Demonstration procedure

Use this as a rehearsal checklist for recording the disconnected **Raspberry Pi 5** Phase 1 demonstration. Commands and device prerequisites are in [PI5_DEPLOYMENT.md](PI5_DEPLOYMENT.md) and `deploy/pi5/README.md`.

## Before recording

- Use the frozen code, frozen default V3 detector (`models/detector_v3.json`, SHA-256 `b2b2126b...`), and verified two-thread Pi 5 manifest (`configs/inference.json`, profile `pi5-cortex-a76-native`).
- Use **fictional synthetic inputs only**. Close private windows, notifications, and unrelated terminals.
- Show the physical Raspberry Pi 5 Model B (16 GB, CPU-only), hardware/OS diagnostics (`cat /proc/device-tree/model`), and disconnected interface state (`ip -br addr` with Wi-Fi off and Ethernet unplugged).
- Check that terminal font size is readable in 1080p playback and that `Source: Llama (validated)` is clearly visible for at least one response on the disconnected Pi.
- Interactive SMS entry is hidden for privacy; show the fictional example in a prepared caption before pasting it, and state that EdgeShield does not echo or save raw SMS text.

## Quick launch commands

- **On physical Raspberry Pi 5 (mandatory submission demonstration, disconnected):**
  - `bash deploy/pi5/smoke_test.sh` runs preflight verification, the 4-case English & Hinglish `--demo` suite with genuine `Llama (validated)` output, and the 2-case labeled fallback check.
  - `bash deploy/pi5/launch.sh --repeat` launches interactive hidden SMS input with the verified Pi 5 runtime.
  - `bash deploy/pi5/launch.sh --demo` runs the 4 built-in synthetic examples interactively.
- **On Ubuntu host (development preview only — clearly labeled HOST TEST; does NOT satisfy Arm device video requirement):**
  - `bash scripts/run_demo_ubuntu.sh --llama` (with host runtime staged) or `python -m edgeshield.cli --stdin --json` (labeled `Template fallback` without model weights).

## Live sequence (disconnected Pi 5)

1. Introduce EdgeShield as an SMS-first local safety assistant for PS3 (citing PS3 mentoring slides 03 and 11). State explicitly that standalone URL classification, network intrusion monitoring, and malware analysis are future work.
2. Show the physical Raspberry Pi 5 (16 GB, CPU-only, passive heatsink), 64-bit Debian 13 (Trixie) OS, and disconnected network interfaces (`ip -br addr`). Explain that Llama 3.2 1B SpinQuant INT4 EO8 runs through ExecuTorch (XNNPACK CPU, 2 threads) while the local V3 detector (`b2b2126b...`) runs locally in Python.
3. Run `bash deploy/pi5/launch.sh --repeat` (or `bash deploy/pi5/launch.sh --demo`).
4. Paste a fictional legitimate OTP notification: `Cedar Bank: Your OTP is 000000. Do not share it with anyone.` Discuss the actual band, score, cues, deterministic `DO:` advice, and `Source: Llama (validated)` explanation.
5. Paste a fictional scam pressure message: `Urgent: Cedar Bank account will be blocked today. Share your OTP at https://bit.ly/synthetic to verify KYC.` Point out the `SCAM` verdict, cue IDs, deterministic `DO:` recommendation, and `Llama (validated)` explanation. Explain that a link cue does not independently classify the destination URL.
6. Optionally paste a Hinglish example (e.g., `Aapka reward ready hai! Jaldi 500 rs UPI collect request approve karo aur prize paise turant pao.`).
7. Highlight the privacy boundary: raw SMS never enters the Llama prompt, only structured `Evidence`. If demonstrating a fallback (e.g., `--advisory-policy off` or invalid config), clearly point out its explicit `Source: Template fallback` label.
8. Summarize verified Pi 5 B0 measurements from `results/pi5/archive/20261118-B0-full/`: `0.92 ms` p95 detector-only inference, `6.81 s` p95 full response (`91/91` validator-accepted advisories in 605.4 s, zero fallbacks), `1.44 GB` (`1.34 GiB`) peak runner RSS, `0 B` swap, and disclosed passive-heatsink peak `83.7 °C` with throttling (`0xe0008`).
9. Show the synthetic holdout detector evaluation separately from explanation acceptance: `50/60` scams detected (`83.33%` recall), `1/60` false positive (`1.67%` FPR; `1/30` Hinglish), `10` missed scams labeled `LEGITIMATE`.
10. Close with remaining limitations (synthetic & spam-proxy data limits, pending human review, passive throttling under continuous load, and deferred PS3 capabilities).

A laptop or template-fallback recording can verify the CLI but **cannot** substitute for the required disconnected physical Pi 5 demonstration showing at least one visible `Llama (validated)` response.
