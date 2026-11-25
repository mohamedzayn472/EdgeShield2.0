# Demo video script (Disconnected Raspberry Pi 5)

**Before recording:** Have the team lead check the actual submission form or organizer email for the video time limit, format, hosting, and link-access rules. The [public PS3 brief](https://arm-education.github.io/Arm-Developer-Labs/Bharat_AI_SoC_2026_27.html) requires a demo video and on-device Llama through ExecuTorch on Arm. The public instructions I could verify give no video duration, required case count, or shot order. The approximately three-minute timing below is an editing target. Adjust it to the verified form limits.

**Status (20 Nov 2026):** The script is ready to record. The disconnected Pi 5 offline evidence files are audited and `VERIFIED` in `results/pi5/offline-20261119/` (`5/5` validated, zero `AF_INET`/`AF_INET6`). The recorded demo video still needs to be captured and reviewed.

**0:00–0:20 — Problem and Phase 1 scope.** “EdgeShield helps users inspect suspicious SMS locally without cloud dependency. Following PS3 mentoring guidance (slides 03 and 11), our Phase 1 prototype delivers one complete on-device scam SMS workflow. The standalone URL detector is experimental. Network traffic analysis is planned for Phase 2.” Show title card and the physical Raspberry Pi 5 terminal.

**0:20–0:45 — Physical Pi 5 hardware, disconnected state, and runtime.** Film the physical **Raspberry Pi 5 Model B (16 GB, CPU-only, passive heatsink)** and the unplugged Ethernet port. From the Pi’s local console, show the device model and the interface flags. Turn off Wi-Fi and confirm the non-loopback interfaces lack the `UP` flag before recording the live inference.

```bash
tr -d '\000' < /proc/device-tree/model
printf '\n'
uname -m
ip -br link
```

Explain that **Llama 3.2 1B Instruct SpinQuant INT4 EO8** runs locally via **ExecuTorch** (`XNNPACK`, `pi5-cortex-a76-native`, 2 CPU threads) while Detector V2 runs locally in Python. Keep the network check and at least the scam inference in the same visible sequence.

**0:45–1:40 — Live disconnected inference with visible `Llama (validated)`.** Run `bash deploy/pi5/launch.sh --repeat` (or `bash deploy/pi5/launch.sh --demo`) on the disconnected Pi 5 using fictional examples shown in a caption:
1. Legitimate transactional SMS: `Cedar Bank: Your OTP is 000000. Do not share it with anyone.`
2. Scam SMS: `Urgent: Cedar Bank account will be blocked today. Share your OTP at https://bit.ly/synthetic to verify KYC.`
3. Optional Hinglish legitimate delivery update: `Aapka parcel aaj shaam ko aayega. Live tracking aapke official app par available hai.`

Interactive input is hidden. Put the fictional SMS in a caption or use `--demo`, which displays the built-in text automatically. Keep the threat band, evidence, deterministic `DO:` action, `WHY:`, and **`Source: Llama (validated)`** readable. On the KYC example, say why the OTP-sharing request is a warning sign and explain how to verify the message through a known official channel. State that link cues do not independently classify URLs.

**1:40–2:05 — Privacy boundary and truthful fallback.** Explain that raw SMS never enters the Llama prompt—only structured `Evidence` (band, score, enumerated cue IDs). If demonstrating a fallback (e.g., `--advisory-policy off` or invalid config), clearly highlight `Source: Template fallback` so it is never confused with Llama output.

**2:05–2:35 — Verified Pi 5 B0 measurements & offline audit.** Show a concise summary slide backed by `results/pi5/archive/20261118-B0-full/`:
- Detector-only p95: **0.92 ms** (`n=100`).
- Sustained B0 (`n=91`, `605.4 s`): **91/91** validator-accepted explanations (`0` fallbacks), **6.81 s** p95 full response (`3.20 s` median TTFT, `13.49 tok/s` decode), **1.44 GB (1.34 GiB)** peak runner RSS, **0 B** swap.
- Passive heatsink thermals: **83.7 °C** peak with disclosed throttling (`0xe0008`).
- Show the audited offline `strace` verification result from `results/pi5/offline-20261119/`: **5/5** explanations passed validation (`0` fallbacks) and **zero Internet-family (`AF_INET`/`AF_INET6`) calls** were observed while `eth0`/`wlan0` were `DOWN` and `routes.json` was empty. Identify this as the saved offline benchmark if it is displayed separately from the live demo.

**2:35–3:00 — Detector evaluation, limits, and GitHub link.** Present synthetic holdout metrics separately from explanation acceptance: **50/60** scams detected (`83.33%` recall; `26/30` English, `24/30` Hinglish), **1/60** false positive (`1.67%` FPR), **10 missed scams** labeled `LEGITIMATE`. Disclose synthetic/spam-proxy limits and pending human review, and close with the public GitHub repository URL.

## Final playback checklist

- [ ] The opening identifies the team, **PS3**, and the scam-SMS workflow.
- [ ] The viewer sees the real Pi 5, disconnected state, and the local application running. The narration names **Llama and ExecuTorch**.
- [ ] A fictional legitimate OTP and a fictional KYC scam each lead to a visible verdict and safe action. At least one **Llama (validated)** explanation is clearly visible.
- [ ] The video shows practical device measurements and states that the passive sustained run throttled. The synthetic detector outcome includes the false alarm and missed scams.
- [ ] The submitted file or link plays with readable text and clear audio, complies with the verified form rules, and is accessible under the required reviewer permissions.

If the form has a tight time limit, keep the hardware and disconnect proof, the two live cases, and a short results card. Trim the optional third example, fallback demonstration, and spoken timing breakdown first. Put detailed runtime settings, the full confusion matrix, raw logs, and reproduction steps in the technical report.
