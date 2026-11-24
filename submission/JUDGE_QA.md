# Judge questions and defensible answers

**Does Llama detect the scam?**  
No. An independent binary TF-IDF/logistic-regression detector (`models/detector_v3.json` default; archived Pi 5 B0 measured `models/detector_v2.json`) computes the score and risk band, and clause-level rules (`src/edgeshield/indicators.py`) extract cue IDs. Llama only explains approved structured `Evidence`. The detector can be wrong independently of the explanation (as demonstrated in `results/host/v3/e2e_host_llama_validation.txt`).

**Why use Llama if templates work?**  
On-device Llama advisory via ExecuTorch is the core PS3 technology requirement. With 1-shot defensive framing and `INDICATOR_PRIORITY` salience ordering (`src/edgeshield/validator.py`), SpinQuant Llama 3.2 1B achieves `91/91` validator acceptance on the physical Pi 5 sustained run (`benchmark.json`) and `432/432` dev / `132/132` holdout / `20/20` comparison on host, while cleanly suppressing noisy benign cues on legitimate messages (e.g., dropping benign delivery/language cues on `4/20` cases in `twenty_case_llama_vs_template.json`). Whether non-expert users prefer Llama wording over templates awaits the 5-person clarity study (`docs/CLARITY_STUDY_INSTRUMENT.md`, `PENDING_PARTICIPANTS`).

**Did it really run on Arm with ExecuTorch?**  
Yes—on a physical **Raspberry Pi 5 Model B Rev 1.1 (16 GB, CPU-only, `aarch64`, Debian 13 Trixie, Python 3.13.5, `glibc 2.41`)** using `Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8` exported with pinned ExecuTorch `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7` (XNNPACK CPU backend, `pi5-cortex-a76-native` runner, 2 CPU threads). Physical Pi 5 evidence is archived with SHA-256 checksums in `results/pi5/archive/20261118-B0-full/`: `4/4` `Llama (validated)` smoke cases (`smoke_test.txt`), `5/5` short benchmark (`benchmark-short.json`), and `91/91` sustained run (`benchmark.json`).

**Is Raspberry Pi 5 permitted?**  
Yes. The official Bharat AI-SoC Challenge 2026–27 page explicitly lists Raspberry Pi 5 and Arm-based Linux devices (`docs/SOURCES.md`).

**Does this satisfy all PS3 capabilities?**  
Phase 1 focuses on one complete, testable on-device scam SMS workflow, aligned with the supplied PS3 mentoring slides 03 and 11 (which name scam SMS as a valid primary scenario). Standalone phishing URL classification, network intrusion detection, and malware analysis are explicitly scoped as future work.

**What are your actual Pi 5 latency, memory, and thermal numbers?**  
Measured on our physical CPU-only Raspberry Pi 5 (16 GB, open board, passive heatsink; `results/pi5/archive/20261118-B0-full/`):
- **Detector-only inference (`benchmark-detector.json`, n=100):** `0.89 ms` median, `0.92 ms` p95.
- **Sustained full-pipeline B0 (`benchmark.json`, n=91 over 605.4 s):** `6.70 s` median, `6.81 s` p95 full response (`1.22 s` median model load, `3.20 s` median runtime TTFT, `13.49 tokens/s` median decode), `91/91` validated explanations, `0` fallbacks.
- **Memory & swap (`benchmark.json`, `process-resources.txt`):** `1.44 GB` decimal (`1.34 GiB`, `1,443,217,408` bytes) peak runner child RSS, `0 bytes` swap used.
- **Thermals (`benchmark.json`, `system-before.txt`, `system-after.txt`):** Short 5-request burst peaked at `69.95 °C` (`throttled=0x0`); continuous 10-minute passive load peaked at `83.7 °C` with thermal throttling (`throttled_after=0xe0008`). Active cooling and an internal 2-second latency goal are ongoing engineering work.

**What does the detector score mean, and how accurate is it?**  
The score is a spam/scam-proxy risk estimate from V2, not a calibrated real-world fraud probability. Two validation-selected thresholds (`[0.25, 0.275]`) define `LEGITIMATE`, `UNCERTAIN` (abstention), and `SCAM`. On the 120-message fresh synthetic holdout (`12` ambiguous excluded; `results/host/v2/heldout_evaluation.json`), V2 achieved `50/60` recall (`83.33%`: `26/30` English, `24/30` Hinglish), `1/60` false positive (`1.67%` FPR; `1/30` Hinglish `v2h066`), `98.04%` precision, and `0.9009` F1, with **10 missed scams labeled `LEGITIMATE`** and `0` abstentions. We never conflate the `91/91` explanation-validator count with detection accuracy.

**How did you prevent data leakage?**  
Synthetic development examples (`432` messages across `72` families) were split by family (`288` train / `48` calibration / `96` validation; `synthetic_development_leakage_check: PASSED`). A separate authoring agent created `132` fresh holdout messages without seeing development data or code. Pre-prediction audit (`canonical` and char 3–5 cosine `>= 0.90`) found `0` overlaps (`data_audit.json`), and all code/model/data hashes were frozen (`evaluation_freeze.json`) before one-time evaluation.

**Are the Indian/Hinglish results realistic?**  
They are AI-assisted fictional test cases, not real user SMS, and UCI spam is a proxy for scams. They reveal real gaps (such as 10 missed scams and 1 Hinglish false positive) but do not establish population fraud accuracy. Independent human label review and representative consented data remain pending.

**Can a malicious SMS prompt-inject Llama?**  
Raw SMS text is excluded at the typed `Evidence` boundary (`src/edgeshield/evidence.py`), verified by 12 adversarial injection tests in `tests/test_safety.py`. This structural isolation is far stronger than prompt instructions alone, though local host compromise and future code changes remain residual risks.

**Does the validator eliminate hallucinations?**  
No universal guarantee is claimed. It restricts accepted `WHY:` output to exact evidence-supported statements and falls back to a labeled template on any rejection, error, or timeout. It cannot verify whether the detector's underlying risk verdict is true.

**How do you prove offline operation?**  
`deploy/pi5/offline_verify.sh` checks that all non-loopback network interfaces are down (`interfaces.json`), captures routing tables (`routes.json`), runs preflight verification (`offline-environment.json`), and executes 5 real Llama inferences under `strace -f -e trace=network` (`network.trace`, `offline-benchmark.json`), failing if any `AF_INET` or `AF_INET6` call appears. Audited artifacts in `results/pi5/offline-20261119/` (`SHA256SUMS` `6/6 OK`, recorded `2026-11-19T12:15:54Z`) verify `eth0`/`wlan0` `DOWN`, empty `routes.json` (`[]`), `5/5` `Llama (validated)` responses (`0` fallbacks, `6.80 s` p95), zero `AF_INET`/`AF_INET6` matches in `network.trace`, and `inference.json` SHA-256 `a4f1f80b...` matching B0.

**What happens if Llama is slow or unavailable?**  
The detector verdict and deterministic `DO:` advice print in `<2 ms` before Llama runs. If Llama times out, fails, is unconfigured, or is skipped by `--advisory-policy`, EdgeShield prints an explicitly labeled `Template fallback`. Fallback is a reliability safeguard, never a substitute for verified on-device Llama execution.

**Where is user data stored?**  
EdgeShield does not persist pasted SMS text, message hashes, or user history, and interactive mode hides terminal input. OS swap, shell history, terminal scrollback, and crash dumps remain outside application guarantees.
