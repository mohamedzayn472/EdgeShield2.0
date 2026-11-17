# Presentation content

This is slide-by-slide source content, not a generated PowerPoint. Replace `[PENDING_HARDWARE]` / `[PENDING_PARTICIPANTS]` placeholders only after executing on the physical Pi 4 and with real human participants. Do not present Ubuntu x86_64 host numbers as Pi 4 results.

## 1. EdgeShield

Private intelligence. Safer decisions.

An SMS-first local safety assistant with independent detection, bounded explanation, and deterministic advice. Team: add the three students' names and roles after review.

## 2. The user problem

People must decide whether an unexpected message deserves action. Ordinary OTP, payment, and delivery notices can resemble scams. False alarms and false reassurance both matter. No unsupported prevalence statistic is needed.

## 3. What Phase 1 delivers

User-pasted SMS, a statistical score and abstaining decision, observable cue IDs, evidence-only Llama 3.2 1B SpinQuant advisory integration via ExecuTorch, strict explanation validation, conditional hybrid policy (`--advisory-policy`), and fixed `DO:` advice. URL reputation, network intrusion, and malware analysis remain gaps.

## 4. Architecture

Use the Mermaid diagram in `docs/ARCHITECTURE.md`. Highlight the raw-text/evidence boundary and separate Python V2 TF-IDF/LR detector (`< 1 ms` host median) from ExecuTorch Llama (`~3.4 s` host median cold subprocess). Advice is application-owned. No cloud inference or automatic action.

## 5. Detector and data

Word + character TF-IDF plus class-weighted binary logistic regression; validation-selected bands (`[0.25, 0.275]`). Explain spam as a proxy, duplicate/template-family controls, and held-out test discipline. Show UCI (`148/164` recall, `1/984` FPR in Windows regression) and synthetic Indian/Hinglish results (`50/60` scams, `24/30` Hinglish, `1/60` false alarm) separately, with sample counts.

## 6. Privacy and explanation safety

Only fixed `Evidence` values reach Llama (`band`, `score`, indicator IDs, `schema_version=1`). Replacing raw internal enum names and zero-shot prompting with 1-shot defensive framing + salience-ordered fallback raised 1B SpinQuant validator acceptance from `11.1%` (`48/432`) to **`100%`** (`432/432` dev, `132/132` holdout, `20/20` comparison). Show an actual valid output and a clearly labelled adversarial validator fixture. State that validation cannot guarantee detector correctness.

## 7. Arm deployment

- Model: `Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8` (`llama3_2.pte`, `1.00 GiB`, SHA-256 `c31e4d37...`, ExecuTorch `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7`, `TiktokenTokenizer`).
- Cross-build prepared for Pi 4 Model B 8 GB (`aarch64`, `-march=armv8-a -mtune=cortex-a72`, Arm GNU `12.2.rel1`, `GLIBC <= 2.34` Bookworm-compatible; SHA-256 `2dff99fe...` & `b4c1c42f...`).
- Physical Pi 4 execution: `[PENDING_HARDWARE]` (insert device diagnostics, OS/GLIBC, and real device photo/logs only after lab run).

## 8. Measured results

- **V2 synthetic holdout (n=120, reproduced on Ubuntu):** `50/60` scams (`83.33%` recall), English `26/30` (`0` false alarms), Hinglish `24/30` (`1` false alarm, `1.67%` FPR), `10` scams assigned `LEGITIMATE`, `0` abstentions. Preserve V1 failure (`1/12` scams, `0/6` Hinglish) as history.
- **Ubuntu x86_64 HOST TESTS (labeled explicitly as host, NOT Pi 4):** `176` software tests pass (`1` skipped); detector median `0.554 ms` (`0.625 ms` mean, `0.989 ms` p95); cold `ExecuTorchAdvisor` (`cpu_threads=2`, 10 reps) `10/10` validated, `llama_ms` median `3434.78 ms` (`1568.5 ms` load, `772.0 ms` prefill, `45.23 tok/s` decode, `1628.5 MiB` child peak RSS); 20-case host comparison `20/20` accepted (`0/20` fallback).
- **Pi 4 device timings & memory:** `[PENDING_HARDWARE]`.

## 9. Offline demo and limitations

Show Pi 4 disconnected interface state and `strace` offline proof (`[PENDING_HARDWARE]`). Disclose scope gaps (no URL/network/malware), synthetic-data limits (`10/60` missed scams, human review open), narrow explanation grammar, and 5-person clarity study status (`[PENDING_PARTICIPANTS]`, instrument in `docs/CLARITY_STUDY_INSTRUMENT.md`).

## 10. Next steps and handoff

Execute lab-visit Pi 4 validation (`deploy/pi4/setup.sh`, `smoke_test.sh`, `offline_verify.sh`, `benchmark.sh`), complete 5-person clarity study & human label review, record on-device demo video, resolve organiser scope questions, and expand representative evaluation and URL/network inputs in Phase 2.
