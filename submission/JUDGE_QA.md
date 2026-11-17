# Judge questions and defensible answers

**Does Llama detect the scam?** No. A separate binary detector provides the score/band and rules provide cue IDs. Llama only explains approved structured evidence. The detector can be wrong independently of the explanation.

**Why use Llama if templates work?** It is the required advisory technology. After fixing 1B prompt framing, genuine SpinQuant Llama achieves `100%` validator acceptance (`20/20` in our host comparison, `432/432` dev, `132/132` holdout) and cleanly suppresses noisy cues on legitimate messages (e.g. dropping benign delivery/language cues on `4/20` cases in `twenty_case_llama_vs_template.json`). Whether users prefer it over templates awaits the 5-person clarity study (`docs/CLARITY_STUDY_INSTRUMENT.md`, `PENDING_PARTICIPANTS`).

**Did it really run on Arm with ExecuTorch?** On our Ubuntu x86_64 host, genuine ExecuTorch SpinQuant inference (`llama3_2.pte` + `llama_main`, commit `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7`) is verified (`10/10` benchmark, `20/20` comparison, `432/432` dev, `132/132` holdout), and Bookworm-compatible (`GLIBC <= 2.34`) `aarch64` Cortex-A72 binaries are cross-compiled and staged. Physical Raspberry Pi 4 device execution remains `PENDING_HARDWARE` until the lab visit — we never substitute host results for Pi results.

**Is Raspberry Pi 4 permitted?** The official page lists Arm Linux devices, so it is a reasoned fit. It does not explicitly name Pi 4. Organiser confirmation remains unresolved unless recorded in the source register.

**Does this satisfy all PS3 capabilities?** The implementation focuses on SMS. Independent URL detection, network intrusion monitoring and malware behavior analysis are not implemented. This is an explicit scope risk against the broader written description.

**What does the score mean?** It is the selected detector's spam/scam-proxy score under its evaluated data distribution. Describe calibration only if actually justified and tested. It is not a guarantee about a sender or the real-world likelihood of fraud.

**Why are there three bands with two training classes?** Two thresholds create an abstention region between low and high model scores. `UNCERTAIN` is a decision, not a third ground-truth class. Report a binary matrix plus two-by-three selective outcomes.

**How did you prevent leakage?** Explain the executed duplicate/near-duplicate grouping and synthetic family split from the dataset report. Thresholds and model choices use development data. Frozen test metrics are reported without tuning on the test results.

**Are the Indian/Hinglish results realistic?** They are authored synthetic cases and cannot establish population accuracy. They test selected behaviors and expose gaps. Representative consented data and broader language coverage remain necessary.

**Can a malicious SMS instruct the model?** Raw SMS is excluded at the typed evidence boundary. Tests check prompt isolation. This is stronger than simply asking a model to ignore malicious instructions, but local compromise and future code changes remain risks.

**Does the validator eliminate hallucinations?** No such guarantee is claimed. It restricts accepted wording to evidence-supported phrases and falls back on rejection. It cannot validate whether the underlying detector decision is true.

**How do you prove offline operation?** Provision locally, disable connectivity and show real inference. Separately trace child-process network system calls to inspect attempts. Disconnected Wi-Fi alone is not sufficient evidence.

**What happens if Llama is too slow or fails?** The detector verdict/advice remains available and a bounded timeout produces a labelled fallback. This is a reliability measure, not a substitute for mandatory genuine model execution.

**Where is the data stored?** The normal application does not persist pasted SMS or message IDs. Dataset artifacts are public/synthetic. Terminal and OS-level copies are outside the application's no-history promise.

**What are your actual latency and memory numbers?** On our Ubuntu x86_64 host (Ryzen 5 8645HS, clearly labeled HOST TEST): V2 detector median is `0.554 ms` (`0.625 ms` mean, `0.989 ms` p95), and cold `ExecuTorchAdvisor` (`cpu_threads=2`) median is `3434.78 ms` (`1568.5 ms` load, `772.0 ms` prefill, `45.23 tok/s` decode, `1628.5 MiB` child peak RSS). Physical Raspberry Pi 4 latency, memory, and thermal numbers remain `PENDING_HARDWARE` until `deploy/pi4/benchmark.sh` runs on device.

**What is the next feature?** Close genuine Arm inference, offline proof and evaluation gates first. Then consider independently evaluated URL and network inputs. Visual polish has lower priority than the required working demonstration.
