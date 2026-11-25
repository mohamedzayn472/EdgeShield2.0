# Reproducible measurement protocol

The [V8 device archive](../results/pi5/v8-device-20261124/) records the five-request offline Pi 5 run. The [V2 sustained benchmark](../results/pi5/archive/20261118-B0-full/) covers a separate 605-second run. Laptop measurements below are historical host results.

## Record conditions before measurement

Record date/time, hardware model, architecture, RAM, OS/kernel, GLIBC, Python and dependency versions, power supply, cooling, CPU governor, thread configuration and background load. Record detector/model/tokenizer/runtime SHA-256 hashes, ExecuTorch revision, quantization and context/output limits. Distinguish CPU-only inference from any future accelerator path.

## Timing protocol

1. Use fixed fictional or public benchmark inputs selected before measurement. Do not put private SMS in a performance dataset.
2. Measure detector, evidence preparation, advisory process, validation and total elapsed time with a monotonic clock. Flush the verdict/advice before advisory generation so detector responsiveness can be observed.
3. Measure first invocation separately from subsequent calls. If the adapter launches a new process for each input, every advisory invocation may include model loading. Do not label total process time as decode time.
4. Run at least 30 measured iterations after any explicitly recorded warmup. Report count, median and p95, and include all timeout/error counts. Never drop slow runs silently.
5. Report load time, prefill, time to first token, generated token count and decode tokens/second only when the runtime exposes reliable boundaries and token counts. Otherwise report them as unavailable. Word count is not token count.
6. Repeat a fixed ordered input list for at least 600 seconds on the Pi. Record start/end times, completed requests, errors, timeout count, thermal throttling indicators and system load. A run stopped early is not a ten-minute sustained test.

Capture process RSS and Linux `VmHWM` while the process is alive. Child-process memory is not represented by the Python parent's RSS. Observe CPU usage and `/sys/class/thermal/thermal_zone0/temp` where available. State sampling frequency and missing readings. Compare only runs with equivalent conditions. Do not estimate achieved Pi speed from x86 results.

## Offline verification protocol

Provision all packages, models, tokenizer files and shared libraries first. Keep a local terminal available before disabling networking. Disable Wi-Fi, disconnect Ethernet and inspect other active interfaces; record interface and route state. This demonstrates loss of connectivity, not absence of attempted network calls.

Run the application under an available system tracer with child following and network-system-call filtering, for example `strace -f -e trace=network`. Save the exact command, tracer version, exit status and raw trace. Examine the full trace for AF_INET/AF_INET6 socket/connect/send operations, distinguishing them from local Unix-domain operations. An attempted connection may fail offline and still violates the intended no-network inference path. Lack of a tracer, permission errors, empty capture from a failed launch or an unobserved child invalidates the claimed proof.

Analyze multiple messages and obtain a genuinely generated, validated Llama explanation while disconnected. An all-template run proves only the fallback path. Record artifact hashes and device diagnostics alongside the trace. Review logs for synthetic-only content before sharing.

## Twenty-case Llama/template comparison

After the actual Llama backend works, freeze twenty case IDs from a separate synthetic usability set: four normal banking/OTP/payment notices, four account/KYC pressure messages, four prize/job/payment lures, four Hinglish cases and four ambiguous/adversarial cases. Avoid choosing cases because Llama happened to answer well.

For each case, run the same detector evidence through the deterministic template and the real backend. Record evidence IDs/band, accepted explanation, explanation source, rejection rule, execution time and whether an attempt occurred. Count `accepted / attempted`, `rejected / attempted`, `runtime failures / attempted` and `fallback / all cases` separately. A fabricated output fixture is a validator unit test, not a Llama comparison. Keep test-only malicious responses separate from real model responses.

Report any selection or grammar change after seeing outputs; rerunning after such a change is a new experiment. Do not claim a measured Llama rejection rate until this comparison runs.

## Five-person clarity study

Recruit five consenting adults; collect no private SMS or identifying details. Use fixed synthetic examples and anonymized participant IDs. Show both explanation styles in randomized order without their source label. Ask each participant to rate clarity, usefulness and uncertainty communication from 1 to 5, then ask what action they would take. Do not train participants to prefer Llama.

Record instrument wording, order, missing answers and counts. Report distributions/medians and qualitative misunderstandings, not population-level claims. Five convenience participants cannot establish general usability. Participation is voluntary; no clarity scores exist until actual participants respond.

## Executed Ubuntu x86_64 host measurements (17 November 2026)

*All metrics below are HOST TESTS on Ubuntu 22.04.5 LTS `x86_64` (AMD Ryzen 5 8645HS, 12 logical CPUs, 14 GiB RAM, Python 3.10.12).*

- **Detector-only (100 reps, `results/host/ubuntu/benchmark_argon_detector.json`):** `detector_ms` mean `0.625 ms`, median `0.554 ms`, p95 `0.989 ms`; `evidence_ms` mean `0.047 ms`, median `0.043 ms`; `total_ms` mean `0.684 ms`, median `0.615 ms`, p95 `1.066 ms`.
- **Cold startup & memory (`results/host/ubuntu/optimization_study.json`):** Cold CLI subprocess (import + `load_detector` + 1 `assess`) median `509.59 ms` (p95 `634.80 ms`), Python peak RSS `111.46 MiB`; `load_detector` single-pass JSON+SHA256 `29.96 ms` cold vs `0.985 ms` cached hit; `llama_main` child peak RSS `1627.86 MiB` (`GNU time -v`).
- **Genuine ExecuTorch `ExecuTorchAdvisor` (`cpu_threads=2`, 10 reps, `benchmark_llama_threads2.json`):** `10/10` `Llama (validated)`; `llama_ms` median `3434.78 ms` (p95 `3779.40 ms`), `model_load_ms` median `1568.5 ms`, `prefill_ms` / TTFT median `772.0 ms`, decode median `45.23 tok/s`, GNU time Max RSS `1628.5 MiB`.
- **Genuine ExecuTorch `ExecuTorchAdvisor` with averages (`cpu_threads=2`, 5 reps, `benchmark_argon_llama.json`):** `5/5` `Llama (validated)`; `llama_ms` mean `3482.29 ms` / median `3477.71 ms` / p95 `3571.48 ms`; `model_load_ms` median `1619 ms`; `prefill_ms` median `763 ms`; decode median `47.47 tok/s`.
- **CPU thread scaling (`optimization_study.json`, 5 reps + 1 warmup):** 1 thread median `4257.7 ms` (`37.14 tok/s`), 2 threads `3408.0 ms` (`44.91 tok/s`), 4 threads `3155.9 ms` (`48.86 tok/s`).
- **20-case Llama-vs-template comparison (`results/host/ubuntu/twenty_case_llama_vs_template.json`):** `accepted/attempted: 20/20`, `rejected/attempted: 0/20`, `runtime_failures/attempted: 0/20`, `fallback/all: 0/20`, `exact_match_with_template: 16/20` (on 4 Hinglish `LEGITIMATE` / ambiguous items, Llama dropped the `HINGLISH_CUE` suffix and returned the clean lower-risk prefix); `llama_ms` median `3379.38 ms` (p95 `3712.02 ms`).
- **5-person clarity study:** Protocol and anonymized worksheet prepared in [CLARITY_STUDY_INSTRUMENT.md](CLARITY_STUDY_INSTRUMENT.md); results remain `PENDING_PARTICIPANTS`.
