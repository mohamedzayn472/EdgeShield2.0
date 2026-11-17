# Technical handoff — 16 November 2026

**Outcome: laptop-tested research baseline and Pi preparation bundle; not a finished competition submission.** Target-domain detection quality failed. Genuine Llama inference is blocked, and all real Pi tests are pending. Read [detector findings](DETECTOR_FINDINGS.md) before demonstrating this system.

## A. Laptop work and executed evidence

Built input normalization/size limits; twelve honest lexical indicators; TF-IDF/logistic-regression detector; separate sigmoid calibration and validation thresholds; JSON model persistence with checksums; typed evidence schema; evidence-only prompt; strict bounded explanation grammar; fallback; application-owned advice; hidden-input/repeated/JSON terminal modes; bounded ExecuTorch subprocess adapter; benchmark and packaging tools.

`python -m pytest -q --junitxml=results/host/pytest.xml`: **138 passed**, no failures/errors/skips in the development workspace. Includes 21 runtime tests, actual child timeout/overflow tests, 12 injection fixtures, serialization, leakage and privacy checks. Test doubles are not Llama execution evidence. `python -m pip check`: no broken requirements. Seven Bash scripts passed `bash -n`; target scripts have not executed on Pi.

UCI grouped preparation: 5,574 messages, 2,770 train / 543 calibration / 1,113 validation / 1,148 test. Repeated training produced the same model hash. Calibration improved validation Brier/log loss; selected thresholds are 0.175 and 0.6. Final evaluation ran once after source/model/data freeze.

UCI heldout: precision 98.01%, recall 90.24%, F1 0.9397, false-positive rate 0.305%, abstention 1.66%. This is historical spam classification, not modern scam accuracy.

Synthetic Indian/Hinglish: 24 labeled cases, 12 scams; only 1 scam detected, 4 abstained, 7 assigned LEGITIMATE. Hinglish scam recall is 0/6. Quality gate **FAILED**. The small AI-assisted fictional sample is not independently labeled or representative. Do not tune on it and call a subsequent result untouched holdout.

Evidence: `results/host/pytest.xml`, `validator.json`, `training_validation.json`, `dataset_manifest.json`, `evaluation_freeze.json`, `heldout_evaluation.json`, `benchmark.json`. Invalid validator fixtures: 12/12 rejected; valid fixtures: 3/3 accepted. These are handwritten fixtures, not real Llama rejection rates.

## B. ExecuTorch status

Pinned inspected revision: `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7` on release/1.5. Source confirms `setup.sh pi4`, Armv8-A/Cortex-A72 flags, local tokenizer/model paths, CPU threads, new-token limit and exact echo/stats protocol. Target model: approved Meta Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8 with its original matching tokenizer. XNNPACK/SpinQuant configuration is documented, not executed.

Export **BLOCKED**; host inference **BLOCKED**; Pi compatibility **PENDING_HARDWARE**. User has no approved/downloaded checkpoint/tokenizer. No accessible Linux export host was established in this session. No weights, PTE or runner were fabricated. Follow [EXECUTORCH.md](EXECUTORCH.md) for gated access, pinned export/build commands and provenance. Adapter tests cannot establish genuine inference.

## C. Transfer inventory

- `dist/edgeshield-pi4-preparation.zip`: source/deployment archive including the trained baseline and target Python wheels.
- `dist/ARTIFACT_INVENTORY.json`: exact archive size/SHA-256 plus every packaged file's path, size and SHA-256. Embedded `BUNDLE_MANIFEST.json` verifies extracted files.
- `models/detector.json`: 437,905 bytes; SHA-256 `9163c20783d76eb1c3cea637dea844e4d1c7d61bec976cd64cb0b69a20cd4c72`.
- `wheelhouse/pi4-cp311/`: seven real PyPI wheels, CPython3.11/aarch64/Linux, GLIBC >=2.27; downloaded but not run on target.
- Missing: approved checkpoint, original tokenizer, exported `.pte`, Pi4 `llama_main`, compatible shared libraries and real device logs.
- Excluded: source corpus text, host Python/venv/cache, private credentials and licensed Llama materials. Model vocabulary derives from public UCI training data.

Checksums establish consistency against a trusted manifest, not authenticity. Upstream source/wheel license notices remain with their materials. This is not a complete Llama deployment archive.

## D. Exact Pi installation order

Provision a 64-bit Pi4 Model B 8GB OS with CPython3.11 (the prepared wheelhouse target), venv/pip, GNU time, strace and iproute2 before the offline demo. Transfer/extract the archive. First command from the extracted `edgeshield` directory:

```bash
bash deploy/pi4/setup.sh
```

It verifies the bundled manifest, checks target identity/ABI/RAM/disk, then installs local dependencies with `--no-index`. It will reject this Windows host. Provision genuine runtime assets following [PI4_DEPLOYMENT.md](PI4_DEPLOYMENT.md), create `configs/inference.json` with `create_manifest.py`, then:

```bash
.venv/bin/python deploy/pi4/verify_environment.py --runtime configs/inference.json --output results/pi4/environment.json
bash deploy/pi4/launch.sh --repeat
```

Once real Llama output is observed, disable Wi-Fi and all other non-loopback interfaces at a local console, disconnect Ethernet, then run:

```bash
bash deploy/pi4/offline_verify.sh
bash deploy/pi4/diagnostic.sh
bash deploy/pi4/benchmark.sh
```

The offline protocol checks connectivity separately from attempted network calls and requires a genuinely validated Llama output. Do not use templates as proof of Llama compliance.

## E. Measurements

Actual host: Windows-11-10.0.26300-SP0, AMD64, Python 3.12.13; 100 measured synthetic-fixture iterations after one detector warmup. Detector median 0.462 ms / p95 0.825 ms; complete fallback pipeline median 0.571 ms / p95 0.975 ms. Timing excludes interactive typing. All 100 explanations were fallback because no runtime was configured. These short host measurements are not a sustained test or Pi estimate.

Real Llama load/prefill/TTFT/token/decode fields are null. The benchmark can record verified numeric runner counters when available; Python CPU/RSS exclude the runner. Use GNU time plus native process monitoring on Pi. Actual Pi memory, CPU, thermals, latency, offline trace and ten-minute sustained run remain `PENDING_HARDWARE`. See [BENCHMARKS.md](BENCHMARKS.md).

## F. Competition readiness

Implemented architectural constraints: independent detector, no raw SMS in prompts, strict explanation validation, deterministic advice, no automatic external actions and local-only application path. Software tests are evidence for those paths, not proof about absent native binaries.

Open gates: failed Indian/Hinglish quality; approved model assets; real Linux export and Arm inference; offline device evidence; 20-case model comparison; five-person clarity study; actual video; reviewed final report; GitHub publication and submission. Pi4 acceptance and SMS-only scope need organiser confirmation. Independent URL, network and malware detection remain NOT_IMPLEMENTED. Official Phase1 deadline is 23 November; team target is 22 November.

Docs, report draft, slide content, two-minute pitch, Q&A and checklist exist under `docs/` and `submission/`. They are editable preparation, not proof of final submission. No source or private assets were uploaded.

## G. Execution summary and next action

Passing: 138 software tests, dependency check, seven shell syntax checks, genuine detector training/repeatability, frozen source-separated evaluation and host benchmark. Remaining failures: intended Indian/Hinglish detection quality. External blockers: model permission/artifacts and Linux export environment. Pending hardware: all Pi installation/runtime/ABI/memory/CPU/thermal/offline/performance checks. No claim of overall completion.

Run locally now: `.venv\Scripts\python.exe -m edgeshield.cli --repeat`. First Pi command after transfer: `bash deploy/pi4/setup.sh`. Preserve the baseline evidence; follow [DETECTOR_FINDINGS.md](DETECTOR_FINDINGS.md) for a separately versioned improvement with fresh evaluation data.

Transfer smoke verification: extracted archive ran 137 passing tests with 1 deliberate corpus-audit skip; the extracted CLI also executed successfully on the host. Archive CRC and per-file SHA-256 checks passed. This tests transfer packaging, not Arm binaries. Evidence: `results/host/bundle_pytest.xml`.
