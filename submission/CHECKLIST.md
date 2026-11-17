# Phase 1 submission gates

Internal target: **22 November 2026**. Official deadline verified on 15 November: **23 November 2026**. Unchecked items are not complete. Refer to `PROJECT_STATUS.md` and `docs/ARGON_COMPLETION_REPORT.md` for verified evidence.

## Mandatory engineering evidence

- [x] Resolve the observed Indian/Hinglish quality failure with a new version and fresh evaluation data; preserve the v1 result (`1/12` scams detected, Hinglish `0/6`; v2 detected `50/60` scams, Hinglish `24/30`, `1/60` false alarm, reproduced on Ubuntu in `results/host/ubuntu/v2_reproduction.json`). *(Synthetic gate passed; human label review still open below.)*
- [x] Review passing unit, privacy, adversarial, and integration results from the updated source (`176 passed, 1 skipped` on Ubuntu x86_64; `results/host/ubuntu/pytest_argon.xml`).
- [x] Review detector provenance, leakage checks, threshold selection, and held-out metrics separately by data source (`results/host/v2/`).
- [x] Verify legally obtained model/tokenizer, required notices, and artifact SHA-256 inventory (`results/host/ubuntu/model_audit.json`, `models/llama/LICENSE_AND_NOTICE.md`, `models/llama/pi4-runtime-manifest.json`).
- [x] Export the real model (`build/executorch/llama3_2.pte`, SHA-256 `c31e4d37...`) and verify genuine ExecuTorch runtime execution on the Ubuntu x86_64 host (`432/432` dev, `132/132` holdout, `20/20` comparison, `10/10` benchmark, `cli_llama_smoke.jsonl`).
- [ ] Demonstrate genuine Llama inference on physical compatible Arm hardware (`PENDING_HARDWARE`; Bookworm-compatible `GLIBC <= 2.34` `aarch64` binaries are cross-compiled and staged under `models/llama/`).
- [x] Show independent detector output and evidence-only Llama prompt without raw SMS (`tests/test_safety.py`, `results/host/ubuntu/demo_ubuntu_llama.txt`).
- [x] Show explanation validation, truthful fallback provenance, and deterministic advice (`src/edgeshield/validator.py`, `src/edgeshield/pipeline.py`).
- [ ] Record Pi hardware, OS, GLIBC, runtime version, quantization, and CPU path (`PENDING_HARDWARE`; `deploy/pi4/diagnostic.sh`).
- [ ] Execute device benchmarks and the full 600 s sustained run; disclose missing measurements (`PENDING_HARDWARE`; `deploy/pi4/benchmark.sh`).
- [ ] Disable connectivity and inspect attempted network calls during real inference on Pi 4 (`PENDING_HARDWARE`; `deploy/pi4/offline_verify.sh`).
- [ ] Verify target installation with only local dependencies before the offline demo (`PENDING_HARDWARE`; `deploy/pi4/setup.sh`).

## Scope and interpretation

- [ ] Resolve or explicitly disclose Pi 4 eligibility interpretation (`UNVERIFIED` organiser clarification).
- [ ] Resolve or explicitly disclose SMS-only scope against the broader PS3 capability list.
- [ ] State URL, network, and malware gaps in report, slides, and video.
- [ ] State that spam labels are a scam proxy and synthetic results are not real-world accuracy (plus complete human label review of synthetic V2 examples).
- [ ] Complete 20-case explanation comparison (`[x]` host run complete in `results/host/ubuntu/twenty_case_llama_vs_template.json`, `20/20` accepted) and 5-person clarity exercise (`[ ]` `PENDING_PARTICIPANTS`, instrument ready in `docs/CLARITY_STUDY_INSTRUMENT.md`).

## Deliverables and submission

- [ ] Review source for private data, secrets, licensed weights, and generated local environments before public upload.
- [ ] Publish reviewed source to the team's GitHub repository when authorized.
- [x] Include reproducible setup, deployment, and evaluation instructions (`README.md`, `docs/PI4_DEPLOYMENT.md`, `docs/LAB_CHECKLIST.md`, `docs/ARGON_COMPLETION_REPORT.md`).
- [ ] Record the actual on-device demonstration; no simulated screens or inference.
- [ ] Finalize technical report and slide content using generated device evidence.
- [ ] Confirm the real submission form's fields, file limits, and upload requirements.
- [ ] Confirm team details, college nomination, and faculty mentor details.
- [ ] Submit through the official form and save the receipt.

Do not mark hardware items complete until physical Raspberry Pi 4 execution succeeds.
