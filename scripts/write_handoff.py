"""Summarize executed evidence without rerunning the frozen evaluation."""
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def main():
    if (ROOT / "results/host/v2/heldout_evaluation.json").exists():
        raise SystemExit("This generator is for the archived v1 handoff; use the current v2 status documents.")
    tests = ET.parse(ROOT / "results/host/pytest.xml").getroot().find("testsuite")
    passed = int(tests.attrib["tests"]) - sum(int(tests.attrib.get(k, 0)) for k in ("failures", "errors", "skipped"))
    metrics = json.loads((ROOT / "results/host/heldout_evaluation.json").read_text())
    bench = json.loads((ROOT / "results/host/benchmark.json").read_text())
    model = ROOT / "models/detector.json"
    modules = [
        ("Input, indicators, evidence firewall, validator, deterministic advice", "PASSED", "PASSED", "PENDING_HARDWARE", "Physical Pi", "Repeat safety/integration checks on device"),
        ("Detector training, calibration, serialization and frozen evaluation", "PASSED", "PASSED", "PENDING_HARDWARE", "Physical Pi", "Preserve v1 evidence; use fresh data/protocol for v2"),
        ("Indian/Hinglish detection quality", "FAILED", "FAILED", "PENDING_HARDWARE", "Representative independently labeled target-domain data", "Train/evaluate a new version on fresh family-heldout data"),
        ("CLI, fallback and host benchmark", "PASSED", "PASSED", "PENDING_HARDWARE", "Physical Pi", "Run target smoke and sustained measurements"),
        ("ExecuTorch adapter and failure handling", "PASSED", "PASSED", "PENDING_HARDWARE", "Actual model/runtime integration", "Exercise same parser with genuine model outputs"),
        ("Genuine Llama export and inference", "BLOCKED", "BLOCKED", "PENDING_HARDWARE", "Approved checkpoint/tokenizer; Linux export/build host; Pi", "Acquire permitted artifacts, export/build pinned revision, execute host then device"),
        ("Pi setup, offline wheelhouse, checksums and scripts", "PASSED", "PASSED", "PENDING_HARDWARE", "Physical Pi and runtime assets", "Verify transfer, provision target, run actual checks"),
        ("Real offline proof and native 10-minute benchmark", "BLOCKED", "BLOCKED", "PENDING_HARDWARE", "Working real Arm ExecuTorch inference", "Disconnect interfaces, trace network calls and measure device"),
        ("20-case Llama comparison and five-person clarity study", "BLOCKED", "BLOCKED", "PENDING_HARDWARE", "Real Llama and consenting participants", "Follow docs/BENCHMARKS.md; no simulated ratings"),
        ("Independent URL, network and malware detection", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "Deferred beyond SMS MVP", "Resolve PS3 scope acceptance; implement/evaluate separately later"),
        ("Submission publication, video and final report", "BLOCKED", "BLOCKED", "PENDING_HARDWARE", "Quality/runtime/hardware gates and authorised publication", "Review docs, record actual demo and submit; nothing uploaded"),
    ]
    status = {"as_of": "2026-11-16", "submission_ready": False, "unit_integration_tests_passed": passed,
              "modules": [dict(zip(("module", "implementation", "host_test", "pi4_test", "blocking_dependency", "next_action"), row)) for row in modules]}
    (ROOT / "results/PROJECT_STATUS.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
    lines = ["# EdgeShield status — 16 November 2026", "", "**NOT SUBMISSION-READY.** Laptop implementation/testing is delivered; Indian/Hinglish quality FAILED, real Llama inference BLOCKED, physical-device checks PENDING_HARDWARE.", "", f"Executed: {passed} tests passed, zero failures/errors/skips in the development workspace. See `results/host/pytest.xml`. The transfer bundle excludes the source corpus, so its dataset split audit is skipped until data preparation is reproduced.", "", "Detailed handoff: [docs/HANDOFF.md](docs/HANDOFF.md). Machine-readable tracker: [results/PROJECT_STATUS.json](results/PROJECT_STATUS.json).", ""]
    for name, implementation, host, pi, blocker, action in modules:
        lines.extend([f"## {name}", "", f"- Implementation: `{implementation}`; host: `{host}`; Pi4: `{pi}`.", f"- Blocking dependency: {blocker}.", f"- Next action: {action}.", ""])
    lines.extend(["## Evidence", "", "- Source and tests: `src/edgeshield/`, `tests/`, `scripts/`.", "- Dataset/model: `data/README.md`, `data/synthetic/`, `models/detector.json` and checksum sidecar.", "- Frozen evaluation: `results/host/evaluation_freeze.json`, `heldout_evaluation.json`, `training_validation.json`, `dataset_manifest.json`.", "- Runtime: `docs/EXECUTORCH.md`, `docs/SOURCES_RUNTIME.md`, `executorch/references/` and `deploy/pi4/`.", "- Bundle inventory: `dist/ARTIFACT_INVENTORY.json` after packaging. Licensed weights, tokenizer and runtime binary are intentionally absent.", "- No model generation, Pi measurements, participant ratings, GitHub publication or submission have been fabricated.", ""])
    (ROOT / "PROJECT_STATUS.md").write_text("\n".join(lines), encoding="utf-8")
    d = bench["timings_ms"]["detector_ms"]
    total = bench["timings_ms"]["total_ms"]
    handoff = f'''# Technical handoff — 16 November 2026

**Outcome: laptop-tested research baseline and Pi preparation bundle; not a finished competition submission.** Target-domain detection quality failed. Genuine Llama inference is blocked, and all real Pi tests are pending. Read [detector findings](DETECTOR_FINDINGS.md) before demonstrating this system.

## A. Laptop work and executed evidence

Built input normalization/size limits; twelve honest lexical indicators; TF-IDF/logistic-regression detector; separate sigmoid calibration and validation thresholds; JSON model persistence with checksums; typed evidence schema; evidence-only prompt; strict bounded explanation grammar; fallback; application-owned advice; hidden-input/repeated/JSON terminal modes; bounded ExecuTorch subprocess adapter; benchmark and packaging tools.

`python -m pytest -q --junitxml=results/host/pytest.xml`: **{passed} passed**, no failures/errors/skips in the development workspace. Includes 21 runtime tests, actual child timeout/overflow tests, 12 injection fixtures, serialization, leakage and privacy checks. Test doubles are not Llama execution evidence. `python -m pip check`: no broken requirements. Seven Bash scripts passed `bash -n`; target scripts have not executed on Pi.

UCI grouped preparation: 5,574 messages, 2,770 train / 543 calibration / 1,113 validation / 1,148 test. Repeated training produced the same model hash. Calibration improved validation Brier/log loss; selected thresholds are 0.175 and 0.6. Final evaluation ran once after source/model/data freeze.

UCI heldout: precision {metrics['uci']['precision']:.2%}, recall {metrics['uci']['recall']:.2%}, F1 {metrics['uci']['f1']:.4f}, false-positive rate {metrics['uci']['false_positive_rate']:.3%}, abstention {metrics['uci']['abstention_rate']:.2%}. This is historical spam classification, not modern scam accuracy.

Synthetic Indian/Hinglish: 24 labeled cases, 12 scams; only 1 scam detected, 4 abstained, 7 assigned LEGITIMATE. Hinglish scam recall is 0/6. Quality gate **FAILED**. The small AI-assisted fictional sample is not independently labeled or representative. Do not tune on it and call a subsequent result untouched holdout.

Evidence: `results/host/pytest.xml`, `validator.json`, `training_validation.json`, `dataset_manifest.json`, `evaluation_freeze.json`, `heldout_evaluation.json`, `benchmark.json`. Invalid validator fixtures: 12/12 rejected; valid fixtures: 3/3 accepted. These are handwritten fixtures, not real Llama rejection rates.

## B. ExecuTorch status

Pinned inspected revision: `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7` on release/1.5. Source confirms `setup.sh pi4`, Armv8-A/Cortex-A72 flags, local tokenizer/model paths, CPU threads, new-token limit and exact echo/stats protocol. Target model: approved Meta Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8 with its original matching tokenizer. XNNPACK/SpinQuant configuration is documented, not executed.

Export **BLOCKED**; host inference **BLOCKED**; Pi compatibility **PENDING_HARDWARE**. User has no approved/downloaded checkpoint/tokenizer. No accessible Linux export host was established in this session. No weights, PTE or runner were fabricated. Follow [EXECUTORCH.md](EXECUTORCH.md) for gated access, pinned export/build commands and provenance. Adapter tests cannot establish genuine inference.

## C. Transfer inventory

- `dist/edgeshield-pi4-preparation.zip`: source/deployment archive including the trained baseline and target Python wheels.
- `dist/ARTIFACT_INVENTORY.json`: exact archive size/SHA-256 plus every packaged file's path, size and SHA-256. Embedded `BUNDLE_MANIFEST.json` verifies extracted files.
- `models/detector.json`: {model.stat().st_size:,} bytes; SHA-256 `{metrics['model_sha256']}`.
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

Actual host: {bench['platform']}, {bench['machine']}, Python {bench['python']}; {bench['repetitions']} measured synthetic-fixture iterations after one detector warmup. Detector median {d['median']:.3f} ms / p95 {d['p95']:.3f} ms; complete fallback pipeline median {total['median']:.3f} ms / p95 {total['p95']:.3f} ms. Timing excludes interactive typing. All 100 explanations were fallback because no runtime was configured. These short host measurements are not a sustained test or Pi estimate.

Real Llama load/prefill/TTFT/token/decode fields are null. The benchmark can record verified numeric runner counters when available; Python CPU/RSS exclude the runner. Use GNU time plus native process monitoring on Pi. Actual Pi memory, CPU, thermals, latency, offline trace and ten-minute sustained run remain `PENDING_HARDWARE`. See [BENCHMARKS.md](BENCHMARKS.md).

## F. Competition readiness

Implemented architectural constraints: independent detector, no raw SMS in prompts, strict explanation validation, deterministic advice, no automatic external actions and local-only application path. Software tests are evidence for those paths, not proof about absent native binaries.

Open gates: failed Indian/Hinglish quality; approved model assets; real Linux export and Arm inference; offline device evidence; 20-case model comparison; five-person clarity study; actual video; reviewed final report; GitHub publication and submission. Pi4 acceptance and SMS-only scope need organiser confirmation. Independent URL, network and malware detection remain NOT_IMPLEMENTED. Official Phase1 deadline is 23 November; team target is 22 November.

Docs, report draft, slide content, two-minute pitch, Q&A and checklist exist under `docs/` and `submission/`. They are editable preparation, not proof of final submission. No source or private assets were uploaded.

## G. Execution summary and next action

Passing: {passed} software tests, dependency check, seven shell syntax checks, genuine detector training/repeatability, frozen source-separated evaluation and host benchmark. Remaining failures: intended Indian/Hinglish detection quality. External blockers: model permission/artifacts and Linux export environment. Pending hardware: all Pi installation/runtime/ABI/memory/CPU/thermal/offline/performance checks. No claim of overall completion.

Run locally now: `.venv\\Scripts\\python.exe -m edgeshield.cli --repeat`. First Pi command after transfer: `bash deploy/pi4/setup.sh`. Preserve the baseline evidence; follow [DETECTOR_FINDINGS.md](DETECTOR_FINDINGS.md) for a separately versioned improvement with fresh evaluation data.
'''
    (ROOT / "docs/HANDOFF.md").write_text(handoff, encoding="utf-8")
    bundle_tests = ROOT / "results/host/bundle_pytest.xml"
    if bundle_tests.exists():
        suite = ET.parse(bundle_tests).getroot().find("testsuite")
        skipped = int(suite.attrib.get("skipped", 0))
        successful = int(suite.attrib["tests"]) - skipped - int(suite.attrib.get("errors", 0)) - int(suite.attrib.get("failures", 0))
        with (ROOT / "docs/HANDOFF.md").open("a", encoding="utf-8") as output:
            output.write(f"\nTransfer smoke verification: extracted archive ran {successful} passing tests with {skipped} deliberate corpus-audit skip; the extracted CLI also executed successfully on the host. Archive CRC and per-file SHA-256 checks passed. This tests transfer packaging, not Arm binaries. Evidence: `results/host/bundle_pytest.xml`.\n")
    print(f"Recorded handoff and status from {passed} passing tests and frozen results.")


if __name__ == "__main__":
    main()
