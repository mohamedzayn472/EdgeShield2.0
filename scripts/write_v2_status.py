"""Write the current handoff from v2 results without rerunning evaluation."""
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def main():
    result = json.loads((ROOT / "results/host/v2/heldout_evaluation.json").read_text())
    tests = ET.parse(ROOT / "results/host/v2/pytest.xml").getroot().find("testsuite")
    count = int(tests.attrib["tests"])
    assert int(tests.attrib["failures"]) == int(tests.attrib["errors"]) == 0
    benchmark = json.loads((ROOT / "results/host/v2/benchmark.json").read_text())
    cases = result["overall"]
    state = {"as_of": "2026-11-16", "default_model": "edgeshield-word-char-lr-v2", "submission_ready": False,
             "tests_passed": count, "synthetic_gate": result["status"], "human_label_review": "BLOCKED",
             "real_world_evaluation": "NOT_IMPLEMENTED", "llama_export": "BLOCKED", "genuine_llama_inference": "BLOCKED",
             "pi4_tests": "PENDING_HARDWARE", "hardware_availability": "User has Pi4; setup deferred until lab",
             "checkpoint": "User reports downloading Llama in dual-boot Linux; name, format and path unverified",
             "archived_v1_quality": "FAILED", "network_url_malware_extensions": "NOT_IMPLEMENTED"}
    (ROOT / "results/PROJECT_STATUS.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    status = f'''# EdgeShield status — 16 November 2026

Windows v2 prototype is ready for the Linux handoff. **The project is not submission-ready.**

- `PASSED`: {count} software tests, including detector serialization, privacy, prompt injection, runtime failure handling and CLI integration.
- `PASSED`: preregistered fresh synthetic checks. V2 caught 50/60 scams with one false alarm among 60 legitimate examples. Hinglish: 24/30 scams detected.
- Important limitation: ten scams were assigned LEGITIMATE. Synthetic data is AI-assisted and not independently human-reviewed. Passing these checks is not real-world validation.
- `BLOCKED`: human label review and clarity study, exact downloaded model verification, Linux export, real ExecuTorch inference, final video and reviewed submission.
- `PENDING_HARDWARE`: Pi4 installation, runtime/ABI, offline trace, latency, memory, CPU, thermals and sustained testing. The Pi exists; setup will happen at the lab.
- `NOT_IMPLEMENTED`: independent URL, network and malware detectors; representative real-world target-domain evaluation.
- `FAILED` (archived): v1 Indian/Hinglish challenge. All v1 code/model/freeze/evaluation evidence is preserved.

The default model is `models/detector_v2.json`. V1 is available explicitly through `--detector models/detector.json`.

Current evidence: `results/host/v2/pytest.xml`, `training_validation.json`, `data_audit.json`, `evaluation_freeze.json`, `heldout_evaluation.json`, `benchmark.json`. Current model and all frozen inputs retain their recorded SHA-256 values.

Read [the current handoff](docs/HANDOFF.md), [Windows-to-Linux steps](docs/WINDOWS_TO_LINUX.md), [v2 results](docs/V2_RESULTS.md) and [lab checklist](docs/LAB_CHECKLIST.md). The archive and per-file inventory are under `dist/`. No public upload or submission has occurred.
'''
    (ROOT / "PROJECT_STATUS.md").write_text(status, encoding="utf-8")
    d = benchmark["timings_ms"]["detector_ms"]
    handoff = f'''# Current technical handoff — v2

## Windows work done

The default detector now combines word and character TF-IDF features. Training used UCI development partitions and a new family-split synthetic development corpus. Six preregistered candidates were compared on validation only. Calibration, thresholds and model weights were frozen before a separately authored fresh synthetic test.

**{count} software tests pass.** The app supports hidden input, repeated analysis and JSON output; detector verdict and fixed advice appear before the explanation. The evidence firewall, strict explanation validator, labeled fallback and bounded local runtime adapter remain in place. V1 stays intact for audit.

Fresh synthetic result: precision {cases['precision']:.2%}, recall {cases['recall']:.2%}, F1 {cases['f1']:.4f}; one false alarm among 60 legitimate cases, ten of 60 scams assigned LEGITIMATE. Hinglish recall: 24/30. No cases abstained. The predefined synthetic gates passed; human review and real-world validation have not happened. See [V2_RESULTS.md](V2_RESULTS.md).

Host benchmark: 100 real iterations, detector median {d['median']:.3f} ms and p95 {d['p95']:.3f} ms on Windows. All explanations used fallback. No Llama timing or Pi performance is claimed. Results live under `results/host/v2/`.

## Linux work next

The user reports downloading Llama in dual-boot Linux. Windows cannot inspect the inactive Linux session. Verify the exact model name, file paths, original tokenizer and parameters first. Then use the pinned instructions in [EXECUTORCH.md](EXECUTORCH.md) to export `.pte` and build `setup.sh pi4`. Keep the actual logs and hashes. Downloading weights does not establish a working export or inference path.

Pinned inspected ExecuTorch revision: `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7`. Actual export and inference are still BLOCKED until the Linux work runs. No runtime binary or licensed model is included in the source bundle.

## Transfer and Pi work

`dist/edgeshield-pi4-preparation.zip` contains source, both detector versions, the Arm64 CPython3.11 wheelhouse and deployment scripts. `dist/ARTIFACT_INVENTORY.json` records exact file sizes and SHA-256 values; the embedded `BUNDLE_MANIFEST.json` verifies the extraction. Raw UCI corpus, Windows environments and licensed Llama files are excluded.

The Pi4 is available but setup waits for the lab. Follow [WINDOWS_TO_LINUX.md](WINDOWS_TO_LINUX.md) and [LAB_CHECKLIST.md](LAB_CHECKLIST.md). On the prepared Pi, the first command from the extracted project folder is:

```bash
bash deploy/pi4/setup.sh
```

After adding real runtime assets and creating their manifest, run the environment check, launch, offline trace, diagnostic and ten-minute benchmark as described in [PI4_DEPLOYMENT.md](PI4_DEPLOYMENT.md). All target execution, memory/CPU/thermal behavior and offline proof remain PENDING_HARDWARE. The older detailed A–G handoff is retained as [HANDOFF_V1.md](HANDOFF_V1.md); its measurements describe v1, not this default version.

## Submission gates still open

Verify the downloaded model; execute Linux export and real Arm ExecuTorch inference; complete the offline/device measurements; review labels with the team; conduct the clarity study; record the real video; update the report with device results; resolve Pi4/SMS-only scope interpretation; and publish/submit with authorisation. Independent URL/network/malware detection remains unimplemented. The deadline is 23 November; the team's target is 22 November.

Run locally: `.venv\\Scripts\\python.exe -m edgeshield.cli --repeat`. The app remains an experimental prototype. No model outputs, hardware results, human ratings or public submission have been fabricated.
'''
    (ROOT / "docs/HANDOFF.md").write_text(handoff, encoding="utf-8")
    bundle = ROOT / "results/host/v2/bundle_pytest.xml"
    if bundle.exists():
        suite = ET.parse(bundle).getroot().find("testsuite")
        skipped = int(suite.attrib.get("skipped", 0))
        passed = int(suite.attrib["tests"]) - skipped - int(suite.attrib.get("errors", 0)) - int(suite.attrib.get("failures", 0))
        with (ROOT / "docs/HANDOFF.md").open("a", encoding="utf-8") as output:
            output.write(f"\nTransfer verification: the extracted v2 archive passed {passed} tests with {skipped} expected corpus-audit skip. CRC and per-file SHA-256 checks passed. This verifies packaging on the host, not execution of Arm binaries.\n")
    print("Current v2 status and handoff written from executed evidence.")


if __name__ == "__main__":
    main()
