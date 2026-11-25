# Raspberry Pi 5 deployment

Primary verified deployment target: **Raspberry Pi 5 Model B Rev 1.1, 16 GB RAM, CPU-only, 64-bit `aarch64` Debian 13 (Trixie), Python 3.13.5, `glibc 2.41`**. Read [docs/PI5_DEPLOYMENT.md](../../docs/PI5_DEPLOYMENT.md) for the complete procedure.

1. Extract the source bundle and (privately on authorized hardware) the lawfully obtained `models/llama/` runtime assets into the same `edgeshield/` folder.
2. Verify source hashes (add `--check-runtime` only when the private runtime archive with `models/llama/RUNTIME_MANIFEST.json` is staged):
   `python3 scripts/verify_bundle.py`
3. Provision the isolated virtual environment:
   `bash deploy/pi5/setup.sh` (or `--offline` when using a pre-populated `wheelhouse/pi5-cp*-aarch64/` cache)
4. Generate `configs/inference.json` (default: `--profile pi5`, dedicated Cortex-A76 `GLIBC <= 2.34`, 2 CPU threads):
   `.venv/bin/python deploy/pi5/create_manifest.py --profile pi5`
   *(Optional profile: `--profile pi5-glibc238`.)*
5. Run smoke test, diagnostics, short/sustained benchmarks, and local-console offline trace:
   - `bash deploy/pi5/smoke_test.sh`
   - `bash deploy/pi5/launch.sh --repeat` (interactive CLI) or `bash deploy/pi5/launch.sh --demo`
   - `bash deploy/pi5/diagnostic.sh`
   - `bash deploy/pi5/benchmark.sh --short-only`
   - `bash deploy/pi5/benchmark.sh`
   - `bash deploy/pi5/offline_verify.sh` (local console, Wi-Fi off & Ethernet unplugged)

Detector V8 is the default. The [24 November V8 device run](../../results/pi5/v8-device-20261124/) records five validated offline Llama explanations on the 16 GB Pi 5. The [605-second sustained run](../../results/pi5/archive/20261118-B0-full/) used Detector V2.
