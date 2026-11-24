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

**Verified device status (24 Nov 2026):** Archived physical Pi 5 smoke test (`4/4` `Llama (validated)`), detector-only run (`0.92 ms` p95), and 605.4 s sustained B0 run (`91/91` validated, `6.81 s` p95, `1.44 GB` / `1.34 GiB` peak RSS, `0 B` swap, `83.7 °C` peak with throttling `0xe0008`) in `results/pi5/archive/20261118-B0-full/`, and disconnected offline verification in `results/pi5/offline-20261119/` (`5/5` validated, `0` fallbacks, `eth0`/`wlan0` `DOWN`, empty `routes.json`, `0` `AF_INET`/`AF_INET6` calls in `network.trace`, manifest `a4f1f80b...` matching B0) were all measured with **Detector V2** (`f37c3dd9060b89ead7ea6bbf1c393b22fff7cfc18ed5d85126e977e03daea6a6`). The promoted default **Detector V8** (`4d3481555460d2bf5dfaf5e28fc107786f38ea34400358e4637b5bd9b0afd365`) passed all host gates (`P1`–`P4`) and awaits on-device Pi 5 verification (`PENDING_HARDWARE`; save new Pi V8 offline/smoke artifacts into a new directory rather than overwriting the V2 archives).
