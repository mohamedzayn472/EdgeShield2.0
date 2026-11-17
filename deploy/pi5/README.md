# Raspberry Pi 5 (4 GB) deployment

Primary deployment target: **Raspberry Pi 5 Model B, 4 GB RAM, 64-bit `aarch64` Raspberry Pi OS** (Bookworm or Trixie). Read [docs/PI5_DEPLOYMENT.md](../../docs/PI5_DEPLOYMENT.md) for the complete procedure.

1. Extract `edgeshield-pi5-preparation.zip` and `edgeshield-aarch64-llama-runtime-private.zip` into the same `edgeshield/` folder.
2. Verify all source and runtime hashes:
   `python3 scripts/verify_bundle.py --check-runtime`
3. Provision the isolated virtual environment:
   `bash deploy/pi5/setup.sh` (or `--offline` when using bundled `wheelhouse/pi5-cp313-aarch64/` or `wheelhouse/pi4-cp311/`)
4. Generate `configs/inference.json`:
   `.venv/bin/python deploy/pi5/create_manifest.py --profile pi5`
   (use `--profile pi4-on-pi5` to test the Pi 4 Cortex-A72 baseline runtime on Pi 5, or `--profile pi5-glibc238` for the `14.3.rel1` KleidiAI build on Trixie/Ubuntu 24.04+)
5. Run smoke test, diagnostics, short/sustained benchmarks, and local-console offline trace:
   `bash deploy/pi5/smoke_test.sh`
   `bash deploy/pi5/diagnostic.sh`
   `bash deploy/pi5/benchmark.sh --short-only`
   `bash deploy/pi5/benchmark.sh`
   `bash deploy/pi5/offline_verify.sh`

Physical Pi 5 execution, memory usage, thermals, and offline traces remain `PENDING_HARDWARE`.
