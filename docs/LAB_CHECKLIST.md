# Lab session checklist

The team has a Raspberry Pi 4 Model B 8 GB available for the lab visit. All host export, Ubuntu inference verification, and Bookworm-compatible `aarch64` cross-compilation are now complete on Ubuntu (`docs/ARGON_COMPLETION_REPORT.md`); **physical Pi 4 execution remains `PENDING_HARDWARE`**.

## Before the lab

1. Transfer both:
   - The verified source/wheelhouse bundle `dist/edgeshield-pi4-preparation.zip` (verify with `scripts/verify_bundle.py`).
   - The separate staged runtime directory `models/llama/` containing `llama_main` (`2dff99fe...`), `libllama_runner.so` (`b4c1c42f...`), `llama3_2.pte` (`c31e4d37...`), `tokenizer.model` (`82e9d319...`), and `LICENSE_AND_NOTICE.md`.
2. Verify on the host before leaving that `models/llama/pi4-runtime-manifest.json` matches the staged Bookworm-compatible (`GLIBC <= 2.34`) files (`results/host/ubuntu/pi4_bookworm_binary_audit.json`).
3. Bring the Pi 4 8 GB, official 5V/3A USB-C power supply, fast microSD/USB storage (for 1.07 GB `.pte` reads), heatsink/fan cooling, local display/keyboard (for disconnected offline testing), and printed sheets from `docs/CLARITY_STUDY_INSTRUMENT.md`.
4. Keep historical V1 (`1/12` scams, `0/6` Hinglish) and V2 (`50/60` scams, `24/30` Hinglish) records intact when preparing final slides.

## At the lab

1. Verify OS/Python on the Pi 4: `uname -a`, `ldd --version`, `python3 --version`, `free -h`, `df -h` (bundle wheelhouse `wheelhouse/pi4-cp311/` expects 64-bit Bookworm CPython 3.11).
2. Extract `edgeshield-pi4-preparation.zip`, copy `models/llama/` into the extracted project root, and run:
   ```bash
   python3 scripts/verify_bundle.py
   bash deploy/pi4/setup.sh
   ```
3. Generate `configs/inference.json` on the Pi 4 and run the smoke test:
   ```bash
   chmod u+x models/llama/llama_main
   .venv/bin/python deploy/pi4/create_manifest.py \
     --runner models/llama/llama_main \
     --model models/llama/llama3_2.pte \
     --tokenizer models/llama/tokenizer.model \
     --library models/llama/libllama_runner.so \
     --arch aarch64 --output configs/inference.json
   bash deploy/pi4/smoke_test.sh
   ```
4. Confirm genuine `Llama (validated)` output in `smoke_test.sh` and `bash deploy/pi4/launch.sh --repeat`.
5. From a local console (Wi-Fi disabled, Ethernet unplugged), run `bash deploy/pi4/offline_verify.sh`, `bash deploy/pi4/diagnostic.sh`, and `bash deploy/pi4/benchmark.sh` (600 s sustained run; optionally compare `cpu_threads` 1, 2, 4).
6. Record the real on-device demo video (`docs/DEMO_SCRIPT.md`), complete the 5-person clarity study (`docs/CLARITY_STUDY_INSTRUMENT.md`) + team synthetic label review, and update `docs/REPORT.md` and `submission/` with actual Pi 4 numbers before submitting.
