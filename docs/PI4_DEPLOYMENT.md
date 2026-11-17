> Ubuntu continuation (17 November 2026): `llama3_2.pte`, `tokenizer.model`, Bookworm-compatible (`GLIBC <= 2.34`) `aarch64` `llama_main` and `libllama_runner.so`, and Meta notices are now compiled and staged under `models/llama/` on the Ubuntu host. Physical Pi 4 installation and device execution remain `PENDING_HARDWARE`. See [ARGON_COMPLETION_REPORT.md](ARGON_COMPLETION_REPORT.md) and [UBUNTU_VERIFICATION.md](UBUNTU_VERIFICATION.md).

# Raspberry Pi 4 deployment handoff

Status: Bookworm-compatible `aarch64` runner binaries, exported SpinQuant `.pte`, matching `tokenizer.model`, Arm64 CPython 3.11 wheelhouse, and deployment scripts are prepared and checksummed on the Ubuntu host; **target installation and all device tests are `PENDING_HARDWARE`**. Note: `dist/edgeshield-pi4-preparation.zip` is the source/wheelhouse bundle (`models/llama/` is excluded by policy from the zip and transferred separately with `LICENSE_AND_NOTICE.md`).

## First device command and prerequisites

Transfer the extracted `dist/edgeshield-pi4-preparation.zip` folder and the staged `models/llama/` directory (`llama_main`, `libllama_runner.so`, `llama3_2.pte`, `tokenizer.model`, `LICENSE_AND_NOTICE.md`) to a Pi 4 Model B 8 GB with 64-bit Raspberry Pi OS Bookworm (CPython 3.11). From its project root run:

```bash
bash deploy/pi4/setup.sh
```

Before that command, provision `python3`, `python3-venv`, `python3-pip`, GNU `time`, `strace`, `iproute2`, and OS runtime libraries using `apt`. The script deliberately does not modify system packages. Run from a local console when preparing offline tests. Do not copy `.venv-host` or x86_64 binaries (`models/llama/host-x86_64/`).

The downloaded wheelhouse `wheelhouse/pi4-cp311/` is for CPython 3.11 `aarch64` only (`requirements/pi4.txt`, `GLIBC >= 2.27`). Note on `aarch64` runner builds: `models/llama/llama_main` and `models/llama/libllama_runner.so` were cross-compiled with Arm GNU Toolchain `12.2.rel1` (`-march=armv8-a -mtune=cortex-a72`, KleidiAI disabled) and verified by `readelf` (`pi4_bookworm_binary_audit.json`) to require at most `GLIBC_2.34` and `GLIBCXX_3.4.30` (compatible with Bookworm's `GLIBC 2.36`). Separate `14.3.rel1` binaries requiring `GLIBC_2.38` are archived under `models/llama/pi4-aarch64-glibc238/` and should NOT be used on stock Bookworm.

## Configure runtime manifest and run smoke test

Ensure `models/llama/` holds the 4 staged runtime files (check SHA-256 values against `models/llama/pi4-runtime-manifest.json`), then generate `configs/inference.json` on the Pi 4:

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

`smoke_test.sh` runs `verify_environment.py --runtime configs/inference.json --output results/pi4/environment.json` and launches the 4-case English/Hinglish `--demo` suite with genuine ExecuTorch Llama inference. For interactive terminal usage, run:

```bash
bash deploy/pi4/launch.sh --repeat
```

The smoke test must display `Llama (validated)` on real Pi 4 hardware. Record the actual input fixture, detector verdict, `WHY`, source, `DO`, and timings. A template fallback is valid safety behavior but fails the mandatory demonstration of genuine Llama generation.

## Offline evidence

Disable Wi-Fi from a local console, disconnect Ethernet, and disable other non-loopback interfaces. Do not terminate a remote SSH session by surprise. Then run:

```bash
bash deploy/pi4/offline_verify.sh
```

This records interface/route state, runs five synthetic fixtures under `strace -f -e trace=network`, requires at least one validated Llama result, and rejects `AF_INET`/`AF_INET6` socket activity in that trace. Logs are saved to `results/pi4/`.

## Measurements and diagnostics

```bash
bash deploy/pi4/diagnostic.sh
bash deploy/pi4/benchmark.sh
```

Benchmarking requests at least 30 samples across 600 seconds with fixed synthetic fixtures. Inspect `llama_validated_count`, fallback rate, runner RSS/VmHWM, CPU, and `/sys/class/thermal/thermal_zone0/temp` (`vcgencmd measure_temp` / `get_throttled`). Repeat with `cpu_threads` 1, 2, and 4 after preserving the original manifest.

## Troubleshooting

- `python_3_11_for_wheelhouse=false`: install on 64-bit Raspberry Pi OS Bookworm (CPython 3.11), or build a matching wheelhouse for the target Python version. Never copy a host `.venv`.
- `GLIBC_2.38 not found`: verify you copied `models/llama/pi4-aarch64/` (`12.2.rel1`, `GLIBC <= 2.34`) rather than `models/llama/pi4-aarch64-glibc238/` (`14.3.rel1`).
- `RUNTIME_ARTIFACT_MISSING`: verify `models/llama/llama_main`, `llama3_2.pte`, `tokenizer.model`, and `libllama_runner.so` exist at the paths in `configs/inference.json`.
- `RUNTIME_INTEGRITY_FAILED`: re-check SHA-256 hashes against `models/llama/pi4-runtime-manifest.json` and `build/executorch/llama3_2.pte.sha256`.
- `Illegal instruction`: confirm `models/llama/llama_main` came from the `-march=armv8-a -mtune=cortex-a72` build with KleidiAI disabled (`pi4_bookworm_binary_audit.json`).
- `RUNNER_TIMEOUT` on Pi 4 cold loading: if 120s is tight on slow SD cards, measure load time first, document any timeout adjustment, and evaluate `--advisory-policy elevated` to skip Llama on clean low-risk messages while keeping `always` verified for compliance.
