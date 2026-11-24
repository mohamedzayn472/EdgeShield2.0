# Raspberry Pi 5 Deployment Guide

**Verified primary target:** **Raspberry Pi 5 Model B Rev 1.1, 16 GB RAM, CPU-only, 64-bit `aarch64` Debian GNU/Linux 13 (Trixie), Python 3.13.5, `glibc 2.41`**.

The current release candidate defaults to **Detector V3** (`models/detector_v3.json`, SHA-256 `b2b2126b872c43eb02ccdef41a7f5040cf86cfd0dc1bfb31f98ef13733d50910`), alongside the exported SpinQuant model (`llama3_2.pte`), tokenizer (`tokenizer.model`), evidence firewall, explanation validator, and deterministic advice. Physical Pi 5 smoke testing (`4/4` `Llama (validated)`), 605.4 s sustained B0 benchmarking (`91/91` validated, `6.81 s` p95 full response, `1.44 GB` / `1.34 GiB` peak runner RSS, `0 B` swap, `83.7 °C` peak with throttling `0xe0008`), and disconnected offline verification (`5/5` validated, `6.80 s` p95, `0` `AF_INET`/`AF_INET6` syscalls) were measured on **Detector V2** (`models/detector_v2.json`, SHA-256 `f37c3dd9060b89ead7ea6bbf1c393b22fff7cfc18ed5d85126e977e03daea6a6`) and are archived in `results/pi5/archive/20261118-B0-full/` and `results/pi5/offline-20261119/`. Physical Pi 5 device verification of **Detector V3 (`b2b2126b...`)** remains `PENDING_HARDWARE`.

> Note: `deploy/pi5/setup.sh` enforces a minimum `>=3 GiB` visible RAM check so smaller Pi 5 boards (such as 4 GB models) can also be trialed; verified competition measurements were collected on the **16 GB** Pi 5 Model B Rev 1.1.

## OS and Python support

Select a **64-bit** (`aarch64`) Raspberry Pi OS image (Debian 13 Trixie or Debian 12 Bookworm). The application declares `requires-python = ">=3.10,<3.14"`. `deploy/pi5/setup.sh` resolves pinned dependencies for the device's interpreter, requires binary wheels, and caches them under `wheelhouse/pi5-cp<ver>-aarch64/` with `SHA256SUMS` for clean offline installs (`--offline`).

If system Python is outside `3.10–3.13`, supply a separate supported interpreter via `EDGESHIELD_PYTHON=/absolute/path/to/python3.13` (do not replace system Python). Native Llama executes as an independent C++ binary (`llama_main`) whose compatibility depends on `aarch64` CPU instructions and system `glibc`/`libstdc++`, not Python version.

## 1. Provision the Raspberry Pi 5

Extract the source bundle (and, privately on the device, your lawfully obtained runtime assets) into `~/edgeshield`, excluding any laptop virtual environments or build directories. Verify host OS and architecture first:

```bash
cat /etc/os-release
uname -m                  # Must output: aarch64
python3 --version         # Must be >=3.10, <3.14
free -h
getconf GNU_LIBC_VERSION
```

Install OS prerequisites while online, then provision the isolated Python environment:

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip time strace iproute2 libatomic1 libstdc++6
cd ~/edgeshield
bash deploy/pi5/setup.sh
```

`setup.sh` creates a fresh `.venv` and refuses to overwrite an existing one unless `--recreate-venv` is passed. For offline reprovisioning later, retain `wheelhouse/pi5-cp*-aarch64/` (including `SHA256SUMS`) and run `bash deploy/pi5/setup.sh --offline`.

## 2. Stage runtime assets and generate `configs/inference.json`

Llama weights and tokenizer are gated under the Meta Llama 3.2 Community License and are not included in the public source archive. Obtain and export them per [docs/EXECUTORCH.md](EXECUTORCH.md) (or transfer the team's private runtime archive on authorized hardware), retaining `models/llama/LICENSE_AND_NOTICE.md`.

Expected private runtime layout under `models/llama/`:
- `models/llama/llama3_2.pte` (SHA-256 `c31e4d376f349de85b4422a8c0405d88f21145709f0e17168b06d809ffe5e8a2`)
- `models/llama/tokenizer.model` (SHA-256 `82e9d31979e92ab929cd544440f129d9ecd797b69e327f80f17e1c50d5551b55`)
- `models/llama/pi5-aarch64/llama_main` (SHA-256 `e628abef24091067f4954b4ea15ce84317570d6d99e2ddc34a3786af7ad8d70c`)
- `models/llama/pi5-aarch64/libllama_runner.so` (SHA-256 `d45f39fd3b7f53bb511190fedab971933d176a3431c73f53f9fd87ad39496731`)
- `models/llama/LICENSE_AND_NOTICE.md`

Generate the verified two-thread Pi 5 manifest using `deploy/pi5/create_manifest.py` (supports `--profile pi5` [default, Cortex-A76 `GLIBC <= 2.34`] or `--profile pi5-glibc238`, plus `--cpu-threads 1..4` [default `2`], `--timeout-seconds` [default `120`], `--output` [default `configs/inference.json`], and `--force`):

```bash
chmod u+x models/llama/pi5-aarch64/llama_main
.venv/bin/python deploy/pi5/create_manifest.py --profile pi5
.venv/bin/python deploy/pi5/verify_environment.py \
  --runtime configs/inference.json --output results/pi5/environment.json
```

If using the private runtime archive with `RUNTIME_MANIFEST.json`, you can also check runtime hashes with:

```bash
python3 scripts/verify_bundle.py --check-runtime
```

## 3. Smoke test, launch, and benchmarks

```bash
# 4-case English/Hinglish synthetic demo + 2-case labeled fallback check
bash deploy/pi5/smoke_test.sh

# Interactive hidden-input CLI
bash deploy/pi5/launch.sh --repeat

# Hardware/OS/thermal diagnostics
bash deploy/pi5/diagnostic.sh

# Short 5-request burst benchmark
bash deploy/pi5/benchmark.sh --short-only

# Full 600-second sustained benchmark (archived B0 already verified)
bash deploy/pi5/benchmark.sh
```

`smoke_test.sh` enforces that genuine `Llama (validated)` output appears before succeeding; template fallback alone does not verify ExecuTorch inference.

**Thermal note:** In the verified B0 sustained run (`results/pi5/archive/20261118-B0-full/benchmark.json`), continuous 605.4 s inference on an open board with a passive heatsink peaked at `83.7 °C` and triggered throttling (`throttled_after=0xe0008`), while the 5-request short burst peaked at `69.95 °C` (`throttled=0x0`). Monitor temperature and `vcgencmd get_throttled` during sustained loads; active cooling is recommended for extended continuous runs.

## 4. Disconnected offline verification

From a **local console** (keyboard/monitor, not SSH), disable Wi-Fi, unplug Ethernet, and confirm no non-loopback interface is `UP`. Back up any prior files in `results/pi5/` first because the script writes fixed filenames:

```bash
cd ~/edgeshield
(
  set -o pipefail
  bash deploy/pi5/offline_verify.sh 2>&1 | tee results/pi5/offline_console.txt
)
```

`offline_verify.sh` records five artifacts under `results/pi5/`:
- `interfaces.json` (must show no non-loopback `UP` interface)
- `routes.json` (must show no external default route)
- `offline-environment.json` (preflight device/runtime check; `NOT_EXECUTED` precedes the traced run)
- `network.trace` (`strace -f -e trace=network`; `grep -E 'AF_INET|AF_INET6' network.trace` must exit 1 with zero matches)
- `offline-benchmark.json` (must show `5/5` `llama_validated_count`, `0` fallbacks, Pi 5 device model, and matching manifest SHA-256)

**Current offline status (`VERIFIED`):** Audited in `results/pi5/offline-20261119/` (`SHA256SUMS` 6/6 `OK`, recorded `2026-11-19T12:15:54Z`): `eth0` and `wlan0` `DOWN` (`lo` only), empty `routes.json` (`[]`), `offline-environment.json` `PASSED`, **5/5** validated Llama explanations (`0` fallbacks, `6.80 s` p95, `1.44 GB` / `1.34 GiB` RSS, `0 B` swap, `73.25 °C` max, `throttled=0x0`), zero `AF_INET`/`AF_INET6` matches in `network.trace`, and `inference.json` SHA-256 `a4f1f80b...` matching B0.
