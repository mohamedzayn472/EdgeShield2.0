# Raspberry Pi 5 — 4 GB deployment

The owner now has a 4 GB Pi 5. Physical execution is still pending. The app,
frozen detectors, exported SpinQuant model, tokenizer, firewall, validator and
fixed advice carry forward. Do not retrain or re-export solely because the
board changed. A target runtime still needs actual loader and inference tests.

Current Raspberry Pi OS is based on Debian Trixie; select the **64-bit** image.
Source: [official OS downloads](https://www.raspberrypi.com/software/operating-systems/),
checked 17 November 2026. OS Lite is a reasonable option on 4 GB to leave more
memory for inference. An existing desktop installation can be tested first.

## Version support

Universal OS/Python support is not established. The application declares
Python >=3.10,<3.14. `deploy/pi5/setup.sh` resolves the pinned dependencies for
the device's actual interpreter, requires binary wheels, and caches them for
offline installs. The old CPython 3.11 wheelhouse cannot serve every Python
version. Native Llama runs as a separate C++ executable; its compatibility
depends on CPU instructions and system libraries rather than Python version.

If Python is outside the supported range, use a separately installed supported
interpreter via `EDGESHIELD_PYTHON=/absolute/path/to/python3.13`; do not replace
system Python. Missing native wheels or loader failures require resolving the
actual mismatch. Changing dependency pins requires regression testing.

## On the Pi

Copy the updated source tree or a newly generated source bundle to the Pi;
exclude laptop venvs and build directories. First inspect:

```bash
cat /etc/os-release
uname -m
python3 --version
free -h
getconf GNU_LIBC_VERSION
```

`uname -m` must report `aarch64`. Provision OS tools while online:

```bash
sudo apt update
sudo apt install python3-venv python3-pip time strace iproute2 libatomic1 libstdc++6
cd ~/edgeshield
bash deploy/pi5/setup.sh
```

This creates a fresh `.venv`; it refuses to overwrite an existing environment.
For later clean offline installations, retain its generated
`wheelhouse/pi5-cp*-aarch64/` including `SHA256SUMS`, and use `setup.sh --offline`.
Those hashes detect changed downloads; they are not independent authentication.
Setup verifies board, architecture, supported Python, disk and >=3 GiB visible
RAM. The memory threshold only permits a 4 GB trial; it is not a measured
inference requirement or proof of available memory.

## Runtime assets

Use the existing real exported `llama3_2.pte` and matching `tokenizer.model`.
Retain the Llama license and Notice. Stage a trusted aarch64 runtime into
`models/llama/llama_main` and `models/llama/libllama_runner.so`.
The saved `pi4-aarch64` Cortex-A72 runtime is a candidate for an initial Pi5
smoke test; its Pi5 execution has not been verified. Do not rename it and claim
it was built with Pi5 flags. The later Bookworm ELF audit records GLIBC <=2.34;
the older `pi4-aarch64-glibc238` files have different requirements.

For a dedicated Pi5 build, the pinned upstream workflow accepts
`bash examples/raspberry_pi/setup.sh pi5 --skip-env-setup`. Run that in a
separate checkout named `executorch` at commit
`985c1ceccc8bb8b6a32294f71aeb5d2f299562f7`, with its own build output and the
provisioned export environment. Preserve existing host/Pi4 outputs. Audit the
resulting ELF architecture and GLIBC/GLIBCXX dependencies before transfer.

After staging real assets:

```bash
chmod u+x models/llama/llama_main
.venv/bin/python deploy/pi4/create_manifest.py \
  --runner models/llama/llama_main --model models/llama/llama3_2.pte \
  --tokenizer models/llama/tokenizer.model \
  --library models/llama/libllama_runner.so \
  --arch aarch64 --output configs/inference.json
.venv/bin/python deploy/pi5/verify_environment.py \
  --runtime configs/inference.json --output results/pi5/environment.json
bash deploy/pi5/smoke_test.sh
bash deploy/pi5/launch.sh --repeat
```

The shared manifest generator records hashes and aarch64 architecture, not
board compatibility. Actual smoke output must show `Llama (validated)`.
A successful template fallback does not establish model inference.

## Device evidence

```bash
bash deploy/pi5/diagnostic.sh
bash deploy/pi5/benchmark.sh
```

Monitor native runner RSS/VmHWM, available RAM, swap, temperature and throttling
during the 600-second benchmark. Stop and diagnose OOM or heavy swap activity.
Start with the existing two-thread runtime configuration; tune only after a
successful measured run. Host RSS and speed do not predict Pi5 results.

From a local console, disable connectivity and unplug Ethernet before:

```bash
bash deploy/pi5/offline_verify.sh
```

Results go to `results/pi5/`, leaving Pi4 evidence separate. The script requires
real validated Llama output and checks its process-tree network trace. All
Pi5 installation, ABI, memory, speed, sustained and offline claims remain
`PENDING_HARDWARE` until these commands run on the physical device.
