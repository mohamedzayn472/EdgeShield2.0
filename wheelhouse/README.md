# Offline detector dependencies

This directory stores verified target-only binary wheels (`aarch64` Linux) for offline installation:

- `pi5-cp313-aarch64/`: Seven binary wheels cross-downloaded on Ubuntu (`requirements/pi5.txt`) for **CPython 3.13 `aarch64`** (Raspberry Pi OS Trixie). Verified with `SHA256SUMS`.

To cross-download Pi 5 `aarch64` wheels on Ubuntu for another supported Python minor version (`3.10`, `3.11`, `3.12`, or `3.13`), run:

```bash
bash scripts/download_pi5_wheels.sh 3.12
```

Check all hashes in `SHA256SUMS` after transfer. Wheels retain their package license/notice metadata. Package versions are pinned in `requirements/pi5.txt`.

Do not install these wheels on `x86_64` or a mismatched Python ABI.

Python, `python3-venv`, OS packages, and the Llama runner/shared libraries are separate prerequisites. Wheelhouses do not contain Llama or ExecuTorch inference assets.
