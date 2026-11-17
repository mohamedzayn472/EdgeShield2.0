# Offline detector dependencies

This directory stores verified target-only binary wheels (`aarch64` Linux) for offline installation:

- `pi5-cp313-aarch64/`: Seven binary wheels cross-downloaded on Ubuntu (`requirements/pi5.txt`) for **CPython 3.13 `aarch64`** (current Raspberry Pi OS Trixie). Verified with `SHA256SUMS`.
- `pi4-cp311/`: Seven binary wheels downloaded from PyPI (`requirements/pi4.txt`) for **CPython 3.11 `aarch64` (`GLIBC >= 2.27`)** (Raspberry Pi OS Bookworm). Note: `deploy/pi5/setup.sh` automatically reuses `pi4-cp311/` to populate `wheelhouse/pi5-cp311-aarch64/` if the Pi 5 is running CPython 3.11.

To cross-download Pi 5 `aarch64` wheels on Ubuntu for another supported Python minor version (`3.10`, `3.11`, `3.12`, or `3.13`), run:

```bash
bash scripts/download_pi5_wheels.sh 3.12
```

Check all hashes in `SHA256SUMS` and `BUNDLE_MANIFEST.json` after transfer. Wheels retain their package license/notice metadata. Package versions are pinned in `requirements/pi4.txt` and `requirements/pi5.txt`.

Do not install these wheels on `x86_64` or a mismatched Python ABI.

Python, `python3-venv`, OS packages, and the Llama runner/shared libraries are separate prerequisites. Wheelhouses do not contain Llama or ExecuTorch inference assets.
