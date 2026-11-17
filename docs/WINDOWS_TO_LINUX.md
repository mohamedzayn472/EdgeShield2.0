> Ubuntu continuation: read [UBUNTU_VERIFICATION.md](UBUNTU_VERIFICATION.md) for verified Linux results and current blockers. Historical Windows results below remain unchanged.

# Windows work and the next Ubuntu session

The laptop uses dual boot. Windows cannot run commands in the separate Ubuntu installation while Ubuntu is shut down. The user reports downloading Llama in Linux; its exact model name, files and format have not yet been inspected.

## Windows

V2 is trained and selected using development data. The fresh 120-case synthetic test met the preregistered checks: 50/60 scams detected, 59/60 legitimate messages not flagged. Hinglish recall was 24/30. Ten scams received LEGITIMATE, so lower risk still must not be treated as safe. No real-world detection claim is justified. Human review remains pending.

Run the app from this project folder:

```powershell
.venv\Scripts\python.exe -m edgeshield.cli --repeat
```

The default model is v2. To reproduce v1 behavior, add `--detector models/detector.json`. The current app uses template explanations until the actual ExecuTorch artifacts are configured. The failed v1 record and both versioned final evaluations are retained.

The transfer archive is `dist/edgeshield-pi4-preparation.zip`. Copy it somewhere Ubuntu can access, such as a shared data partition or a USB drive. Keep a separate copy of the approved model in Linux; it is not included in this archive. Neither Windows Python environments nor Windows binaries belong in the Pi installation.

## Next time Ubuntu is running

Extract the archive into a normal Linux working directory. Before exporting, collect:

```bash
uname -m
python3 --version
free -h
```

Also identify the downloaded model directory and its filenames. The selected workflow expects the **SpinQuant INT4 EO8 Instruct 1B** checkpoint, matching `params.json` and original `tokenizer.model`. A model ending in GGUF, a different Llama size, ordinary non-quantized weights or a `tokenizer.json` alone cannot be assumed compatible. Do not rename files to mimic the expected format.

Follow `docs/EXECUTORCH.md` to provision the pinned Linux export/build environment. Export `.pte`, build with `setup.sh pi4`, and retain the actual logs and hashes. That is the next technical gate; downloading the checkpoint does not demonstrate export or inference success.

## At the lab

The Pi4 exists but is not yet set up for this project. Follow `docs/LAB_CHECKLIST.md` and `docs/PI4_DEPLOYMENT.md`. Install target dependencies, verify the model/runtime manifest and loader, run real Llama generation, then record offline/network-trace and sustained benchmark evidence. The project cannot be called submission-ready before these tests and the demo/report are done.
