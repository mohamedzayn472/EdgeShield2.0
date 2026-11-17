# Detector artifact

`detector.json` is a plain-JSON TF-IDF vocabulary, IDF vector, binary logistic regression coefficients, validation-selected sigmoid transform and thresholds. `detector.json.sha256` is required by the loader. Both must come from a trusted release; a replaceable sidecar is integrity checking, not a signature.

Trained on the public UCI SMS Spam Collection only. Score is a historical spam proxy and must not be called a verified scam probability. The three UI bands are not three trained classes. Unknown-vocabulary inputs abstain. The artifact contains training vocabulary tokens, so train only on approved public data; do not train it on a private inbox.

Host training executed twice with the same fixed split and seed. Both generated identical SHA-256 `9163c20783d76eb1c3cea637dea844e4d1c7d61bec976cd64cb0b69a20cd4c72` (437905 bytes). Validation sigmoid selection and serialization parity results are in `results/host/training_validation.json`. Actual heldout results, when authorized after freeze, are written separately.

No Llama model is included in this detector artifact. This classifier uses ordinary Python/scikit-learn and is not an ExecuTorch program.

Final evaluation has now executed: see `results/host/heldout_evaluation.json`. Indian/Hinglish challenge quality FAILED (1/12 scams detected; Hinglish 0/6). Preserve the frozen v1 artifact and read `docs/DETECTOR_FINDINGS.md` before use.
