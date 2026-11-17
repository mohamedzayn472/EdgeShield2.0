# V2 results and remaining limits

V2 uses word and character TF-IDF features with logistic regression. Training combines the original UCI training partition with 288 synthetic development examples. Separate calibration and validation partitions choose calibration, regularization, sample weighting and thresholds. Neither final test set was used for selection.

The development corpus has 432 examples in 72 families. A different authoring agent wrote 132 fresh heldout examples without reading that corpus or model code: 120 labeled cases and 12 ambiguous ones. These are AI-assisted fictional messages, not real SMS or independently reviewed human labels. Six variants of one development family remain correlated examples, not six independent campaigns.

The pre-prediction audit found no canonical or >=0.90 character-cosine matches between the fresh holdout and development/reference training data. That heuristic does not establish semantic independence. The model, code, protocol, data and audit hashes were frozen before the one-time evaluation.

## Fresh synthetic test

- 120 labeled cases: 60 scams and 60 legitimate messages.
- 50 scams detected; 10 incorrectly assigned LEGITIMATE; no cases abstained.
- One false alarm among 60 legitimate examples.
- Precision 98.04%, recall 83.33%, F1 0.9009; false-positive rate 1.67%.
- English: 26/30 scams detected, no false alarms among 30 legitimate examples.
- Hinglish: 24/30 scams detected, one false alarm among 30 legitimate examples.

These results pass the provisional synthetic checks registered in `V2_FINAL_EVALUATION.md`. They do not pass an unmeasured real-world quality gate. In particular, the ten falsely reassuring LEGITIMATE decisions matter. The narrow validation-selected uncertainty band produced no abstentions here; selective classification alone did not protect those ten cases.

V1 and v2 used different fresh synthetic tests, so do not present their recall percentages as a controlled before/after comparison. The old UCI test is explicitly a reused regression comparison for v2. All earlier failures remain recorded. No thresholds were changed after the fresh v2 result.

## Evidence and next work

See `results/host/v2/training_validation.json`, `data_audit.json`, `evaluation_freeze.json` and `heldout_evaluation.json`. The v2 JSON model and checksum are in `models/`.

Use v2 as an experimental prototype. Have the team review labels and add a representative, legally sourced evaluation before making deployment-quality claims. Any further model tuning needs another version and fresh confirmation data. Actual ExecuTorch export, Arm inference, offline testing, device measurements, human clarity study and video remain separate requirements.
