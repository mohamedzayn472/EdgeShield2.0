# V2 final evaluation plan

Registered before v2 final predictions, 16 November 2026.

The v1 model, code, data and report stay unchanged. Its poor Indian/Hinglish results are the reason for this new experiment, not a test set to tune against.

## What is new

A separate authoring agent prepares development examples. Another agent writes a fresh heldout set without reading development data, model code or earlier test messages. Both sets are AI-assisted synthetic data. Separate authoring does not make them independently human-labeled or representative of real messages. Human label review remains a submission gate.

The modeling agent may use UCI training/calibration/validation partitions and the new development partitions. It must not inspect the new holdout. The original UCI test is a regression comparison, not a newly untouched dataset.

## Audit before predictions

Require unique IDs, declared sources, allowed labels and family-exclusive development partitions. Compare canonicalized text and character 3–5 gram cosine similarity across development and holdout, without printing text or running detector predictions. Exclude heldout examples with canonical matches or cosine similarity >=0.90 against development or UCI training/calibration/validation. Keep their IDs and similarity values in the audit. This rule is fixed before inspecting any prediction. Report excluded counts; never silently replace an excluded item after results are seen.

Hash the model, inference source, training source, protocol, audit and both synthetic datasets before final evaluation. Run once and refuse overwriting the report. Any later change is a new experiment with a new report, not a correction to this result.

## Provisional engineering gates

These are project acceptance checks, not competition rules or promises about real-world performance:

- At least 40 labeled heldout examples per class after exclusions.
- SCAM recall >=80%, false-positive rate <=5%, and abstention <=30% overall.
- For each language: at least 20 examples per class, SCAM recall >=80%, false-positive rate <=5%, and abstention <=30%.
- Report the fraction of scams assigned LEGITIMATE separately. A low false-positive rate must not hide missed scams.

Report precision, recall, F1, false-positive rate, coverage, abstention and the binary-truth/three-band matrix. Precision/recall for a subset without positive labels are unavailable rather than a success claim. Store error IDs, labels, scores and bands without message text. Ambiguous messages have null labels and are reported qualitatively, outside supervised metrics.

Passing these checks would support a stronger synthetic-tested prototype. Submission readiness still needs human review of labels, approved Llama assets, genuine Arm ExecuTorch inference, offline trace, device measurements and the actual demo video. If a gate fails, preserve and disclose it.
