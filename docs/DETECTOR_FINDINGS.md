# Detector findings: Indian scam quality gate FAILED

The frozen baseline is a functioning, tested historical spam detector. It is **not an adequate Indian/Hinglish scam detector** on the project's challenge cases. Passing software tests and strong UCI scores do not establish suitability for the intended user scenario. Do not label this quality gate PASSED or describe a LEGITIMATE decision as authentication or proof of safety.

## Executed evidence

The root agent executed one final evaluation after freezing the source, protocol, model and test datasets. The recorded evidence is `results/host/evaluation_freeze.json` and `results/host/heldout_evaluation.json`. Model SHA-256: `9163c20783d76eb1c3cea637dea844e4d1c7d61bec976cd64cb0b69a20cd4c72`.

On 1,148 UCI examples, SCAM-band precision was 98.01%, recall 90.24% and F1 0.9397. Three of 984 ham examples were classified SCAM: false-positive rate 0.305%. Of 164 spam examples, 148 were SCAM, nine UNCERTAIN and seven LEGITIMATE. Nineteen total examples abstained (1.66%). These are historical spam/ham results, not modern fraud detection accuracy.

On 24 labeled synthetic Indian/Hinglish examples, only **one of 12 scam examples** was classified SCAM: recall **8.33%**, F1 **0.1538**. Four scam examples abstained and seven were incorrectly assigned LEGITIMATE. None of the 12 legitimate examples was classified SCAM, but five abstained. Overall abstention was 37.5%. The observed 100% precision comes from just one positive prediction and is not a credible standalone success claim.

The Hinglish subset contained ten examples: four legitimate and six scam. **Zero of six scam examples was classified SCAM**. Five were assigned LEGITIMATE and one UNCERTAIN. Two legitimate examples abstained. Zero Hinglish scam recall is a serious failure on these cases; the small sample does not permit an estimate of population-level performance.

The legitimate-only subset has no positive ground truth, so its stored zero precision/recall/F1 values are the evaluator's `zero_division=0` convention, not meaningful positive-class quality measures. Its useful observations are 0/12 false positives and 5/12 abstentions. Four ambiguous/adversarial synthetic cases have null labels and were excluded from supervised metrics.

## Interpretation and limits

The model learned English word unigrams/bigrams from historical UCI spam and ham only. Current payment-collection, KYC, impersonation and Romanized Hindi language patterns can differ substantially. This domain/language shift is a plausible explanation for failure, not a proven causal analysis. Calibration and thresholds were learned using the same source domain; improving UCI validation Brier loss does not calibrate Indian scam probabilities.

The deterministic indicator subsystem can identify selected cues, but those cues do not independently establish fraud or automatically override the frozen classifier. Llama only explains structured evidence and must not repair detection by reading the raw SMS. Neither an explanation nor fallback changes the measured detector quality.

Synthetic cases are AI-assisted project-written fictional examples, with family-exclusive development/test splits. They were not independently human-labeled and are not representative prevalence samples. Their failures reveal concrete weaknesses; their rates must not be presented as real-world Indian accuracy. Likewise, there is no evidence that the favorable UCI score generalizes to the target population.

## Preserve this result

Keep the baseline model, source, protocol, freeze manifest and final results unchanged. Do not lower thresholds, add keyword overrides or select new demonstration messages after viewing these results and then report this test set as untouched. These 24 labeled examples are now inspected regression/development evidence for future work. Any reused-set metrics must be labeled exploratory. No additional experiment on this baseline was performed for this findings document.

## Proposed v2 work, not implemented

1. Write a new protocol and define target-domain quality gates before fitting. Specify recall, legitimate-message false-positive tolerance, abstention/coverage, minimum per-language and per-scenario sample counts, and how uncertainty is reported. Agree numerical targets with the team; no new targets are retroactively assigned to this run.
2. Obtain legally usable, consented or appropriately public target-domain data. Retain provenance and licensing. Develop fictional synthetic training examples across scam and legitimate banking, OTP, UPI, KYC, delivery, job and payment contexts; mark them synthetic. Do not scrape private inboxes or treat AI-written labels as independent truth.
3. Have independent reviewers label examples using a written rubric, resolve disagreements and retain an ambiguous category outside forced binary scoring. Use fresh family/author/campaign groups for holdout, and prevent exact, near-duplicate and template leakage. Keep new test examples inaccessible to tuning; the current inspected challenge examples cannot be the new final holdout.
4. Fit an explicitly versioned augmented baseline. Evaluate plausible word/character features and language coverage using training and validation partitions only. Fit calibration separately and select thresholds only on validation. Any rule-assisted decision mechanism needs its own preregistered evaluation and must not encode demonstration answers.
5. Freeze v2 artifacts and evaluate once on the fresh target-domain holdout. Report UCI, independently sourced target data and synthetic subsets separately, including false-negative LEGITIMATE decisions, abstentions, sample counts and uncertainty. Preserve v1 results alongside v2 so the change is auditable.
6. Only after acceptable target-domain results and the separate genuine Llama/ExecuTorch, Arm-device and offline gates pass should the team claim the intended end-to-end scam-detection scenario is ready. Pi performance remains PENDING_HARDWARE.
