# V2 development and evaluation protocol

Registered before fitting v2 on 2026-11-16. V1 artifacts, source, protocol and results stay unchanged. This protocol describes an experimental synthetic-trained model, not a validated real-world scam detector.

## Data boundary

Use only the existing UCI training, calibration and validation partitions and `data/synthetic/v2_development.jsonl`. Do not read or evaluate either UCI final test messages, v1 synthetic heldout messages or `data/synthetic/v2_holdout.jsonl` while selecting v2. Synthetic development rows must specify binary label, family, language and train/calibration/validation split. A family cannot cross splits. Reject normalized exact duplicates across splits. Run character-neighbor leakage checks on synthetic development data and require no cross-split cosine similarity >=0.90 after URL/number canonicalization. Human review is still needed for semantically related templates below that threshold.

Require at least ten examples of each class in synthetic calibration and validation. This is a minimum execution guard, not sufficient evidence for population performance. All synthetic data must be identified as such, with fictional details and provenance. No private inbox access or live user SMS collection.

## Fixed candidates

Fit the classifier TF-IDF transforms on combined training data only: word unigrams/bigrams (sublinear TF, min_df=2, maximum 25000 terms) and character-within-word 3-5 grams (sublinear TF, min_df=2, maximum 40000 terms). Concatenate the two individually L2-normalized blocks, giving them equal fixed weight. Retain the standard production Unicode/input normalization. Unknown-feature messages abstain.

Fit binary logistic regression, balanced class weights, liblinear solver, max_iter=2000 and seed 20261116. The complete finite search is C in {1,4,16} crossed with synthetic sample multiplier in {2,6}: six candidates. No manually encoded verdicts, trigger phrases, sender names or demonstration exceptions. Deterministic indicators remain explanation evidence and do not override these predictions. If the solver does not converge, report the candidate as failed rather than silently increasing the search.

For each candidate, fit one sigmoid calibrator on separate calibration logits. Weight UCI and synthetic calibration sources equally in total; preserve each source's observed class proportions. Calibrator is logistic regression with C=10 and max_iter=2000. Compare raw and calibrated scores on validation using equal-source macro averages of Brier loss and log loss. Retain calibration only if both improve and slope is positive. Brier also reflects discrimination; this is not proof of calibration on real-world scam prevalence.

## Validation selection

Evaluate UCI and synthetic validation separately. Search lower thresholds {0,0.025,...,0.45} and upper thresholds {0.20,0.225,...,0.975,1.0}, requiring lower < upper. Lower endpoint is LEGITIMATE, upper endpoint SCAM; middle and unknown-feature messages are UNCERTAIN. Positive recall counts all abstained positives as missed. False-positive rate uses all ground-truth negatives as denominator. Coverage is the non-abstained fraction.

The provisional validation gate requires synthetic scam recall >=85%, synthetic false-positive rate <=5%, synthetic positive assigned LEGITIMATE <=10%, synthetic coverage >=70%, UCI spam recall >=80% and UCI false-positive rate <=2%. These are project selection criteria, not competition rules, achieved results or safety guarantees. Small synthetic counts make these rates coarse and optimistic for generalization. The final fresh-synthetic gate, coordinated by root before opening final results, is recall >=80%, false-positive rate <=5%, abstention <=30%; language slices and false-LEGITIMATE rate must also be reported.

Rank passing candidate/threshold combinations first. Within passing combinations maximize synthetic recall, then minimize synthetic false-positive rate, then maximize synthetic coverage, then maximize UCI F1, then minimize synthetic positive assigned LEGITIMATE, then maximize UCI coverage. If none passes, rank combinations meeting both source false-positive ceilings first, then use the same ordering and explicitly mark the quality gate FAILED. Stable loop order breaks remaining ties. Do not relax gates or expand the search after seeing results. Save all candidate calibration comparisons, selected thresholds and source-separated validation metrics.

## Freeze and final evaluation

Before opening fresh heldout data, freeze model, source, preparation/training scripts, protocol and final-test hashes. Root coordinates the final evaluation separately from this modeling agent under `docs/V2_FINAL_EVALUATION.md`. Before any predictions, quarantine heldout rows with canonical-exact or character-cosine >=0.90 matches against development/UCI training, calibration or validation data; preserve the sealed source hash and report excluded IDs and counts. Require at least 40 remaining examples per class overall and 20 per class in each language; otherwise the final gate cannot pass. Family leakage must also be reported and resolved without seeing predictions. Do not regenerate or replace examples after any final predictions. Development cross-split duplicate checks still reject training input rather than silently removing rows.

Evaluate once on the eligible fresh family-heldout synthetic set and report sample counts, class distribution, language/scenario slices, precision/recall/F1, false-positive rate, abstention/coverage and binary-truth-by-three-decision confusion matrices. Keep errors and abstentions as ID/label/band/score records without corpus text. No post-result threshold changes or replacement test data are permitted for this experiment.

Since v1 UCI and synthetic final results have been inspected by the project, they are not fresh v2 confirmation data. Any subsequent v2 evaluation there is a clearly labeled regression/exploratory comparison; do not call it an untouched test. New final synthetic results still cannot establish real-world Indian accuracy, even if the provisional gate passes. Independent human labels and representative licensed data remain necessary.

No v2 model is promoted solely because training or software tests succeed. Genuine Llama/ExecuTorch inference, offline proof and physical Pi verification remain separate gates.
