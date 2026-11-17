"""Train on training partition, calibrate separately, select using validation only."""
import json
from pathlib import Path
import numpy as np
import sklearn
from scipy.special import expit
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, log_loss
from edgeshield.datasets import read_jsonl, digest
from edgeshield.detector import Detector, MODEL_VERSION, save_artifact

ROOT = Path(__file__).resolve().parents[1]


def select_thresholds(y, scores):
    # Maximize coverage subject to observed validation FPR <= 1% and
    # missed-positive fraction <= 5%. These are selection criteria, not guarantees.
    best = None
    for low in np.arange(0.05, 0.50, 0.025):
        for high in np.arange(0.50, 0.976, 0.025):
            fp = np.mean(scores[y == 0] >= high)
            missed = np.mean(scores[y == 1] <= low)
            coverage = np.mean((scores <= low) | (scores >= high))
            if fp <= 0.01 and missed <= 0.05:
                rank = (coverage, -fp, -missed, -low, high)
                if best is None or rank > best[0]:
                    best = (rank, float(low), float(high))
    if best is None:
        # Explicit abstention-only fallback; positive/negative exact endpoints are rare.
        return [0.0, 1.0], "NO_VALIDATION_CANDIDATE"
    return [round(best[1], 5), round(best[2], 5)], "SELECTED_ON_VALIDATION"


def main():
    partitions = {s: read_jsonl(ROOT / f"data/processed/{s}.jsonl") for s in ("train", "calibration", "validation")}
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2, max_features=20000)
    train = partitions["train"]
    matrix = vectorizer.fit_transform([r["text"] for r in train])
    model = LogisticRegression(class_weight="balanced", C=1.0, solver="liblinear", max_iter=1000, random_state=20261115)
    model.fit(matrix, [r["label"] for r in train])
    logits, labels = {}, {}
    for s in ("calibration", "validation"):
        rows = partitions[s]
        logits[s] = model.decision_function(vectorizer.transform([r["text"] for r in rows]))
        labels[s] = np.array([r["label"] for r in rows])
    calibrator = LogisticRegression(C=1000, solver="lbfgs", max_iter=1000)
    calibrator.fit(logits["calibration"].reshape(-1, 1), labels["calibration"])
    a, b = float(calibrator.coef_[0, 0]), float(calibrator.intercept_[0])
    raw = expit(logits["validation"])
    calibrated = expit(a * logits["validation"] + b)
    y = labels["validation"]
    comparison = {name: {"brier": float(brier_score_loss(y, p)), "log_loss": float(log_loss(y, p))} for name, p in (("uncalibrated", raw), ("sigmoid", calibrated))}
    use_calibration = a > 0 and comparison["sigmoid"]["brier"] < comparison["uncalibrated"]["brier"] and comparison["sigmoid"]["log_loss"] < comparison["uncalibrated"]["log_loss"]
    scores = calibrated if use_calibration else raw
    thresholds, threshold_status = select_thresholds(y, scores)
    artifact = {"format": 1, "model_version": MODEL_VERSION, "vocabulary": vectorizer.vocabulary_,
                "idf": vectorizer.idf_.tolist(), "coef": model.coef_[0].tolist(), "intercept": float(model.intercept_[0]),
                "calibration": [a, b] if use_calibration else [1.0, 0.0], "thresholds": thresholds,
                "training": {"sklearn": sklearn.__version__, "source": "UCI SMS Spam Collection", "seed": 20261115,
                             "train_sha256": digest(ROOT / "data/processed/train.jsonl"), "calibration_sha256": digest(ROOT / "data/processed/calibration.jsonl"),
                             "validation_sha256": digest(ROOT / "data/processed/validation.jsonl")}}
    artifact["vocabulary"] = {k: int(v) for k, v in artifact["vocabulary"].items()}
    save_artifact(ROOT / "models/detector.json", artifact)
    loaded = Detector.load(ROOT / "models/detector.json")
    np.testing.assert_allclose(loaded.scores([r["text"] for r in partitions["validation"]]), scores, rtol=1e-12, atol=1e-12)
    report = {"partition": "validation", "calibration_comparison": comparison, "calibration_selected": use_calibration,
              "thresholds": thresholds, "threshold_status": threshold_status, "serialization_parity": "PASSED",
              "n": len(y), "validation_observed_false_positive_rate": float(np.mean(scores[y == 0] >= thresholds[1])),
              "validation_missed_positive_fraction": float(np.mean(scores[y == 1] <= thresholds[0])),
              "validation_abstention_rate": float(np.mean((scores > thresholds[0]) & (scores < thresholds[1]))),
              "heldout_test": "NOT_EXECUTED", "model_sha256": digest(ROOT / "models/detector.json")}
    (ROOT / "results/host/training_validation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
