"""Finite preregistered v2 development search. Never reads final-test files."""
from __future__ import annotations
import json
from pathlib import Path
import warnings
import numpy as np
from scipy import sparse
from scipy.special import expit
from sklearn.exceptions import ConvergenceWarning
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, log_loss
from edgeshield.datasets import canonical, check_leakage, digest, group_near_duplicates, read_jsonl
from edgeshield.detector_v2 import DetectorV2, MODEL_VERSION, save_artifact
from edgeshield.privacy import normalize_sms

ROOT = Path(__file__).resolve().parents[1]
SPLITS = ("train", "calibration", "validation")
PARAMETERS = [(c, weight) for c in (1, 4, 16) for weight in (2, 6)]


def development_data():
    synthetic = read_jsonl(ROOT / "data/synthetic/v2_development.jsonl")
    if not synthetic:
        raise ValueError("Synthetic development dataset is empty")
    ids = set()
    for row in synthetic:
        if row.get("split") not in SPLITS or type(row.get("label")) is not int or row["label"] not in (0, 1):
            raise ValueError("Invalid development split or label")
        if not all(type(row.get(k)) is str and row[k] for k in ("id", "family", "language", "source")):
            raise ValueError("Missing synthetic provenance")
        if not row["source"].startswith("synthetic") or row["id"] in ids:
            raise ValueError("Invalid synthetic source or duplicate ID")
        row["text"] = normalize_sms(row["text"])
        ids.add(row["id"])
    check_leakage(synthetic)
    groups = group_near_duplicates(synthetic)
    near_splits = {}
    for row, group in zip(synthetic, groups):
        if group in near_splits and near_splits[group] != row["split"]:
            raise ValueError("Cross-split near-duplicate synthetic development text")
        near_splits[group] = row["split"]
    parts = {}
    for split in SPLITS:
        target = [r for r in synthetic if r["split"] == split]
        if any(sum(r["label"] == label for r in target) < 10 for label in (0, 1)):
            raise ValueError("Each development split requires at least ten examples per class")
        source = read_jsonl(ROOT / f"data/processed/{split}.jsonl")
        for row in source:
            row["text"] = normalize_sms(row["text"])
        parts[split] = {"uci": source, "synthetic": target}
    # UCI and synthetic sources cannot conceal an exact duplicate across partitions.
    combined = [dict(r, group=f"{source}:{r.get('group', r.get('family'))}")
                for part in parts.values() for source, rows in part.items() for r in rows]
    check_leakage(combined)
    return parts


def feature_block(vectorizer):
    return {"vocabulary": {k: int(v) for k, v in vectorizer.vocabulary_.items()}, "idf": vectorizer.idf_.tolist()}


def summary(y, scores, low, high, known=None):
    y = np.asarray(y, dtype=int)
    scores = np.asarray(scores, dtype=float)
    if known is None:
        known = np.ones(len(y), dtype=bool)
    positive = (scores >= high) & known
    negative = (scores <= low) & known
    tp = int(np.sum(positive & (y == 1)))
    fp = int(np.sum(positive & (y == 0)))
    positives = int(np.sum(y == 1))
    negatives = int(np.sum(y == 0))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / positives if positives else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"n": len(y), "positive_count": positives, "negative_count": negatives,
            "precision": precision, "recall": recall, "f1": f1,
            "false_positive_rate": fp / negatives if negatives else None,
            "positive_as_legitimate_rate": int(np.sum(negative & (y == 1))) / positives if positives else None,
            "coverage": float(np.mean(positive | negative)), "abstention_rate": float(np.mean(~(positive | negative))),
            "confusion_matrix_2_by_3": [[int(np.sum((y == label) & negative)), int(np.sum((y == label) & ~(positive | negative))), int(np.sum((y == label) & positive))] for label in (0, 1)]}


def choose_thresholds(labels, scores, known):
    best = None
    for lower in np.arange(0, .451, .025):
        for upper in np.arange(.20, 1.001, .025):
            low, high = round(float(lower), 6), round(float(upper), 6)
            if low >= high:
                continue
            metrics = {name: summary(labels[name], scores[name], low, high, known[name]) for name in labels}
            target, uci = metrics["synthetic"], metrics["uci"]
            fpr_ok = target["false_positive_rate"] <= .05 and uci["false_positive_rate"] <= .02
            passed = fpr_ok and target["recall"] >= .85 and target["positive_as_legitimate_rate"] <= .10 and target["coverage"] >= .70 and uci["recall"] >= .80
            rank = (passed, fpr_ok, target["recall"], -target["false_positive_rate"], target["coverage"], uci["f1"], -target["positive_as_legitimate_rate"], uci["coverage"])
            if best is None or rank > best["rank"]:
                best = {"rank": rank, "thresholds": [low, high], "metrics": metrics, "validation_quality_gate": "PASSED" if passed else "FAILED"}
    return best


def main():
    output = ROOT / "results/host/v2"
    output.mkdir(parents=True, exist_ok=True)
    protocol_hash = digest(ROOT / "docs/EVALUATION_V2.md")
    # Protect experiment order; do not train after a final evaluation has been saved.
    if any(output.glob("*heldout*")) or any(output.glob("*freeze*")):
        raise SystemExit("V2 freeze/final evaluation already exists; preserve this experiment")
    parts = development_data()
    hashes = {f"data/processed/{s}.jsonl": digest(ROOT / f"data/processed/{s}.jsonl") for s in SPLITS}
    hashes["data/synthetic/v2_development.jsonl"] = digest(ROOT / "data/synthetic/v2_development.jsonl")
    rows = {split: sum((part[source] for source in ("uci", "synthetic")), []) for split, part in parts.items()}
    word = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2, max_features=25000)
    char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=2, max_features=40000)
    texts = [r["text"] for r in rows["train"]]
    x_train = sparse.hstack((word.fit_transform(texts), char.fit_transform(texts)), format="csr")
    y_train = np.array([r["label"] for r in rows["train"]])
    matrices, labels, known = {}, {}, {}
    for split in ("calibration", "validation"):
        matrices[split], labels[split], known[split] = {}, {}, {}
        for source, subset in parts[split].items():
            text = [r["text"] for r in subset]
            matrix = sparse.hstack((word.transform(text), char.transform(text)), format="csr")
            matrices[split][source] = matrix
            labels[split][source] = np.array([r["label"] for r in subset])
            known[split][source] = np.diff(matrix.indptr) > 0
    candidates, best = [], None
    for c, multiplier in PARAMETERS:
        sample_weight = np.concatenate((np.ones(len(parts["train"]["uci"])), np.full(len(parts["train"]["synthetic"]), multiplier)))
        model = LogisticRegression(C=c, class_weight="balanced", solver="liblinear", max_iter=2000, random_state=20261116)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", ConvergenceWarning)
                model.fit(x_train, y_train, sample_weight=sample_weight)
        except ConvergenceWarning:
            candidates.append({"C": c, "synthetic_weight": multiplier, "status": "FAILED_CONVERGENCE"})
            continue
        logits = {split: {source: model.decision_function(matrix) for source, matrix in matrices[split].items()} for split in matrices}
        calibration_x = np.concatenate([logits["calibration"][s] for s in ("uci", "synthetic")])
        calibration_y = np.concatenate([labels["calibration"][s] for s in ("uci", "synthetic")])
        calibration_weights = np.concatenate([np.full(len(labels["calibration"][s]), len(calibration_y) / (2 * len(labels["calibration"][s]))) for s in ("uci", "synthetic")])
        calibrator = LogisticRegression(C=10, solver="lbfgs", max_iter=2000)
        with warnings.catch_warnings():
            warnings.simplefilter("error", ConvergenceWarning)
            calibrator.fit(calibration_x.reshape(-1, 1), calibration_y, sample_weight=calibration_weights)
        a, b = float(calibrator.coef_[0, 0]), float(calibrator.intercept_[0])
        raw = {s: expit(v) for s, v in logits["validation"].items()}
        calibrated = {s: expit(a * v + b) for s, v in logits["validation"].items()}
        comparison = {}
        for name, values in (("raw", raw), ("sigmoid", calibrated)):
            comparison[name] = {s: {"brier": float(brier_score_loss(labels["validation"][s], p)), "log_loss": float(log_loss(labels["validation"][s], p))} for s, p in values.items()}
            comparison[name]["macro_brier"] = float(np.mean([m["brier"] for m in comparison[name].values()]))
            comparison[name]["macro_log_loss"] = float(np.mean([comparison[name][s]["log_loss"] for s in ("uci", "synthetic")]))
        use_calibration = a > 0 and all(comparison["sigmoid"][metric] < comparison["raw"][metric] for metric in ("macro_brier", "macro_log_loss"))
        scores = calibrated if use_calibration else raw
        chosen = choose_thresholds(labels["validation"], scores, known["validation"])
        record = {"C": c, "synthetic_weight": multiplier, "status": "TRAINED", "calibration_selected": use_calibration,
                  "calibration_comparison": comparison, **chosen}
        candidates.append(record)
        if best is None or chosen["rank"] > best["record"]["rank"]:
            best = {"record": record, "model": model, "calibration": [a, b] if use_calibration else [1.0, 0.0], "scores": scores}
    if best is None:
        raise RuntimeError("No classifier candidate converged")
    artifact = {"format": 2, "model_version": MODEL_VERSION, "word": feature_block(word), "char": feature_block(char),
                "coef": best["model"].coef_[0].tolist(), "intercept": float(best["model"].intercept_[0]),
                "calibration": best["calibration"], "thresholds": best["record"]["thresholds"],
                "training": {"seed": 20261116, "C": best["record"]["C"], "synthetic_weight": best["record"]["synthetic_weight"],
                             "protocol_sha256": protocol_hash, "data_sha256": hashes, "quality_scope": "experimental_synthetic_trained"}}
    model_path = ROOT / "models/detector_v2.json"
    save_artifact(model_path, artifact)
    loaded = DetectorV2.load(model_path)
    for source in ("uci", "synthetic"):
        np.testing.assert_allclose(loaded.scores([r["text"] for r in parts["validation"][source]]), best["scores"][source], rtol=1e-11, atol=1e-12)
    report = {"scope": "DEVELOPMENT VALIDATION ONLY; synthetic-trained experimental model, no real-world accuracy claim",
              "protocol_sha256": protocol_hash, "data_sha256": hashes, "model_sha256": digest(model_path),
              "split_counts": {split: {source: len(subset) for source, subset in part.items()} for split, part in parts.items()},
              "synthetic_development_leakage_check": "PASSED", "serialization_parity": "PASSED", "candidates": candidates,
              "selected": best["record"], "fresh_holdout": "NOT_READ_OR_EVALUATED"}
    (output / "training_validation.json").write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("model_sha256", "split_counts", "serialization_parity", "selected", "fresh_holdout")}, indent=2))


if __name__ == "__main__":
    main()
