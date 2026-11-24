"""Principled V3 development search with numeric/banking canonicalization.

Strictly uses train / calibration / validation splits only. Never reads holdout or test files.
"""
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
from edgeshield.datasets import check_leakage, digest, group_near_duplicates, read_jsonl
from edgeshield.detector_v3 import DetectorV3, MODEL_VERSION, canonicalize_features, save_artifact
from edgeshield.privacy import normalize_sms

ROOT = Path(__file__).resolve().parents[1]
SPLITS = ("train", "calibration", "validation")
PARAMETERS = [(c, w) for c in (1, 2, 4, 8) for w in (2, 4, 6)]


def development_data():
    synthetic = read_jsonl(ROOT / "data/synthetic/v3_development.jsonl")
    if not synthetic:
        raise ValueError("Synthetic V3 development dataset is empty")
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
    combined = [
        dict(r, group=f"{src}:{r.get('group', r.get('family'))}")
        for part in parts.values()
        for src, rows in part.items()
        for r in rows
    ]
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
    tn = int(np.sum(negative & (y == 0)))
    fn = int(np.sum(negative & (y == 1)))
    u0 = int(np.sum((~positive) & (~negative) & (y == 0)))
    u1 = int(np.sum((~positive) & (~negative) & (y == 1)))
    pos_n = int(np.sum(y == 1))
    neg_n = int(np.sum(y == 0))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / pos_n if pos_n else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(y) if len(y) else 0.0
    return {
        "n": int(len(y)),
        "positive_count": pos_n,
        "negative_count": neg_n,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fp / neg_n if neg_n else 0.0,
        "false_negative_rate": (fn + u1) / pos_n if pos_n else 0.0,
        "positive_as_legitimate_rate": fn / pos_n if pos_n else 0.0,
        "coverage": (tp + fp + tn + fn) / len(y) if len(y) else 0.0,
        "abstention_rate": (u0 + u1) / len(y) if len(y) else 0.0,
        "confusion_matrix_2_by_3": [[tn, u0, fp], [fn, u1, tp]],
    }


def fit_sigmoid(margins, labels, weights):
    # Use balanced class weighting during sigmoid calibration so UCI's 88:12 ham:spam base rate
    # does not shift calibrated scam scores downward on balanced synthetic evaluations.
    model = LogisticRegression(C=100.0, class_weight="balanced", max_iter=1000, random_state=20261120)
    model.fit(margins.reshape(-1, 1), labels, sample_weight=weights)
    return float(model.coef_[0][0]), float(model.intercept_[0])


def choose_thresholds(labels, scores, known):
    """Validation-only selective threshold selection with calibrated margin tie-breaking."""
    grid = [round(x, 4) for x in np.linspace(0.15, 0.80, 27)]
    best = None
    for low in grid:
        for high in grid:
            gap = round(high - low, 4)
            if gap < 0.10 or gap > 0.20:
                continue
            metrics = {s: summary(labels[s], scores[s], low, high, known[s]) for s in ("uci", "synthetic")}
            syn, uci = metrics["synthetic"], metrics["uci"]
            fpr_ok = syn["false_positive_rate"] <= 0.02 and uci["false_positive_rate"] <= 0.02
            rec_ok = syn["recall"] >= 0.90 and uci["recall"] >= 0.85
            abs_ok = syn["abstention_rate"] <= 0.05 and uci["abstention_rate"] <= 0.05
            macro_f1 = 0.5 * (syn["f1"] + uci["f1"])
            macro_acc = 0.5 * (syn["accuracy"] + uci["accuracy"])
            center_dist = abs(0.5 * (low + high) - 0.50) + 0.5 * abs(gap - 0.15)
            rank = (
                fpr_ok and rec_ok and abs_ok,
                fpr_ok,
                round(macro_f1, 4),
                round(macro_acc, 4),
                -round(max(syn["false_positive_rate"], uci["false_positive_rate"]), 4),
                -round(syn["positive_as_legitimate_rate"], 4),
                round(min(syn["recall"], uci["recall"]), 4),
                -round(center_dist, 4),
            )
            if best is None or rank > best["rank"]:
                best = {
                    "rank": rank,
                    "thresholds": [float(low), float(high)],
                    "metrics": metrics,
                    "validation_quality_gate": "PASSED" if (fpr_ok and rec_ok and abs_ok) else "FAILED",
                }
    return best


def main():
    parts = development_data()
    output = ROOT / "results/host/v3"
    output.mkdir(parents=True, exist_ok=True)
    hashes = {
        "v3_development": digest(ROOT / "data/synthetic/v3_development.jsonl"),
        **{f"uci_{s}": digest(ROOT / f"data/processed/{s}.jsonl") for s in SPLITS},
    }

    train_rows = parts["train"]["uci"] + parts["train"]["synthetic"]
    train_texts = [canonicalize_features(r["text"]) for r in train_rows]
    train_labels = np.array([r["label"] for r in train_rows], dtype=int)

    word = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), sublinear_tf=True, min_df=2, max_features=30000)
    char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=2, max_features=50000)
    x_train = sparse.hstack((word.fit_transform(train_texts), char.fit_transform(train_texts)), format="csr")

    matrices = {}
    labels = {}
    known = {}
    for split in ("calibration", "validation"):
        matrices[split], labels[split], known[split] = {}, {}, {}
        for source in ("uci", "synthetic"):
            texts = [canonicalize_features(r["text"]) for r in parts[split][source]]
            mat = sparse.hstack((word.transform(texts), char.transform(texts)), format="csr")
            matrices[split][source] = mat
            labels[split][source] = np.array([r["label"] for r in parts[split][source]], dtype=int)
            known[split][source] = np.asarray(mat.getnnz(axis=1) > 0, dtype=bool)

    candidates = []
    best = None
    for c, multiplier in PARAMETERS:
        weights = np.array([1.0] * len(parts["train"]["uci"]) + [float(multiplier)] * len(parts["train"]["synthetic"]))
        model = LogisticRegression(C=c, class_weight="balanced", max_iter=2000, random_state=20261120)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ConvergenceWarning)
            model.fit(x_train, train_labels, sample_weight=weights)
        if any(issubclass(w.category, ConvergenceWarning) for w in caught):
            candidates.append({"C": c, "synthetic_weight": multiplier, "status": "FAILED_CONVERGENCE"})
            continue

        cal_margins = np.concatenate([model.decision_function(matrices["calibration"][s]) for s in ("uci", "synthetic")])
        cal_labels = np.concatenate([labels["calibration"][s] for s in ("uci", "synthetic")])
        cal_weights = np.array([1.0] * len(parts["calibration"]["uci"]) + [float(multiplier)] * len(parts["calibration"]["synthetic"]))
        a, b = fit_sigmoid(cal_margins, cal_labels, cal_weights)

        val_margins = {s: model.decision_function(matrices["validation"][s]) for s in ("uci", "synthetic")}
        raw = {s: expit(val_margins[s]) for s in ("uci", "synthetic")}
        calibrated = {s: expit(a * val_margins[s] + b) for s in ("uci", "synthetic")}

        comparison = {}
        for name, sc in (("raw", raw), ("sigmoid", calibrated)):
            comparison[name] = {
                s: {
                    "brier": float(brier_score_loss(labels["validation"][s], sc[s])),
                    "log_loss": float(log_loss(labels["validation"][s], np.clip(sc[s], 1e-12, 1 - 1e-12))),
                }
                for s in ("uci", "synthetic")
            }
            comparison[name]["macro_brier"] = float(np.mean([comparison[name][s]["brier"] for s in ("uci", "synthetic")]))
            comparison[name]["macro_log_loss"] = float(np.mean([comparison[name][s]["log_loss"] for s in ("uci", "synthetic")]))

        use_calibration = a > 0 and all(
            comparison["sigmoid"][m] < comparison["raw"][m] for m in ("macro_brier", "macro_log_loss")
        )
        scores = calibrated if use_calibration else raw
        val_log_loss = comparison["sigmoid"]["macro_log_loss"] if use_calibration else comparison["raw"]["macro_log_loss"]
        chosen = choose_thresholds(labels["validation"], scores, known["validation"])
        # Rank candidates by validation gate, macro F1, low FPR, then lowest validation log-loss.
        cand_rank = (
            chosen["rank"][0],
            chosen["rank"][1],
            chosen["rank"][2],
            chosen["rank"][3],
            -round(val_log_loss, 4),
            chosen["rank"][4],
            chosen["rank"][5],
        )
        record = {
            "C": c,
            "synthetic_weight": multiplier,
            "status": "TRAINED",
            "calibration_selected": use_calibration,
            "val_macro_log_loss": round(val_log_loss, 5),
            "calibration_comparison": comparison,
            **chosen,
            "candidate_rank": cand_rank,
        }
        candidates.append(record)
        if best is None or cand_rank > best["record"]["candidate_rank"]:
            best = {
                "record": record,
                "model": model,
                "calibration": [a, b] if use_calibration else [1.0, 0.0],
                "scores": scores,
            }

    if best is None:
        raise RuntimeError("No V3 classifier candidate converged")

    artifact = {
        "format": 3,
        "model_version": MODEL_VERSION,
        "word": feature_block(word),
        "char": feature_block(char),
        "coef": best["model"].coef_[0].tolist(),
        "intercept": float(best["model"].intercept_[0]),
        "calibration": best["calibration"],
        "thresholds": best["record"]["thresholds"],
        "training": {
            "seed": 20261120,
            "C": best["record"]["C"],
            "synthetic_weight": best["record"]["synthetic_weight"],
            "data_sha256": hashes,
            "quality_scope": "experimental_synthetic_trained_v3_banking_hardened",
        },
    }
    model_path = ROOT / "models/detector_v3.json"
    save_artifact(model_path, artifact)
    loaded = DetectorV3.load(model_path)
    for source in ("uci", "synthetic"):
        np.testing.assert_allclose(
            loaded.scores([r["text"] for r in parts["validation"][source]]),
            best["scores"][source],
            rtol=1e-11,
            atol=1e-12,
        )

    report = {
        "scope": "DEVELOPMENT VALIDATION ONLY; synthetic-trained experimental V3 model",
        "data_sha256": hashes,
        "model_sha256": digest(model_path),
        "split_counts": {sp: {src: len(sub) for src, sub in part.items()} for sp, part in parts.items()},
        "synthetic_development_leakage_check": "PASSED",
        "serialization_parity": "PASSED",
        "candidates": candidates,
        "selected": best["record"],
        "holdout_read": False,
    }
    (output / "training_validation.json").write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps({
        "model_sha256": report["model_sha256"],
        "model_bytes": model_path.stat().st_size,
        "split_counts": report["split_counts"],
        "selected_C": best["record"]["C"],
        "selected_weight": best["record"]["synthetic_weight"],
        "calibration_selected": best["record"]["calibration_selected"],
        "thresholds": best["record"]["thresholds"],
        "validation_metrics": best["record"]["metrics"],
        "validation_quality_gate": best["record"]["validation_quality_gate"],
    }, indent=2))


if __name__ == "__main__":
    main()
