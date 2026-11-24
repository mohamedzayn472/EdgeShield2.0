"""Train, 5-fold GroupKFold validate, domain-balanced calibrate, and threshold-select V7 strictly on dev splits.

Reads strictly from data/synthetic/v7_development.jsonl and data/processed/{train,calibration,validation}.jsonl.
Never reads any holdout or test files. Enforces a hard validation quality gate guard before saving
models/detector_v7.json.
"""
from __future__ import annotations

import json
import warnings
from pathlib import Path
import numpy as np
from scipy import sparse
from scipy.optimize import minimize_scalar
from scipy.special import expit
from sklearn.exceptions import ConvergenceWarning
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, log_loss, roc_auc_score
from sklearn.model_selection import GroupKFold

from edgeshield.datasets import check_leakage, digest, read_jsonl
from edgeshield.detector_v7 import DetectorV7, MODEL_VERSION, canonicalize_features_v7, save_artifact
from edgeshield.model_loader import load_detector
from edgeshield.privacy import normalize_sms

ROOT = Path(__file__).resolve().parents[1]
SPLITS = ("train", "calibration", "validation")
PARAMETERS = [(c, w) for c in (1.0, 2.0, 4.0) for w in (2, 3, 4, 6)]


def development_data():
    synthetic = read_jsonl(ROOT / "data/synthetic/v7_development.jsonl")
    if not synthetic:
        raise ValueError("Synthetic V7 development dataset is empty")
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


def _ece_10bin(y_true: np.ndarray, y_prob: np.ndarray) -> float:
    bins = np.linspace(0.0, 1.0, 11)
    ece = 0.0
    for i in range(10):
        lo, hi = bins[i], bins[i + 1]
        mask = (y_prob >= lo) & (y_prob <= hi if i == 9 else y_prob < hi)
        cnt = int(np.sum(mask))
        if cnt > 0:
            ece += (cnt / len(y_true)) * abs(float(np.mean(y_true[mask])) - float(np.mean(y_prob[mask])))
    return float(ece)


def summary(y, scores, low, high, known=None):
    y = np.asarray(y, dtype=int)
    scores = np.clip(np.asarray(scores, dtype=float), 1e-12, 1.0 - 1e-12)
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
        "benign_uncertain_rate": u0 / neg_n if neg_n else 0.0,
        "coverage": (tp + fp + tn + fn) / len(y) if len(y) else 0.0,
        "abstention_rate": (u0 + u1) / len(y) if len(y) else 0.0,
        "roc_auc": float(roc_auc_score(y, scores)),
        "pr_auc": float(average_precision_score(y, scores)),
        "brier": float(brier_score_loss(y, scores)),
        "log_loss": float(log_loss(y, scores, labels=[0, 1])),
        "ece_10bin": _ece_10bin(y, scores),
        "confusion_matrix_2_by_3": [[tn, u0, fp], [fn, u1, tp]],
    }


def _quadrant_weights(labels_by_src: dict[str, np.ndarray]) -> np.ndarray:
    weights = []
    for src in ("uci", "synthetic"):
        y_src = labels_by_src[src]
        w_src = np.zeros(len(y_src), dtype=float)
        for cls in (0, 1):
            mask = y_src == cls
            cnt = int(np.sum(mask))
            if cnt == 0:
                raise ValueError(f"Missing class {cls} in {src}")
            w_src[mask] = 0.25 / cnt
        weights.append(w_src)
    return np.concatenate(weights)


def _quadrant_balanced_loss(labels_by_src: dict[str, np.ndarray], probs_by_src: dict[str, np.ndarray]) -> float:
    losses = []
    for src in ("uci", "synthetic"):
        y_src = labels_by_src[src]
        p_src = np.clip(probs_by_src[src], 1e-12, 1.0 - 1e-12)
        for cls in (0, 1):
            mask = y_src == cls
            if cls == 1:
                losses.append(float(-np.mean(np.log(p_src[mask]))))
            else:
                losses.append(float(-np.mean(np.log(1.0 - p_src[mask]))))
    return float(np.mean(losses))


def fit_calibrators(cal_margins_by_src: dict, cal_labels_by_src: dict) -> dict[str, tuple[float, float]]:
    margins = np.concatenate([cal_margins_by_src["uci"], cal_margins_by_src["synthetic"]])
    labels = np.concatenate([cal_labels_by_src["uci"], cal_labels_by_src["synthetic"]])
    w_quad = _quadrant_weights(cal_labels_by_src)

    calibrators: dict[str, tuple[float, float]] = {"raw": (1.0, 0.0)}

    def _temp_loss(a: float) -> float:
        p = np.clip(expit(a * margins), 1e-12, 1.0 - 1e-12)
        return float(-np.sum(w_quad * (labels * np.log(p) + (1.0 - labels) * np.log(1.0 - p))))

    res = minimize_scalar(_temp_loss, bounds=(0.05, 10.0), method="bounded")
    calibrators["temperature_scaled"] = (float(res.x), 0.0)

    m_quad = LogisticRegression(C=10.0, max_iter=2000, random_state=20261123)
    m_quad.fit(margins.reshape(-1, 1), labels, sample_weight=w_quad * len(labels))
    calibrators["sigmoid_quadrant_balanced"] = (float(m_quad.coef_[0][0]), float(m_quad.intercept_[0]))

    m_syn = LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000, random_state=20261123)
    m_syn.fit(cal_margins_by_src["synthetic"].reshape(-1, 1), cal_labels_by_src["synthetic"])
    calibrators["sigmoid_synthetic_balanced"] = (float(m_syn.coef_[0][0]), float(m_syn.intercept_[0]))

    return calibrators


def group_kfold_synthetic_eval(uci_train: list[dict], syn_train: list[dict], c: float, multiplier: int) -> dict:
    syn_groups = np.array([r["family"] for r in syn_train])
    syn_labels = np.array([r["label"] for r in syn_train], dtype=int)
    syn_texts = [canonicalize_features_v7(r["text"]) for r in syn_train]
    uci_texts = [canonicalize_features_v7(r["text"]) for r in uci_train]
    uci_labels = np.array([r["label"] for r in uci_train], dtype=int)

    gkf = GroupKFold(n_splits=5)
    oof_margins = np.zeros(len(syn_train), dtype=float)

    for tr_idx, va_idx in gkf.split(syn_texts, syn_labels, groups=syn_groups):
        fold_syn_texts = [syn_texts[i] for i in tr_idx]
        fold_syn_labels = syn_labels[tr_idx]
        fold_val_texts = [syn_texts[i] for i in va_idx]

        word = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), sublinear_tf=True, min_df=2, max_features=35000)
        char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=2, max_features=55000)
        fold_tr_texts = uci_texts + fold_syn_texts
        x_tr = sparse.hstack((word.fit_transform(fold_tr_texts), char.fit_transform(fold_tr_texts)), format="csr")
        y_tr = np.concatenate([uci_labels, fold_syn_labels])
        w_tr = np.array([1.0] * len(uci_texts) + [float(multiplier)] * len(fold_syn_texts))

        clf = LogisticRegression(C=c, class_weight="balanced", max_iter=2000, random_state=20261123)
        clf.fit(x_tr, y_tr, sample_weight=w_tr)

        x_va = sparse.hstack((word.transform(fold_val_texts), char.transform(fold_val_texts)), format="csr")
        oof_margins[va_idx] = clf.decision_function(x_va)

    oof_probs = np.clip(expit(oof_margins), 1e-12, 1.0 - 1e-12)
    return {
        "gkf_oof_syn_auc": float(roc_auc_score(syn_labels, oof_probs)),
        "gkf_oof_syn_pr_auc": float(average_precision_score(syn_labels, oof_probs)),
        "gkf_oof_syn_brier": float(brier_score_loss(syn_labels, oof_probs)),
        "gkf_oof_syn_log_loss": float(log_loss(syn_labels, oof_probs, labels=[0, 1])),
        "gkf_oof_syn_fpr_050": float(np.mean(oof_probs[syn_labels == 0] >= 0.50)),
        "gkf_oof_syn_rec_050": float(np.mean(oof_probs[syn_labels == 1] >= 0.50)),
    }


def choose_thresholds(labels, scores, known):
    """Select balanced validation thresholds enforcing 4-boundary safety margin across UCI and Synthetic."""
    low_grid = [round(x, 4) for x in np.linspace(0.325, 0.55, 10)]
    high_grid = [round(x, 4) for x in np.linspace(0.55, 0.725, 8)]
    q98_syn_neg = float(np.percentile(scores["synthetic"][labels["synthetic"] == 0], 98))
    q02_syn_pos = float(np.percentile(scores["synthetic"][labels["synthetic"] == 1], 2))
    q99_uci_neg = float(np.percentile(scores["uci"][labels["uci"] == 0], 99))
    q10_uci_pos = float(np.percentile(scores["uci"][labels["uci"] == 1], 10))

    best = None
    for low in low_grid:
        for high in high_grid:
            gap = round(high - low, 4)
            if gap < 0.10 or gap > 0.25:
                continue
            metrics = {s: summary(labels[s], scores[s], low, high, known[s]) for s in ("uci", "synthetic")}
            syn, uci = metrics["synthetic"], metrics["uci"]
            fpr_ok = syn["false_positive_rate"] <= 0.012 and uci["false_positive_rate"] <= 0.008
            rec_ok = syn["recall"] >= 0.96 and uci["recall"] >= 0.91
            fn_ok = syn["positive_as_legitimate_rate"] <= 0.02 and uci["positive_as_legitimate_rate"] <= 0.06
            abs_ok = syn["abstention_rate"] <= 0.06 and syn["benign_uncertain_rate"] <= 0.045 and uci["abstention_rate"] <= 0.05
            passed = fpr_ok and rec_ok and fn_ok and abs_ok
            safety_margin = float(min(
                high - q98_syn_neg,
                q02_syn_pos - high,
                high - q99_uci_neg,
                q10_uci_pos - high,
                q02_syn_pos - low,
            ))
            macro_f1 = 0.5 * (syn["f1"] + uci["f1"])
            macro_acc = 0.5 * (syn["accuracy"] + uci["accuracy"])
            center_dist = abs(0.5 * (low + high) - 0.50) + 0.5 * abs(gap - 0.175)
            rank = (
                passed,
                fpr_ok and rec_ok,
                round(macro_f1, 4),
                round(macro_acc, 4),
                round(safety_margin, 3),
                -round(center_dist, 4),
            )
            if best is None or rank > best["rank"]:
                best = {
                    "rank": rank,
                    "thresholds": [float(low), float(high)],
                    "macro_f1": round(macro_f1, 5),
                    "safety_margin": round(safety_margin, 5),
                    "val_syn_q98_neg": round(q98_syn_neg, 5),
                    "val_syn_q02_pos": round(q02_syn_pos, 5),
                    "val_uci_q99_neg": round(q99_uci_neg, 5),
                    "val_uci_q10_pos": round(q10_uci_pos, 5),
                    "metrics": metrics,
                    "validation_quality_gate": "PASSED" if passed else "FAILED",
                }
    return best


def main():
    parts = development_data()
    output = ROOT / "results/host/v7"
    output.mkdir(parents=True, exist_ok=True)
    hashes = {
        "v7_development": digest(ROOT / "data/synthetic/v7_development.jsonl"),
        **{f"uci_{s}": digest(ROOT / f"data/processed/{s}.jsonl") for s in SPLITS},
    }

    det_v5 = load_detector(ROOT / "models/detector_v5.json")
    v5_val_baseline = {
        s: summary(
            np.array([r["label"] for r in parts["validation"][s]], dtype=int),
            det_v5.scores([r["text"] for r in parts["validation"][s]]),
            det_v5.low,
            det_v5.high,
        )
        for s in ("uci", "synthetic")
    }

    train_rows = parts["train"]["uci"] + parts["train"]["synthetic"]
    train_texts = [canonicalize_features_v7(r["text"]) for r in train_rows]
    train_labels = np.array([r["label"] for r in train_rows], dtype=int)

    word = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), sublinear_tf=True, min_df=2, max_features=35000)
    char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=2, max_features=55000)
    x_train = sparse.hstack((word.fit_transform(train_texts), char.fit_transform(train_texts)), format="csr")

    matrices, labels, known = {}, {}, {}
    for split in ("calibration", "validation"):
        matrices[split], labels[split], known[split] = {}, {}, {}
        for source in ("uci", "synthetic"):
            texts = [canonicalize_features_v7(r["text"]) for r in parts[split][source]]
            mat = sparse.hstack((word.transform(texts), char.transform(texts)), format="csr")
            matrices[split][source] = mat
            labels[split][source] = np.array([r["label"] for r in parts[split][source]], dtype=int)
            known[split][source] = np.asarray(mat.getnnz(axis=1) > 0, dtype=bool)

    candidates = []
    best = None
    for c, multiplier in PARAMETERS:
        oof = group_kfold_synthetic_eval(parts["train"]["uci"], parts["train"]["synthetic"], c, multiplier)
        weights = np.array([1.0] * len(parts["train"]["uci"]) + [float(multiplier)] * len(parts["train"]["synthetic"]))
        model = LogisticRegression(C=c, class_weight="balanced", max_iter=2000, random_state=20261123)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ConvergenceWarning)
            model.fit(x_train, train_labels, sample_weight=weights)
        if any(issubclass(w.category, ConvergenceWarning) for w in caught):
            candidates.append({"C": c, "synthetic_weight": multiplier, "status": "FAILED_CONVERGENCE"})
            continue

        cal_margins_src = {s: model.decision_function(matrices["calibration"][s]) for s in ("uci", "synthetic")}
        val_margins = {s: model.decision_function(matrices["validation"][s]) for s in ("uci", "synthetic")}
        calibrators = fit_calibrators(cal_margins_src, labels["calibration"])

        cal_comp = {}
        valid_cal_options = []
        for cal_name, (a, b) in calibrators.items():
            sc = {s: expit(a * val_margins[s] + b) for s in ("uci", "synthetic")}
            per_src = {
                s: {
                    "brier": float(brier_score_loss(labels["validation"][s], sc[s])),
                    "log_loss": float(log_loss(labels["validation"][s], np.clip(sc[s], 1e-12, 1 - 1e-12))),
                    "ece": _ece_10bin(labels["validation"][s], sc[s]),
                    "roc_auc": float(roc_auc_score(labels["validation"][s], sc[s])),
                }
                for s in ("uci", "synthetic")
            }
            per_src["quadrant_balanced_log_loss"] = _quadrant_balanced_loss(labels["validation"], sc)
            per_src["macro_brier"] = float(np.mean([per_src[s]["brier"] for s in ("uci", "synthetic")]))
            per_src["macro_log_loss"] = float(np.mean([per_src[s]["log_loss"] for s in ("uci", "synthetic")]))
            per_src["macro_auc"] = float(np.mean([per_src[s]["roc_auc"] for s in ("uci", "synthetic")]))
            cal_comp[cal_name] = per_src
            if a > 0 and cal_name != "raw":
                valid_cal_options.append((cal_name, (a, b), sc, per_src))

        chosen_cal_name, (best_a, best_b), best_scores, best_cal_metrics = min(
            valid_cal_options,
            key=lambda item: (round(item[3]["quadrant_balanced_log_loss"], 6), round(item[3]["macro_brier"], 6)),
        )
        chosen = choose_thresholds(labels["validation"], best_scores, known["validation"])
        val_passed = chosen["validation_quality_gate"] == "PASSED"
        val_uci_auc = best_cal_metrics["uci"]["roc_auc"]
        cand_rank = (
            val_passed,
            round(0.5 * (oof["gkf_oof_syn_auc"] + val_uci_auc), 4),
            round(chosen["macro_f1"], 4),
            round(chosen["safety_margin"], 3),
            -float(c),
        )
        record = {
            "C": c,
            "synthetic_weight": multiplier,
            "status": "TRAINED",
            **oof,
            "calibration_method_selected": chosen_cal_name,
            "calibration_params": [best_a, best_b],
            "val_quadrant_log_loss": round(best_cal_metrics["quadrant_balanced_log_loss"], 5),
            "val_macro_brier": round(best_cal_metrics["macro_brier"], 5),
            "val_macro_roc_auc": round(best_cal_metrics["macro_auc"], 5),
            "calibration_comparison": cal_comp,
            **chosen,
            "candidate_rank": cand_rank,
        }
        candidates.append(record)
        if best is None or cand_rank > best["record"]["candidate_rank"]:
            best = {"record": record, "model": model, "calibration": [best_a, best_b], "scores": best_scores}

    if best is None:
        raise RuntimeError("No V7 classifier candidate converged")

    if best["record"]["validation_quality_gate"] != "PASSED":
        (output / "training_validation_failed.json").write_text(
            json.dumps({"candidates": candidates, "best": best["record"]}, indent=2),
            encoding="utf-8",
        )
        raise RuntimeError(
            "V7 training refused to save artifact: best candidate failed validation_quality_gate. "
            f"Metrics={best['record']['metrics']}"
        )

    artifact = {
        "format": 7,
        "model_version": MODEL_VERSION,
        "word": feature_block(word),
        "char": feature_block(char),
        "coef": best["model"].coef_[0].tolist(),
        "intercept": float(best["model"].intercept_[0]),
        "calibration": best["calibration"],
        "thresholds": best["record"]["thresholds"],
        "training": {
            "seed": 20261123,
            "C": best["record"]["C"],
            "synthetic_weight": best["record"]["synthetic_weight"],
            "calibration_method": best["record"]["calibration_method_selected"],
            "gkf_oof_syn_auc": best["record"]["gkf_oof_syn_auc"],
            "gkf_oof_syn_log_loss": best["record"]["gkf_oof_syn_log_loss"],
            "data_sha256": hashes,
            "quality_scope": "candidate_v7_multidomain_calibrated_hardgated",
        },
    }
    model_path = ROOT / "models/detector_v7.json"
    save_artifact(model_path, artifact)
    loaded = DetectorV7.load(model_path)
    for source in ("uci", "synthetic"):
        np.testing.assert_allclose(
            loaded.scores([r["text"] for r in parts["validation"][source]]),
            best["scores"][source],
            rtol=1e-11,
            atol=1e-12,
        )

    report = {
        "scope": "DEVELOPMENT VALIDATION ONLY; V7 GroupKFold OOF + 4-quadrant calibration + hard-gated threshold selection",
        "data_sha256": hashes,
        "model_sha256": digest(model_path),
        "split_counts": {sp: {src: len(sub) for src, sub in part.items()} for sp, part in parts.items()},
        "synthetic_development_leakage_check": "PASSED",
        "serialization_parity": "PASSED",
        "v5_baseline_on_identical_v7_validation": v5_val_baseline,
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
        "gkf_oof_syn_auc": best["record"]["gkf_oof_syn_auc"],
        "gkf_oof_syn_log_loss": best["record"]["gkf_oof_syn_log_loss"],
        "calibration_method": best["record"]["calibration_method_selected"],
        "calibration_params": best["record"]["calibration_params"],
        "thresholds": best["record"]["thresholds"],
        "safety_margin": best["record"]["safety_margin"],
        "v7_val_synthetic": {k: best["record"]["metrics"]["synthetic"][k] for k in ("accuracy", "precision", "recall", "false_positive_rate", "positive_as_legitimate_rate", "roc_auc", "brier", "confusion_matrix_2_by_3")},
        "v7_val_uci": {k: best["record"]["metrics"]["uci"][k] for k in ("accuracy", "precision", "recall", "false_positive_rate", "positive_as_legitimate_rate", "roc_auc", "brier", "confusion_matrix_2_by_3")},
        "validation_quality_gate": best["record"]["validation_quality_gate"],
    }, indent=2))


if __name__ == "__main__":
    main()
