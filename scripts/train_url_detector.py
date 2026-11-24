"""Train and calibrate UrlDetectorV1 (format 101) exclusively on train/calibration/validation splits."""
from __future__ import annotations

import json
import math
from pathlib import Path
import sys
import numpy as np
from scipy import sparse
from scipy.special import expit
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, roc_auc_score
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from edgeshield.url_detector import (  # noqa: E402
    FORMAT_VERSION,
    MODEL_VERSION,
    STRUCTURAL_FEATURE_NAMES,
    UrlDetectorV1,
    band_for_score,
    extract_structural_features,
    save_url_artifact,
    tokenize_url_for_tfidf,
)

PROCESSED_DIR = ROOT / "data" / "processed"
OUT_MODEL = ROOT / "models" / "url_detector_v1.json"
OUT_REPORT = ROOT / "results" / "host" / "url_v1" / "training_validation.json"


def _load_split(name: str) -> tuple[list[str], np.ndarray]:
    path = PROCESSED_DIR / f"url_{name}.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [r["url"] for r in rows], np.asarray([int(r["label"]) for r in rows], dtype=np.int64)


def _eval_thresholds(y_true: np.ndarray, scores: np.ndarray, low: float, high: float) -> dict[str, float]:
    preds = [band_for_score(float(s), low, high) for s in scores]
    neg_idx = y_true == 0
    pos_idx = y_true == 1
    fp = sum(1 for p, neg in zip(preds, neg_idx) if neg and p == "SCAM")
    tp = sum(1 for p, pos in zip(preds, pos_idx) if pos and p == "SCAM")
    fn = sum(1 for p, pos in zip(preds, pos_idx) if pos and p == "LEGITIMATE")
    tn = sum(1 for p, neg in zip(preds, neg_idx) if neg and p == "LEGITIMATE")
    unc = sum(1 for p in preds if p == "UNCERTAIN")
    fpr = fp / max(int(neg_idx.sum()), 1)
    recall = tp / max(int(pos_idx.sum()), 1)
    prec = tp / max(tp + fp, 1)
    f1 = (2 * prec * recall / (prec + recall)) if (prec + recall) else 0.0
    acc = (tp + tn) / len(y_true)
    return {
        "fpr": round(fpr, 4),
        "recall": round(recall, 4),
        "precision": round(prec, 4),
        "f1": round(f1, 4),
        "accuracy": round(acc, 4),
        "abstention_rate": round(unc / len(y_true), 4),
        "fp": fp,
        "fn": fn,
    }


def main() -> None:
    x_tr, y_tr = _load_split("train")
    x_ca, y_ca = _load_split("calibration")
    x_va, y_va = _load_split("validation")

    scaler = StandardScaler()
    s_tr = sparse.csr_matrix(scaler.fit_transform([extract_structural_features(u) for u in x_tr]) / 5.0)
    s_ca = sparse.csr_matrix(scaler.transform([extract_structural_features(u) for u in x_ca]) / 5.0)
    s_va = sparse.csr_matrix(scaler.transform([extract_structural_features(u) for u in x_va]) / 5.0)

    tok_tr = [tokenize_url_for_tfidf(u) for u in x_tr]
    tok_ca = [tokenize_url_for_tfidf(u) for u in x_ca]
    tok_va = [tokenize_url_for_tfidf(u) for u in x_va]

    word_vec = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), sublinear_tf=True, max_features=12000, min_df=5)
    char_vec = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), sublinear_tf=True, max_features=20000, min_df=4)

    w_tr = word_vec.fit_transform([t[0] for t in tok_tr])
    c_tr = char_vec.fit_transform([t[1] for t in tok_tr])
    m_tr = sparse.hstack((s_tr, w_tr, c_tr), format="csr")

    m_ca = sparse.hstack((s_ca, word_vec.transform([t[0] for t in tok_ca]), char_vec.transform([t[1] for t in tok_ca])), format="csr")
    m_va = sparse.hstack((s_va, word_vec.transform([t[0] for t in tok_va]), char_vec.transform([t[1] for t in tok_va])), format="csr")

    best = None
    for c_val in (1.0, 2.0, 4.0):
        clf = LogisticRegression(C=c_val, max_iter=2000, random_state=20261124)
        clf.fit(m_tr, y_tr)
        logits_ca = clf.decision_function(m_ca).reshape(-1, 1)
        cal = LogisticRegression(C=1e6, max_iter=1000, random_state=20261124)
        cal.fit(logits_ca, y_ca)
        a = float(cal.coef_[0][0])
        b = float(cal.intercept_[0])
        if a <= 0:
            a, b = 1.0, 0.0
        scores_va = expit(a * clf.decision_function(m_va) + b)
        auc_va = float(roc_auc_score(y_va, scores_va))
        brier_va = float(brier_score_loss(y_va, scores_va))

        for low in np.arange(0.30, 0.56, 0.05):
            for high in np.arange(max(low + 0.10, 0.55), 0.86, 0.05):
                m = _eval_thresholds(y_va, scores_va, float(round(low, 3)), float(round(high, 3)))
                # Prioritize low FPR <= 1.5%, then highest F1, recall, and AUC.
                feasible = 1 if m["fpr"] <= 0.015 else 0
                rank_key = (feasible, m["f1"], m["recall"], -m["fpr"], auc_va, -brier_va)
                if best is None or rank_key > best[0]:
                    best = (rank_key, c_val, clf, (a, b), (float(round(low, 3)), float(round(high, 3))), m, auc_va, brier_va)

    assert best is not None
    _, c_val, clf, (a, b), (low, high), val_metrics, auc_va, brier_va = best
    artifact = {
        "format": FORMAT_VERSION,
        "model_version": MODEL_VERSION,
        "structural_features": list(STRUCTURAL_FEATURE_NAMES),
        "struct_mean": [float(x) for x in scaler.mean_],
        "struct_scale": [float(x) for x in scaler.scale_],
        "word": {
            "vocabulary": {k: int(v) for k, v in word_vec.vocabulary_.items()},
            "idf": [float(x) for x in word_vec.idf_],
        },
        "char": {
            "vocabulary": {k: int(v) for k, v in char_vec.vocabulary_.items()},
            "idf": [float(x) for x in char_vec.idf_],
        },
        "coef": [float(x) for x in clf.coef_[0]],
        "intercept": float(clf.intercept_[0]),
        "calibration": [a, b],
        "thresholds": [low, high],
        "train_config": {"C": c_val, "class_weight": "balanced"},
    }
    sha = save_url_artifact(OUT_MODEL, artifact)
    # Smoke-verify reload via UrlDetectorV1.load
    reloaded = UrlDetectorV1.load(OUT_MODEL)
    assert reloaded.artifact_sha256 == sha

    report = {
        "model_version": MODEL_VERSION,
        "sha256": sha,
        "bytes": OUT_MODEL.stat().st_size,
        "C": c_val,
        "calibration": [round(a, 6), round(b, 6)],
        "thresholds": [low, high],
        "word_vocab_size": len(word_vec.vocabulary_),
        "char_vocab_size": len(char_vec.vocabulary_),
        "validation_metrics": {**val_metrics, "roc_auc": round(auc_va, 5), "brier": round(brier_va, 5)},
    }
    OUT_REPORT.parent.mkdir(parents=True, exist_ok=True)
    OUT_REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
