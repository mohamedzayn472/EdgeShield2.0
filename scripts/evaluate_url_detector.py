"""Evaluate frozen UrlDetectorV1 once on time-aware OpenPhish future test & unseen Indian/global holdout."""
from __future__ import annotations

import json
from pathlib import Path
import statistics
import sys
from time import perf_counter
import numpy as np
from sklearn.metrics import brier_score_loss, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from edgeshield.indicators import detect_url_indicators  # noqa: E402
from edgeshield.url_detector import load_url_detector  # noqa: E402

MODEL_PATH = ROOT / "models" / "url_detector_v1.json"
TEMPORAL_PATH = ROOT / "data" / "processed" / "url_test_temporal.jsonl"
HOLDOUT_PATH = ROOT / "data" / "synthetic" / "url_holdout.jsonl"
OUT_PATH = ROOT / "results" / "host" / "url_v1" / "evaluation_report.json"


def _score_rows(detector, rows: list[dict]) -> dict:
    y_true = np.asarray([int(r["label"]) for r in rows], dtype=np.int64)
    scores = []
    preds = []
    latencies_ms = []
    misses = []
    false_alarms = []

    for r in rows:
        t0 = perf_counter()
        out = detector.predict(r["url"])
        latencies_ms.append((perf_counter() - t0) * 1000)
        score = float(out["score"])
        band = str(out["band"])
        scores.append(score)
        preds.append(band)
        if r["label"] == 1 and band == "LEGITIMATE":
            misses.append({"url": r["url"], "score": round(score, 4), "source": r.get("source"), "cues": list(detect_url_indicators(r["url"]))})
        if r["label"] == 0 and band == "SCAM":
            false_alarms.append({"url": r["url"], "score": round(score, 4), "source": r.get("source"), "cues": list(detect_url_indicators(r["url"]))})

    scores_arr = np.asarray(scores, dtype=np.float64)
    tn = sum(1 for y, p in zip(y_true, preds) if y == 0 and p == "LEGITIMATE")
    u_neg = sum(1 for y, p in zip(y_true, preds) if y == 0 and p == "UNCERTAIN")
    fp = sum(1 for y, p in zip(y_true, preds) if y == 0 and p == "SCAM")
    fn = sum(1 for y, p in zip(y_true, preds) if y == 1 and p == "LEGITIMATE")
    u_pos = sum(1 for y, p in zip(y_true, preds) if y == 1 and p == "UNCERTAIN")
    tp = sum(1 for y, p in zip(y_true, preds) if y == 1 and p == "SCAM")

    neg_n = int((y_true == 0).sum())
    pos_n = int((y_true == 1).sum())
    prec = tp / max(tp + fp, 1)
    rec = tp / max(pos_n, 1)
    fpr = fp / max(neg_n, 1)
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
    acc = (tp + tn) / len(rows)

    return {
        "n": len(rows),
        "negative_n": neg_n,
        "positive_n": pos_n,
        "confusion_matrix_2x3": [[tn, u_neg, fp], [fn, u_pos, tp]],
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "false_positive_rate": round(fpr, 4),
        "f1": round(f1, 4),
        "abstention_rate": round((u_neg + u_pos) / len(rows), 4),
        "roc_auc": round(float(roc_auc_score(y_true, scores_arr)), 5),
        "brier": round(float(brier_score_loss(y_true, scores_arr)), 5),
        "latency_ms": {
            "median": round(statistics.median(latencies_ms), 4),
            "p95": round(float(np.percentile(latencies_ms, 95)), 4),
            "max": round(max(latencies_ms), 4),
        },
        "false_alarms_sample": false_alarms[:10],
        "misses_sample": misses[:10],
    }


def main() -> None:
    detector = load_url_detector(MODEL_PATH)
    temporal_rows = [json.loads(l) for l in TEMPORAL_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]
    holdout_rows = [json.loads(l) for l in HOLDOUT_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]
    indian_rows = [r for r in holdout_rows if r.get("subset") == "indian"]

    report = {
        "model_version": detector.predict("https://example.org")["model_version"],
        "detector_sha256": detector.artifact_sha256,
        "thresholds": [detector.low, detector.high],
        "datasets": {
            "test_temporal": _score_rows(detector, temporal_rows),
            "url_holdout_200": _score_rows(detector, holdout_rows),
            "url_holdout_indian_subset": _score_rows(detector, indian_rows),
        },
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
