"""Final heldout evaluation; requires an explicit code freeze marker and no prior run."""
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix, brier_score_loss
from edgeshield.datasets import read_jsonl, digest
from edgeshield.detector import Detector

ROOT = Path(__file__).resolve().parents[1]


def metrics(detector, rows):
    if not rows:
        return {"n": 0, "status": "NO_SAMPLES", "precision": None, "recall": None, "f1": None}
    y = np.array([r["label"] for r in rows])
    predictions = [detector.predict(r["text"]) for r in rows]
    scores = np.array([r["score"] for r in predictions])
    bands = np.array([r["band"] for r in predictions])
    positive = bands == "SCAM"
    precision, recall, f1, _ = precision_recall_fscore_support(y, positive, average="binary", zero_division=0)
    # Ground truth is binary. UNCERTAIN is only a prediction column, never a fake ground-truth class.
    matrix = [[int(np.sum((y == label) & (bands == band))) for band in ("LEGITIMATE", "UNCERTAIN", "SCAM")] for label in (0, 1)]
    errors = [{"id": row["id"], "label": row["label"], "band": prediction["band"], "score": prediction["score"],
               "family": row.get("family")} for row, prediction in zip(rows, predictions)
              if prediction["band"] == "UNCERTAIN" or (prediction["band"] == "SCAM") != bool(row["label"])]
    return {"n": len(rows), "precision": float(precision), "recall": float(recall), "f1": float(f1),
            "false_positive_rate": float(np.mean(positive[y == 0])) if np.any(y == 0) else None,
            "false_negative_legitimate_rate": float(np.mean((bands == "LEGITIMATE")[y == 1])) if np.any(y == 1) else None,
            "abstention_rate": float(np.mean(bands == "UNCERTAIN")), "coverage": float(np.mean(bands != "UNCERTAIN")),
            "confusion_matrix_2_by_3": matrix, "rows": ["ham_or_legitimate", "spam_or_synthetic_scam"],
            "columns": ["LEGITIMATE", "UNCERTAIN", "SCAM"], "brier_score": float(brier_score_loss(y, scores)),
            "binary_0_5_confusion_matrix": confusion_matrix(y, scores >= 0.5, labels=[0, 1]).tolist(),
            "errors_and_abstentions": errors}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--freeze", required=True, type=Path)
    args = parser.parse_args()
    output = ROOT / "results/host/heldout_evaluation.json"
    if output.exists():
        raise SystemExit("Final evaluation already exists; retain it. New experiments require a new protocol and heldout data.")
    freeze = json.loads(args.freeze.read_text(encoding="utf-8"))
    if freeze.get("model_sha256") != digest(ROOT / "models/detector.json"):
        raise SystemExit("Freeze marker does not match detector artifact")
    required = {"src/edgeshield/detector.py", "src/edgeshield/datasets.py", "src/edgeshield/privacy.py",
                "scripts/train_detector.py", "scripts/prepare_dataset.py", "scripts/evaluate_detector.py",
                "docs/EVALUATION.md", "data/processed/test.jsonl", "data/synthetic/indian_sms.jsonl"}
    hashes = freeze.get("file_sha256", {})
    if not required.issubset(hashes):
        raise SystemExit("Freeze marker must cover code, protocol and test datasets")
    for name, expected in hashes.items():
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file() or digest(path) != expected:
            raise SystemExit("Frozen file integrity mismatch")
    detector = Detector.load(ROOT / "models/detector.json")
    uci = read_jsonl(ROOT / "data/processed/test.jsonl")
    synthetic = [r for r in read_jsonl(ROOT / "data/synthetic/indian_sms.jsonl") if r["split"] == "test" and r["label"] is not None]
    report = {"protocol_sha256": digest(ROOT / "docs/EVALUATION.md"), "model_sha256": freeze["model_sha256"],
              "scope": "HOST detector evaluation; UCI spam proxy; synthetic cases are not evidence of real-world Indian accuracy",
              "uci": metrics(detector, uci), "synthetic_indian_hinglish": metrics(detector, synthetic),
              "synthetic_hinglish": metrics(detector, [r for r in synthetic if r["language"] == "hinglish"]),
              "synthetic_legitimate": metrics(detector, [r for r in synthetic if r["label"] == 0]),
              "pi4": "PENDING_HARDWARE"}
    output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
