"""Freeze and evaluate v2 once. Synthetic success is not real-world validation."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
from sklearn.metrics import precision_recall_fscore_support
from edgeshield.datasets import read_jsonl
from edgeshield.detector_v2 import DetectorV2

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results/host/v2"


def metric(detector, rows):
    if not rows:
        return {"n": 0, "status": "NO_SAMPLES"}
    predictions = [detector.predict(r["text"]) for r in rows]
    y = np.asarray([r["label"] for r in rows])
    bands = np.asarray([r["band"] for r in predictions])
    positive = bands == "SCAM"
    precision, recall, f1, _ = precision_recall_fscore_support(y, positive, average="binary", zero_division=0)
    npos, nneg = int(sum(y == 1)), int(sum(y == 0))
    return {"n": len(rows), "positive_n": npos, "negative_n": nneg,
            "precision": float(precision) if positive.any() else None,
            "recall": float(recall) if npos else None, "f1": float(f1) if npos else None,
            "false_positive_rate": float(np.mean(positive[y == 0])) if nneg else None,
            "scam_assigned_legitimate_rate": float(np.mean((bands == "LEGITIMATE")[y == 1])) if npos else None,
            "abstention_rate": float(np.mean(bands == "UNCERTAIN")),
            "confusion_matrix": [[int(sum((y == label) & (bands == band))) for band in ("LEGITIMATE", "UNCERTAIN", "SCAM")] for label in (0, 1)],
            "rows": ["legitimate", "scam_or_uci_spam"], "columns": ["LEGITIMATE", "UNCERTAIN", "SCAM"],
            "outcomes": [{"id": r["id"], "label": r["label"], "band": p["band"], "score": p["score"]} for r, p in zip(rows, predictions)]}


def gate(m, minimum):
    return (m.get("positive_n", 0) >= minimum and m.get("negative_n", 0) >= minimum and
            m["recall"] >= .80 and m["false_positive_rate"] <= .05 and m["abstention_rate"] <= .30)


def main():
    output = OUT / "heldout_evaluation.json"
    freeze_path = OUT / "evaluation_freeze.json"
    if output.exists() or freeze_path.exists():
        raise SystemExit("V2 evaluation/freeze already exists. Preserve this experiment.")
    files = ["src/edgeshield/detector_v2.py", "src/edgeshield/privacy.py", "src/edgeshield/datasets.py",
             "scripts/train_detector_v2.py", "scripts/evaluate_detector_v2.py", "scripts/audit_v2_data.py",
             "docs/EVALUATION_V2.md", "docs/V2_FINAL_EVALUATION.md", "results/host/v2/data_audit.json",
             "data/synthetic/v2_development.jsonl", "data/synthetic/v2_holdout.jsonl",
             "models/detector_v2.json", "models/detector_v2.json.sha256"]
    hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files}
    audit = json.loads((OUT / "data_audit.json").read_text())
    if audit["development_sha256"] != hashes["data/synthetic/v2_development.jsonl"] or audit["holdout_sha256"] != hashes["data/synthetic/v2_holdout.jsonl"]:
        raise SystemExit("Data changed after audit")
    freeze_path.write_text(json.dumps({"created_at_utc": datetime.now(timezone.utc).isoformat(), "file_sha256": hashes}, indent=2), encoding="utf-8")
    detector = DetectorV2.load(ROOT / "models/detector_v2.json")
    held = read_jsonl(ROOT / "data/synthetic/v2_holdout.jsonl")
    usable = [r for r in held if r["id"] not in audit["excluded_ids"]]
    labeled = [r for r in usable if r["label"] is not None]
    all_metrics = metric(detector, labeled)
    languages = {lang: metric(detector, [r for r in labeled if r["language"] == lang]) for lang in ("english", "hinglish")}
    passed = gate(all_metrics, 40) and all(gate(m, 20) for m in languages.values())
    ambiguous = [{"id": r["id"], **{k: v for k, v in detector.predict(r["text"]).items() if k in {"band", "score"}}} for r in usable if r["label"] is None]
    report = {"status": "PASSED" if passed else "FAILED", "scope": "Fresh AI-assisted synthetic challenge only; no human label review or real-world validation",
              "freeze_sha256": hashlib.sha256(freeze_path.read_bytes()).hexdigest(), "overall": all_metrics,
              "by_language": languages, "excluded_n": len(audit["excluded_ids"]), "ambiguous_outcomes": ambiguous,
              "uci_regression_not_fresh_holdout": metric(detector, read_jsonl(ROOT / "data/processed/test.jsonl")),
              "submission_ready": False, "real_arm_inference": "PENDING_HARDWARE"}
    output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps({"status": report["status"], "overall": {k: v for k, v in all_metrics.items() if k != "outcomes"},
                      "by_language": {k: {key: val for key, val in value.items() if key != "outcomes"} for k, value in languages.items()}}, indent=2))


if __name__ == "__main__":
    main()
