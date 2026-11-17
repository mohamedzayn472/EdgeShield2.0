"""Read-only reproduction of the frozen V2 one-time evaluation on this host.

Never rewrites frozen artifacts. Verifies the recorded freeze hashes, re-scores
the frozen holdout with the frozen model and compares every per-case band and
score to results/host/v2/heldout_evaluation.json. The UCI regression set is
excluded from the transfer bundle, so it is reported as NOT_AVAILABLE.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from edgeshield.datasets import read_jsonl  # noqa: E402
from edgeshield.detector_v2 import DetectorV2  # noqa: E402


def counts(rows):
    pos = [r for r in rows if r["label"] == 1]
    neg = [r for r in rows if r["label"] == 0]
    return {"n": len(rows),
            "scams_detected": sum(r["band"] == "SCAM" for r in pos), "scams": len(pos),
            "scams_assigned_legitimate": sum(r["band"] == "LEGITIMATE" for r in pos),
            "false_alarms": sum(r["band"] == "SCAM" for r in neg), "legitimate": len(neg),
            "uncertain": sum(r["band"] == "UNCERTAIN" for r in rows)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if a.output.exists():
        p.error("Output exists; preserve prior results")
    freeze = json.loads((ROOT / "results/host/v2/evaluation_freeze.json").read_text())
    hash_check = {}
    for name, expected in freeze["file_sha256"].items():
        path = ROOT / name
        actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        hash_check[name] = "MATCH" if actual == expected else ("MISSING" if actual is None else "CHANGED")
    recorded = json.loads((ROOT / "results/host/v2/heldout_evaluation.json").read_text())
    audit = json.loads((ROOT / "results/host/v2/data_audit.json").read_text())
    detector = DetectorV2.load(ROOT / "models/detector_v2.json")
    held = [r for r in read_jsonl(ROOT / "data/synthetic/v2_holdout.jsonl") if r["id"] not in audit["excluded_ids"]]
    labeled = [r for r in held if r["label"] is not None]
    rows = []
    for r in labeled:
        pred = detector.predict(r["text"])
        rows.append({"id": r["id"], "label": r["label"], "language": r["language"],
                     "band": pred["band"], "score": pred["score"]})
    rec = {o["id"]: o for o in recorded["overall"]["outcomes"]}
    band_mismatch = [r["id"] for r in rows if rec[r["id"]]["band"] != r["band"]]
    max_score_diff = max(abs(rec[r["id"]]["score"] - r["score"]) for r in rows)
    report = {
        "kind": "READ_ONLY_REPRODUCTION_UBUNTU_HOST",
        "platform": platform.platform(), "python": platform.python_version(),
        "freeze_hash_check": hash_check,
        "all_frozen_hashes_match": all(v == "MATCH" for v in hash_check.values()),
        "overall": counts(rows),
        "english": counts([r for r in rows if r["language"] == "english"]),
        "hinglish": counts([r for r in rows if r["language"] == "hinglish"]),
        "per_case_band_mismatches_vs_recorded": band_mismatch,
        "max_abs_score_diff_vs_recorded": max_score_diff,
        "missed_scams": [{"id": r["id"], "language": r["language"], "score": r["score"]}
                         for r in rows if r["label"] == 1 and r["band"] != "SCAM"],
        "false_alarms": [{"id": r["id"], "language": r["language"], "score": r["score"]}
                         for r in rows if r["label"] == 0 and r["band"] == "SCAM"],
        "thresholds": {"low": detector.low, "high": detector.high} if hasattr(detector, "low") else None,
        "uci_regression": "NOT_AVAILABLE (raw UCI corpus excluded from transfer bundle)",
        "scope": "Synthetic AI-assisted holdout only; not real-world validation",
    }
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(json.dumps({k: report[k] for k in ("all_frozen_hashes_match", "overall", "english", "hinglish",
                                              "per_case_band_mismatches_vs_recorded", "max_abs_score_diff_vs_recorded")}, indent=1))


if __name__ == "__main__":
    main()
