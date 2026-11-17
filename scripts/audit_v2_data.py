"""Audit v2 splits and quarantine near-duplicate holdout cases before predictions."""
import hashlib
import json
from pathlib import Path
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors
from edgeshield.datasets import canonical, read_jsonl, check_leakage

ROOT = Path(__file__).resolve().parents[1]


def main():
    out = ROOT / "results/host/v2/data_audit.json"
    if out.exists():
        raise SystemExit("Audit already exists; preserve this version.")
    dev_path = ROOT / "data/synthetic/v2_development.jsonl"
    held_path = ROOT / "data/synthetic/v2_holdout.jsonl"
    dev, held = read_jsonl(dev_path), read_jsonl(held_path)
    check_leakage(dev)
    combined = dev + held
    if len({r["id"] for r in combined}) != len(combined):
        raise ValueError("Duplicate IDs")
    for row in combined:
        if row["label"] not in (0, 1, None) or row["language"] not in ("english", "hinglish"):
            raise ValueError("Invalid label or language")
        if not row["source"].startswith("synthetic"):
            raise ValueError("Synthetic provenance missing")
    reference = [r for r in dev]
    for split in ("train", "calibration", "validation"):
        reference.extend(read_jsonl(ROOT / f"data/processed/{split}.jsonl"))
    reference_text = [canonical(r["text"]) for r in reference]
    holdout_text = [canonical(r["text"]) for r in held]
    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=50000)
    vectorizer.fit(reference_text + holdout_text)
    matrix = vectorizer.transform(reference_text)
    neighbors = NearestNeighbors(n_neighbors=1, metric="cosine", algorithm="brute", n_jobs=1).fit(matrix)
    distances, indices = neighbors.kneighbors(vectorizer.transform(holdout_text))
    canon_set = set(reference_text)
    exclusions = []
    for row, canon, distance, idx in zip(held, holdout_text, distances[:, 0], indices[:, 0]):
        similarity = float(1 - distance)
        if canon in canon_set or similarity >= .90:
            exclusions.append({"id": row["id"], "reference_id": reference[int(idx)]["id"], "similarity": similarity,
                               "reason": "canonical" if canon in canon_set else "near_duplicate"})
    report = {"status": "PASSED", "method": "canonical and char3-5 cosine>=0.90; no model predictions",
              "development_n": len(dev), "heldout_n": len(held), "excluded": exclusions,
              "excluded_ids": [r["id"] for r in exclusions],
              "development_sha256": hashlib.sha256(dev_path.read_bytes()).hexdigest(),
              "holdout_sha256": hashlib.sha256(held_path.read_bytes()).hexdigest()}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k not in ("excluded", "excluded_ids")}))
    print("Excluded heldout examples:", len(exclusions))


if __name__ == "__main__":
    main()
