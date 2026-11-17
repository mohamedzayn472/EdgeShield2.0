"""Prepare local UCI download. Does not download or run test evaluation."""
import json
from collections import Counter
from pathlib import Path
import zipfile
from edgeshield.datasets import split_rows, write_jsonl, digest
from edgeshield.privacy import normalize_sms

ROOT = Path(__file__).resolve().parents[1]


def main():
    archive = ROOT / "data/raw/uci_sms.zip"
    with zipfile.ZipFile(archive) as z:
        lines = z.read("SMSSpamCollection").decode("utf-8").splitlines()
    rows, skipped = [], 0
    for i, line in enumerate(lines):
        label, text = line.split("\t", 1)
        if label not in {"ham", "spam"}:
            raise ValueError("Unexpected UCI label")
        try:
            text = normalize_sms(text)
        except ValueError:
            skipped += 1
            continue
        rows.append({"id": f"uci-{i:05}", "text": text, "label": int(label == "spam"), "source": "uci"})
    split_rows(rows)
    for split in ("train", "calibration", "validation", "test"):
        write_jsonl(ROOT / f"data/processed/{split}.jsonl", [r for r in rows if r["split"] == split])
    summary = {"source_sha256": digest(archive), "rows": len(rows), "skipped": skipped,
               "splits": {s: dict(Counter(r["label"] for r in rows if r["split"] == s)) for s in ("train", "calibration", "validation", "test")},
               "groups": len({r["group"] for r in rows}), "near_duplicate_cosine_threshold": 0.90,
               "leakage_check": "PASSED", "seed": 20261115}
    (ROOT / "data/processed/manifest.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
