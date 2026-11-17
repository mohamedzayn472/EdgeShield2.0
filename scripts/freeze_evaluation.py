"""Record immutable baseline identities before the one-time heldout evaluation."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "src/edgeshield/detector.py", "src/edgeshield/datasets.py", "src/edgeshield/privacy.py",
    "scripts/train_detector.py", "scripts/prepare_dataset.py", "scripts/evaluate_detector.py",
    "docs/EVALUATION.md", "data/processed/test.jsonl", "data/synthetic/indian_sms.jsonl",
    "data/processed/train.jsonl", "data/processed/calibration.jsonl", "data/processed/validation.jsonl",
)


def main():
    destination = ROOT / "results/host/evaluation_freeze.json"
    if destination.exists() or (ROOT / "results/host/heldout_evaluation.json").exists():
        raise SystemExit("Freeze or final results already exist; retain them and version any new experiment separately.")
    sha = lambda p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
    record = {"created_at_utc": datetime.now(timezone.utc).isoformat(),
              "purpose": "Laptop baseline evaluation freeze; not a claim of final submission or hardware freeze",
              "model_sha256": sha("models/detector.json"),
              "file_sha256": {name: sha(name) for name in FILES}}
    destination.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print("Recorded baseline code/data/model freeze. Final evaluation has not run yet.")


if __name__ == "__main__":
    main()
