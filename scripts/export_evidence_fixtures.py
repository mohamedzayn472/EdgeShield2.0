"""Export closed-schema detector evidence (no message text) for Llama host studies.

Runs in the application environment (.venv-host). For every row of a synthetic
corpus it records id, label, language, detector band/score and indicator IDs.
SMS text is never written. Output is consumed by scripts/verify_llama_host.py.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from edgeshield.datasets import read_jsonl  # noqa: E402
from edgeshield.model_loader import load_detector  # noqa: E402
from edgeshield.pipeline import assess  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, required=True)
    p.add_argument("--detector", type=Path, default=ROOT / "models/detector_v2.json")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if a.output.exists():
        p.error("Output exists; preserve prior results")
    detector = load_detector(a.detector)
    cases = []
    for row in read_jsonl(a.data):
        result = assess(row["text"], detector)
        cases.append({"id": row["id"], "label": row.get("label"), "language": row.get("language"),
                      "band": result.evidence.band, "score": result.evidence.score,
                      "indicators": list(result.evidence.indicators)})
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open("x", encoding="utf-8") as f:
        json.dump({"source": a.data.name, "detector": a.detector.name,
                   "note": "Evidence only; message text intentionally omitted", "cases": cases}, f, indent=1)
    print(f"Wrote {len(cases)} evidence rows")


if __name__ == "__main__":
    main()
