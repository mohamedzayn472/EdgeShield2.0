import hashlib
import json
from pathlib import Path
import numpy as np
import pytest
from edgeshield.datasets import check_leakage, canonical, read_jsonl, group_near_duplicates
from edgeshield.detector import Detector, decision_band

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def detector():
    return Detector.load(ROOT / "models/detector.json")


@pytest.mark.parametrize("score,expected", [(0.2, "LEGITIMATE"), (0.5, "UNCERTAIN"), (0.8, "SCAM")])
def test_threshold_boundaries(score, expected):
    assert decision_band(score, .2, .8) == expected


@pytest.mark.parametrize("score,low,high", [(float("nan"), .2, .8), (1.1, .2, .8), (.5, .8, .2), (.5, .2, .2)])
def test_invalid_thresholds(score, low, high):
    with pytest.raises(ValueError):
        decision_band(score, low, high)


def test_deterministic_serialization(detector):
    message = "An ordinary example message about the appointment tomorrow."
    result = detector.predict(message)
    again = Detector.load(ROOT / "models/detector.json").predict(message)
    assert result["score"] == again["score"]
    assert result["band"] == again["band"]
    assert 0 <= result["score"] <= 1
    assert result["detector_ms"] >= 0
    np.testing.assert_allclose(detector.scores([message])[0], result["score"])


def test_unknown_vocabulary_abstains(detector):
    assert detector.predict("zzzzqqqqxxxxvvvv")['band'] == 'UNCERTAIN'


@pytest.mark.parametrize("text", ["", " " , "x" * 4097, None])
def test_input_validation(detector, text):
    with pytest.raises(ValueError):
        detector.predict(text)


def test_unicode_normalization(detector):
    assert detector.predict("Ｈｅｌｌｏ friend")["score"] == detector.predict("Hello friend")["score"]


def test_integrity_rejects_tampering(tmp_path):
    path = tmp_path / "model.json"
    raw = (ROOT / "models/detector.json").read_bytes()
    path.write_bytes(raw + b" ")
    Path(str(path)+".sha256").write_text(hashlib.sha256(raw).hexdigest())
    with pytest.raises(ValueError, match="checksum"):
        Detector.load(path)


def test_schema_rejects_untrusted_version():
    data = json.loads((ROOT / "models/detector.json").read_text())
    data["model_version"] = "\x1b[2J"
    with pytest.raises(ValueError):
        Detector(data)


def test_source_split_integrity():
    if not (ROOT / "data/processed/test.jsonl").exists():
        pytest.skip("Corpus excluded from transfer bundle; reproduce local dataset preparation to run split audit")
    rows = []
    for split in ("train", "calibration", "validation", "test"):
        rows += read_jsonl(ROOT / f"data/processed/{split}.jsonl")
    check_leakage(rows)


def test_synthetic_family_integrity():
    rows = read_jsonl(ROOT / "data/synthetic/indian_sms.jsonl")
    check_leakage(rows)
    assert all(row['source'].startswith('synthetic') for row in rows)
    assert any(row['language'] == 'hinglish' for row in rows)


def test_leakage_checker_rejects_family_crossing():
    with pytest.raises(ValueError):
        check_leakage([{"text": "first sample", "family": "shared", "split": "train"}, {"text": "second sample", "family": "shared", "split": "test"}])


def test_canonical_duplicate_grouping():
    assert canonical("Pay 123 at https://one.example/a") == canonical("Pay 456 at https://two.example/b")
    rows = [{"text": "Your code is 12345, keep it private."}, {"text": "Your code is 67890, keep it private."}, {"text": "Lunch tomorrow by the library."}]
    groups = group_near_duplicates(rows)
    assert groups[0] == groups[1]
    assert groups[0] != groups[2]
