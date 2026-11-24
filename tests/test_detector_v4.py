import copy
from pathlib import Path
import numpy as np
import pytest
from edgeshield.detector_v4 import (
    DetectorV4,
    MODEL_VERSION,
    SCORE_LABEL,
    canonicalize_features_v4,
    save_artifact,
)
from edgeshield.indicators import detect_indicators

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tiny_v4_artifact():
    return {
        "format": 4,
        "model_version": MODEL_VERSION,
        "word": {"vocabulary": {"credited": 0, "blocked": 1, "inramount": 2}, "idf": [1.0, 1.0, 1.0]},
        "char": {"vocabulary": {"cre": 0, "blo": 1}, "idf": [1.0, 1.0]},
        "coef": [-1.5, 1.5, -0.5, -1.0, 1.0],
        "intercept": 0.0,
        "calibration": [1.0, 0.0],
        "thresholds": [0.35, 0.65],
    }


def test_canonicalize_v4_normalizes_unicode_and_banking():
    out = canonicalize_features_v4(
        "Don\u2019t share one\u2011time password: Ac XX1234 credited INR 5,000.00 on 20-Nov-26."
    )
    assert "don't" in out.lower()
    assert "one-time" in out.lower()
    assert "bankacctmask" in out
    assert "inramount" in out
    assert "datetoken" in out


def test_v4_roundtrip_and_tamper_detection(tiny_v4_artifact, tmp_path):
    model = DetectorV4(tiny_v4_artifact)
    assert model.predict("credited INR 5,000.00")["band"] == "LEGITIMATE"
    assert model.predict("blocked")["band"] == "SCAM"
    assert model.predict("qqqqxxxxzzzz")["band"] == "UNCERTAIN"
    path = tmp_path / "v4.json"
    save_artifact(path, tiny_v4_artifact)
    loaded = DetectorV4.load(path)
    np.testing.assert_allclose(model.scores(["credited", "blocked"]), loaded.scores(["credited", "blocked"]))
    assert loaded.predict("credited")["score_label"] == SCORE_LABEL
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="checksum"):
        DetectorV4.load(path)


def test_v4_invalid_artifact_rejected(tiny_v4_artifact):
    bad = copy.deepcopy(tiny_v4_artifact)
    bad["format"] = 3
    with pytest.raises(ValueError, match="Invalid v4"):
        DetectorV4(bad)
    bad2 = copy.deepcopy(tiny_v4_artifact)
    bad2["thresholds"] = [0.8, 0.2]
    with pytest.raises(ValueError, match="Invalid v4"):
        DetectorV4(bad2)


def test_trained_v4_candidate_integrity_and_cues():
    model = DetectorV4.load(ROOT / "models/detector_v4.json")
    for text in (
        "Your A/c XX1234 has been credited with INR 5,000.00 on 20-Nov-26. Info: NEFT-REF12345. Avl Bal: INR 24,500.00.",
        "Bank Security Advisory: Fraudsters send fake account block and KYC update links. Bank staff will never ask for your OTP, password, or UPI PIN.",
    ):
        pred = model.predict(text)
        assert pred["model_version"] == MODEL_VERSION
        assert pred["band"] == "LEGITIMATE"
        assert "BANK_IMPERSONATION" not in detect_indicators(text)
