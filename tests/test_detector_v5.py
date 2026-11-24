import copy
from pathlib import Path
import numpy as np
import pytest
from edgeshield.detector_v5 import (
    DetectorV5,
    MODEL_VERSION,
    SCORE_LABEL,
    canonicalize_features_v5,
    save_artifact,
)
from edgeshield.indicators import detect_indicators

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tiny_v5_artifact():
    return {
        "format": 5,
        "model_version": MODEL_VERSION,
        "word": {"vocabulary": {"credited": 0, "blocked": 1, "inramount": 2}, "idf": [1.0, 1.0, 1.0]},
        "char": {"vocabulary": {"cre": 0, "blo": 1}, "idf": [1.0, 1.0]},
        "coef": [-1.5, 1.5, -0.5, -1.0, 1.0],
        "intercept": 0.0,
        "calibration": [1.0, 0.0],
        "thresholds": [0.35, 0.65],
    }


def test_canonicalize_v5_normalizes_urls_endings_and_refs():
    benign = canonicalize_features_v5(
        "Don\u2019t click short URLs: Download October passbook for savings account ending 7301 at https://unseenbank.example/statements/oct26 Ref NM8831042 Consumer #CP55102."
    )
    assert "don't" in benign.lower()
    assert "unseenbank" not in benign.lower()
    assert "urltoken statements" in benign.lower()
    assert "bankacctmask" in benign
    assert "txrefnum" in benign
    assert "refidtoken" in benign

    scam = canonicalize_features_v5("Click https://bit.ly/fake-kyc right now.")
    assert "urltoken shortenerurl bit.ly" in scam


def test_v5_roundtrip_and_tamper_detection(tiny_v5_artifact, tmp_path):
    model = DetectorV5(tiny_v5_artifact)
    assert model.predict("credited INR 5,000.00")["band"] == "LEGITIMATE"
    assert model.predict("blocked")["band"] == "SCAM"
    assert model.predict("qqqqxxxxzzzz")["band"] == "UNCERTAIN"
    path = tmp_path / "v5.json"
    save_artifact(path, tiny_v5_artifact)
    loaded = DetectorV5.load(path)
    np.testing.assert_allclose(model.scores(["credited", "blocked"]), loaded.scores(["credited", "blocked"]))
    assert loaded.predict("credited")["score_label"] == SCORE_LABEL
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="checksum"):
        DetectorV5.load(path)


def test_v5_invalid_artifact_rejected(tiny_v5_artifact):
    bad = copy.deepcopy(tiny_v5_artifact)
    bad["format"] = 4
    with pytest.raises(ValueError, match="Invalid v5"):
        DetectorV5(bad)
    bad2 = copy.deepcopy(tiny_v5_artifact)
    bad2["thresholds"] = [0.8, 0.2]
    with pytest.raises(ValueError, match="Invalid v5"):
        DetectorV5(bad2)


def test_trained_v5_candidate_integrity_and_cues():
    model = DetectorV5.load(ROOT / "models/detector_v5.json")
    for text in (
        "Your A/c XX1234 has been credited with INR 5,000.00 on 20-Nov-26. Info: NEFT-REF12345. Avl Bal: INR 24,500.00.",
        "Bank Security Advisory: Fraudsters send fake account block and KYC update links. Bank staff will never ask for your OTP, password, or UPI PIN.",
    ):
        pred = model.predict(text)
        assert pred["model_version"] == MODEL_VERSION
        assert pred["band"] == "LEGITIMATE"
        assert "BANK_IMPERSONATION" not in detect_indicators(text)
