import copy
from pathlib import Path
import numpy as np
import pytest
from edgeshield.detector_v7 import (
    DetectorV7,
    MODEL_VERSION,
    SCORE_LABEL,
    canonicalize_features_v7,
    save_artifact,
)
from edgeshield.indicators import detect_indicators

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tiny_v7_artifact():
    return {
        "format": 7,
        "model_version": MODEL_VERSION,
        "word": {"vocabulary": {"credited": 0, "blocked": 1, "inramount": 2, "otpnum": 3}, "idf": [1.0, 1.0, 1.0, 1.0]},
        "char": {"vocabulary": {"cre": 0, "blo": 1}, "idf": [1.0, 1.0]},
        "coef": [-1.5, 1.5, -0.5, -0.5, -1.0, 1.0],
        "intercept": 0.0,
        "calibration": [1.0, 0.0],
        "thresholds": [0.35, 0.65],
    }


def test_canonicalize_v7_separates_otpnum_from_shortnum_and_keeps_context():
    benign = canonicalize_features_v7(
        "Verification: Enter passcode 590283 inside official mobile app; 123456 is your OTP for INR 499.00 on A/c XX3719."
    )
    assert "passcode otpnum inside" in benign.lower()
    assert "otpnum is your otp" in benign.lower()
    assert "shortnum" not in benign
    assert "inramount" in benign
    assert "bankacctmask" in benign

    uci_shortcode = canonicalize_features_v7("Text WIN to 87121 right now at https://bit.ly/claim-prize!")
    assert "to shortnum right" in uci_shortcode
    assert "otpnum" not in uci_shortcode
    assert "shortenerurl bit.ly" in uci_shortcode


def test_v7_roundtrip_and_tamper_detection(tiny_v7_artifact, tmp_path):
    model = DetectorV7(tiny_v7_artifact)
    assert model.predict("credited INR 5,000.00")["band"] == "LEGITIMATE"
    assert model.predict("blocked")["band"] == "SCAM"
    assert model.predict("qqqqxxxxzzzz")["band"] == "UNCERTAIN"
    path = tmp_path / "v7.json"
    save_artifact(path, tiny_v7_artifact)
    loaded = DetectorV7.load(path)
    np.testing.assert_allclose(model.scores(["credited", "blocked"]), loaded.scores(["credited", "blocked"]))
    assert loaded.predict("credited")["score_label"] == SCORE_LABEL
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="checksum"):
        DetectorV7.load(path)


def test_v7_invalid_artifact_rejected(tiny_v7_artifact):
    bad = copy.deepcopy(tiny_v7_artifact)
    bad["format"] = 6
    with pytest.raises(ValueError, match="Invalid v7"):
        DetectorV7(bad)
    bad2 = copy.deepcopy(tiny_v7_artifact)
    bad2["thresholds"] = [0.8, 0.2]
    with pytest.raises(ValueError, match="Invalid v7"):
        DetectorV7(bad2)


def test_trained_v7_candidate_integrity_and_cues():
    model = DetectorV7.load(ROOT / "models/detector_v7.json")
    for text in (
        "Your A/c XX1234 has been credited with INR 5,000.00 on 20-Nov-26. Info: NEFT-REF12345. Avl Bal: INR 24,500.00.",
        "Bank Security Advisory: Fraudsters send fake account block and KYC update links. Bank staff will never ask for your OTP, password, or UPI PIN.",
    ):
        pred = model.predict(text)
        assert pred["model_version"] == MODEL_VERSION
        assert pred["band"] == "LEGITIMATE"
        assert "BANK_IMPERSONATION" not in detect_indicators(text)
