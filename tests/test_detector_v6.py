import copy
from pathlib import Path
import numpy as np
import pytest
from edgeshield.detector_v6 import (
    DetectorV6,
    MODEL_VERSION,
    SCORE_LABEL,
    canonicalize_features_v6,
    save_artifact,
)
from edgeshield.indicators import detect_indicators

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tiny_v6_artifact():
    return {
        "format": 6,
        "model_version": MODEL_VERSION,
        "word": {"vocabulary": {"credited": 0, "blocked": 1, "inramount": 2}, "idf": [1.0, 1.0, 1.0]},
        "char": {"vocabulary": {"cre": 0, "blo": 1}, "idf": [1.0, 1.0]},
        "coef": [-1.5, 1.5, -0.5, -1.0, 1.0],
        "intercept": 0.0,
        "calibration": [1.0, 0.0],
        "thresholds": [0.35, 0.65],
    }


def test_canonicalize_v6_extracts_risk_keywords_and_drops_brands():
    benign = canonicalize_features_v6(
        "Don\u2019t click short URLs: Download November passbook for savings account ending 3719 at https://tungabhadra.example/statements/nov Ref TB4491820 Consumer #SP44091."
    )
    assert "don't" in benign.lower()
    assert "tungabhadra" not in benign.lower()
    assert "urltoken statements nov" in benign.lower()
    assert "bankacctmask" in benign
    assert "txrefnum" in benign
    assert "refidtoken" in benign

    scam_host = canonicalize_features_v6("Sign in via https://sabarmati-unblock.example/wap right away.")
    assert "sabarmati" not in scam_host
    assert "urltoken" in scam_host
    assert "urlkw_unblock" in scam_host
    assert "wap" in scam_host

    short = canonicalize_features_v6("Click https://bit.ly/fake-kyc right now.")
    assert "urltoken shortenerurl bit.ly" in short


def test_v6_roundtrip_and_tamper_detection(tiny_v6_artifact, tmp_path):
    model = DetectorV6(tiny_v6_artifact)
    assert model.predict("credited INR 5,000.00")["band"] == "LEGITIMATE"
    assert model.predict("blocked")["band"] == "SCAM"
    assert model.predict("qqqqxxxxzzzz")["band"] == "UNCERTAIN"
    path = tmp_path / "v6.json"
    save_artifact(path, tiny_v6_artifact)
    loaded = DetectorV6.load(path)
    np.testing.assert_allclose(model.scores(["credited", "blocked"]), loaded.scores(["credited", "blocked"]))
    assert loaded.predict("credited")["score_label"] == SCORE_LABEL
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="checksum"):
        DetectorV6.load(path)


def test_v6_invalid_artifact_rejected(tiny_v6_artifact):
    bad = copy.deepcopy(tiny_v6_artifact)
    bad["format"] = 5
    with pytest.raises(ValueError, match="Invalid v6"):
        DetectorV6(bad)
    bad2 = copy.deepcopy(tiny_v6_artifact)
    bad2["thresholds"] = [0.8, 0.2]
    with pytest.raises(ValueError, match="Invalid v6"):
        DetectorV6(bad2)


def test_trained_v6_candidate_integrity_and_cues():
    model = DetectorV6.load(ROOT / "models/detector_v6.json")
    for text in (
        "Your A/c XX1234 has been credited with INR 5,000.00 on 20-Nov-26. Info: NEFT-REF12345. Avl Bal: INR 24,500.00.",
        "Bank Security Advisory: Fraudsters send fake account block and KYC update links. Bank staff will never ask for your OTP, password, or UPI PIN.",
    ):
        pred = model.predict(text)
        assert pred["model_version"] == MODEL_VERSION
        assert pred["band"] == "LEGITIMATE"
        assert "BANK_IMPERSONATION" not in detect_indicators(text)
