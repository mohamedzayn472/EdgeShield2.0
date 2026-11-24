import copy
import json
from pathlib import Path
import numpy as np
import pytest
from edgeshield.detector_v3 import DetectorV3, MODEL_VERSION, SCORE_LABEL, band_for_score, canonicalize_features, save_artifact
from edgeshield.indicators import detect_indicators

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tiny_v3_artifact():
    return {
        "format": 3,
        "model_version": MODEL_VERSION,
        "word": {"vocabulary": {"credited": 0, "blocked": 1, "inramount": 2}, "idf": [1.0, 1.0, 1.0]},
        "char": {"vocabulary": {"cre": 0, "blo": 1}, "idf": [1.0, 1.0]},
        "coef": [-1.5, 1.5, -0.5, -1.0, 1.0],
        "intercept": 0.0,
        "calibration": [1.0, 0.0],
        "thresholds": [0.35, 0.65],
    }


def test_canonicalize_features_normalizes_banking_patterns():
    out = canonicalize_features("Your A/c XX1234 credited with INR 5,000.00 on 20-Nov-26 Ref 632145678901.")
    assert "bankacctmask" in out
    assert "inramount" in out
    assert "datetoken" in out
    assert "txrefnum" in out
    url_out = canonicalize_features("Verify now at https://bit.ly/fake-kyc")
    assert "urltoken" in url_out
    assert "shortenerurl" in url_out


def test_v3_roundtrip_and_tamper_detection(tiny_v3_artifact, tmp_path):
    model = DetectorV3(tiny_v3_artifact)
    assert model.predict("credited INR 5,000.00")["band"] == "LEGITIMATE"
    assert model.predict("blocked")["band"] == "SCAM"
    assert model.predict("qqqqxxxxzzzz")["band"] == "UNCERTAIN"
    path = tmp_path / "v3.json"
    save_artifact(path, tiny_v3_artifact)
    loaded = DetectorV3.load(path)
    np.testing.assert_allclose(model.scores(["credited", "blocked"]), loaded.scores(["credited", "blocked"]))
    assert loaded.predict("credited")["score_label"] == SCORE_LABEL
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="checksum"):
        DetectorV3.load(path)


def test_v3_invalid_artifact_rejected(tiny_v3_artifact):
    bad = copy.deepcopy(tiny_v3_artifact)
    bad["format"] = 2
    with pytest.raises(ValueError, match="Invalid v3"):
        DetectorV3(bad)
    bad2 = copy.deepcopy(tiny_v3_artifact)
    bad2["thresholds"] = [0.8, 0.2]
    with pytest.raises(ValueError, match="Invalid v3"):
        DetectorV3(bad2)


def test_trained_v3_banking_false_positives_and_scam_consistency():
    model = DetectorV3.load(ROOT / "models/detector_v3.json")
    legit_samples = [
        "Your A/c XX1234 has been credited with INR 5,000.00 on 20-Nov-26. Info: NEFT-REF12345. Avl Bal: INR 24,500.00.",
        "Alert: Your A/c XX9012 is debited by INR 850.00 on 20-Nov-26 towards UPI/Merchant. Call customer care if unauthorized.",
        "123456 is your OTP for transaction of INR 499.00 on your HDFC Bank Card XX1234. Do not share OTP with anyone. Valid for 10 mins.",
        "Rs 350.00 paid to Fresh Mart via UPI. UPI Ref No 432198765432. A/c XX1234.",
        "Notice: Internal assessment timetable for Semester 5 is published on the department notice board. Classes resume Monday.",
        "Your e-statement for Bank A/c XX1234 for October 2026 has been sent to your registered email ID.",
    ]
    scam_samples = [
        "Urgent: Your bank account will be blocked today. Update KYC immediately at https://bit.ly/verify-kyc.",
        "Dear user, your bank KYC is pending. Share your 6 digit OTP immediately to avoid account suspension.",
        "Alert: Unusual activity on your bank card. Enter your PIN and CVV at https://secure-bank-login.example to unlock.",
    ]
    for msg in legit_samples:
        pred = model.predict(msg)
        inds = detect_indicators(msg)
        assert pred["band"] == "LEGITIMATE", f"Unexpected non-LEGITIMATE ({pred}) for: {msg}"
        assert "BANK_IMPERSONATION" not in inds, f"Unexpected BANK_IMPERSONATION ({inds}) for: {msg}"
    for msg in scam_samples:
        pred = model.predict(msg)
        inds = detect_indicators(msg)
        assert pred["band"] == "SCAM", f"Unexpected non-SCAM ({pred}) for: {msg}"
        assert "BANK_IMPERSONATION" in inds, f"Missing BANK_IMPERSONATION ({inds}) for: {msg}"
