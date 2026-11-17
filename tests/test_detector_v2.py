import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import numpy as np
import pytest
from edgeshield.detector_v2 import DetectorV2, MODEL_VERSION, SCORE_LABEL, band_for_score, save_artifact

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tiny_artifact():
    return {"format": 2, "model_version": MODEL_VERSION,
            "word": {"vocabulary": {"hello": 0, "danger": 1}, "idf": [1.0, 1.0]},
            "char": {"vocabulary": {"hel": 0, "dan": 1}, "idf": [1.0, 1.0]},
            "coef": [-1.0, 1.0, -1.0, 1.0], "intercept": 0.0,
            "calibration": [1.0, 0.0], "thresholds": [.2, .8]}


def test_two_feature_blocks_and_roundtrip(tiny_artifact, tmp_path):
    model = DetectorV2(tiny_artifact)
    assert model.predict("hello")["band"] == "LEGITIMATE"
    assert model.predict("danger")["band"] == "SCAM"
    path = tmp_path / "model.json"
    save_artifact(path, tiny_artifact)
    loaded = DetectorV2.load(path)
    np.testing.assert_allclose(model.scores(["hello", "danger"]), loaded.scores(["hello", "danger"]))
    assert loaded.predict("hello")["score_label"] == SCORE_LABEL


def test_oov_abstains(tiny_artifact):
    model = DetectorV2(tiny_artifact)
    assert model.predict("qqqqxxxxzzzz")["band"] == "UNCERTAIN"


def test_normalization_and_timing(tiny_artifact):
    model = DetectorV2(tiny_artifact)
    assert model.predict("Ｈｅｌｌｏ")["score"] == model.predict("Hello")["score"]
    assert model.predict("hello")["detector_ms"] >= 0


@pytest.mark.parametrize("text", ["", " ", "x" * 4097, None, "\ud800"])
def test_invalid_input(tiny_artifact, text):
    with pytest.raises(ValueError):
        DetectorV2(tiny_artifact).predict(text)


@pytest.mark.parametrize("score,band", [(0.2, "LEGITIMATE"), (.21, "UNCERTAIN"), (.8, "SCAM")])
def test_threshold_endpoint(score, band):
    assert band_for_score(score, .2, .8) == band


@pytest.mark.parametrize("values", [(float("nan"), .2, .8), (.5, .5, .5), (True, .2, .8), (-.1, .2, .8), (.5, 0, 1.1)])
def test_invalid_threshold(values):
    with pytest.raises(ValueError):
        band_for_score(*values)


@pytest.mark.parametrize("key,value", [("model_version", "\x1b[2J"), ("coef", [0, 1]), ("coef", [0, 1, float("nan"), 1]), ("calibration", [-1, 0]), ("thresholds", [1, 0]), ("intercept", float("inf"))])
def test_invalid_artifact(tiny_artifact, key, value):
    tiny_artifact[key] = value
    with pytest.raises(ValueError, match="Invalid v2"):
        DetectorV2(tiny_artifact)


def test_bad_vocab_and_idf(tiny_artifact):
    bad = copy.deepcopy(tiny_artifact)
    bad["word"]["vocabulary"] = {"hello": True, "danger": 0}
    with pytest.raises(ValueError):
        DetectorV2(bad)
    bad = copy.deepcopy(tiny_artifact)
    bad["char"]["idf"] = [0, 1]
    with pytest.raises(ValueError):
        DetectorV2(bad)


def test_tampered_artifact(tiny_artifact, tmp_path):
    path = tmp_path / "model.json"
    save_artifact(path, tiny_artifact)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="checksum"):
        DetectorV2.load(path)


def test_empty_checksum(tiny_artifact, tmp_path):
    path = tmp_path / "model.json"
    save_artifact(path, tiny_artifact)
    Path(str(path) + ".sha256").write_text("")
    with pytest.raises(ValueError):
        DetectorV2.load(path)


def test_selection_counts_abstention_as_missed_recall():
    spec = importlib.util.spec_from_file_location("train_v2", ROOT / "scripts/train_detector_v2.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.summary(np.array([0, 0, 1, 1]), np.array([.1, .3, .4, .9]), .2, .8)
    assert result["recall"] == .5
    assert result["abstention_rate"] == .5
    assert result["false_positive_rate"] == 0
    assert result["confusion_matrix_2_by_3"] == [[1, 1, 0], [0, 1, 1]]


def test_trained_artifact_roundtrip_and_safe_metadata():
    model = DetectorV2.load(ROOT / "models/detector_v2.json")
    # Neutral manufactured probe, not a development or heldout example.
    result = model.predict("A blue notebook rests on the wooden desk.")
    assert result["model_version"] == MODEL_VERSION
    assert result["score_label"] == SCORE_LABEL
    assert 0 <= result["score"] <= 1
    assert result["band"] in {"LEGITIMATE", "UNCERTAIN", "SCAM"}
    assert result["score"] == model.predict("A blue notebook rests on the wooden desk.")["score"]
