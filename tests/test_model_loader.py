import json
from pathlib import Path
import pytest
from edgeshield.model_loader import load_detector


@pytest.mark.parametrize("path,version", [
    ("models/detector.json", "edgeshield-tfidf-lr-v1"),
    ("models/detector_v2.json", "edgeshield-word-char-lr-v2"),
    ("models/detector_v3.json", "edgeshield-word-char-lr-v3"),
    ("models/detector_v4.json", "edgeshield-word-char-lr-v4"),
    ("models/detector_v5.json", "edgeshield-word-char-lr-v5"),
    ("models/detector_v6.json", "edgeshield-word-char-lr-v6"),
    ("models/detector_v7.json", "edgeshield-word-char-lr-v7"),
    ("models/detector_v8.json", "edgeshield-word-char-lr-v8"),
])
def test_supported_models(path, version):
    assert load_detector(path).predict("A blue notebook rests on the wooden desk.")["model_version"] == version


@pytest.mark.parametrize("value", [[], {"format": True}, {"format": 99}, {"format": "2"}])
def test_unknown_format_fails(value, tmp_path):
    path = tmp_path / "model.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        load_detector(path)


def test_loader_cache_hit_and_tamper_invalidation(tmp_path):
    from edgeshield.detector_v2 import MODEL_VERSION, save_artifact
    artifact = {
        "format": 2,
        "model_version": MODEL_VERSION,
        "word": {"vocabulary": {"hello": 0, "danger": 1}, "idf": [1.0, 1.0]},
        "char": {"vocabulary": {"hel": 0, "dan": 1}, "idf": [1.0, 1.0]},
        "coef": [-1.0, 1.0, -1.0, 1.0],
        "intercept": 0.0,
        "calibration": [1.0, 0.0],
        "thresholds": [0.2, 0.8],
    }
    path = tmp_path / "cached_v2.json"
    save_artifact(path, artifact)
    first = load_detector(path)
    second = load_detector(path)
    assert first is second

    original_bytes = path.read_bytes()
    path.write_bytes(original_bytes + b" ")
    with pytest.raises(ValueError, match="checksum"):
        load_detector(path)

    path.write_bytes(original_bytes)
    sha_path = Path(str(path) + ".sha256")
    original_sha = sha_path.read_text(encoding="ascii")
    sha_path.write_text("0" * 64 + "\n", encoding="ascii")
    with pytest.raises(ValueError, match="checksum"):
        load_detector(path)

    sha_path.write_text(original_sha + " " * 300, encoding="ascii")
    with pytest.raises(ValueError, match="checksum"):
        load_detector(path)
