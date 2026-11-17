"""TF-IDF logistic regression inference with non-executable JSON artifacts."""
from __future__ import annotations
import hashlib
import json
import math
from pathlib import Path
import time
import numpy as np
from scipy.special import expit
from sklearn.feature_extraction.text import TfidfVectorizer
from .privacy import normalize_sms

MODEL_VERSION = "edgeshield-tfidf-lr-v1"
SCORE_LABEL = "UCI spam proxy score (not verified scam probability)"


def decision_band(score: float, low: float, high: float) -> str:
    if not all(math.isfinite(x) for x in (score, low, high)) or not 0 <= score <= 1 or not 0 <= low < high <= 1:
        raise ValueError("Invalid score or thresholds")
    return "LEGITIMATE" if score <= low else "SCAM" if score >= high else "UNCERTAIN"


class Detector:
    def __init__(self, artifact: dict):
        try:
            if artifact["format"] != 1 or artifact["model_version"] != MODEL_VERSION:
                raise ValueError()
            vocab = artifact["vocabulary"]
            if not isinstance(vocab, dict) or not 1 <= len(vocab) <= 50000:
                raise ValueError()
            if sorted(vocab.values()) != list(range(len(vocab))) or not all(isinstance(k, str) and len(k) <= 256 for k in vocab):
                raise ValueError()
            self.coef = np.asarray(artifact["coef"], dtype=float)
            idf = np.asarray(artifact["idf"], dtype=float)
            if self.coef.shape != (len(vocab),) or idf.shape != self.coef.shape or not np.isfinite(self.coef).all() or not np.isfinite(idf).all() or (idf <= 0).any():
                raise ValueError()
            self.intercept = float(artifact["intercept"])
            self.calibration = tuple(float(x) for x in artifact["calibration"])
            if len(self.calibration) != 2 or not all(math.isfinite(x) for x in (*self.calibration, self.intercept)) or self.calibration[0] <= 0:
                raise ValueError()
            self.low, self.high = (float(x) for x in artifact["thresholds"])
            decision_band(0.5, self.low, self.high)
            self.vectorizer = TfidfVectorizer(vocabulary=vocab, ngram_range=(1, 2), sublinear_tf=True, lowercase=True, token_pattern=r"(?u)\b\w\w+\b")
            self.vectorizer.idf_ = idf
        except (KeyError, TypeError, ValueError, OverflowError):
            raise ValueError("Invalid detector artifact") from None

    @classmethod
    def load(cls, path: str | Path) -> "Detector":
        path = Path(path)
        if path.stat().st_size > 20_000_000:
            raise ValueError("Detector artifact exceeds size limit")
        raw = path.read_bytes()
        expected = Path(str(path) + ".sha256").read_text(encoding="ascii").split()[0]
        if len(expected) != 64 or hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("Detector checksum mismatch")
        return cls(json.loads(raw))

    def scores(self, texts: list[str]) -> np.ndarray:
        matrix = self.vectorizer.transform([normalize_sms(text) for text in texts])
        logits = np.asarray(matrix @ self.coef).ravel() + self.intercept
        return expit(self.calibration[0] * logits + self.calibration[1])

    def predict(self, text: str) -> dict:
        start = time.perf_counter()
        normalized = normalize_sms(text)
        vector = self.vectorizer.transform([normalized])
        score = float(expit(self.calibration[0] * (float((vector @ self.coef)[0]) + self.intercept) + self.calibration[1]))
        # An entirely unknown vocabulary has no text evidence. Abstain rather than using the intercept alone.
        band = "UNCERTAIN" if vector.nnz == 0 else decision_band(score, self.low, self.high)
        return {"score": score, "band": band, "model_version": MODEL_VERSION,
                "score_label": SCORE_LABEL, "detector_ms": (time.perf_counter() - start) * 1000}


def save_artifact(path: Path, artifact: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(artifact, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    path.write_bytes(raw)
    Path(str(path) + ".sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n", encoding="ascii")
