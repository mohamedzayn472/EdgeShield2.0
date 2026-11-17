"""Experimental word/character classifier with non-executable JSON artifacts."""
from __future__ import annotations
import hashlib
import json
import math
from pathlib import Path
from time import perf_counter
import numpy as np
from scipy import sparse
from scipy.special import expit
from sklearn.feature_extraction.text import TfidfVectorizer
from .privacy import normalize_sms

MODEL_VERSION = "edgeshield-word-char-lr-v2"
SCORE_LABEL = "Experimental synthetic-trained risk score (not real-world calibrated)"


def band_for_score(score, low, high):
    if not all(type(x) in (int, float) and math.isfinite(x) for x in (score, low, high)) or not 0 <= score <= 1 or not 0 <= low < high <= 1:
        raise ValueError("Invalid score or thresholds")
    return "LEGITIMATE" if score <= low else "SCAM" if score >= high else "UNCERTAIN"


def _vectorizer(block, analyzer, ngrams, limit):
    if type(block) is not dict or set(block) != {"vocabulary", "idf"}:
        raise ValueError()
    vocab = block["vocabulary"]
    if type(vocab) is not dict or not 1 <= len(vocab) <= limit:
        raise ValueError()
    if not all(type(k) is str and 1 <= len(k) <= 4096 and type(v) is int for k, v in vocab.items()):
        raise ValueError()
    if sorted(vocab.values()) != list(range(len(vocab))):
        raise ValueError()
    idf = np.asarray(block["idf"], dtype=np.float64)
    if idf.shape != (len(vocab),) or not np.isfinite(idf).all() or np.any(idf < 1) or np.any(idf > 30):
        raise ValueError()
    result = TfidfVectorizer(vocabulary=vocab, analyzer=analyzer, ngram_range=ngrams, sublinear_tf=True)
    result.idf_ = idf
    return result


class Detector:
    def __init__(self, artifact):
        try:
            if type(artifact) is not dict or artifact.get("format") != 2 or artifact.get("model_version") != MODEL_VERSION:
                raise ValueError()
            self.word = _vectorizer(artifact["word"], "word", (1, 2), 25000)
            self.char = _vectorizer(artifact["char"], "char_wb", (3, 5), 40000)
            size = len(self.word.vocabulary) + len(self.char.vocabulary)
            self.coef = np.asarray(artifact["coef"], dtype=np.float64)
            if self.coef.shape != (size,) or not np.isfinite(self.coef).all() or np.any(np.abs(self.coef) > 1e6):
                raise ValueError()
            self.intercept = float(artifact["intercept"])
            self.a, self.b = [float(x) for x in artifact["calibration"]]
            if not all(math.isfinite(x) and abs(x) <= 1e6 for x in (self.intercept, self.a, self.b)) or self.a <= 0:
                raise ValueError()
            self.low, self.high = [float(x) for x in artifact["thresholds"]]
            band_for_score(.5, self.low, self.high)
        except (KeyError, TypeError, ValueError, OverflowError):
            raise ValueError("Invalid v2 detector artifact") from None

    @classmethod
    def load(cls, path):
        path = Path(path)
        if path.stat().st_size > 30_000_000:
            raise ValueError("Detector artifact exceeds size limit")
        raw = path.read_bytes()
        checksum = Path(str(path) + ".sha256")
        if checksum.stat().st_size > 256:
            raise ValueError("Invalid detector checksum")
        expected = checksum.read_text(encoding="ascii").strip()
        if len(expected) != 64 or hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("Detector checksum mismatch")
        return cls(json.loads(raw))

    def _matrix(self, texts):
        clean = [normalize_sms(text) for text in texts]
        return sparse.hstack((self.word.transform(clean), self.char.transform(clean)), format="csr")

    def scores(self, texts):
        matrix = self._matrix(texts)
        return expit(self.a * (np.asarray(matrix @ self.coef).ravel() + self.intercept) + self.b)

    def predict(self, text):
        start = perf_counter()
        matrix = self._matrix([text])
        score = float(expit(self.a * (float((matrix @ self.coef)[0]) + self.intercept) + self.b))
        band = "UNCERTAIN" if matrix.nnz == 0 else band_for_score(score, self.low, self.high)
        return {"score": score, "band": band, "model_version": MODEL_VERSION,
                "score_label": SCORE_LABEL, "detector_ms": (perf_counter() - start) * 1000}


def save_artifact(path, artifact):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(artifact, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    path.write_bytes(raw)
    Path(str(path) + ".sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n", encoding="ascii")


DetectorV2 = Detector
