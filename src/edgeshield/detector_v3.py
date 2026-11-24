"""Experimental V3 word/character classifier with numeric/banking canonicalization."""
from __future__ import annotations
import hashlib
import json
import math
import re
from pathlib import Path
from time import perf_counter
from urllib.parse import urlsplit
import numpy as np
from scipy import sparse
from scipy.special import expit
from sklearn.feature_extraction.text import TfidfVectorizer
from .privacy import normalize_sms

MODEL_VERSION = "edgeshield-word-char-lr-v3"
SCORE_LABEL = "Experimental synthetic-trained risk score (not real-world calibrated)"

_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"}
_URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>]+|\b[a-z0-9](?:[a-z0-9-]*\.)+(?:com|in|org|net|io|co|me|ly|example|test)\b(?:/[^\s<>]*)?",
    re.I,
)
_BANK_ACCT_RE = re.compile(
    r"\b(?:a/c|acct|account)\s*(?:no\.?|number|#)?\s*(?:ending\s+(?:with|in)\s+)?(?:[x*]{2,}\d{2,6}|\d{2,6}[x*]{2,})\b",
    re.I,
)
_MASKED_ID_RE = re.compile(r"\b(?:[x*]{2,}\d{2,6}|\d{2,4}[x*]{2,}\d{2,4})\b", re.I)
_INR_AMT_RE = re.compile(r"(?:(?:\binr|\brs\.?|₹)\s*\d[\d,]*(?:\.\d{1,2})?|\b\d[\d,]*(?:\.\d{1,2})?\s*(?:inr|rs\.?|rupees)\b)", re.I)
_FOREIGN_AMT_RE = re.compile(r"(?:(?:£|\$|\busd|\bgbp)\s*\d[\d,]*(?:\.\d{1,2})?|\b\d[\d,]*(?:\.\d{1,2})?\s*(?:gbp|usd|pounds)\b)", re.I)
_DATE_RE = re.compile(
    r"\b(?:\d{1,2}[-/\s](?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*[-/\s]\d{2,4}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})\b",
    re.I,
)
_TIME_RE = re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\s*(?:am|pm)?\b", re.I)
_TX_REF_RE = re.compile(r"\b(?:upi\s+ref(?:\s*no\.?)?|ref(?:\s*no\.?)?|utr|txn(?:\s*id)?|rrn|info)\s*[:#-]?\s*[a-z0-9/-]{5,24}\b", re.I)
_TOLLFREE_RE = re.compile(r"\b1800[-\s]?\d{3,4}[-\s]?\d{3,4}\b")
_LONG_NUM_RE = re.compile(r"\b\d{7,18}\b")
_SHORT_NUM_RE = re.compile(r"\b\d{4,6}\b")


def canonicalize_features(text: str) -> str:
    """Normalize arbitrary amounts, masked account IDs, dates, and reference numbers.

    Prevents spurious collisions between Indian transactional formatting (e.g., '5,000.00',
    'XX1234', '20-Nov-26') and historical UK spam numeric tokens while preserving URL and
    shortener signals.
    """
    clean = normalize_sms(text)

    def _replace_url(match: re.Match) -> str:
        raw = match.group(0)
        try:
            host = (urlsplit(raw if "://" in raw else "https://" + raw).hostname or "").lower()
        except ValueError:
            host = ""
        if host in _SHORTENERS:
            return f" urltoken shortenerurl {host} "
        return f" urltoken {host} " if host else " urltoken "

    clean = _URL_RE.sub(_replace_url, clean)
    clean = _BANK_ACCT_RE.sub(" bankacctmask ", clean)
    clean = _MASKED_ID_RE.sub(" acctmask ", clean)
    clean = _INR_AMT_RE.sub(" inramount ", clean)
    clean = _FOREIGN_AMT_RE.sub(" foreignamount ", clean)
    clean = _DATE_RE.sub(" datetoken ", clean)
    clean = _TIME_RE.sub(" timetoken ", clean)
    clean = _TOLLFREE_RE.sub(" tollfreenum ", clean)
    clean = _TX_REF_RE.sub(" txrefnum ", clean)
    clean = _LONG_NUM_RE.sub(" longnum ", clean)
    clean = _SHORT_NUM_RE.sub(" shortnum ", clean)
    return " ".join(clean.split())


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


class DetectorV3:
    def __init__(self, artifact):
        try:
            if type(artifact) is not dict or artifact.get("format") != 3 or artifact.get("model_version") != MODEL_VERSION:
                raise ValueError()
            self.word = _vectorizer(artifact["word"], "word", (1, 2), 30000)
            self.char = _vectorizer(artifact["char"], "char_wb", (3, 5), 50000)
            size = len(self.word.vocabulary) + len(self.char.vocabulary)
            self.coef = np.asarray(artifact["coef"], dtype=np.float64)
            if self.coef.shape != (size,) or not np.isfinite(self.coef).all() or np.any(np.abs(self.coef) > 1e6):
                raise ValueError()
            self.intercept = float(artifact["intercept"])
            self.a, self.b = [float(x) for x in artifact["calibration"]]
            if not all(math.isfinite(x) and abs(x) <= 1e6 for x in (self.intercept, self.a, self.b)) or self.a <= 0:
                raise ValueError()
            self.low, self.high = [float(x) for x in artifact["thresholds"]]
            band_for_score(0.5, self.low, self.high)
        except (KeyError, TypeError, ValueError, OverflowError):
            raise ValueError("Invalid v3 detector artifact") from None

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
        clean = [canonicalize_features(text) for text in texts]
        return sparse.hstack((self.word.transform(clean), self.char.transform(clean)), format="csr")

    def scores(self, texts):
        matrix = self._matrix(texts)
        return expit(self.a * (np.asarray(matrix @ self.coef).ravel() + self.intercept) + self.b)

    def predict(self, text):
        start = perf_counter()
        matrix = self._matrix([text])
        score = float(expit(self.a * (float((matrix @ self.coef)[0]) + self.intercept) + self.b))
        band = "UNCERTAIN" if matrix.nnz == 0 else band_for_score(score, self.low, self.high)
        return {
            "score": score,
            "band": band,
            "model_version": MODEL_VERSION,
            "score_label": SCORE_LABEL,
            "detector_ms": (perf_counter() - start) * 1000,
        }


def save_artifact(path, artifact):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(artifact, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    path.write_bytes(raw)
    Path(str(path) + ".sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n", encoding="ascii")
