"""Offline Phishing URL detector (format 101) with structural + lexical TF-IDF features."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from time import perf_counter
import unicodedata
import numpy as np
from scipy import sparse
from scipy.special import expit
from sklearn.feature_extraction.text import TfidfVectorizer
from .indicators import (
    BRAND_OFFICIAL_DOMAINS,
    RISKY_EXTENSIONS,
    SUSPICIOUS_TLDS,
    TRUSTED_INDIAN_GOV_BANK_SUFFIXES,
    URL_SHORTENERS,
    parse_url_parts,
)

MODEL_VERSION = "edgeshield-url-char-lexical-lr-v1"
FORMAT_VERSION = 101
DEFAULT_URL_DETECTOR_PATH = Path("models/url_detector_v1.json")
MAX_URL_CHARS = 2048
SCORE_LABEL = "Experimental time-split URL risk score (not real-world calibrated)"

_AUTH_LURE_TOKENS = frozenset({
    "kyc", "ekyc", "netbanking", "webscr", "login", "signin", "verify",
    "update", "secure", "account", "unlock", "unblock", "suspend", "confirm",
})
_SCHEME_PREFIX_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
_WHITESPACE_RE = re.compile(r"\s")

_URL_CACHE: dict[tuple[str, str], "UrlDetectorV1"] = {}


def normalize_url(raw: str) -> str:
    """Validate and canonicalize user-supplied URL without leaking input in errors."""
    if type(raw) is not str:
        raise ValueError("URL must be nonempty text")
    stripped = raw.strip()
    if not stripped or len(stripped) > MAX_URL_CHARS:
        raise ValueError("URL must be nonempty and at most 2048 characters")
    text = unicodedata.normalize("NFKC", stripped)
    if any(unicodedata.category(c) in {"Cs", "Co"} or unicodedata.category(c).startswith("C") for c in text):
        raise ValueError("URL contains unsupported control or Unicode characters")
    if _WHITESPACE_RE.search(text):
        raise ValueError("URL must not contain internal whitespace")
    if len(text) > MAX_URL_CHARS:
        raise ValueError("URL exceeds 2048-character limit")
    scheme_match = _SCHEME_PREFIX_RE.match(text)
    if scheme_match:
        scheme = scheme_match.group(0).lower()
        if scheme not in ("http://", "https://"):
            raise ValueError("Only http:// or https:// URLs are supported")
    parts = parse_url_parts(text)
    if not parts["host"]:
        raise ValueError("URL must contain a valid host")
    return text


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_structural_features(url: str) -> list[float]:
    """Compute 23 deterministic, network-free structural URL features."""
    parts = parse_url_parts(url)
    scheme = str(parts["scheme"])
    netloc = str(parts["netloc"])
    host = str(parts["host"])
    port = parts["port"]
    reg_domain = str(parts["reg_domain"])
    sub_labels = list(parts["sub_labels"])  # type: ignore[arg-type]
    non_www_subs = list(parts["non_www_subs"])  # type: ignore[arg-type]
    labels = list(parts["labels"])  # type: ignore[arg-type]
    tld = str(parts["tld"])
    path = str(parts["path"])
    query = str(parts["query"])
    path_lower = path.lower()
    query_lower = query.lower()
    path_query = f"{path_lower}?{query_lower}" if query_lower else path_lower

    host_tokens = set(re.findall(r"[a-z0-9]+", host))
    sub_tokens = set(re.findall(r"[a-z0-9]+", ".".join(sub_labels)))
    pq_tokens = set(re.findall(r"[a-z0-9]+", f"{path_lower} {query_lower}"))
    all_tokens = host_tokens | pq_tokens
    is_trusted_gov_bank = 1.0 if host.endswith(TRUSTED_INDIAN_GOV_BANK_SUFFIXES) else 0.0

    brand_in_sub = 0.0
    brand_in_path_mismatch = 0.0
    for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():
        if reg_domain not in official_domains and not is_trusted_gov_bank:
            if brand in sub_tokens or (brand in host_tokens and reg_domain not in official_domains):
                brand_in_sub = 1.0
            if brand in pq_tokens:
                brand_in_path_mismatch = 1.0

    has_risky_ext = 1.0 if any(
        path_lower.endswith(ext) or f"{ext}?" in path_lower or f"{ext}&" in query_lower or query_lower.endswith(ext)
        for ext in RISKY_EXTENSIONS
    ) else 0.0
    has_at_or_puny = 1.0 if (parts["has_at"] or any(lbl.startswith("xn--") for lbl in labels)) else 0.0
    has_nonstd_port = 1.0 if port not in (None, 80, 443) else 0.0
    has_auth_kw = 1.0 if (not is_trusted_gov_bank and bool(all_tokens & _AUTH_LURE_TOKENS)) else 0.0
    longest_lbl = max((len(lbl) for lbl in labels), default=0)
    num_params = float(len([p for p in query.split("&") if p])) if query else 0.0

    return [
        len(host) / 100.0,
        len(path) / 150.0,
        len(query) / 150.0,
        float(max(0, len(non_www_subs) - 1)),
        float(host.count("-")),
        sum(c.isdigit() for c in host) / max(len(host), 1),
        sum(c.isdigit() for c in path_query) / max(len(path_query), 1),
        sum(c in "-_@" for c in netloc) / max(len(netloc), 1),
        sum(c in "-_~=?&%" for c in path_query) / max(len(path_query), 1),
        _shannon_entropy(host),
        1.0 if scheme == "http" else 0.0,
        1.0 if parts["is_ip"] else 0.0,
        has_at_or_puny,
        has_nonstd_port,
        1.0 if host in URL_SHORTENERS else 0.0,
        1.0 if tld in SUSPICIOUS_TLDS else 0.0,
        has_risky_ext,
        brand_in_sub,
        brand_in_path_mismatch,
        has_auth_kw,
        longest_lbl / 50.0,
        num_params,
        is_trusted_gov_bank,
    ]


STRUCTURAL_FEATURE_NAMES = (
    "host_len_scaled",
    "path_len_scaled",
    "query_len_scaled",
    "excess_subdomain_depth",
    "host_hyphen_count",
    "host_digit_ratio",
    "path_digit_ratio",
    "host_special_ratio",
    "path_special_ratio",
    "host_entropy",
    "is_http",
    "has_ip_host",
    "has_at_or_punycode",
    "has_nonstd_port",
    "is_shortener",
    "has_suspicious_tld",
    "has_risky_ext",
    "has_brand_in_subdomain",
    "has_brand_in_path_mismatch",
    "has_auth_lure_kw",
    "longest_host_label_len_scaled",
    "num_query_params",
    "is_trusted_indian_gov_ac_bank_tld",
)


def tokenize_url_for_tfidf(url: str) -> tuple[str, str]:
    """Return `(word_token_doc, char_surface)` for pure lexical/char TF-IDF vectorization."""
    parts = parse_url_parts(url)
    host = str(parts["host"])
    tld = str(parts["tld"])
    scheme = str(parts["scheme"])
    path_query = f"{parts['path']} {parts['query']}".lower()
    host_tokens = re.findall(r"[a-z0-9]+", host)
    pq_tokens = re.findall(r"[a-z0-9]+", path_query)

    markers: list[str] = []
    if scheme:
        markers.append(f"scheme_{scheme}")
    if tld:
        markers.append(f"tld_{tld}")
    if parts["is_ip"]:
        markers.append("tok_ip_host")
    if parts["has_at"]:
        markers.append("tok_at_netloc")
    if host in URL_SHORTENERS:
        markers.append("tok_shortener")
    if tld in SUSPICIOUS_TLDS:
        markers.append("tok_susptld")
    if host.endswith(TRUSTED_INDIAN_GOV_BANK_SUFFIXES):
        markers.append("tok_trusted_in_govbank")

    word_doc = " ".join([*host_tokens, *pq_tokens, *markers])
    char_host = host[4:] if host.startswith("www.") else host
    char_surface = char_host[:256]
    return word_doc, char_surface


def band_for_score(score: float, low: float, high: float) -> str:
    if not (0 <= low < high <= 1):
        raise ValueError("Invalid thresholds")
    return "LEGITIMATE" if score < low else "SCAM" if score >= high else "UNCERTAIN"


def _vectorizer(block: dict, analyzer: str, ngrams: tuple[int, int], limit: int) -> TfidfVectorizer:
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


class UrlDetectorV1:
    """Offline URL phishing classifier (format 101: structural + word + char TF-IDF LR)."""

    def __init__(self, artifact: dict):
        try:
            if type(artifact) is not dict or artifact.get("format") != FORMAT_VERSION or artifact.get("model_version") != MODEL_VERSION:
                raise ValueError()
            self.word = _vectorizer(artifact["word"], "word", (1, 2), 45000)
            self.char = _vectorizer(artifact["char"], "char", (3, 5), 65000)
            self.struct_mean = np.asarray(artifact["struct_mean"], dtype=np.float64)
            self.struct_scale = np.asarray(artifact["struct_scale"], dtype=np.float64)
            n_struct = len(STRUCTURAL_FEATURE_NAMES)
            if self.struct_mean.shape != (n_struct,) or self.struct_scale.shape != (n_struct,):
                raise ValueError()
            if not (np.isfinite(self.struct_mean).all() and np.isfinite(self.struct_scale).all() and np.all(self.struct_scale > 0)):
                raise ValueError()
            size = n_struct + len(self.word.vocabulary) + len(self.char.vocabulary)
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
            raise ValueError("Invalid v1 URL detector artifact") from None
        self.artifact_sha256: str | None = None

    @classmethod
    def load(cls, path: str | Path) -> "UrlDetectorV1":
        return load_url_detector(path)

    def _matrix(self, urls: list[str]) -> sparse.csr_matrix:
        structs = np.asarray([extract_structural_features(u) for u in urls], dtype=np.float64)
        scaled_structs = sparse.csr_matrix(((structs - self.struct_mean) / self.struct_scale) / 5.0)
        tokenized = [tokenize_url_for_tfidf(u) for u in urls]
        word_docs = [pair[0] for pair in tokenized]
        char_docs = [pair[1] for pair in tokenized]
        return sparse.hstack((scaled_structs, self.word.transform(word_docs), self.char.transform(char_docs)), format="csr")

    def scores(self, urls: list[str]) -> np.ndarray:
        matrix = self._matrix(urls)
        return expit(self.a * (np.asarray(matrix @ self.coef).ravel() + self.intercept) + self.b)

    def predict(self, raw_url: str) -> dict[str, object]:
        start = perf_counter()
        url = normalize_url(raw_url)
        matrix = self._matrix([url])
        score = float(expit(self.a * (float((matrix @ self.coef)[0]) + self.intercept) + self.b))
        band = band_for_score(score, self.low, self.high)
        return {
            "score": score,
            "band": band,
            "model_version": MODEL_VERSION,
            "score_label": SCORE_LABEL,
            "detector_ms": (perf_counter() - start) * 1000,
        }


def resolve_default_url_detector(path: Path) -> Path:
    """Resolve the default relative URL detector against repo or venv bundle root from any cwd."""
    if path == DEFAULT_URL_DETECTOR_PATH and not path.exists():
        candidates = [
            Path(__file__).resolve().parents[2] / DEFAULT_URL_DETECTOR_PATH,
            Path(sys.prefix).parent / DEFAULT_URL_DETECTOR_PATH,
            Path(sys.prefix).resolve().parent / DEFAULT_URL_DETECTOR_PATH,
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
    return path


def load_url_detector(path: str | Path) -> UrlDetectorV1:
    """Load and SHA-256 verify `models/url_detector_v1.json` with in-memory caching."""
    path = Path(path)
    if path.stat().st_size > 30_000_000:
        raise ValueError("URL detector artifact exceeds size limit")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    checksum = Path(str(path) + ".sha256")
    if checksum.stat().st_size > 256:
        raise ValueError("Invalid URL detector checksum")
    parts = checksum.read_text(encoding="ascii").split()
    expected = parts[0] if parts else ""
    if len(expected) != 64 or digest != expected:
        raise ValueError("URL detector checksum mismatch")
    resolved = str(path.resolve())
    cached = _URL_CACHE.get((resolved, digest))
    if cached is not None:
        return cached
    detector = UrlDetectorV1(json.loads(raw))
    detector.artifact_sha256 = digest
    _URL_CACHE[(resolved, digest)] = detector
    return detector


def save_url_artifact(path: str | Path, artifact: dict) -> str:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(artifact, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    path.write_bytes(raw)
    Path(str(path) + ".sha256").write_text(digest + "\n", encoding="ascii")
    return digest
