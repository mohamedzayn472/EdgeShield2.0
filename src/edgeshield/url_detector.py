"""Offline Phishing URL detector (format 102) with structural + lexical TF-IDF features."""
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
    ABUSED_HOSTING_SUFFIXES,
    BRAND_OFFICIAL_DOMAINS,
    RISKY_EXTENSIONS,
    SUSPICIOUS_TLDS,
    TRUSTED_INDIAN_GOV_BANK_SUFFIXES,
    URL_SHORTENERS,
    detect_brand_typosquat,
    has_homoglyph_punycode,
    is_verified_official_domain,
    parse_url_parts,
)

MODEL_VERSION = "edgeshield-url-char-lexical-lr-v1"
FORMAT_VERSION = 102
DEFAULT_URL_DETECTOR_PATH = Path("models/url_detector_v1.json")
MAX_URL_CHARS = 2048
SCORE_LABEL = "Experimental time-split URL risk score (not real-world calibrated)"

_AUTH_LURE_TOKENS = frozenset({
    "kyc", "ekyc", "netbanking", "webscr", "login", "signin", "verify",
    "update", "secure", "account", "unlock", "unblock", "suspend", "confirm",
})
_NOISE_WORD_TOKENS = frozenset({"com", "org", "net", "in", "co", "www", "http", "https", "xn"})
_ANY_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.-]*):(.*)$", re.I)
_PORT_TAIL_RE = re.compile(r"^\d+(?:/|\?|#|$)")
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
    scheme_match = _ANY_SCHEME_RE.match(text)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        rest = scheme_match.group(2)
        if not (scheme in ("http", "https") and rest.startswith("//")) and not _PORT_TAIL_RE.match(rest):
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
    """Compute 25 deterministic, network-free structural URL features."""
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

    has_brand_typosquat = 1.0 if detect_brand_typosquat(host, reg_domain, bool(is_trusted_gov_bank)) else 0.0
    has_risky_ext = 1.0 if any(
        path_lower.endswith(ext) or f"{ext}?" in path_lower or f"{ext}&" in query_lower or query_lower.endswith(ext)
        for ext in RISKY_EXTENSIONS
    ) else 0.0
    has_at_or_puny = 1.0 if (parts["has_at"] or has_homoglyph_punycode(labels)) else 0.0
    has_nonstd_port = 1.0 if port not in (None, 80, 443) else 0.0
    has_abused_hosting = host.endswith(ABUSED_HOSTING_SUFFIXES)
    has_susp_host_ctx = (
        scheme == "http"
        or tld in SUSPICIOUS_TLDS
        or bool(parts["is_ip"])
        or has_at_or_puny == 1.0
        or host in URL_SHORTENERS
        or has_nonstd_port == 1.0
        or brand_in_sub == 1.0
        or brand_in_path_mismatch == 1.0
        or has_brand_typosquat == 1.0
        or host.count("-") >= 2
        or has_abused_hosting
    )
    has_suspicious_auth_ctx = 1.0 if (not is_trusted_gov_bank and bool(all_tokens & _AUTH_LURE_TOKENS) and has_susp_host_ctx) else 0.0
    longest_lbl = max((len(lbl) for lbl in labels), default=0)
    num_params = float(len([p for p in query.split("&") if p])) if query else 0.0

    return [
        len(host) / 100.0,
        len(path) / 150.0,
        len(query) / 150.0,
        float(max(0, len(non_www_subs) - 2)),
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
        has_suspicious_auth_ctx,
        longest_lbl / 50.0,
        num_params,
        is_trusted_gov_bank,
        has_brand_typosquat,
        1.0 if has_abused_hosting else 0.0,
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
    "has_suspicious_auth_context",
    "longest_host_label_len_scaled",
    "num_query_params",
    "is_trusted_indian_gov_ac_bank_tld",
    "has_brand_typosquat",
    "is_abused_hosting",
)
CONTINUOUS_STRUCTURAL_INDICES: tuple[int, ...] = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 20, 21)
STRUCTURAL_Z_CLIP = 3.0


def scale_structural_matrix(raw_structs: np.ndarray, mean: np.ndarray, scale: np.ndarray) -> sparse.csr_matrix:
    """Standardize structural features, clip continuous z-scores to [-3, +3], and match TF-IDF L2 norm."""
    z = (np.asarray(raw_structs, dtype=np.float64) - mean) / scale
    z[:, CONTINUOUS_STRUCTURAL_INDICES] = np.clip(
        z[:, CONTINUOUS_STRUCTURAL_INDICES], -STRUCTURAL_Z_CLIP, STRUCTURAL_Z_CLIP
    )
    return sparse.csr_matrix(z / 5.0)


def tokenize_url_for_tfidf(url: str) -> tuple[str, str]:
    """Return `(word_token_doc, char_surface)` for pure lexical/char TF-IDF vectorization."""
    parts = parse_url_parts(url)
    host = str(parts["host"])
    reg_domain = str(parts["reg_domain"])
    tld = str(parts["tld"])
    scheme = str(parts["scheme"])
    labels = list(parts["labels"])  # type: ignore[arg-type]
    path_lower = str(parts["path"]).lower()
    query_lower = str(parts["query"]).lower()
    path_query = f"{path_lower} {query_lower}"
    is_trusted_gov_bank = host.endswith(TRUSTED_INDIAN_GOV_BANK_SUFFIXES)

    matched_abused_suffix = next((suf for suf in ABUSED_HOSTING_SUFFIXES if host.endswith(suf)), "")
    host_surface = host[:-len(matched_abused_suffix)] if matched_abused_suffix else host

    drop_tokens = set(_NOISE_WORD_TOKENS)
    if tld and tld not in SUSPICIOUS_TLDS:
        drop_tokens.add(tld)
    if not parts["has_at"] and not parts["is_ip"]:
        for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():
            if reg_domain in official_domains:
                drop_tokens.add(brand)

    raw_host_tokens = re.findall(r"[a-z0-9]+", host_surface)
    raw_host_token_set = set(raw_host_tokens)
    mismatched_host_brands = {
        brand
        for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items()
        if not is_trusted_gov_bank and brand in raw_host_token_set and reg_domain not in official_domains
    }
    host_drop_tokens = drop_tokens | mismatched_host_brands
    host_tokens = [t for t in raw_host_tokens if t not in host_drop_tokens]
    pq_tokens = [t for t in re.findall(r"[a-z0-9]+", path_query) if t not in drop_tokens]

    markers: list[str] = []
    if scheme == "http":
        markers.append("scheme_http")
    if tld in SUSPICIOUS_TLDS:
        markers.append(f"tld_{tld}")
        markers.append("tok_susptld")
    if parts["is_ip"]:
        markers.append("tok_ip_host")
    if parts["has_at"]:
        markers.append("tok_at_netloc")
    if has_homoglyph_punycode(labels):
        markers.append("tok_homoglyph_punycode")
    if host in URL_SHORTENERS:
        markers.append("tok_shortener")
    if any(path_lower.endswith(ext) or f"{ext}?" in path_lower or f"{ext}&" in query_lower or query_lower.endswith(ext)
           for ext in RISKY_EXTENSIONS):
        markers.append("tok_risky_ext")
    if matched_abused_suffix:
        markers.append("tok_abused_hosting")
        if (raw_host_token_set | set(pq_tokens)) & _AUTH_LURE_TOKENS:
            markers.append("tok_abused_host_lure")
    if is_trusted_gov_bank:
        markers.append("tok_trusted_in_govbank")
    if mismatched_host_brands:
        markers.append("tok_brand_mismatch")
    if detect_brand_typosquat(host, reg_domain, is_trusted_gov_bank):
        markers.append("tok_brand_typosquat")

    word_doc = " ".join([*host_tokens, *pq_tokens, *markers])
    char_host = host_surface[4:] if host_surface.startswith("www.") else host_surface
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
    """Offline URL phishing classifier (format 102: structural + word + char TF-IDF LR)."""

    def __init__(self, artifact: dict):
        try:
            if type(artifact) is not dict or artifact.get("format") != FORMAT_VERSION or artifact.get("model_version") != MODEL_VERSION:
                raise ValueError()
            if artifact.get("structural_features") != list(STRUCTURAL_FEATURE_NAMES):
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
        scaled_structs = scale_structural_matrix(structs, self.struct_mean, self.struct_scale)
        tokenized = [tokenize_url_for_tfidf(u) for u in urls]
        word_docs = [pair[0] for pair in tokenized]
        char_docs = [pair[1] for pair in tokenized]
        return sparse.hstack((scaled_structs, self.word.transform(word_docs), self.char.transform(char_docs)), format="csr")

    def scores(self, urls: list[str]) -> np.ndarray:
        matrix = self._matrix(urls)
        return expit(self.a * (np.asarray(matrix @ self.coef).ravel() + self.intercept) + self.b)

    def predict(self, raw_url: str, *, use_verified_policy: bool = True) -> dict[str, object]:
        start = perf_counter()
        url = normalize_url(raw_url)
        matrix = self._matrix([url])
        raw_score = float(expit(self.a * (float((matrix @ self.coef)[0]) + self.intercept) + self.b))
        verified = bool(use_verified_policy and is_verified_official_domain(url))
        score = min(raw_score, self.low * 0.5) if verified else raw_score
        band = band_for_score(score, self.low, self.high)
        return {
            "score": score,
            "raw_score": raw_score,
            "verified_domain_applied": verified,
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
