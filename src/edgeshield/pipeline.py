"""Separate immediate detection/advice from optional bounded explanation."""
from dataclasses import dataclass
from time import perf_counter
from .privacy import normalize_sms
from .indicators import detect_indicators
from .evidence import Evidence
from .recommendations import recommendation
from .validator import build_prompt, validate_explanation, fallback

ADVISORY_POLICIES = ("always", "elevated", "uncertain", "off")


def should_run_advisor(evidence: Evidence, policy: str = "always") -> bool:
    """Decide whether to invoke the local LLM advisor for validated evidence."""
    if policy not in ADVISORY_POLICIES:
        raise ValueError("Invalid advisory policy")
    if policy == "always":
        return True
    if policy == "elevated":
        return evidence.band in ("SCAM", "UNCERTAIN") or bool(evidence.indicators)
    if policy == "uncertain":
        return evidence.band == "UNCERTAIN"
    return False


@dataclass(frozen=True)
class Assessment:
    evidence: Evidence
    score_label: str
    model_version: str
    detector_ms: float
    evidence_ms: float
    advice: str


@dataclass(frozen=True)
class Explanation:
    why: str
    source: str
    reason: str
    llama_ms: float | None
    validation_ms: float


def assess(text, detector) -> Assessment:
    start = perf_counter()
    clean = normalize_sms(text)
    prediction = detector.predict(clean)
    detector_ms = (perf_counter() - start) * 1000
    start = perf_counter()
    evidence = Evidence(prediction["band"], prediction["score"], detect_indicators(clean))
    return Assessment(evidence, prediction["score_label"], prediction["model_version"], detector_ms,
                      (perf_counter() - start) * 1000, recommendation(evidence.band))


def explain(evidence: Evidence, advisor=None, *, policy: str = "always") -> Explanation:
    evidence.validated()
    should = should_run_advisor(evidence, policy)
    llama_ms = None
    reason = "RUNTIME_NOT_CONFIGURED"
    output = None
    generated = False
    if advisor is not None and not should:
        start = perf_counter()
        return Explanation(fallback(evidence), "Template fallback", "SKIPPED_BY_POLICY", None,
                           (perf_counter() - start) * 1000)
    if advisor is not None:
        start = perf_counter()
        try:
            output = advisor.generate(build_prompt(evidence))
            generated = True
        except Exception:
            # Runtime errors may contain stdout or local paths. Never expose them.
            reason = "RUNTIME_ERROR"
        finally:
            llama_ms = (perf_counter() - start) * 1000
    start = perf_counter()
    if generated:
        accepted, reason = validate_explanation(output, evidence)
        if accepted:
            return Explanation(output, "Llama (validated)", reason, llama_ms, (perf_counter() - start) * 1000)
    return Explanation(fallback(evidence), "Template fallback", reason, llama_ms, (perf_counter() - start) * 1000)
