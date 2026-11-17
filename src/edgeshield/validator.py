"""Conservative controlled-language validator; not a general semantic verifier."""
import re
from .evidence import Evidence
from .indicators import DESCRIPTIONS

PREFIXES = {
    "SCAM": "The detector estimates elevated risk.",
    "UNCERTAIN": "The detector is uncertain.",
    "LEGITIMATE": "The detector estimates lower risk, without authenticating the sender.",
}
INDICATOR_PRIORITY = (
    "OTP_REQUEST",
    "UPI_COLLECT_LURE",
    "SHORTENER_LINK",
    "THREAT_OF_BLOCK",
    "KYC_IMPERSONATION",
    "PRIZE_LURE",
    "JOB_LURE",
    "LINK_PRESENT",
    "URGENCY",
    "BANK_IMPERSONATION",
    "DELIVERY_LURE",
    "HINGLISH_CUE",
)


def allowed_explanations(evidence: Evidence) -> tuple[str, ...]:
    evidence.validated()
    prefix = PREFIXES[evidence.band]
    choices = ["WHY: " + prefix]
    for indicator in evidence.indicators:
        choices.append("WHY: " + prefix + " " + DESCRIPTIONS[indicator] + ".")
    return tuple(choices)


def validate_explanation(text, evidence: Evidence) -> tuple[bool, str]:
    evidence.validated()
    if type(text) is not str or not text:
        return False, "EMPTY"
    if len(text) > 512:
        return False, "SIZE"
    if not text.isascii() or any(ord(c) < 32 for c in text):
        return False, "UNICODE_OR_CONTROL"
    if not text.startswith("WHY: ") or text != text.strip():
        return False, "FORMAT"
    if len(text[5:].split()) > 25:
        return False, "WORD_LIMIT"
    if re.search(r"\b(?:definitely|certainly|guaranteed|safe|authenticated|always|never)\b", text, re.I):
        return False, "CERTAINTY"
    if re.search(r"https?://|www\.|@|\d|\b[a-z]+\.(?:com|in|org|net)\b", text, re.I):
        return False, "SENSITIVE_OR_LINK"
    if text not in allowed_explanations(evidence):
        return False, "UNSUPPORTED_OR_INSTRUCTION"
    return True, "ACCEPTED"


def fallback(evidence: Evidence) -> str:
    choices = allowed_explanations(evidence)
    if not evidence.indicators:
        return choices[0]
    by_indicator = dict(zip(evidence.indicators, choices[1:]))
    for indicator in INDICATOR_PRIORITY:
        if indicator in by_indicator:
            return by_indicator[indicator]
    return choices[-1]


def build_prompt(evidence: Evidence) -> str:
    evidence.validated()
    # Llama 3 instruction framing. All interpolations originate from closed enums/numbers.
    allowed = "\n".join(allowed_explanations(evidence))
    preferred = fallback(evidence)
    return (
        "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
        "You format a defensive spam-filter status line for a separate detector's evidence. "
        "Echo the target WHY line below verbatim, keeping the exact \"WHY: \" prefix. "
        "Do not add advice or claims. Output one single line only.<|eot_id|>"
        "<|start_header_id|>user<|end_header_id|>\n\n"
        "Target line:\nWHY: The detector is uncertain.<|eot_id|>"
        "<|start_header_id|>assistant<|end_header_id|>\n\n"
        "WHY: The detector is uncertain.<|eot_id|>"
        "<|start_header_id|>user<|end_header_id|>\n\n"
        f"Band: {evidence.band}\nDetector risk score, not real-world probability: {evidence.score:.3f}\n"
        f"Allowed lines:\n{allowed}\n"
        f"Target line:\n{preferred}<|eot_id|>"
        "<|start_header_id|>assistant<|end_header_id|>\n\n"
    )
