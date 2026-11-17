"""Observable lexical cues, never proof of fraud or sender identity."""
import re
from urllib.parse import urlsplit
from .privacy import normalize_sms

DESCRIPTIONS = {
    "URGENCY": "Urgent wording appears",
    "THREAT_OF_BLOCK": "Account restriction wording appears",
    "OTP_REQUEST": "A code sharing request appears",
    "LINK_PRESENT": "Link-like text appears",
    "SHORTENER_LINK": "A known link shortener appears",
    "BANK_IMPERSONATION": "Bank-related wording appears",
    "KYC_IMPERSONATION": "Identity verification wording appears",
    "UPI_COLLECT_LURE": "Payment collection wording appears",
    "DELIVERY_LURE": "Delivery-related wording appears",
    "PRIZE_LURE": "Prize-related wording appears",
    "JOB_LURE": "Job-related wording appears",
    "HINGLISH_CUE": "Romanized Hindi wording appears",
}
PATTERNS = {
    "URGENCY": r"\b(?:urgent|immediately|right now|last chance|jaldi|turant)\b",
    "THREAT_OF_BLOCK": r"\b(?:block(?:ed)?|suspend(?:ed)?|deactivat(?:e|ed|ion)|freeze|frozen)\b",
    "OTP_REQUEST": r"\b(?:share|send|tell|provide|enter|bhej[oa]?|batao)\b[^.!?;]{0,35}?\b(?:otp|one[ -]time (?:password|code)|verification code)\b",
    "BANK_IMPERSONATION": r"\b(?:bank|banking|banker)\b",
    "KYC_IMPERSONATION": r"\b(?:kyc|know your customer|identity verification)\b",
    "UPI_COLLECT_LURE": r"\b(?:upi|payment)\b.{0,35}\b(?:collect|request|approve|accept)\b|\b(?:approve|accept)\b.{0,35}\b(?:upi|payment)\b",
    "DELIVERY_LURE": r"\b(?:parcel|delivery|courier|shipment)\b",
    "PRIZE_LURE": r"\b(?:prize|lottery|jackpot|winner|won)\b",
    "JOB_LURE": r"\b(?:job|recruitment|hiring|vacancy|work from home)\b",
    "HINGLISH_CUE": r"\b(?:aapka|aapke|karo|karein|jaldi|turant|paisa|paise|bhejo|batao|nahi)\b",
}
LINK = re.compile(r"(?:https?://|www\.)[^\s<>]+|\b[a-z0-9](?:[a-z0-9-]*\.)+(?:com|in|org|net|io|co|me|ly|example|test)\b(?:/[^\s<>]*)?", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"}
COMPILED_PATTERNS = {name: re.compile(pattern) for name, pattern in PATTERNS.items()}
NEGATION = re.compile(r"\b(?:do not|don't|don’t|never|not to)\s+(?:ever\s+)?$")


def detect_indicators(text: str) -> tuple[str, ...]:
    text = normalize_sms(text).lower()
    found = {name for name, pattern in COMPILED_PATTERNS.items() if pattern.search(text)}
    # Assess each request separately: a benign warning must not mask a later request.
    if "OTP_REQUEST" in found:
        requests = list(COMPILED_PATTERNS["OTP_REQUEST"].finditer(text))
        if requests and not any(not NEGATION.search(text[max(0, m.start() - 30):m.start()]) for m in requests):
            found.discard("OTP_REQUEST")
    for match in LINK.finditer(text):
        found.add("LINK_PRESENT")
        try:
            url = match.group()
            host = urlsplit(url if "://" in url else "https://" + url).hostname
            if host in SHORTENERS:
                found.add("SHORTENER_LINK")
        except ValueError:
            pass
    return tuple(name for name in DESCRIPTIONS if name in found)
