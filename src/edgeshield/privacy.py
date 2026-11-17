"""Input boundary. Never include input content in exceptions."""
import unicodedata

MAX_SMS_CHARS = 4096


def normalize_sms(text: str) -> str:
    if type(text) is not str or not text.strip():
        raise ValueError("SMS must be nonempty text")
    if len(text) > MAX_SMS_CHARS:
        raise ValueError("SMS exceeds 4096-character limit")
    text = unicodedata.normalize("NFKC", text)
    if any(unicodedata.category(c) in {"Cs", "Co"} for c in text):
        raise ValueError("SMS contains unsupported Unicode characters")
    # Remove zero-width and bidi controls, including terminal escape characters.
    text = "".join(c for c in text if not unicodedata.category(c).startswith("C") or c in "\n\t\r")
    text = " ".join(text.split())
    if not text or len(text) > MAX_SMS_CHARS:
        raise ValueError("SMS is empty or exceeds normalized size limit")
    return text
