ADVICE = {
    "SCAM": "DO: Do not open suspicious links. Verify the message using the organization's independently known official channel.",
    "UNCERTAIN": "DO: Confirm the request through the official application or a trusted contact method before taking action.",
    "LEGITIMATE": "DO: The detector estimates lower risk. Verify unusual requests independently.",
}

URL_ADVICE = {
    "SCAM": "DO: Do not visit this URL or enter credentials. Navigate via an independent bookmark or official app instead.",
    "UNCERTAIN": "DO: Verify the destination domain carefully using an independent bookmark or official app before opening.",
    "LEGITIMATE": "DO: The URL detector estimates lower risk. Confirm the domain spelling before entering sensitive details.",
}


def recommendation(band: str) -> str:
    return ADVICE[band]


def url_recommendation(band: str) -> str:
    return URL_ADVICE[band]
