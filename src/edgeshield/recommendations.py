ADVICE = {
    "SCAM": "DO: Do not open suspicious links. Verify the message using the organization's independently known official channel.",
    "UNCERTAIN": "DO: Confirm the request through the official application or a trusted contact method before taking action.",
    "LEGITIMATE": "DO: The detector estimates lower risk. Verify unusual requests independently.",
}


def recommendation(band: str) -> str:
    return ADVICE[band]
