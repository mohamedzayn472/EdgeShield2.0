"""Terminal interface. SMS input never appears in argv, logs, or output."""
import argparse
import getpass
import warnings
import json
import platform
import sys
from dataclasses import asdict, replace
from pathlib import Path
from .indicators import DESCRIPTIONS
from .model_loader import load_detector, resolve_default_detector
from .pipeline import ADVISORY_POLICIES, assess, assess_url, explain
from .privacy import MAX_SMS_CHARS
from .url_detector import DEFAULT_URL_DETECTOR_PATH, MAX_URL_CHARS, load_url_detector, resolve_default_url_detector

DEMO_CASES = (
    ("english_legit_otp", "English legitimate OTP notice",
     "Cedar Bank: Your OTP is 000000. Do not share it with anyone."),
    ("english_scam_kyc_shortener", "English KYC/account-block scam",
     "Urgent: Cedar Bank account will be blocked today. Share your OTP at https://bit.ly/synthetic to verify KYC."),
    ("hinglish_legit_delivery", "Hinglish legitimate delivery update",
     "Aapka parcel aaj shaam ko aayega. Live tracking aapke official app par available hai."),
    ("hinglish_scam_upi_prize", "Hinglish UPI collect/prize scam",
     "Aapka reward ready hai! Jaldi 500 rs UPI collect request approve karo aur prize paise turant pao."),
)

URL_DEMO_CASES = (
    ("legit_indian_bank_deep_url", "Legitimate Indian banking deep URL",
     "https://www.onlinesbi.sbi/sbijava/retail/html/faq.html"),
    ("phish_indian_kyc_subdomain", "Phishing Indian bank KYC subdomain spoof",
     "http://sbi.kyc-verify-account.xyz/netbanking/login.php?session=9281"),
    ("legit_indian_upi_docs", "Legitimate NPCI UPI information URL",
     "https://www.npci.org.in/what-we-do/upi/product-overview"),
    ("phish_ip_apk_lure", "Phishing numeric IP executable download URL",
     "http://198.51.100.42:8080/parivahan/echallan-update.apk"),
)


def parser():
    p = argparse.ArgumentParser(description="EdgeShield — Private intelligence. Safer decisions.")
    p.add_argument("--mode", choices=("sms", "url"), default="sms",
                   help="Inspection mode: sms (default) or standalone phishing url")
    p.add_argument("--detector", type=Path, default=Path("models/detector_v8.json"))
    p.add_argument("--url-detector", type=Path, default=DEFAULT_URL_DETECTOR_PATH)
    p.add_argument("--runtime-config", type=Path, help="Verified local ExecuTorch manifest/config")
    p.add_argument("--advisory-policy", choices=ADVISORY_POLICIES, default="always",
                   help="When to invoke the verified ExecuTorch advisor")
    p.add_argument("--stdin", action="store_true", help="Read one SMS from standard input (4096 character limit)")
    p.add_argument("--url-stdin", action="store_true", help="Shortcut for --mode url --stdin (2048 character limit)")
    p.add_argument("--repeat", action="store_true", help="Prompt repeatedly; empty input exits")
    p.add_argument("--demo", action="store_true", help="Run built-in synthetic demo cases for the selected mode")
    p.add_argument("--json", action="store_true", help="JSON result without raw input; detection event precedes explanation event")
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    mode = "url" if args.url_stdin else args.mode
    use_stdin = args.stdin or args.url_stdin
    if use_stdin and args.repeat:
        p.error("--stdin/--url-stdin and --repeat cannot be combined")
    if args.demo and (use_stdin or args.repeat):
        p.error("--demo cannot be combined with --stdin/--url-stdin or --repeat")
    try:
        if mode == "url":
            detector = load_url_detector(resolve_default_url_detector(args.url_detector))
        else:
            detector = load_detector(resolve_default_detector(args.detector))
    except Exception:
        print("Detector unavailable or invalid. Verify the selected model and checksum.", file=sys.stderr)
        return 2
    advisor = None
    runtime_status = "not configured; template fallback"
    if args.runtime_config:
        try:
            from .advisory import ExecuTorchAdvisor
            advisor = ExecuTorchAdvisor(args.runtime_config)
            runtime_status = "configured; inference not yet verified in this session"
        except Exception:
            runtime_status = "configuration rejected; template fallback"
    if not args.json:
        print("EdgeShield | Private intelligence. Safer decisions.")
        det_sha = getattr(detector, "artifact_sha256", None)
        det_status = f"loaded ({det_sha[:12]})" if det_sha else "loaded"
        print(f"Device: {platform.system()} {platform.machine()} | Detector: {det_status}")
        print(f"ExecuTorch: {runtime_status}")
        print("Network: application uses local processing; connectivity and traffic NOT VERIFIED.")
        if mode == "url":
            print("Privacy: URL is not saved or fetched. Zero DNS/HTTP requests. Lower risk does not prove safety.")
            print("Experimental time-split URL detector. Human review and real-world validation are still pending.")
        else:
            print("Privacy: SMS is not saved. No automatic message actions. Lower risk does not prove safety.")
            if hasattr(detector, "char"):
                print("Experimental synthetic-trained detector. Human review and real-world validation are still pending.")
            else:
                print("Experimental baseline: Indian/Hinglish scam detection failed the held-out challenge. Do not rely on it for protection.")

    demo_cases = URL_DEMO_CASES if mode == "url" else DEMO_CASES
    demo_index = 0
    try:
        while True:
            demo_key = None
            if args.demo:
                if demo_index >= len(demo_cases):
                    return 0
                demo_key, demo_title, text = demo_cases[demo_index]
                demo_index += 1
                if not args.json:
                    print(f"\n=== Demo {demo_index}/{len(demo_cases)}: {demo_title} ===")
                    label = "Synthetic URL" if mode == "url" else "Synthetic SMS"
                    print(f"{label}: {text}")
            elif use_stdin:
                max_chars = MAX_URL_CHARS if mode == "url" else MAX_SMS_CHARS
                text = sys.stdin.read(max_chars + 1)
            else:
                if not sys.stdin.isatty():
                    print("Use --stdin for piped input.", file=sys.stderr)
                    return 2
                prompt_label = "Paste URL (empty to exit): " if mode == "url" else "Paste SMS (empty to exit): "
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("error", getpass.GetPassWarning)
                        text = getpass.getpass(prompt_label)
                except getpass.GetPassWarning:
                    print("Hidden terminal input unavailable. Use --stdin.", file=sys.stderr)
                    return 2
                if not text.strip():
                    return 0
            try:
                result = assess_url(text, detector) if mode == "url" else assess(text, detector)
            except (ValueError, TypeError):
                if mode == "url":
                    print("Invalid URL input; use a single nonempty http/https URL up to 2048 characters.", file=sys.stderr)
                else:
                    print("Invalid SMS input; use nonempty text up to 4096 characters.", file=sys.stderr)
                if args.repeat:
                    continue
                return 2
            finally:
                text = None  # Best effort only; Python cannot promise memory zeroization.
            if args.json:
                if mode == "url":
                    quality = "EXPERIMENTAL_TIME_SPLIT_URL_MODEL"
                else:
                    quality = "EXPERIMENTAL_SYNTHETIC_TRAINED" if hasattr(detector, "char") else "FAILED_INDIAN_HINGLISH_CHALLENGE"
                payload = {
                    "event": "detection",
                    "quality_status": quality,
                    "detector_sha256": getattr(detector, "artifact_sha256", None),
                    **asdict(result),
                }
                if mode == "url":
                    payload["mode"] = "url"
                if demo_key is not None:
                    payload["demo_case"] = demo_key
                print(json.dumps(payload), flush=True)
            else:
                print(f"\nThreat band: {result.evidence.band}")
                print(f"{result.score_label}: {result.evidence.score:.3f}")
                print("Indicators: " + (", ".join(result.evidence.indicators) or "none"))
                if result.evidence.indicators:
                    print("Indicator details: " + "; ".join(DESCRIPTIONS[i] for i in result.evidence.indicators))
                print(result.advice)
                print(f"Detector: {result.detector_ms:.2f} ms | Evidence: {result.evidence_ms:.2f} ms", flush=True)
            explanation = explain(result.evidence, advisor, policy=args.advisory_policy)
            if args.runtime_config and advisor is None and args.advisory_policy != "off":
                explanation = replace(explanation, reason="RUNTIME_CONFIGURATION_REJECTED")
            if args.json:
                payload = {"event": "explanation", **asdict(explanation)}
                if demo_key is not None:
                    payload["demo_case"] = demo_key
                print(json.dumps(payload), flush=True)
            else:
                print(explanation.why)
                print(f"Source: {explanation.source} | Status: {explanation.reason}")
                llama = "not run" if explanation.llama_ms is None else f"{explanation.llama_ms:.2f} ms"
                total_ms = result.detector_ms + result.evidence_ms + (explanation.llama_ms or 0.0) + explanation.validation_ms
                print(f"Llama execution: {llama} | Validation: {explanation.validation_ms:.2f} ms | Total: {total_ms:.2f} ms")
            if not args.repeat and not args.demo:
                return 0
    except (KeyboardInterrupt, EOFError):
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
