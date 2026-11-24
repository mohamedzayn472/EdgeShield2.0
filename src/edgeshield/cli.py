"""Terminal interface. SMS input never appears in argv, logs, or output."""
import argparse
import json
import platform
import sys
from dataclasses import asdict, replace
from pathlib import Path
from .indicators import DESCRIPTIONS
from .model_loader import load_detector, resolve_default_detector
from .pipeline import ADVISORY_POLICIES, assess, explain
from .privacy import MAX_SMS_CHARS

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


def parser():
    p = argparse.ArgumentParser(description="EdgeShield — Private intelligence. Safer decisions.")
    p.add_argument("--detector", type=Path, default=Path("models/detector_v8.json"))
    p.add_argument("--runtime-config", type=Path, help="Verified local ExecuTorch manifest/config")
    p.add_argument("--advisory-policy", choices=ADVISORY_POLICIES, default="always",
                   help="When to invoke the verified ExecuTorch advisor")
    p.add_argument("--stdin", action="store_true", help="Read one SMS from standard input (4096 character limit)")
    p.add_argument("--repeat", action="store_true", help="Prompt repeatedly; empty input exits")
    p.add_argument("--demo", action="store_true", help="Run built-in English and Hinglish synthetic demo cases")
    p.add_argument("--json", action="store_true", help="JSON result without SMS; detection event precedes explanation event")
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if args.stdin and args.repeat:
        p.error("--stdin and --repeat cannot be combined")
    if args.demo and (args.stdin or args.repeat):
        p.error("--demo cannot be combined with --stdin or --repeat")
    try:
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
        print("Privacy: SMS is not saved. No automatic message actions. Lower risk does not prove safety.")
        if hasattr(detector, "char"):
            print("Experimental synthetic-trained detector. Human review and real-world validation are still pending.")
        else:
            print("Experimental baseline: Indian/Hinglish scam detection failed the held-out challenge. Do not rely on it for protection.")

    demo_index = 0
    try:
        while True:
            demo_key = None
            if args.demo:
                if demo_index >= len(DEMO_CASES):
                    return 0
                demo_key, demo_title, text = DEMO_CASES[demo_index]
                demo_index += 1
                if not args.json:
                    print(f"\n=== Demo {demo_index}/{len(DEMO_CASES)}: {demo_title} ===")
                    print(f"Synthetic SMS: {text}")
            elif args.stdin:
                text = sys.stdin.read(MAX_SMS_CHARS + 1)
            else:
                if not sys.stdin.isatty():
                    print("Use --stdin for piped input.", file=sys.stderr)
                    return 2
                text = input("Paste SMS (empty to exit): ")
                if not text.strip():
                    return 0
            try:
                result = assess(text, detector)
            except (ValueError, TypeError):
                print("Invalid SMS input; use nonempty text up to 4096 characters.", file=sys.stderr)
                if args.repeat:
                    continue
                return 2
            finally:
                text = None  # Best effort only; Python cannot promise memory zeroization.
            if args.json:
                quality = "EXPERIMENTAL_SYNTHETIC_TRAINED" if hasattr(detector, "char") else "FAILED_INDIAN_HINGLISH_CHALLENGE"
                payload = {
                    "event": "detection",
                    "quality_status": quality,
                    "detector_sha256": getattr(detector, "artifact_sha256", None),
                    **asdict(result),
                }
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
