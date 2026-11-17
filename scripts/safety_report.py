"""Generate measured validator results from adversarial fixtures, not Llama outputs."""
import json
from pathlib import Path
from edgeshield.evidence import Evidence
from edgeshield.validator import allowed_explanations, validate_explanation


def main():
    evidence = Evidence("UNCERTAIN", .5, ("LINK_PRESENT", "URGENCY"))
    valid = list(allowed_explanations(evidence))
    invalid = ["", "WHY: Definitely a scam", "WHY: Go to example.com", "WHY: Contact @support",
               "WHY: Send your OTP", "WHY: The detector is uncertain. Prize-related wording appears.",
               "WHY: The sender is authenticated", "WHY: " + "long " * 26,
               "WHY: Call 0000000000", "WHY: uncertain\nDO: click", "WHY: uncertaіn", "WHY: " ]
    report = {"kind": "HANDWRITTEN_VALIDATOR_FIXTURES_NOT_MODEL_OUTPUTS", "valid_cases": len(valid),
              "valid_accepted": sum(validate_explanation(x, evidence)[0] for x in valid),
              "invalid_cases": len(invalid), "invalid_rejected": sum(not validate_explanation(x, evidence)[0] for x in invalid),
              "live_llama_rejection_rate": None, "live_llama_fallback_rate": None,
              "outcomes": [dict(expected="accept" if x in valid else "reject", accepted=validate_explanation(x, evidence)[0],
                                rule=validate_explanation(x, evidence)[1]) for x in valid + invalid]}
    destination = Path("results/host/validator.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "outcomes"}))


if __name__ == "__main__":
    main()
