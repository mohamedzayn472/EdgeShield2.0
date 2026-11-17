"""Execute the preregistered 20-case Llama-vs-template comparison (host or target runtime).

Follows docs/BENCHMARKS.md § 'Twenty-case Llama/template comparison':
  - 4 normal English banking/OTP/payment/KYC notices
  - 4 English account/KYC/banking pressure scams
  - 4 English prize/job/payment lure scams
  - 4 Hinglish cases (2 legitimate, 2 scam)
  - 4 ambiguous cases (2 English, 2 Hinglish, label=None)

Case IDs are frozen from v2_holdout.jsonl family/label/language metadata without
inspecting Llama outputs. Raw SMS text is never written to the output report.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from edgeshield.advisory import ExecuTorchAdvisor  # noqa: E402
from edgeshield.benchmarking import distribution  # noqa: E402
from edgeshield.datasets import read_jsonl  # noqa: E402
from edgeshield.model_loader import load_detector  # noqa: E402
from edgeshield.pipeline import assess, explain  # noqa: E402
from edgeshield.validator import fallback  # noqa: E402

FROZEN_CASES = (
    ("v2h001", "normal_notice"),
    ("v2h003", "normal_notice"),
    ("v2h005", "normal_notice"),
    ("v2h007", "normal_notice"),
    ("v2h031", "account_kyc_pressure"),
    ("v2h041", "account_kyc_pressure"),
    ("v2h045", "account_kyc_pressure"),
    ("v2h053", "account_kyc_pressure"),
    ("v2h035", "prize_job_payment_lure"),
    ("v2h037", "prize_job_payment_lure"),
    ("v2h039", "prize_job_payment_lure"),
    ("v2h055", "prize_job_payment_lure"),
    ("v2h061", "hinglish"),
    ("v2h063", "hinglish"),
    ("v2h091", "hinglish"),
    ("v2h099", "hinglish"),
    ("v2h121", "ambiguous"),
    ("v2h122", "ambiguous"),
    ("v2h127", "ambiguous"),
    ("v2h128", "ambiguous"),
)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--detector", type=Path, default=ROOT / "models/detector_v2.json")
    p.add_argument("--runtime-config", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error("Output exists; preserve prior comparison artifacts")

    rows_by_id = {row["id"]: row for row in read_jsonl(ROOT / "data/synthetic/v2_holdout.jsonl")}
    detector = load_detector(args.detector)
    advisor = ExecuTorchAdvisor(args.runtime_config)

    cases = []
    for case_id, slice_name in FROZEN_CASES:
        row = rows_by_id[case_id]
        assessment = assess(row["text"], detector)
        template_why = fallback(assessment.evidence)
        explanation = explain(assessment.evidence, advisor, policy="always")
        cases.append({
            "id": case_id,
            "slice": slice_name,
            "language": row.get("language"),
            "family": row.get("family"),
            "ground_truth_label": row.get("label"),
            "band": assessment.evidence.band,
            "score": assessment.evidence.score,
            "indicators": list(assessment.evidence.indicators),
            "template_why": template_why,
            "llama_why": explanation.why,
            "explanation_source": explanation.source,
            "validator_reason": explanation.reason,
            "llama_matches_template": explanation.why == template_why,
            "attempted": True,
            "detector_ms": assessment.detector_ms,
            "evidence_ms": assessment.evidence_ms,
            "llama_ms": explanation.llama_ms,
            "validation_ms": explanation.validation_ms,
            "runner_stats": advisor.last_stats,
        })

    attempted = sum(1 for c in cases if c["attempted"])
    accepted = sum(1 for c in cases if c["explanation_source"] == "Llama (validated)")
    runtime_failures = sum(1 for c in cases if c["validator_reason"] == "RUNTIME_ERROR")
    rejected = sum(
        1 for c in cases
        if c["explanation_source"] != "Llama (validated)" and c["validator_reason"] != "RUNTIME_ERROR"
    )
    fallback_count = len(cases) - accepted

    report = {
        "kind": "TWENTY_CASE_LLAMA_VS_TEMPLATE_COMPARISON",
        "hardware_verified_pi4": False,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "detector_sha256": hashlib.sha256(args.detector.read_bytes()).hexdigest(),
        "runtime_config_sha256": hashlib.sha256(args.runtime_config.read_bytes()).hexdigest(),
        "total_cases": len(cases),
        "attempted": attempted,
        "accepted_over_attempted": f"{accepted}/{attempted}",
        "rejected_over_attempted": f"{rejected}/{attempted}",
        "runtime_failures_over_attempted": f"{runtime_failures}/{attempted}",
        "fallback_over_all_cases": f"{fallback_count}/{len(cases)}",
        "accepted_count": accepted,
        "rejected_count": rejected,
        "runtime_failure_count": runtime_failures,
        "fallback_count": fallback_count,
        "exact_match_with_template_count": sum(1 for c in cases if c["llama_matches_template"]),
        "llama_ms_distribution": distribution([c["llama_ms"] for c in cases]),
        "scope": "Synthetic holdout IDs selected strictly from metadata; raw SMS omitted",
        "cases": cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(
        f"Recorded {len(cases)} comparison cases to {args.output}: "
        f"accepted={accepted}/{attempted}, rejected={rejected}/{attempted}, "
        f"runtime_failures={runtime_failures}/{attempted}, fallback={fallback_count}/{len(cases)}"
    )


if __name__ == "__main__":
    main()
