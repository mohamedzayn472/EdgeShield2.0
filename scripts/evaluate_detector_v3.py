"""Evaluate frozen V3 detector & refined BANK_IMPERSONATION indicator vs V2 baseline."""
from __future__ import annotations
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from edgeshield.datasets import digest, read_jsonl
from edgeshield.indicators import HIGH_RISK_INDICATORS, detect_indicators
from edgeshield.model_loader import load_detector
from edgeshield.privacy import normalize_sms

ROOT = Path(__file__).resolve().parents[1]
OLD_BANK_RE = re.compile(r"\b(?:bank|banking|banker)\b")

# Representative unseen diagnostic suite matching the 6 Pi 5 legitimate tests,
# the 1 earlier bank credit notification, and 5 paired genuine bank scams.
DIAGNOSTIC_SUITE = [
    ("legit_1_bank_credit", 0, "Your A/c XX1234 has been credited with INR 5,000.00 on 20-Nov-26. Info: NEFT-REF12345. Avl Bal: INR 24,500.00."),
    ("legit_2_bank_debit", 0, "Alert: Your A/c XX9012 is debited by INR 850.00 on 20-Nov-26 towards UPI/Merchant. Call customer care if unauthorized."),
    ("legit_3_banking_otp", 0, "123456 is your OTP for transaction of INR 499.00 on your HDFC Bank Card XX1234. Do not share OTP with anyone. Valid for 10 mins."),
    ("legit_4_upi_confirm", 0, "Rs 350.00 paid to Fresh Mart via UPI. UPI Ref No 432198765432. A/c XX1234."),
    ("legit_5_college_notice", 0, "Notice: Internal assessment timetable for Semester 5 is published on the department notice board. Classes resume Monday."),
    ("legit_6_bank_statement", 0, "Your e-statement for Bank A/c XX1234 for October 2026 has been sent to your registered email ID."),
    ("legit_7_earlier_credit", 0, "Dear Customer, Rs. 2,500.00 has been credited to your A/c no. XXXX4321 on 19/11/2026 via IMPS. Available balance is Rs. 15,200.50."),
    ("scam_1_account_block", 1, "Urgent: Your bank account will be blocked today. Update KYC immediately at https://bit.ly/verify-kyc."),
    ("scam_2_otp_share", 1, "Dear user, your bank KYC is pending. Share your 6 digit OTP immediately to avoid account suspension."),
    ("scam_3_fake_kyc", 1, "PAN not linked with your savings bank A/c. Complete e-KYC now at https://ekyc-pan-alert.example or account will be frozen."),
    ("scam_4_suspicious_bank_link", 1, "Your bank reward points worth INR 5,500 expire tonight. Claim cash credit immediately at https://bit.ly/bank-bonus-26."),
    ("scam_5_credentials", 1, "Alert: Unusual activity on your bank card. Enter your PIN and CVV at https://secure-bank-login.example to unlock."),
]


def _old_bank_triggered(text: str) -> bool:
    return bool(OLD_BANK_RE.search(normalize_sms(text).lower()))


def evaluate_rows(detector, rows: list[dict]) -> dict:
    tp = fp = tn = fn = u0 = u1 = 0
    old_bank_fp = new_bank_fp = old_bank_tp = new_bank_tp = 0
    inconsistent_low_with_bank = 0
    outcomes = []

    for r in rows:
        lbl = r["label"]
        if lbl not in (0, 1):
            continue
        pred = detector.predict(r["text"])
        band = pred["band"]
        score = float(pred["score"])
        inds = detect_indicators(r["text"])
        old_b = _old_bank_triggered(r["text"])
        new_b = "BANK_IMPERSONATION" in inds

        if lbl == 1:
            if band == "SCAM":
                tp += 1
            elif band == "LEGITIMATE":
                fn += 1
            else:
                u1 += 1
            if old_b:
                old_bank_tp += 1
            if new_b:
                new_bank_tp += 1
        else:
            if band == "LEGITIMATE":
                tn += 1
            elif band == "SCAM":
                fp += 1
            else:
                u0 += 1
            if old_b:
                old_bank_fp += 1
            if new_b:
                new_bank_fp += 1
        if band == "LEGITIMATE" and new_b:
            inconsistent_low_with_bank += 1

        outcomes.append({
            "id": r["id"],
            "label": lbl,
            "language": r.get("language", "unknown"),
            "category": r.get("category", "unknown"),
            "score": round(score, 6),
            "band": band,
            "indicators": list(inds),
            "old_bank_impersonation": old_b,
            "new_bank_impersonation": new_b,
        })

    pos_n = tp + fn + u1
    neg_n = tn + fp + u0
    n = pos_n + neg_n
    # Standard binary view treats SCAM as positive prediction and LEGITIMATE/UNCERTAIN as non-SCAM
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / pos_n if pos_n else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / n if n else 0.0
    fpr = fp / neg_n if neg_n else 0.0
    fnr = (fn + u1) / pos_n if pos_n else 0.0
    scam_as_legit_rate = fn / pos_n if pos_n else 0.0
    abstention_rate = (u0 + u1) / n if n else 0.0

    return {
        "n": n,
        "positive_n": pos_n,
        "negative_n": neg_n,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "scam_assigned_legitimate_rate": round(scam_as_legit_rate, 4),
        "abstention_rate": round(abstention_rate, 4),
        "confusion_matrix_2x3": [[tn, u0, fp], [fn, u1, tp]],
        "confusion_matrix_binary": [[tn + u0, fp], [fn + u1, tp]],
        "rows": ["legitimate", "scam"],
        "columns_2x3": ["LEGITIMATE", "UNCERTAIN", "SCAM"],
        "bank_impersonation_audit": {
            "old_rule_legit_false_triggers": old_bank_fp,
            "new_rule_legit_false_triggers": new_bank_fp,
            "old_rule_scam_triggers": old_bank_tp,
            "new_rule_scam_triggers": new_bank_tp,
            "legitimate_band_with_new_bank_indicator": inconsistent_low_with_bank,
        },
        "false_positives": [o for o in outcomes if o["label"] == 0 and o["band"] == "SCAM"],
        "false_negatives": [o for o in outcomes if o["label"] == 1 and o["band"] != "SCAM"],
        "uncertain_legit": [o for o in outcomes if o["label"] == 0 and o["band"] == "UNCERTAIN"],
    }


def main():
    out_dir = ROOT / "results/host/v3"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Record evaluation freeze hashes
    freeze_files = [
        "src/edgeshield/detector_v3.py",
        "src/edgeshield/indicators.py",
        "scripts/create_v3_datasets.py",
        "scripts/train_detector_v3.py",
        "data/synthetic/v3_development.jsonl",
        "data/synthetic/v3_holdout.jsonl",
        "models/detector_v3.json",
        "models/detector_v3.json.sha256",
    ]
    freeze = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "file_sha256": {f: digest(ROOT / f) for f in freeze_files},
    }
    (out_dir / "evaluation_freeze.json").write_text(json.dumps(freeze, indent=2), encoding="utf-8")

    det_v2 = load_detector(ROOT / "models/detector_v2.json")
    det_v3 = load_detector(ROOT / "models/detector_v3.json")

    v3_holdout = read_jsonl(ROOT / "data/synthetic/v3_holdout.jsonl")
    v2_holdout = [r for r in read_jsonl(ROOT / "data/synthetic/v2_holdout.jsonl") if r.get("label") in (0, 1)]
    uci_test = read_jsonl(ROOT / "data/processed/test.jsonl")

    # Evaluate V2 vs V3 across all three datasets
    comparison = {}
    for name, rows in (
        ("v3_holdout_160", v3_holdout),
        ("v2_holdout_120", v2_holdout),
        ("uci_test_1148", uci_test),
    ):
        comparison[name] = {
            "v2_before": evaluate_rows(det_v2, rows),
            "v3_after": evaluate_rows(det_v3, rows),
        }

    # Language and category breakdowns on V3 holdout
    v3_by_lang = {
        lang: {
            "v2_before": evaluate_rows(det_v2, [r for r in v3_holdout if r["language"] == lang]),
            "v3_after": evaluate_rows(det_v3, [r for r in v3_holdout if r["language"] == lang]),
        }
        for lang in ("english", "hinglish")
    }
    cats = sorted({r["category"] for r in v3_holdout})
    v3_by_cat = {
        cat: {
            "v2_before": evaluate_rows(det_v2, [r for r in v3_holdout if r["category"] == cat]),
            "v3_after": evaluate_rows(det_v3, [r for r in v3_holdout if r["category"] == cat]),
        }
        for cat in cats
    }

    # Diagnostic suite before-and-after
    diag_rows = []
    for name, lbl, txt in DIAGNOSTIC_SUITE:
        p2 = det_v2.predict(txt)
        p3 = det_v3.predict(txt)
        inds = list(detect_indicators(txt))
        old_b = _old_bank_triggered(txt)
        diag_rows.append({
            "case": name,
            "label": lbl,
            "text": txt,
            "v2_score": round(p2["score"], 3),
            "v2_band": p2["band"],
            "old_bank_impersonation": old_b,
            "v3_score": round(p3["score"], 3),
            "v3_band": p3["band"],
            "v3_indicators": inds,
            "new_bank_impersonation": "BANK_IMPERSONATION" in inds,
        })

    full_report = {
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        "v2_thresholds": [det_v2.low, det_v2.high],
        "v3_thresholds": [det_v3.low, det_v3.high],
        "datasets": comparison,
        "v3_holdout_by_language": v3_by_lang,
        "v3_holdout_by_category": v3_by_cat,
        "diagnostic_banking_suite": diag_rows,
    }
    (out_dir / "v2_vs_v3_comparison.json").write_text(json.dumps(full_report, indent=2), encoding="utf-8")

    # Compact console summary
    print("=== BEFORE (V2) vs AFTER (V3) SUMMARY ===")
    print(f"V2 thresholds: [{det_v2.low}, {det_v2.high}] | V3 thresholds: [{det_v3.low}, {det_v3.high}]")
    for ds_name in ("v3_holdout_160", "v2_holdout_120", "uci_test_1148"):
        b = comparison[ds_name]["v2_before"]
        a = comparison[ds_name]["v3_after"]
        print(f"\n[{ds_name}]")
        print(f"  V2 BEFORE: acc={b['accuracy']:.4f} P={b['precision']:.4f} R={b['recall']:.4f} F1={b['f1']:.4f} FPR={b['false_positive_rate']:.4f} FNR={b['false_negative_rate']:.4f} abs={b['abstention_rate']:.4f} cm={b['confusion_matrix_2x3']} old_bank_fp={b['bank_impersonation_audit']['old_rule_legit_false_triggers']}")
        print(f"  V3 AFTER : acc={a['accuracy']:.4f} P={a['precision']:.4f} R={a['recall']:.4f} F1={a['f1']:.4f} FPR={a['false_positive_rate']:.4f} FNR={a['false_negative_rate']:.4f} abs={a['abstention_rate']:.4f} cm={a['confusion_matrix_2x3']} new_bank_fp={a['bank_impersonation_audit']['new_rule_legit_false_triggers']}")
    print("\n=== DIAGNOSTIC BANKING SUITE (BEFORE -> AFTER) ===")
    for r in diag_rows:
        print(
            f"  {r['case']:28s} | y={r['label']} | V2={r['v2_score']:.3f} {r['v2_band']:10s} (oldBank={str(r['old_bank_impersonation']):5s}) "
            f"-> V3={r['v3_score']:.3f} {r['v3_band']:10s} ind={r['v3_indicators']}"
        )


if __name__ == "__main__":
    main()
