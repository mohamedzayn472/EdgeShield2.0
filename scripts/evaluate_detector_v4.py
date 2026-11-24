"""One-time frozen evaluation comparing V3 baseline vs V4 candidate across all sets.

Never modifies model weights, training splits, or validation-selected thresholds after reading holdouts.
Reports full 2x3 truth-by-verdict matrices, English/Hinglish stratification, Wilson 95% CIs on v4_holdout,
calibration/discrimination metrics, paired-control outcomes, regressions, and programmatic promotion gates.
"""
from __future__ import annotations

import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
from sklearn.metrics import average_precision_score, brier_score_loss, log_loss, roc_auc_score

from edgeshield.datasets import digest, read_jsonl
from edgeshield.indicators import detect_indicators
from edgeshield.model_loader import load_detector
from edgeshield.privacy import normalize_sms

ROOT = Path(__file__).resolve().parents[1]

REPRODUCED_EVAL_CASES = [
    ("1_antifraud_notice_en", 0, "english", "fraud_awareness",
     "Bank Security Advisory: Fraudsters send fake account block and KYC update links. Bank staff will never ask for your OTP, password, or UPI PIN."),
    ("1b_antifraud_bank_only", 0, "english", "fraud_awareness",
     "HDFC Bank Alert: Never share your OTP, ATM PIN, CVV, or password with anyone. Bank employees never call to ask for KYC or card details."),
    ("1c_antifraud_hi", 0, "hinglish", "fraud_awareness",
     "Bank Suraksha Soochna: Fraudsters nakli account block ya KYC update link bhejte hain. Bank staff kabhi bhi aapka OTP, password ya UPI PIN nahi maangta."),
    ("2_user_card_block_en", 0, "english", "user_card_block",
     "Cedar Bank: Confirmation that you blocked your debit card XX1234 in the official Cedar Bank app. Call 1800-000-0000 if you did not initiate this."),
    ("2b_card_block_hi", 0, "hinglish", "user_card_block",
     "Aapne official app mein apna debit card XX4512 block kar diya hai. Agar aapne yeh nahi kiya to 1800-000-0000 par call karein."),
    ("3_kyc_branch_appt_en", 0, "english", "branch_kyc_appointment",
     "Cedar Bank: Reminder that your routine KYC update appointment at the Main Street branch is scheduled for 25-Nov-26 at 11:00 AM."),
    ("3b_kyc_completed_en", 0, "english", "branch_kyc_appointment",
     "Cedar Bank: Your KYC verification at the branch has been completed successfully."),
    ("4_statement_link_en", 0, "english", "statement_link",
     "Cedar Bank: Your October 2026 e-statement for A/c XX1234 is ready. View it at https://mybank.example/statement."),
    ("7a_ctrl_genuine_otp", 0, "english", "otp_delivery",
     "123456 is your OTP for transaction of INR 499.00 on Cedar Bank Card XX1234. Never share your OTP with anyone. Valid for 10 mins."),
    ("7d_paired_refund_legit", 0, "english", "failed_payment_reversal",
     "Your failed UPI payment of Rs 850.00 has been reversed and credited back to your A/c XX1234."),
    ("5_family_imp_en", 1, "english", "family_impersonation",
     "Hi Mom, my phone broke and I am texting from a new number. Please transfer Rs. 4500 urgently via UPI right now, do not call this number as mic is damaged."),
    ("5b_family_hi", 1, "hinglish", "family_impersonation",
     "Papa mera phone toot gaya hai, yeh mera naya number hai. Please turant 5000 rs is UPI par bhej do, abhi call mat karna mic kharab hai."),
    ("6_hinglish_read_aloud", 1, "hinglish", "hinglish_read_aloud",
     "Sir aapke card par 4999 ka galat charge laga hai, charge reverse karne ke liye phone par aaya one-time code abhi bol kar batao."),
    ("6c_hinglish_read_aloud_uncertain", 1, "hinglish", "hinglish_read_aloud",
     "Charge reverse karne ke liye aapke number par jo one-time code aaya hai woh padh kar bata do."),
    ("7b_ctrl_active_otp_req", 1, "english", "otp_request",
     "Cedar Bank Alert: Share your 6-digit OTP immediately to cancel an unauthorized debit of INR 4,999.00."),
    ("7c_ctrl_warn_then_req", 1, "english", "warning_then_request",
     "Never share your OTP with strangers. However, send your OTP now to confirm your refund."),
    ("7e_paired_refund_scam", 1, "english", "fake_refund",
     "Approve this collect request of Rs 850 to receive your failed payment refund immediately."),
]


def wilson_ci(k: int, n: int, z: float = 1.959963984540054) -> list[float] | None:
    if n <= 0:
        return None
    p = k / n
    denom = 1.0 + (z * z) / n
    center = (p + (z * z) / (2.0 * n)) / denom
    half = (z * math.sqrt((p * (1.0 - p) + (z * z) / (4.0 * n)) / n)) / denom
    return [round(max(0.0, center - half), 4), round(min(1.0, center + half), 4)]


def _ece_10bin(y_true: np.ndarray, y_prob: np.ndarray) -> float:
    if len(y_true) == 0:
        return 0.0
    bins = np.linspace(0.0, 1.0, 11)
    ece = 0.0
    for i in range(10):
        lo, hi = bins[i], bins[i + 1]
        mask = (y_prob >= lo) & (y_prob <= hi if i == 9 else y_prob < hi)
        cnt = int(np.sum(mask))
        if cnt > 0:
            ece += (cnt / len(y_true)) * abs(float(np.mean(y_true[mask])) - float(np.mean(y_prob[mask])))
    return float(ece)


def evaluate_rows(detector, rows: list[dict], *, include_wilson: bool = False) -> tuple[dict, list[dict]]:
    tp = fp = tn = fn = u0 = u1 = 0
    y_true = []
    y_prob = []
    per_row = []

    for r in rows:
        lbl = r["label"]
        if lbl not in (0, 1):
            continue
        pred = detector.predict(r["text"])
        score = float(pred["score"])
        band = pred["band"]
        inds = list(detect_indicators(r["text"]))
        y_true.append(lbl)
        y_prob.append(score)

        if lbl == 1:
            if band == "SCAM":
                tp += 1
            elif band == "LEGITIMATE":
                fn += 1
            else:
                u1 += 1
        else:
            if band == "LEGITIMATE":
                tn += 1
            elif band == "SCAM":
                fp += 1
            else:
                u0 += 1

        per_row.append({
            "id": r["id"],
            "label": lbl,
            "language": r.get("language", "unknown"),
            "category": r.get("category", r.get("family", "unknown")),
            "pair_id": r.get("pair_id"),
            "score": round(score, 6),
            "band": band,
            "indicators": inds,
        })

    pos_n = tp + fn + u1
    neg_n = tn + fp + u0
    n = pos_n + neg_n
    decided = n - u0 - u1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / pos_n if pos_n else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc = (tp + tn) / n if n else 0.0
    fpr = fp / neg_n if neg_n else 0.0
    fnr = (fn + u1) / pos_n if pos_n else 0.0
    scam_legit = fn / pos_n if pos_n else 0.0
    benign_unc = u0 / neg_n if neg_n else 0.0
    coverage = decided / n if n else 0.0

    y_arr = np.asarray(y_true, dtype=int)
    p_arr = np.clip(np.asarray(y_prob, dtype=float), 1e-12, 1.0 - 1e-12) if n else np.asarray([], dtype=float)
    has_both = n > 0 and len(set(y_true)) == 2

    out = {
        "n": n,
        "negative_n": neg_n,
        "positive_n": pos_n,
        "confusion_matrix_2x3": [[tn, u0, fp], [fn, u1, tp]],
        "rows": ["Legitimate(0)", "Scam(1)"],
        "cols": ["LEGITIMATE", "UNCERTAIN", "SCAM"],
        "false_positives_count": fp,
        "false_positives_den": neg_n,
        "false_positive_rate": round(fpr, 4),
        "false_positive_note": f"0/{neg_n} on this set" if fp == 0 else f"{fp}/{neg_n} on this set",
        "scam_recall_count": tp,
        "scam_recall_den": pos_n,
        "recall": round(rec, 4),
        "scams_as_legitimate_count": fn,
        "scams_as_legitimate_den": pos_n,
        "scams_as_legitimate_rate": round(scam_legit, 4),
        "benign_as_uncertain_count": u0,
        "benign_as_uncertain_den": neg_n,
        "benign_as_uncertain_rate": round(benign_unc, 4),
        "coverage_count": decided,
        "coverage_den": n,
        "coverage": round(coverage, 4),
        "abstention_rate": round((u0 + u1) / n, 4) if n else 0.0,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(float(roc_auc_score(y_arr, p_arr)), 5) if has_both else None,
        "pr_auc": round(float(average_precision_score(y_arr, p_arr)), 5) if has_both else None,
        "brier": round(float(brier_score_loss(y_arr, p_arr)), 5) if n else None,
        "log_loss": round(float(log_loss(y_arr, p_arr, labels=[0, 1])), 5) if has_both else None,
        "ece_10bin": round(_ece_10bin(y_arr, p_arr), 5) if n else None,
    }
    if include_wilson:
        out["wilson_95_ci"] = {
            "fpr": wilson_ci(fp, neg_n),
            "scam_recall": wilson_ci(tp, pos_n),
            "scams_as_legitimate": wilson_ci(fn, pos_n),
            "benign_as_uncertain": wilson_ci(u0, neg_n),
            "coverage": wilson_ci(decided, n),
        }
    return out, per_row


def compare_dataset(det_base, det_cand, rows: list[dict], *, include_wilson: bool = False) -> dict:
    s_base, r_base = evaluate_rows(det_base, rows, include_wilson=include_wilson)
    s_cand, r_cand = evaluate_rows(det_cand, rows, include_wilson=include_wilson)

    by_lang = {}
    langs = sorted({r.get("language", "unknown") for r in rows})
    if len(langs) > 1 or langs != ["unknown"]:
        for lang in langs:
            sub = [r for r in rows if r.get("language", "unknown") == lang]
            if sub:
                lb, _ = evaluate_rows(det_base, sub, include_wilson=include_wilson)
                lc, _ = evaluate_rows(det_cand, sub, include_wilson=include_wilson)
                by_lang[lang] = {"v3": lb, "v4": lc}

    scam_to_legit_regressions = []
    new_false_alarms = []
    other_regressions = []
    improvements = []
    remaining_v4_errors = []

    for a, b, orig in zip(r_base, r_cand, rows):
        expected = "SCAM" if orig["label"] == 1 else "LEGITIMATE"
        v3_ok = a["band"] == expected
        v4_ok = b["band"] == expected
        item = {
            "id": orig["id"],
            "label": orig["label"],
            "expected": expected,
            "language": orig.get("language", "unknown"),
            "category": orig.get("category", orig.get("family", "unknown")),
            "v3_score": a["score"],
            "v3_band": a["band"],
            "v4_score": b["score"],
            "v4_band": b["band"],
            "indicators": b["indicators"],
            "text": orig["text"],
        }
        if orig["label"] == 1 and b["band"] == "LEGITIMATE" and a["band"] != "LEGITIMATE":
            scam_to_legit_regressions.append(item)
        elif orig["label"] == 0 and b["band"] == "SCAM" and a["band"] != "SCAM":
            new_false_alarms.append(item)
        elif v3_ok and not v4_ok:
            other_regressions.append(item)
        elif not v3_ok and v4_ok:
            improvements.append(item)

        if not v4_ok:
            remaining_v4_errors.append(item)

    return {
        "v3": s_base,
        "v4": s_cand,
        "by_language": by_lang,
        "diffs": {
            "scam_to_legitimate_regressions": scam_to_legit_regressions,
            "newly_introduced_false_alarms": new_false_alarms,
            "other_v3_ok_to_v4_non_exact": other_regressions,
            "improvements_over_v3": improvements,
            "remaining_v4_errors": remaining_v4_errors,
        },
        "per_row_v4": r_cand,
        "per_row_v3": r_base,
    }


def evaluate_ambiguous(det_v3, det_v4, rows: list[dict]) -> dict:
    c3, c4 = Counter(), Counter()
    items = []
    for r in rows:
        p3 = det_v3.predict(r["text"])
        p4 = det_v4.predict(r["text"])
        c3[p3["band"]] += 1
        c4[p4["band"]] += 1
        items.append({
            "id": r["id"],
            "language": r.get("language"),
            "category": r.get("category"),
            "v3_score": round(float(p3["score"]), 6),
            "v3_band": p3["band"],
            "v4_score": round(float(p4["score"]), 6),
            "v4_band": p4["band"],
            "indicators": list(detect_indicators(r["text"])),
        })
    return {
        "n": len(rows),
        "note": "Reported strictly outside binary accuracy.",
        "v3_bands": dict(c3),
        "v4_bands": dict(c4),
        "rows": items,
    }


def main() -> None:
    out_dir = ROOT / "results/host/v4"
    out_dir.mkdir(parents=True, exist_ok=True)

    freeze_files = [
        "src/edgeshield/detector_v4.py",
        "src/edgeshield/indicators.py",
        "src/edgeshield/model_loader.py",
        "scripts/create_v4_datasets.py",
        "scripts/train_detector_v4.py",
        "data/synthetic/v4_development.jsonl",
        "data/synthetic/v4_holdout.jsonl",
        "models/detector_v4.json",
        "models/detector_v4.json.sha256",
        "models/detector_v3.json",
        "models/detector_v3.json.sha256",
        "docs/V4_EVALUATION_PROTOCOL.md",
    ]
    freeze = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "file_sha256": {f: digest(ROOT / f) for f in freeze_files},
    }
    (out_dir / "evaluation_freeze.json").write_text(json.dumps(freeze, indent=2) + "\n", encoding="utf-8")

    det_v3 = load_detector(ROOT / "models/detector_v3.json")
    det_v4 = load_detector(ROOT / "models/detector_v4.json")

    repro_rows = [
        {"id": cid, "label": lbl, "language": lang, "category": cat, "text": txt}
        for cid, lbl, lang, cat, txt in REPRODUCED_EVAL_CASES
    ]
    v4_all = read_jsonl(ROOT / "data/synthetic/v4_holdout.jsonl")
    v4_labeled = [r for r in v4_all if r.get("label") in (0, 1)]
    v4_ambig = [r for r in v4_all if r.get("label") is None]
    v3_hold = read_jsonl(ROOT / "data/synthetic/v3_holdout.jsonl")
    v2_all = read_jsonl(ROOT / "data/synthetic/v2_holdout.jsonl")
    v2_labeled = [r for r in v2_all if r.get("label") in (0, 1)]
    v2_ambig = [r for r in v2_all if r.get("label") is None]
    uci_test = read_jsonl(ROOT / "data/processed/test.jsonl")
    ind_all = read_jsonl(ROOT / "data/synthetic/indian_sms.jsonl")
    ind_test_labeled = [r for r in ind_all if r.get("split") == "test" and r.get("label") in (0, 1)]
    ind_dev_labeled = [r for r in ind_all if r.get("split") == "development" and r.get("label") in (0, 1)]
    ind_ambig = [r for r in ind_all if r.get("label") is None]

    res_repro = compare_dataset(det_v3, det_v4, repro_rows)
    res_v4 = compare_dataset(det_v3, det_v4, v4_labeled, include_wilson=True)
    res_v3 = compare_dataset(det_v3, det_v4, v3_hold)
    res_v2 = compare_dataset(det_v3, det_v4, v2_labeled)
    res_uci = compare_dataset(det_v3, det_v4, uci_test)
    res_ind_test = compare_dataset(det_v3, det_v4, ind_test_labeled)
    res_ind_dev = compare_dataset(det_v3, det_v4, ind_dev_labeled)

    # Paired control verification inside v4_holdout + repro
    paired_controls = {}
    by_pair: dict[str, list[dict]] = {}
    for row in res_v4["per_row_v4"]:
        if row.get("pair_id"):
            by_pair.setdefault(row["pair_id"], []).append(row)
    for pid, members in sorted(by_pair.items()):
        benign = [m for m in members if m["label"] == 0]
        scam = [m for m in members if m["label"] == 1]
        paired_controls[pid] = {
            "benign_n": len(benign),
            "benign_non_scam": sum(m["band"] != "SCAM" for m in benign),
            "benign_legit": sum(m["band"] == "LEGITIMATE" for m in benign),
            "scam_n": len(scam),
            "scam_non_legit": sum(m["band"] != "LEGITIMATE" for m in scam),
            "scam_detected": sum(m["band"] == "SCAM" for m in scam),
        }

    # Programmatic pre-declared gate checks (P1, P2, P3)
    benign_repro = [r for r in res_repro["per_row_v4"] if r["label"] == 0]
    scam_repro = [r for r in res_repro["per_row_v4"] if r["label"] == 1]
    bad_ind_repro = {"BANK_IMPERSONATION", "THREAT_OF_BLOCK", "KYC_IMPERSONATION", "UPI_COLLECT_LURE"}
    p1_ok = (
        all(r["band"] != "SCAM" and not (bad_ind_repro & set(r["indicators"])) for r in benign_repro)
        and all(r["band"] != "LEGITIMATE" for r in scam_repro)
    )
    v4m = res_v4["v4"]
    v3_on_v4 = res_v4["v3"]
    v4_en = res_v4["by_language"]["english"]["v4"]
    v4_hi = res_v4["by_language"]["hinglish"]["v4"]
    p2_ok = (
        v4m["false_positive_rate"] <= 0.03
        and v4m["false_positive_rate"] < v3_on_v4["false_positive_rate"]
        and v4m["recall"] >= 0.90
        and v4_en["recall"] >= 0.86
        and v4_hi["recall"] >= 0.86
        and v4m["scams_as_legitimate_rate"] <= 0.05
        and v4m["benign_as_uncertain_rate"] <= 0.06
        and v4m["coverage"] >= 0.90
        and v4m["roc_auc"] >= v3_on_v4["roc_auc"]
        and v4m["brier"] <= v3_on_v4["brier"]
    )
    p3_ok = (
        res_v3["v4"]["false_positive_rate"] <= 0.025
        and res_v3["v4"]["recall"] >= 0.95
        and res_v2["v4"]["false_positive_rate"] <= 0.0334
        and res_v2["v4"]["recall"] >= 0.883
        and res_v2["v4"]["scams_as_legitimate_count"] <= 5
        and res_uci["v4"]["false_positive_rate"] <= 0.005
        and res_uci["v4"]["recall"] >= 0.858
    )

    report = {
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "One-time frozen comparison of V3 baseline vs V4 candidate; synthetic results do not measure real-world prevalence.",
        "models": {
            "v3": {"sha256": freeze["file_sha256"]["models/detector_v3.json"], "thresholds": [det_v3.low, det_v3.high]},
            "v4": {"sha256": freeze["file_sha256"]["models/detector_v4.json"], "thresholds": [det_v4.low, det_v4.high]},
        },
        "promotion_gates": {
            "P1_reproduced_failures_and_controls": p1_ok,
            "P2_fresh_v4_holdout_240": p2_ok,
            "P3_existing_regression_suites": p3_ok,
            "P4_host_product_and_clean_pkg": "VERIFY_IN_STEP_6",
            "P5_physical_pi5_device_verification": "PENDING_HARDWARE",
            "overall_host_gates_p1_to_p3": p1_ok and p2_ok and p3_ok,
        },
        "datasets": {
            "reproduced_failures_and_controls": res_repro,
            "v4_holdout_labeled_240": res_v4,
            "v4_holdout_ambiguous_24": evaluate_ambiguous(det_v3, det_v4, v4_ambig),
            "v3_holdout_160": res_v3,
            "v2_holdout_labeled_120": res_v2,
            "v2_holdout_ambiguous_12": evaluate_ambiguous(det_v3, det_v4, v2_ambig),
            "uci_test_1148": res_uci,
            "indian_sms_test_labeled_24": res_ind_test,
            "indian_sms_dev_labeled_8": res_ind_dev,
            "indian_sms_ambiguous_4": evaluate_ambiguous(det_v3, det_v4, ind_ambig),
        },
        "paired_controls_v4_holdout": paired_controls,
    }

    (out_dir / "v3_vs_v4_evaluation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("=== ONE-TIME FROZEN V3 vs V4 EVALUATION SUMMARY ===")
    print("Promotion gates P1..P3:", report["promotion_gates"])
    for key in ("reproduced_failures_and_controls", "v4_holdout_labeled_240", "v3_holdout_160", "v2_holdout_labeled_120", "uci_test_1148", "indian_sms_test_labeled_24"):
        ds = report["datasets"][key]
        v3, v4 = ds["v3"], ds["v4"]
        print(f"\n[{key}]")
        print(f"  V3: cm={v3['confusion_matrix_2x3']} fpr={v3['false_positive_note']} rec={v3['scam_recall_count']}/{v3['scam_recall_den']}({v3['recall']}) fn={v3['scams_as_legitimate_count']} u0={v3['benign_as_uncertain_count']} cov={v3['coverage']} auc={v3['roc_auc']} brier={v3['brier']}")
        print(f"  V4: cm={v4['confusion_matrix_2x3']} fpr={v4['false_positive_note']} rec={v4['scam_recall_count']}/{v4['scam_recall_den']}({v4['recall']}) fn={v4['scams_as_legitimate_count']} u0={v4['benign_as_uncertain_count']} cov={v4['coverage']} auc={v4['roc_auc']} brier={v4['brier']}")
        if "wilson_95_ci" in v4:
            print("  V4 Wilson 95% CI:", v4["wilson_95_ci"])
        print("  diffs:", {k: len(v) for k, v in ds["diffs"].items()})


if __name__ == "__main__":
    main()
