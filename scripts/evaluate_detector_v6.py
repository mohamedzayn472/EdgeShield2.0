"""One-time frozen evaluation comparing V3 baseline, V5 prior candidate, and V6 candidate.

Never modifies model weights, indicators, training splits, or validation-selected thresholds
after reading any holdout set. Records hashes of all source/model/dataset artifacts in
results/host/v6/evaluation_freeze.json and writes complete metrics & programmatic gate verdicts
in results/host/v6/v3_v5_v6_evaluation.json.
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

ROOT = Path(__file__).resolve().parents[1]
IMP_CUES = frozenset({"BANK_IMPERSONATION", "THREAT_OF_BLOCK", "KYC_IMPERSONATION", "OTP_REQUEST", "UPI_COLLECT_LURE"})

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
    benign_imp_err = 0
    y_true, y_prob, per_row = [], [], []

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
            if set(inds) & IMP_CUES:
                benign_imp_err += 1
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
        "benign_imp_cue_error_count": benign_imp_err,
        "benign_imp_cue_error_den": neg_n,
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


def compare_models(detectors: dict[str, object], rows: list[dict], *, include_wilson: bool = False) -> dict:
    summaries, per_rows = {}, {}
    for name, det in detectors.items():
        s, pr = evaluate_rows(det, rows, include_wilson=include_wilson)
        summaries[name] = s
        per_rows[name] = pr

    by_lang = {}
    langs = sorted({r.get("language", "unknown") for r in rows})
    if len(langs) > 1 or langs != ["unknown"]:
        for lang in langs:
            sub = [r for r in rows if r.get("language", "unknown") == lang]
            if sub:
                by_lang[lang] = {
                    name: evaluate_rows(det, sub, include_wilson=include_wilson)[0]
                    for name, det in detectors.items()
                }

    scam_to_legit_reg_vs_v3, new_fa_vs_v3, imp_vs_v3, rem_v6_err = [], [], [], []
    for r3, r6, orig in zip(per_rows["v3"], per_rows["v6"], rows):
        expected = "SCAM" if orig["label"] == 1 else "LEGITIMATE"
        v3_ok = r3["band"] == expected
        v6_ok = r6["band"] == expected
        item = {
            "id": orig["id"],
            "label": orig["label"],
            "language": orig.get("language", "unknown"),
            "category": orig.get("category", orig.get("family", "unknown")),
            "v3_score": r3["score"],
            "v3_band": r3["band"],
            "v6_score": r6["score"],
            "v6_band": r6["band"],
            "indicators": r6["indicators"],
            "text": orig["text"],
        }
        if orig["label"] == 1 and r6["band"] == "LEGITIMATE" and r3["band"] != "LEGITIMATE":
            scam_to_legit_reg_vs_v3.append(item)
        elif orig["label"] == 0 and r6["band"] == "SCAM" and r3["band"] != "SCAM":
            new_fa_vs_v3.append(item)
        elif not v3_ok and v6_ok:
            imp_vs_v3.append(item)
        if not v6_ok:
            rem_v6_err.append(item)

    return {
        **summaries,
        "by_language": by_lang,
        "diffs_vs_v3": {
            "scam_to_legitimate_regressions": scam_to_legit_reg_vs_v3,
            "newly_introduced_false_alarms": new_fa_vs_v3,
            "improvements_over_v3": imp_vs_v3,
            "remaining_v6_errors": rem_v6_err,
        },
        "per_row_v6": per_rows["v6"],
    }


def evaluate_ambiguous(detectors: dict[str, object], rows: list[dict]) -> dict:
    counts = {name: Counter() for name in detectors}
    items = []
    for r in rows:
        item = {
            "id": r["id"],
            "language": r.get("language"),
            "category": r.get("category"),
            "indicators": list(detect_indicators(r["text"])),
        }
        for name, det in detectors.items():
            p = det.predict(r["text"])
            counts[name][p["band"]] += 1
            item[f"{name}_score"] = round(float(p["score"]), 6)
            item[f"{name}_band"] = p["band"]
        items.append(item)
    return {
        "n": len(rows),
        "note": "Reported strictly outside binary accuracy.",
        "bands": {name: dict(c) for name, c in counts.items()},
        "rows": items,
    }


def main() -> None:
    out_dir = ROOT / "results/host/v6"
    out_dir.mkdir(parents=True, exist_ok=True)

    freeze_files = [
        "src/edgeshield/detector_v6.py",
        "src/edgeshield/indicators.py",
        "src/edgeshield/model_loader.py",
        "scripts/create_v6_datasets.py",
        "scripts/train_detector_v6.py",
        "scripts/evaluate_detector_v6.py",
        "docs/V6_EVALUATION_PROTOCOL.md",
        "models/detector_v6.json",
        "models/detector_v6.json.sha256",
        "models/detector_v5.json",
        "models/detector_v4.json",
        "models/detector_v3.json",
        "data/synthetic/v6_development.jsonl",
        "data/synthetic/v6_holdout.jsonl",
        "data/synthetic/v5_holdout.jsonl",
        "data/synthetic/v4_holdout.jsonl",
        "data/synthetic/v3_holdout.jsonl",
        "data/synthetic/v2_holdout.jsonl",
        "data/synthetic/indian_sms.jsonl",
        "data/processed/train.jsonl",
        "data/processed/calibration.jsonl",
        "data/processed/validation.jsonl",
        "data/processed/test.jsonl",
    ]
    freeze = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "file_sha256": {f: digest(ROOT / f) for f in freeze_files},
    }
    (out_dir / "evaluation_freeze.json").write_text(json.dumps(freeze, indent=2) + "\n", encoding="utf-8")

    detectors = {
        "v3": load_detector(ROOT / "models/detector_v3.json"),
        "v5": load_detector(ROOT / "models/detector_v5.json"),
        "v6": load_detector(ROOT / "models/detector_v6.json"),
    }

    repro_rows = [
        {"id": cid, "label": lbl, "language": lang, "category": cat, "text": txt}
        for cid, lbl, lang, cat, txt in REPRODUCED_EVAL_CASES
    ]
    v6_all = read_jsonl(ROOT / "data/synthetic/v6_holdout.jsonl")
    v6_labeled = [r for r in v6_all if r.get("label") in (0, 1)]
    v6_ambig = [r for r in v6_all if r.get("label") is None]

    v5_all = read_jsonl(ROOT / "data/synthetic/v5_holdout.jsonl")
    v5_labeled = [r for r in v5_all if r.get("label") in (0, 1)]
    v5_ambig = [r for r in v5_all if r.get("label") is None]

    v4_all = read_jsonl(ROOT / "data/synthetic/v4_holdout.jsonl")
    v4_labeled = [r for r in v4_all if r.get("label") in (0, 1)]
    v4_ambig = [r for r in v4_all if r.get("label") is None]

    v3_hold = read_jsonl(ROOT / "data/synthetic/v3_holdout.jsonl")
    v2_all = read_jsonl(ROOT / "data/synthetic/v2_holdout.jsonl")
    v2_labeled = [r for r in v2_all if r.get("label") in (0, 1)]
    v2_ambig = [r for r in v2_all if r.get("label") is None]

    uci_test = read_jsonl(ROOT / "data/processed/test.jsonl")
    ind_all = read_jsonl(ROOT / "data/synthetic/indian_sms.jsonl")
    ind_test = [r for r in ind_all if r.get("split") == "test" and r.get("label") in (0, 1)]
    ind_dev = [r for r in ind_all if r.get("split") == "development" and r.get("label") in (0, 1)]
    ind_ambig = [r for r in ind_all if r.get("label") is None]

    res_repro = compare_models(detectors, repro_rows)
    res_v6 = compare_models(detectors, v6_labeled, include_wilson=True)
    res_v5 = compare_models(detectors, v5_labeled, include_wilson=True)
    res_v4 = compare_models(detectors, v4_labeled, include_wilson=True)
    res_v3 = compare_models(detectors, v3_hold)
    res_v2 = compare_models(detectors, v2_labeled)
    res_uci = compare_models(detectors, uci_test)
    res_ind_test = compare_models(detectors, ind_test)
    res_ind_dev = compare_models(detectors, ind_dev)

    paired_controls = {}
    by_pair: dict[str, list[dict]] = {}
    for row in res_v6["per_row_v6"]:
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

    benign_repro = [r for r in res_repro["per_row_v6"] if r["label"] == 0]
    scam_repro = [r for r in res_repro["per_row_v6"] if r["label"] == 1]
    p1_ok = (
        all(r["band"] != "SCAM" and not (IMP_CUES & set(r["indicators"])) for r in benign_repro)
        and all(r["band"] == "SCAM" for r in scam_repro)
    )

    v6m, v3_on_v6 = res_v6["v6"], res_v6["v3"]
    v6_en, v6_hi = res_v6["by_language"]["english"]["v6"], res_v6["by_language"]["hinglish"]["v6"]
    p2_checks = {
        "fpr_le_3pct": v6m["false_positive_rate"] <= 0.03,
        "fpr_lt_v3": v6m["false_positive_rate"] < v3_on_v6["false_positive_rate"],
        "recall_ge_90pct": v6m["recall"] >= 0.90,
        "en_recall_ge_86pct": v6_en["recall"] >= 0.86,
        "hi_recall_ge_86pct": v6_hi["recall"] >= 0.86,
        "scams_as_legit_le_5pct": v6m["scams_as_legitimate_rate"] <= 0.05,
        "benign_as_uncertain_le_6pct": v6m["benign_as_uncertain_rate"] <= 0.06,
        "coverage_ge_90pct": v6m["coverage"] >= 0.90,
        "auc_ge_v3": v6m["roc_auc"] >= v3_on_v6["roc_auc"],
        "brier_le_v3": v6m["brier"] <= v3_on_v6["brier"],
        "benign_imp_cues_le_3": v6m["benign_imp_cue_error_count"] <= 3,
    }
    p2_ok = all(p2_checks.values())

    p3_checks = {
        "v5_fpr_le_3pct": res_v5["v6"]["false_positive_rate"] <= 0.03,
        "v5_recall_ge_90pct": res_v5["v6"]["recall"] >= 0.90,
        "v5_fn_le_5pct": res_v5["v6"]["scams_as_legitimate_rate"] <= 0.05,
        "v5_benign_imp_cues_le_2": res_v5["v6"]["benign_imp_cue_error_count"] <= 2,
        "v4_fpr_le_417pct": res_v4["v6"]["false_positive_rate"] <= 0.0417,
        "v4_recall_ge_90pct": res_v4["v6"]["recall"] >= 0.90,
        "v4_fn_le_5pct": res_v4["v6"]["scams_as_legitimate_rate"] <= 0.05,
        "v4_benign_imp_cues_le_2": res_v4["v6"]["benign_imp_cue_error_count"] <= 2,
        "v3_fpr_le_25pct": res_v3["v6"]["false_positive_rate"] <= 0.025,
        "v3_recall_ge_95pct": res_v3["v6"]["recall"] >= 0.95,
        "v2_fpr_le_334pct": res_v2["v6"]["false_positive_rate"] <= 0.0334,
        "v2_recall_ge_90pct": res_v2["v6"]["recall"] >= 0.90,
        "v2_fn_le_5": res_v2["v6"]["scams_as_legitimate_count"] <= 5,
        "uci_fpr_le_05pct": res_uci["v6"]["false_positive_rate"] <= 0.005,
        "uci_recall_ge_86pct": res_uci["v6"]["recall"] >= 0.86,
    }
    p3_ok = all(p3_checks.values())

    report = {
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "One-time frozen comparison of V3, V5, and V6; synthetic results do not measure real-world prevalence.",
        "models": {
            k: {"sha256": freeze["file_sha256"][f"models/detector_{k}.json"], "thresholds": [det.low, det.high]}
            for k, det in detectors.items()
        },
        "promotion_gates": {
            "P1_reproduced_failures_and_controls": p1_ok,
            "P2_fresh_v6_holdout_240": p2_ok,
            "P2_detail": p2_checks,
            "P3_existing_regression_suites": p3_ok,
            "P3_detail": p3_checks,
            "P4_host_product_and_clean_pkg": "VERIFY_IN_STEP_6",
            "P5_physical_pi5_device_verification": "PENDING_HARDWARE",
            "overall_host_gates_p1_to_p3": p1_ok and p2_ok and p3_ok,
        },
        "datasets": {
            "reproduced_failures_and_controls": res_repro,
            "v6_holdout_labeled_240": res_v6,
            "v6_holdout_ambiguous_24": evaluate_ambiguous(detectors, v6_ambig),
            "v5_holdout_labeled_240": res_v5,
            "v5_holdout_ambiguous_24": evaluate_ambiguous(detectors, v5_ambig),
            "v4_holdout_labeled_240": res_v4,
            "v4_holdout_ambiguous_24": evaluate_ambiguous(detectors, v4_ambig),
            "v3_holdout_160": res_v3,
            "v2_holdout_labeled_120": res_v2,
            "v2_holdout_ambiguous_12": evaluate_ambiguous(detectors, v2_ambig),
            "uci_test_1148": res_uci,
            "indian_sms_test_labeled_24": res_ind_test,
            "indian_sms_dev_labeled_8": res_ind_dev,
            "indian_sms_ambiguous_4": evaluate_ambiguous(detectors, ind_ambig),
        },
        "paired_controls_v6_holdout": paired_controls,
    }

    (out_dir / "v3_v5_v6_evaluation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("=== ONE-TIME FROZEN V3 vs V5 vs V6 EVALUATION SUMMARY ===")
    print("Promotion gates P1..P3:", json.dumps(report["promotion_gates"], indent=2))
    for key in (
        "reproduced_failures_and_controls",
        "v6_holdout_labeled_240",
        "v5_holdout_labeled_240",
        "v4_holdout_labeled_240",
        "v3_holdout_160",
        "v2_holdout_labeled_120",
        "uci_test_1148",
        "indian_sms_test_labeled_24",
    ):
        ds = report["datasets"][key]
        print(f"\n[{key}]")
        for mname in ("v3", "v5", "v6"):
            m = ds[mname]
            print(
                f"  {mname.upper()}: cm={m['confusion_matrix_2x3']} fpr={m['false_positive_note']} "
                f"imp_err={m['benign_imp_cue_error_count']}/{m['benign_imp_cue_error_den']} "
                f"rec={m['scam_recall_count']}/{m['scam_recall_den']}({m['recall']}) "
                f"fn={m['scams_as_legitimate_count']} u0={m['benign_as_uncertain_count']} "
                f"cov={m['coverage']} auc={m['roc_auc']} brier={m['brier']}"
            )
        if "wilson_95_ci" in ds["v6"]:
            print("  V6 Wilson 95% CI:", ds["v6"]["wilson_95_ci"])
        print("  diffs vs V3:", {k: len(v) for k, v in ds["diffs_vs_v3"].items()})


if __name__ == "__main__":
    main()
