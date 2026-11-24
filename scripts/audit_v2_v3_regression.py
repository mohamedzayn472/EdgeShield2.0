"""Audit frozen V2 vs V3 calibration, split hygiene, identical-row regressions, and fresh diagnostics."""
from __future__ import annotations

import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
from sklearn.metrics import brier_score_loss, log_loss

from edgeshield.datasets import check_leakage, digest, group_near_duplicates, read_jsonl
from edgeshield.indicators import detect_indicators
from edgeshield.model_loader import load_detector
from edgeshield.privacy import normalize_sms

ROOT = Path(__file__).resolve().parents[1]

# Separate diagnostic cases (NOT part of training, calibration, validation, or held-out benchmarks).
FRESH_DIAGNOSTIC_CASES = [
    ("diag_card_block_en", 0, "english", "completed_card_block",
     "Cedar Bank: Your debit card XX1234 has been blocked as per your request. Call 1800-000-0000 if not done by you."),
    ("diag_card_block_hi", 0, "hinglish", "completed_card_block",
     "Aapke request par aapka bank debit card XX4512 block kar diya gaya hai."),
    ("diag_kyc_completed_en", 0, "english", "completed_kyc",
     "Cedar Bank: Your KYC verification has been completed successfully."),
    ("diag_kyc_completed_hi", 0, "hinglish", "completed_kyc",
     "Willow Bank: Aapka KYC update poora ho gaya hai."),
    ("diag_kyc_scheduled_en", 0, "english", "scheduled_kyc_branch",
     "Reminder: Your branch appointment for routine KYC update is scheduled on 25-Nov-26 at 11:00 AM."),
    ("diag_kyc_scheduled_hi", 0, "hinglish", "scheduled_kyc_branch",
     "Aapki KYC update ke liye branch appointment kal 11 AM ko scheduled hai."),
    ("diag_statement_link_en", 0, "english", "generic_statement_link",
     "Cedar Bank: Your monthly e-statement is ready. Open https://mybank.example/statement to view it."),
    ("diag_antifraud_en", 0, "english", "educational_antifraud",
     "Bank Security Advisory: Fraudsters send fake account block and KYC update links. Never share your OTP, PIN, or CVV with anyone."),
    ("diag_antifraud_hi", 0, "hinglish", "educational_antifraud",
     "Cyber thag nakli KYC block link bhejte hain. Apna OTP ya MPIN kisi ke saath share mat karo."),
    ("diag_hinglish_neg_otp", 0, "hinglish", "hinglish_negation",
     "Apna OTP kisi ke saath share mat karo."),
    ("diag_hinglish_neg_mpin", 0, "hinglish", "hinglish_negation",
     "Apna MPIN kisi ko na batayein. Bank kabhi aapka PIN nahi poochta."),
    ("diag_family_imp_en", 1, "english", "family_impersonation",
     "Hi Mom, my phone broke and I am texting from a new number. Please send Rs. 4500 urgently via UPI, I will pay you back tonight."),
    ("diag_family_imp_hi", 1, "hinglish", "family_impersonation",
     "Papa mera phone gir gaya hai, yeh mera naya number hai. Please turant 5000 rs is UPI ID par bhej do, bahut urgent hai."),
    ("diag_read_aloud_en", 1, "english", "read_code_aloud",
     "Customer care calling: read out the 6-digit code aloud to cancel the pending charge on your bank card."),
    ("diag_read_aloud_hi", 1, "hinglish", "read_code_aloud",
     "Phone par jo OTP code aaya hai woh bol kar sunao."),
    ("diag_neg_then_aloud_en", 1, "english", "benign_then_malicious",
     "Never share your OTP with anyone. However, read out the 6-digit code aloud for your Cedar Bank card."),
    ("diag_kyc_done_then_otp_en", 1, "english", "benign_then_malicious",
     "Cedar Bank: Your KYC verification has been completed. Share your OTP now to enable net banking."),
    ("diag_advisory_then_shortener_en", 1, "english", "benign_then_malicious",
     "Bank Security Advisory: Never share OTP. Click https://bit.ly/fake to verify KYC."),
    ("diag_ov_hinglish_otp", 1, "hinglish", "hinglish_ov",
     "Aapke phone par aaya OTP mujhe turant bhej do."),
    ("diag_ov_hinglish_cred", 1, "hinglish", "hinglish_ov",
     "Apna ATM PIN aur CVV bhej do."),
    ("diag_abbrev_cred", 1, "english", "abbreviations",
     "Ac no XX1234: send pwd and tpin immediately."),
    ("diag_unicode_otp", 1, "english", "unicode_obfuscation",
     "\uff33\uff48\uff41\uff52\uff45 your one\u2011time password at https://bit.ly/x"),
]

PI_SIX_PROXY_CASES = [
    ("pi_diag_1_credit", 0, "Your A/c XX1234 has been credited with INR 5,000.00 on 20-Nov-26. Info: NEFT-REF12345. Avl Bal: INR 24,500.00."),
    ("pi_diag_2_debit", 0, "Alert: Your A/c XX9012 is debited by INR 850.00 on 20-Nov-26 towards UPI/Merchant. Call customer care if unauthorized."),
    ("pi_diag_3_otp", 0, "123456 is your OTP for transaction of INR 499.00 on your HDFC Bank Card XX1234. Do not share OTP with anyone. Valid for 10 mins."),
    ("pi_diag_4_upi", 0, "Rs 350.00 paid to Fresh Mart via UPI. UPI Ref No 432198765432. A/c XX1234."),
    ("pi_diag_5_college", 0, "Notice: Internal assessment timetable for Semester 5 is published on the department notice board. Classes resume Monday."),
    ("pi_diag_6_statement", 0, "Your e-statement for Bank A/c XX1234 for October 2026 has been sent to your registered email ID."),
]


def _ece_10bin(y_true: np.ndarray, y_prob: np.ndarray) -> float:
    if len(y_true) == 0:
        return 0.0
    bins = np.linspace(0.0, 1.0, 11)
    ece = 0.0
    for i in range(10):
        lo, hi = bins[i], bins[i + 1]
        if i == 9:
            mask = (y_prob >= lo) & (y_prob <= hi)
        else:
            mask = (y_prob >= lo) & (y_prob < hi)
        count = int(np.sum(mask))
        if count > 0:
            ece += (count / len(y_true)) * abs(float(np.mean(y_true[mask])) - float(np.mean(y_prob[mask])))
    return float(ece)


def evaluate_subset(detector, rows: list[dict]) -> tuple[dict, list[dict]]:
    tp = fp = tn = fn = u0 = u1 = 0
    y_true = []
    y_prob = []
    per_row = []

    for r in rows:
        lbl = r.get("label")
        if lbl not in (0, 1):
            continue
        pred = detector.predict(r["text"])
        score = float(pred["score"])
        band = pred["band"]
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
            "family": r.get("family", r.get("category", "unknown")),
            "score": round(score, 6),
            "band": band,
        })

    pos_n = tp + fn + u1
    neg_n = tn + fp + u0
    n = pos_n + neg_n
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / pos_n if pos_n else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / n if n else 0.0
    fpr = fp / neg_n if neg_n else 0.0
    fnr = (fn + u1) / pos_n if pos_n else 0.0
    scam_as_legit = fn / pos_n if pos_n else 0.0
    abstention = (u0 + u1) / n if n else 0.0

    y_arr = np.asarray(y_true, dtype=int)
    p_arr = np.clip(np.asarray(y_prob, dtype=float), 1e-7, 1 - 1e-7) if n else np.asarray([], dtype=float)
    brier = float(brier_score_loss(y_arr, p_arr)) if n else None
    ll = float(log_loss(y_arr, p_arr, labels=[0, 1])) if n else None
    ece = _ece_10bin(y_arr, p_arr) if n else None

    summary = {
        "n": n,
        "negative_n": neg_n,
        "positive_n": pos_n,
        "confusion_matrix_2x3": [[tn, u0, fp], [fn, u1, tp]],
        "rows": ["LEGITIMATE(0)", "SCAM(1)"],
        "cols": ["LEGITIMATE", "UNCERTAIN", "SCAM"],
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "positive_as_legitimate_rate": round(scam_as_legit, 4),
        "abstention_rate": round(abstention, 4),
        "brier_score": round(brier, 5) if brier is not None else None,
        "log_loss": round(ll, 5) if ll is not None else None,
        "ece_10bin": round(ece, 5) if ece is not None else None,
    }
    return summary, per_row


def evaluate_ambiguous(det_v2, det_v3, rows: list[dict]) -> dict:
    v2_bands = Counter()
    v3_bands = Counter()
    items = []
    for r in rows:
        p2 = det_v2.predict(r["text"])
        p3 = det_v3.predict(r["text"])
        v2_bands[p2["band"]] += 1
        v3_bands[p3["band"]] += 1
        items.append({
            "id": r["id"],
            "language": r.get("language", "unknown"),
            "family": r.get("family", "unknown"),
            "v2_score": round(float(p2["score"]), 6),
            "v2_band": p2["band"],
            "v3_score": round(float(p3["score"]), 6),
            "v3_band": p3["band"],
            "indicators": list(detect_indicators(r["text"])),
        })
    return {
        "n": len(rows),
        "note": "Reported strictly outside binary accuracy.",
        "v2_band_counts": dict(v2_bands),
        "v3_band_counts": dict(v3_bands),
        "rows": items,
    }


def compare_pair(det_v2, det_v3, rows: list[dict]) -> dict:
    s2, r2 = evaluate_subset(det_v2, rows)
    s3, r3 = evaluate_subset(det_v3, rows)
    by_lang = {}
    langs = sorted({r.get("language", "unknown") for r in rows})
    if len(langs) > 1 or langs != ["unknown"]:
        for lang in langs:
            sub = [r for r in rows if r.get("language", "unknown") == lang]
            if sub:
                l2, _ = evaluate_subset(det_v2, sub)
                l3, _ = evaluate_subset(det_v3, sub)
                by_lang[lang] = {"v2": l2, "v3": l3}

    newly_introduced = []
    resolved = []
    both_wrong = []
    for a, b, orig in zip(r2, r3, rows):
        expected = "SCAM" if orig["label"] == 1 else "LEGITIMATE"
        v2_ok = a["band"] == expected
        v3_ok = b["band"] == expected
        rec = {
            "id": orig["id"],
            "label": orig["label"],
            "expected_band": expected,
            "language": orig.get("language", "unknown"),
            "family": orig.get("family", orig.get("group", "unknown")),
            "v2_score": a["score"],
            "v2_band": a["band"],
            "v3_score": b["score"],
            "v3_band": b["band"],
            "indicators": list(detect_indicators(orig["text"])),
        }
        if v2_ok and not v3_ok:
            newly_introduced.append(rec)
        elif not v2_ok and v3_ok:
            resolved.append(rec)
        elif not v2_ok and not v3_ok:
            both_wrong.append(rec)

    return {
        "v2": s2,
        "v3": s3,
        "by_language": by_lang,
        "paired_diff_counts": {
            "newly_introduced_errors": len(newly_introduced),
            "resolved_errors": len(resolved),
            "both_wrong_or_abstained": len(both_wrong),
        },
        "newly_introduced_errors": newly_introduced,
        "resolved_errors": resolved,
        "both_wrong_or_abstained": both_wrong[:50],
    }


def explain_v3_token_contributions(det_v3, text: str, top_k: int = 8) -> dict:
    from edgeshield.detector_v3 import canonicalize_features
    from scipy.special import expit

    canon = canonicalize_features(text)
    mat = det_v3._matrix([text])
    w_names = det_v3.word.get_feature_names_out()
    c_names = det_v3.char.get_feature_names_out()
    w_len = len(w_names)
    contribs = []
    row_csr = mat.tocsr()
    for idx, val in zip(row_csr.indices, row_csr.data):
        weight = float(det_v3.coef[idx])
        contrib = float(val * weight)
        feat = f"w:{w_names[idx]}" if idx < w_len else f"c:{c_names[idx - w_len]}"
        contribs.append((contrib, feat, float(val), weight))
    contribs_pos = sorted([c for c in contribs if c[0] > 0], reverse=True)[:top_k]
    contribs_neg = sorted([c for c in contribs if c[0] < 0])[:top_k]
    margin = float((mat @ det_v3.coef)[0]) + det_v3.intercept
    score = float(expit(det_v3.a * margin + det_v3.b))
    return {
        "canonical": canon,
        "raw_margin": round(margin, 5),
        "calibrated_score": round(score, 6),
        "top_scam_features": [{"feature": f, "contrib": round(c, 5), "coef": round(w, 4)} for c, f, _, w in contribs_pos],
        "top_legit_features": [{"feature": f, "contrib": round(c, 5), "coef": round(w, 4)} for c, f, _, w in contribs_neg],
    }


def audit_data_and_calibration(det_v2, det_v3) -> dict:
    v3_dev = read_jsonl(ROOT / "data/synthetic/v3_development.jsonl")
    v3_hold = read_jsonl(ROOT / "data/synthetic/v3_holdout.jsonl")
    v2_hold = read_jsonl(ROOT / "data/synthetic/v2_holdout.jsonl")
    ind_rows = read_jsonl(ROOT / "data/synthetic/indian_sms.jsonl")

    split_summary = {}
    for split in ("train", "calibration", "validation"):
        sub = [r for r in v3_dev if r["split"] == split]
        split_summary[split] = {
            "total": len(sub),
            "label_0": sum(r["label"] == 0 for r in sub),
            "label_1": sum(r["label"] == 1 for r in sub),
            "english": sum(r["language"] == "english" for r in sub),
            "hinglish": sum(r["language"] == "hinglish" for r in sub),
            "families": sorted({r["family"] for r in sub}),
        }

    hold_summary = {
        "total": len(v3_hold),
        "label_0": sum(r["label"] == 0 for r in v3_hold),
        "label_1": sum(r["label"] == 1 for r in v3_hold),
        "english": sum(r["language"] == "english" for r in v3_hold),
        "hinglish": sum(r["language"] == "hinglish" for r in v3_hold),
        "families": sorted({r["family"] for r in v3_hold}),
        "categories": dict(Counter(r["category"] for r in v3_hold)),
    }

    dev_fams = {r["family"] for r in v3_dev}
    hold_fams = {r["family"] for r in v3_hold}
    dev_texts = {normalize_sms(r["text"]).lower() for r in v3_dev}
    hold_texts = {normalize_sms(r["text"]).lower() for r in v3_hold}
    v2_hold_texts = {normalize_sms(r["text"]).lower() for r in v2_hold}
    ind_texts = {normalize_sms(r["text"]).lower() for r in ind_rows}

    # Check family overlaps across dev splits
    split_fams = {s: {r["family"] for r in v3_dev if r["split"] == s} for s in ("train", "calibration", "validation")}
    cross_split_fam_overlap = {
        f"{a}_vs_{b}": sorted(split_fams[a] & split_fams[b])
        for i, a in enumerate(("train", "calibration", "validation"))
        for b in ("train", "calibration", "validation")[i + 1:]
    }

    # Check group_near_duplicates across dev + holdout
    near_dups = group_near_duplicates(v3_dev + v3_hold)
    near_map = {}
    cross_dev_hold_near = []
    for row, g in zip(v3_dev + v3_hold, near_dups):
        origin = "holdout" if row in v3_hold else f"dev:{row['split']}"
        if g in near_map and near_map[g] != origin:
            cross_dev_hold_near.append((g, near_map[g], origin, row["id"]))
        near_map[g] = origin

    v2_art = json.loads((ROOT / "models/detector_v2.json").read_text(encoding="utf-8"))
    v3_art = json.loads((ROOT / "models/detector_v3.json").read_text(encoding="utf-8"))

    # Inspect V3 calibration & threshold selection artifacts
    tv3 = json.loads((ROOT / "results/host/v3/training_validation.json").read_text(encoding="utf-8"))
    selected_cand = next(
        c for c in tv3["candidates"]
        if c["C"] == 4 and c["synthetic_weight"] == 2
    )

    return {
        "model_artifacts": {
            "v1": {
                "path": "models/detector.json",
                "sha256": digest(ROOT / "models/detector.json"),
                "sidecar": (ROOT / "models/detector.json.sha256").read_text(encoding="ascii").strip(),
            },
            "v2": {
                "path": "models/detector_v2.json",
                "sha256": digest(ROOT / "models/detector_v2.json"),
                "sidecar": (ROOT / "models/detector_v2.json.sha256").read_text(encoding="ascii").strip(),
                "calibration": v2_art["calibration"],
                "thresholds": v2_art["thresholds"],
                "intercept": v2_art["intercept"],
                "vocab_word": len(v2_art["word"]["vocabulary"]),
                "vocab_char": len(v2_art["char"]["vocabulary"]),
            },
            "v3": {
                "path": "models/detector_v3.json",
                "sha256": digest(ROOT / "models/detector_v3.json"),
                "sidecar": (ROOT / "models/detector_v3.json.sha256").read_text(encoding="ascii").strip(),
                "calibration": v3_art["calibration"],
                "thresholds": v3_art["thresholds"],
                "intercept": v3_art["intercept"],
                "vocab_word": len(v3_art["word"]["vocabulary"]),
                "vocab_char": len(v3_art["char"]["vocabulary"]),
                "selection_hyperparams": {"C": 4, "synthetic_weight": 2},
                "calibration_method": "Balanced logistic sigmoid (Platt scaling) on calibration split margins",
                "validation_metrics_at_selection": selected_cand["metrics"],
                "validation_calibration_comparison": selected_cand["calibration_comparison"],
            },
        },
        "v3_development_splits": split_summary,
        "v3_holdout_summary": hold_summary,
        "separation_checks": {
            "dev_vs_holdout_family_overlap": sorted(dev_fams & hold_fams),
            "dev_vs_dev_cross_split_family_overlap": cross_split_fam_overlap,
            "dev_vs_holdout_exact_text_overlap": len(dev_texts & hold_texts),
            "dev_vs_v2_holdout_exact_text_overlap": len(dev_texts & v2_hold_texts),
            "dev_vs_indian_sms_exact_text_overlap": len(dev_texts & ind_texts),
            "near_duplicate_cross_split_or_holdout": cross_dev_hold_near,
            "has_family_impersonation_in_v3_dev": any("family" in f for f in dev_fams),
            "has_antifraud_advisory_in_v3_dev": any("advis" in f or "anti_fraud" in f or "antifraud" in f for f in dev_fams),
        },
        "failure_mode_feature_attribution": {
            "legit_antifraud_en": explain_v3_token_contributions(
                det_v3,
                "Bank Security Advisory: Fraudsters send fake account block and KYC update links. Never share your OTP, PIN, or CVV with anyone.",
            ),
            "legit_antifraud_hi": explain_v3_token_contributions(
                det_v3,
                "Cyber thag nakli KYC block link bhejte hain. Apna OTP ya MPIN kisi ke saath share mat karo.",
            ),
            "scam_family_impersonation_en": explain_v3_token_contributions(
                det_v3,
                "Hi Mom, my phone broke and I am texting from a new number. Please send Rs. 4500 urgently via UPI, I will pay you back tonight.",
            ),
            "scam_family_impersonation_hi": explain_v3_token_contributions(
                det_v3,
                "Papa mera phone gir gaya hai, yeh mera naya number hai. Please turant 5000 rs is UPI ID par bhej do, bahut urgent hai.",
            ),
        },
    }


def main():
    det_v2 = load_detector(ROOT / "models/detector_v2.json")
    det_v3 = load_detector(ROOT / "models/detector_v3.json")

    v2_holdout_all = read_jsonl(ROOT / "data/synthetic/v2_holdout.jsonl")
    v2_holdout_labeled = [r for r in v2_holdout_all if r.get("label") in (0, 1)]
    v2_holdout_ambiguous = [r for r in v2_holdout_all if r.get("label") is None]
    v3_holdout = read_jsonl(ROOT / "data/synthetic/v3_holdout.jsonl")
    uci_test = read_jsonl(ROOT / "data/processed/test.jsonl")
    indian_all = read_jsonl(ROOT / "data/synthetic/indian_sms.jsonl")
    indian_test_labeled = [r for r in indian_all if r.get("split") == "test" and r.get("label") in (0, 1)]
    indian_dev_labeled = [r for r in indian_all if r.get("split") == "development" and r.get("label") in (0, 1)]
    indian_ambiguous = [r for r in indian_all if r.get("label") is None]

    # Verify dataset leakage check runs cleanly across dev splits and holdout
    check_leakage(
        [dict(r, split="holdout") for r in v3_holdout]
        + read_jsonl(ROOT / "data/synthetic/v3_development.jsonl")
    )

    fresh_rows = []
    for fid, lbl, lang, cat, text in FRESH_DIAGNOSTIC_CASES:
        p2 = det_v2.predict(text)
        p3 = det_v3.predict(text)
        inds = detect_indicators(text)
        fresh_rows.append({
            "id": fid,
            "label": lbl,
            "language": lang,
            "category": cat,
            "v2_score": round(float(p2["score"]), 6),
            "v2_band": p2["band"],
            "v3_score": round(float(p3["score"]), 6),
            "v3_band": p3["band"],
            "repaired_indicators": list(inds),
        })

    pi6_rows = []
    for fid, lbl, text in PI_SIX_PROXY_CASES:
        p2 = det_v2.predict(text)
        p3 = det_v3.predict(text)
        inds = detect_indicators(text)
        pi6_rows.append({
            "id": fid,
            "label": lbl,
            "v2_score": round(float(p2["score"]), 6),
            "v2_band": p2["band"],
            "v3_score": round(float(p3["score"]), 6),
            "v3_band": p3["band"],
            "repaired_indicators": list(inds),
        })

    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Point 3 & Point 4 identical-row V2 vs V3 audit; synthetic metrics do NOT measure real-world prevalence.",
        "data_and_calibration_audit": audit_data_and_calibration(det_v2, det_v3),
        "identical_row_comparisons": {
            "v2_holdout_labeled_120": compare_pair(det_v2, det_v3, v2_holdout_labeled),
            "v2_holdout_ambiguous_12": evaluate_ambiguous(det_v2, det_v3, v2_holdout_ambiguous),
            "v3_holdout_160": compare_pair(det_v2, det_v3, v3_holdout),
            "uci_test_1148": compare_pair(det_v2, det_v3, uci_test),
            "indian_sms_test_labeled_24": compare_pair(det_v2, det_v3, indian_test_labeled),
            "indian_sms_dev_labeled_8": compare_pair(det_v2, det_v3, indian_dev_labeled),
            "indian_sms_ambiguous_4": evaluate_ambiguous(det_v2, det_v3, indian_ambiguous),
            "stress_test_54_status": "NOT_FOUND_IN_REPO_OR_GIT_HISTORY (verified only 36-row indian_sms.jsonl exists)",
        },
        "separate_fresh_diagnostic_cases": {
            "note": "Reported strictly outside holdout accuracy.",
            "n": len(fresh_rows),
            "rows": fresh_rows,
        },
        "pi_six_proxy_diagnostic_cases": {
            "note": "Representative reconstructs matching original 6 Pi 5 categories; never used in training.",
            "n": len(pi6_rows),
            "rows": pi6_rows,
        },
    }

    out_path = ROOT / "results/host/v3/full_v2_v3_regression_audit.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    # Compact console summary
    for key in ("v2_holdout_labeled_120", "v3_holdout_160", "uci_test_1148", "indian_sms_test_labeled_24"):
        comp = report["identical_row_comparisons"][key]
        print(f"=== {key} ===")
        print(f"  V2 cm2x3={comp['v2']['confusion_matrix_2x3']} acc={comp['v2']['accuracy']} rec={comp['v2']['recall']} fpr={comp['v2']['false_positive_rate']} brier={comp['v2']['brier_score']} ece={comp['v2']['ece_10bin']}")
        print(f"  V3 cm2x3={comp['v3']['confusion_matrix_2x3']} acc={comp['v3']['accuracy']} rec={comp['v3']['recall']} fpr={comp['v3']['false_positive_rate']} brier={comp['v3']['brier_score']} ece={comp['v3']['ece_10bin']}")
        print(f"  paired_diff={comp['paired_diff_counts']}")
    print("Audit written to", out_path.relative_to(ROOT))


if __name__ == "__main__":
    main()
