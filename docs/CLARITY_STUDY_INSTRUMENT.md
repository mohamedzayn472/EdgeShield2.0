# Five-Person Clarity Study Instrument & Protocol

**Status:** `PENDING_PARTICIPANTS` (protocol and anonymized stimulus sheet prepared; **0 human responses collected** — no scores fabricated).

Follows [docs/BENCHMARKS.md](BENCHMARKS.md) § "Five-person clarity study".

---

## 1. Study Rules & Privacy Constraints

1. **Participants:** Recruit 5 consenting adults (no minors, no team model authors). Record only anonymized participant IDs (`P1`–`P5`); collect no private SMS, phone numbers, or personally identifying details.
2. **Stimuli:** Use fixed synthetic examples only (drawn from the frozen 20-case comparison IDs in `results/host/ubuntu/twenty_case_llama_vs_template.json` or `docs/DEMO_SCRIPT.md`).
3. **Blinding & Randomization:** Show the two explanation styles (`Template fallback` vs `Llama (validated)`) side-by-side as **Option A** and **Option B** with randomized A/B assignment per item and **without disclosing which source generated each line**. Do not coach participants to prefer Llama.
4. **Honest Reporting:** Record exact wording shown, order, missing answers, per-item counts, medians, and qualitative misunderstandings. Five convenience participants do not establish population-level usability.

---

## 2. Standard Participant Prompt & Questions

For each stimulus item:

> **Message shown:** *(Synthetic example text for the chosen Case ID)*  
> **Detector band:** `SCAM` / `UNCERTAIN` / `LEGITIMATE`  
> **Advice shown:** *(Application `DO:` recommendation)*  
>
> **Explanation A:** `<WHY line 1>`  
> **Explanation B:** `<WHY line 2>`  

Ask the participant to answer for **each explanation (A and B)** on a **1–5 Likert scale** (`1 = very poor`, `5 = very clear/helpful`):

1. **Clarity (1–5):** How clear and easy to understand is this explanation?
2. **Usefulness (1–5):** How helpful is it for deciding what to do next?
3. **Uncertainty communication (1–5):** How well does it communicate that the estimate is not guaranteed / does not prove sender identity?
4. **Action check (free response):** What action would you take after reading this screen?
5. **Preference (A / B / No preference):** Which explanation did you find clearer, and why?

---

## 3. Recommended 6-Item Synthetic Subset (from Frozen 20-Case Set)

Use these 6 diverse frozen IDs from `data/synthetic/v2_holdout.jsonl` (covering normal notice, English scams, Hinglish, and ambiguous cases):

| Item | Holdout ID | Slice | Detector Band | Notes for Facilitator |
|---:|---|---|---|---|
| 1 | `v2h001` | Normal English receipt | `LEGITIMATE` | Check whether user understands "does not authenticate sender" |
| 2 | `v2h003` | Normal English OTP notice | `LEGITIMATE` | Observe reaction to benign OTP wording |
| 3 | `v2h031` | English bank/OTP scam | `SCAM` | Observe whether `WHY:` + `DO:` motivates independent verification |
| 4 | `v2h045` | English KYC pressure scam | `SCAM` | Check comprehension of identity verification cue |
| 5 | `v2h091` | Hinglish bank hold OTP scam | `SCAM` or `LEGITIMATE` | Note detector misclassification honestly if showing raw V2 output |
| 6 | `v2h121` | Ambiguous English case | `LEGITIMATE` / `UNCERTAIN` | Check whether uncertainty/limitation warning prevents blind trust |

---

## 4. Anonymized Recording Sheet (`PENDING_PARTICIPANTS`)

| Participant ID | Consent Recorded | Item ID | Order (`T/L` or `L/T`) | Clarity A/B (1–5) | Usefulness A/B (1–5) | Uncertainty A/B (1–5) | Stated Action | Preference & Notes |
|---|---|---|---|---|---|---|---|---|
| `P1` | `[ ]` | | | | | | | |
| `P2` | `[ ]` | | | | | | | |
| `P3` | `[ ]` | | | | | | | |
| `P4` | `[ ]` | | | | | | | |
| `P5` | `[ ]` | | | | | | | |

*Do not summarize participant scores in the report or slides until at least 5 completed sheets are recorded and stored under `results/` without personal identifiers.*
