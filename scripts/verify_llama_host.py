"""Run real ExecuTorch host generation on structured evidence, never SMS.

Run with the separate export environment (build/executorch/.venv) after the
model has been exported. This is a HOST diagnostic: it does not replace the
bounded application adapter and does not establish Raspberry Pi compatibility.
Its inputs are closed-schema Evidence objects (band, score, indicator IDs); its
output contains model text generated only from that evidence.

Suites:
  smoke     three fixed evidence fixtures (original Codex diagnostic)
  evidence  every distinct evidence object in a JSON file produced by
            scripts/export_evidence_fixtures.py (no message text inside)
"""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import platform
import statistics
import sys
import time

END_TOKENS = ("<|eot_id|>", "<|end_of_text|>")


def load_runtime():
    # The pip-installed ExecuTorch uses a shared libexecutorch.so registry. The
    # XNNPACK delegate, optimized/quantized kernels and LLM custom ops register
    # themselves only when their libraries are loaded. _llm_runner does not load
    # them itself; without these imports loading fails with
    # "Backend XnnpackBackend is not registered" (observed 17 Nov 2026).
    from executorch.extension.pybindings import portable_lib  # noqa: F401
    import executorch.kernels.quantized  # noqa: F401
    from executorch.extension.llm.custom_ops import custom_ops  # noqa: F401
    from executorch.extension.llm.runner import GenerationConfig, TextLLMRunner
    return GenerationConfig, TextLLMRunner


def strip_terminal(text):
    text = text.strip()
    for ending in END_TOKENS:
        if text.endswith(ending):
            text = text[: -len(ending)].strip()
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--tokenizer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--suite", choices=("smoke", "evidence"), default="smoke")
    parser.add_argument("--evidence", type=Path, help="Evidence JSON for --suite evidence")
    parser.add_argument("--max-new-tokens", type=int, default=48)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("This diagnostic is exclusively for the Linux x86_64 host")
    if args.output.exists():
        parser.error("Output already exists; preserve prior results with a new filename")
    if not args.model.is_file() or not args.tokenizer.is_file():
        parser.error("Real exported model and matching tokenizer are required")
    if args.suite == "evidence" and (args.evidence is None or not args.evidence.is_file()):
        parser.error("--suite evidence requires --evidence FILE")

    # Explicit local source import, without importing the host detector environment.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from edgeshield.evidence import Evidence
    from edgeshield.validator import build_prompt, fallback, validate_explanation
    GenerationConfig, TextLLMRunner = load_runtime()

    if args.suite == "smoke":
        fixtures = [
            Evidence("SCAM", 0.95, ("OTP_REQUEST", "LINK_PRESENT")),
            Evidence("LEGITIMATE", 0.05, ()),
            Evidence("UNCERTAIN", 0.50, ("URGENCY",)),
        ]
        weights = [1, 1, 1]
    else:
        data = json.loads(args.evidence.read_text(encoding="utf-8"))
        groups = {}
        for row in data["cases"]:
            ev = Evidence(row["band"], round(row["score"], 3), tuple(row["indicators"]))
            groups[ev] = groups.get(ev, 0) + 1
        fixtures, weights = list(groups), list(groups.values())

    started = time.perf_counter()
    runner = TextLLMRunner(str(args.model.resolve()), str(args.tokenizer.resolve()))
    construct_ms = (time.perf_counter() - started) * 1000
    rows = []
    for index, evidence in enumerate(fixtures):
        prompt = build_prompt(evidence)
        pieces, stats = [], {}

        def capture_stats(value):
            for key in ("num_prompt_tokens", "num_generated_tokens", "model_load_start_ms",
                        "model_load_end_ms", "inference_start_ms", "inference_end_ms",
                        "prompt_eval_end_ms", "first_token_ms"):
                if hasattr(value, key):
                    stats[key] = getattr(value, key)

        runner.reset()  # independent cases: no KV state carried between prompts
        t0 = time.perf_counter()
        runner.generate(prompt, GenerationConfig(echo=False, max_new_tokens=args.max_new_tokens,
                                                 temperature=0.0), pieces.append, capture_stats)
        wall = (time.perf_counter() - t0) * 1000
        raw = "".join(pieces)
        generated = strip_terminal(raw)
        accepted, reason = validate_explanation(generated, evidence)
        rows.append({"evidence": asdict(evidence), "weight": weights[index],
                     "raw_generated_text": raw, "generated_text": generated,
                     "validator_accepted": accepted, "validator_reason": reason,
                     "matches_template_fallback": generated == fallback(evidence),
                     "generate_wall_ms": wall, "stats": stats})
    # Determinism check: re-run the first case after reset and compare.
    runner.reset()
    pieces = []
    runner.generate(build_prompt(fixtures[0]), GenerationConfig(echo=False, max_new_tokens=args.max_new_tokens,
                                                               temperature=0.0), pieces.append, lambda s: None)
    deterministic = strip_terminal("".join(pieces)) == rows[0]["generated_text"]
    del runner

    walls = [r["generate_wall_ms"] for r in rows]
    weighted_accept = sum(r["weight"] for r in rows if r["validator_accepted"])
    total_weight = sum(weights)
    reasons = {}
    for r in rows:
        reasons[r["validator_reason"]] = reasons.get(r["validator_reason"], 0) + r["weight"]
    report = {
        "kind": "GENUINE_EXECUTORCH_HOST_RUN",
        "suite": args.suite,
        "machine": platform.machine(),
        "platform": platform.platform(),
        "model": str(args.model.resolve()),
        "runner": "executorch.extension.llm.runner.TextLLMRunner (pybind, persistent, reset per case)",
        "runner_construct_ms": construct_ms,
        "distinct_evidence_cases": len(rows),
        "weighted_cases": total_weight,
        "validator_accepted_distinct": sum(r["validator_accepted"] for r in rows),
        "validator_accepted_weighted": weighted_accept,
        "validator_reasons_weighted": reasons,
        "llama_choice_equals_template_weighted": sum(r["weight"] for r in rows if r["matches_template_fallback"]),
        "deterministic_rerun_first_case": deterministic,
        "generate_wall_ms": {"median": statistics.median(walls), "max": max(walls), "min": min(walls)},
        "cases": rows,
        "pi_status": "PENDING_HARDWARE",
        "scope": "Structured evidence only; host diagnostic, not app adapter, not quality or Pi evaluation",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
    print(f"Real generation finished; validator accepted {sum(r['validator_accepted'] for r in rows)}/{len(rows)} "
          f"distinct cases ({weighted_accept}/{total_weight} weighted); deterministic={deterministic}")


if __name__ == "__main__":
    main()
