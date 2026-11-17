"""Measure startup, loader cache, preprocessing, policy, memory, and CPU-thread trade-offs on Ubuntu host.

All measurements produced by this script are UBUNTU HOST measurements; never report them as
Raspberry Pi 4 performance.
"""
import argparse
import json
from pathlib import Path
import platform
import re
import resource
import statistics
import subprocess
import sys
import tempfile
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from edgeshield.advisory import ExecuTorchAdvisor  # noqa: E402
from edgeshield.benchmarking import FIXTURES, distribution, runtime_measurements  # noqa: E402
from edgeshield.datasets import read_jsonl  # noqa: E402
from edgeshield.indicators import detect_indicators  # noqa: E402
from edgeshield.model_loader import _CACHE, load_detector  # noqa: E402
from edgeshield.pipeline import ADVISORY_POLICIES, assess, explain, should_run_advisor  # noqa: E402


def measure_cold_cli_startup(detector_path: Path) -> dict:
    """Spawn a clean subprocess to measure cold Python import + detector load + single assess."""
    samples = []
    max_rss_bytes = []
    for _ in range(5):
        t0 = perf_counter()
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import resource; "
                    "from edgeshield.model_loader import load_detector; "
                    "from edgeshield.pipeline import assess; "
                    f"d = load_detector({str(detector_path)!r}); "
                    "assess('Your OTP is 000000. Do not share your OTP.', d); "
                    "print(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024)"
                ),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        samples.append((perf_counter() - t0) * 1000)
        max_rss_bytes.append(int(proc.stdout.strip().splitlines()[-1]))
    return {
        "cold_subprocess_wall_ms": distribution(samples),
        "cold_subprocess_peak_rss_bytes": distribution(max_rss_bytes),
    }


def measure_loader_and_preprocessing(detector_path: Path) -> dict:
    _CACHE.clear()
    t0 = perf_counter()
    detector = load_detector(detector_path)
    cold_load_ms = (perf_counter() - t0) * 1000

    hit_ms = []
    for _ in range(10):
        t0 = perf_counter()
        load_detector(detector_path)
        hit_ms.append((perf_counter() - t0) * 1000)

    holdout_texts = [row["text"] for row in read_jsonl(ROOT / "data/synthetic/v2_holdout.jsonl")]
    ind_per_msg_ms = []
    assess_per_msg_ms = []
    for _ in range(10):
        t0 = perf_counter()
        for text in holdout_texts:
            detect_indicators(text)
        ind_per_msg_ms.append(((perf_counter() - t0) * 1000) / len(holdout_texts))

        t0 = perf_counter()
        for text in holdout_texts:
            assess(text, detector)
        assess_per_msg_ms.append(((perf_counter() - t0) * 1000) / len(holdout_texts))

    return {
        "cold_load_ms": cold_load_ms,
        "cached_load_with_sha256_verify_ms": distribution(hit_ms),
        "indicators_per_message_ms_over_holdout": distribution(ind_per_msg_ms),
        "assess_per_message_ms_over_holdout": distribution(assess_per_msg_ms),
        "holdout_message_count": len(holdout_texts),
    }


def measure_policy_rates(detector_path: Path) -> dict:
    detector = load_detector(detector_path)
    rows = read_jsonl(ROOT / "data/synthetic/v2_holdout.jsonl")
    assessments = [assess(row["text"], detector) for row in rows]
    summary = {}
    for policy in ADVISORY_POLICIES:
        invoked = sum(should_run_advisor(a.evidence, policy) for a in assessments)
        summary[policy] = {
            "invoked_count": invoked,
            "total_count": len(assessments),
            "invocation_rate": invoked / len(assessments),
            "skipped_rate": 1.0 - (invoked / len(assessments)),
        }
    return summary


def measure_child_llama_rss(runtime_config: Path) -> dict | None:
    """Measure one real llama_main child process peak RSS with GNU time -v."""
    cfg = json.loads(runtime_config.read_text(encoding="utf-8"))
    base = runtime_config.parent.resolve()
    runner = (base / cfg["artifacts"]["runner"]["path"]).resolve()
    model = (base / cfg["artifacts"]["model"]["path"]).resolve()
    tokenizer = (base / cfg["artifacts"]["tokenizer"]["path"]).resolve()
    libs = [str((base / item["path"]).resolve().parent) for item in cfg["artifacts"]["shared_libraries"]]
    env = {"PATH": "/usr/bin:/bin"}
    if libs:
        env["LD_LIBRARY_PATH"] = ":".join(sorted(set(libs)))
    prompt = (
        "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
        "Output WHY: The detector is uncertain.<|eot_id|>"
        "<|start_header_id|>user<|end_header_id|>\n\nWHY: The detector is uncertain.<|eot_id|>"
        "<|start_header_id|>assistant<|end_header_id|>\n\n"
    )
    proc = subprocess.run(
        [
            "/usr/bin/time",
            "-v",
            str(runner),
            "--model_path",
            str(model),
            "--tokenizer_path",
            str(tokenizer),
            "--seq_len",
            str(cfg["seq_len"]),
            "--max_new_tokens",
            str(cfg["max_new_tokens"]),
            "--cpu_threads",
            str(cfg["cpu_threads"]),
            "--temperature",
            "0",
            "--prompt",
            prompt,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", proc.stderr)
    return {
        "returncode": proc.returncode,
        "child_peak_rss_kib": int(match.group(1)) if match else None,
        "child_peak_rss_mib": (int(match.group(1)) / 1024.0) if match else None,
    }


def measure_thread_scaling(runtime_config: Path, detector_path: Path, threads: tuple[int, ...], reps: int) -> dict:
    detector = load_detector(detector_path)
    base_cfg = json.loads(runtime_config.read_text(encoding="utf-8"))
    base_dir = runtime_config.resolve().parent
    # Rewrite artifact paths relative to the temp config directory.
    def absolutize(item):
        return {"path": str((base_dir / item["path"]).resolve()), "sha256": item["sha256"]}

    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        for t in threads:
            cfg = dict(base_cfg)
            cfg["cpu_threads"] = t
            cfg["artifacts"] = {
                "runner": absolutize(base_cfg["artifacts"]["runner"]),
                "model": absolutize(base_cfg["artifacts"]["model"]),
                "tokenizer": absolutize(base_cfg["artifacts"]["tokenizer"]),
                "shared_libraries": [absolutize(x) for x in base_cfg["artifacts"]["shared_libraries"]],
            }
            tmp_cfg = Path(tmp) / f"cfg_t{t}.json"
            tmp_cfg.write_text(json.dumps(cfg), encoding="utf-8")
            advisor = ExecuTorchAdvisor(tmp_cfg)
            # 1 warmup call (excluded from distribution) to populate OS page cache equally across thread counts.
            warm = assess(FIXTURES[0], detector)
            explain(warm.evidence, advisor)

            samples = []
            for i in range(reps):
                a = assess(FIXTURES[i % len(FIXTURES)], detector)
                exp = explain(a.evidence, advisor)
                rt = runtime_measurements(advisor.last_stats)
                samples.append({
                    "llama_ms": exp.llama_ms,
                    "source": exp.source,
                    "reason": exp.reason,
                    **rt,
                })
            results[str(t)] = {
                "cpu_threads": t,
                "repetitions": reps,
                "llama_validated_count": sum(s["source"] == "Llama (validated)" for s in samples),
                "llama_ms": distribution([s["llama_ms"] for s in samples]),
                "model_load_ms": distribution([s["model_load_ms"] for s in samples]),
                "prefill_ms": distribution([s["prefill_ms"] for s in samples]),
                "time_to_first_token_ms": distribution([s["time_to_first_token_ms"] for s in samples]),
                "decode_tokens_per_second": distribution([s["decode_tokens_per_second"] for s in samples]),
            }
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--detector", type=Path, default=ROOT / "models/detector_v2.json")
    p.add_argument("--runtime-config", type=Path, required=True)
    p.add_argument("--thread-reps", type=int, default=5)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error("Output exists; preserve prior results")

    report = {
        "kind": "UBUNTU_HOST_OPTIMIZATION_STUDY",
        "hardware_verified_pi4": False,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "detector": str(args.detector),
        "cold_cli_startup": measure_cold_cli_startup(args.detector),
        "loader_and_preprocessing": measure_loader_and_preprocessing(args.detector),
        "advisory_policy_holdout_rates": measure_policy_rates(args.detector),
        "llama_child_memory": measure_child_llama_rss(args.runtime_config),
        "cpu_thread_scaling": measure_thread_scaling(args.runtime_config, args.detector, (1, 2, 4), args.thread_reps),
        "parent_peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Wrote optimization study to {args.output}")


if __name__ == "__main__":
    main()
