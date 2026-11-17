"""Record Pi 5 runtime assets into configs/inference.json; never claim hardware inference."""
import argparse
import hashlib
import json
import os
from pathlib import Path

REVISION = "985c1ceccc8bb8b6a32294f71aeb5d2f299562f7"
ROOT = Path(__file__).resolve().parents[2]

PROFILES = {
    "pi5": {
        "runner": Path("models/llama/pi5-aarch64/llama_main"),
        "library": Path("models/llama/pi5-aarch64/libllama_runner.so"),
        "description": "Dedicated Pi 5 Cortex-A76 runtime (GLIBC <= 2.34, Bookworm & Trixie compatible)",
    },
    "pi5-glibc238": {
        "runner": Path("models/llama/pi5-aarch64-glibc238/llama_main"),
        "library": Path("models/llama/pi5-aarch64-glibc238/libllama_runner.so"),
        "description": "Dedicated Pi 5 Cortex-A76 runtime with KleidiAI (GLIBC <= 2.38, Trixie/Ubuntu 24.04+)",
    },
    "pi4-on-pi5": {
        "runner": Path("models/llama/pi4-aarch64/llama_main"),
        "library": Path("models/llama/pi4-aarch64/libllama_runner.so"),
        "description": "Pi 4-built Cortex-A72 runtime reused on Pi 5 for baseline/initial validation (GLIBC <= 2.34)",
    },
}


def _resolve_default(rel_path: Path) -> Path:
    if rel_path.exists():
        return rel_path
    candidate = ROOT / rel_path
    return candidate if candidate.exists() else rel_path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--profile",
        choices=tuple(PROFILES),
        default="pi5",
        help="Runtime binary profile (default: pi5). Ignored for runner/library when explicitly overridden.",
    )
    p.add_argument("--runner", type=Path, help="Path to llama_main executable")
    p.add_argument("--model", type=Path, default=_resolve_default(Path("models/llama/llama3_2.pte")))
    p.add_argument("--tokenizer", type=Path, default=_resolve_default(Path("models/llama/tokenizer.model")))
    p.add_argument("--library", type=Path, action="append", default=[], help="Required shared library (repeatable)")
    p.add_argument("--arch", choices=["aarch64", "x86_64"], default="aarch64")
    p.add_argument("--cpu-threads", type=int, default=2)
    p.add_argument("--timeout-seconds", type=int, default=120)
    p.add_argument("--output", type=Path, default=Path("configs/inference.json"))
    p.add_argument("--force", action="store_true", help="Overwrite an existing output manifest")
    return p


def main(argv=None):
    p = build_parser()
    args = p.parse_args(argv)
    if not 1 <= args.cpu_threads <= 4:
        p.error("--cpu-threads must be between 1 and 4")
    if not 1 <= args.timeout_seconds <= 300:
        p.error("--timeout-seconds must be between 1 and 300")
    if args.model.suffix != ".pte" or args.tokenizer.name != "tokenizer.model":
        p.error("Expected exported .pte and matching Meta tokenizer.model; renaming formats does not convert them")
    if args.output.exists() and not args.force:
        p.error(f"Output already exists: {args.output}. Pass --force to overwrite.")

    profile = PROFILES[args.profile]
    runner = args.runner if args.runner is not None else _resolve_default(profile["runner"])
    libraries = args.library if args.library else [_resolve_default(profile["library"])]

    args.output.parent.mkdir(parents=True, exist_ok=True)

    def record(path: Path) -> dict[str, str]:
        if not path.is_file() or not path.stat().st_size:
            p.error(f"A required nonempty artifact is missing: {path}")
        return {
            "path": os.path.relpath(path.resolve(), args.output.parent.resolve()).replace("\\", "/"),
            "sha256": _sha256(path),
        }

    config = {
        "schema_version": 1,
        "executorch_revision": REVISION,
        "target_arch": args.arch,
        "model_family": "Llama-3.2-1B-Instruct",
        "tokenizer_format": "tiktoken_model",
        "seq_len": 768,
        "max_new_tokens": 48,
        "cpu_threads": args.cpu_threads,
        "timeout_seconds": args.timeout_seconds,
        "max_output_bytes": 65536,
        "stdout_mode": "prompt_echo",
        "artifacts": {
            "runner": record(runner),
            "model": record(args.model),
            "tokenizer": record(args.tokenizer),
            "shared_libraries": [record(x) for x in libraries],
        },
    }
    mode = "w" if args.force else "x"
    with args.output.open(mode, encoding="utf-8") as stream:
        json.dump(config, stream, indent=2)
    print(
        f"Manifest recorded for profile '{args.profile}' ({profile['description']}). "
        "Confirm assets came from pinned export/build; hashing does not prove hardware compatibility."
    )


if __name__ == "__main__":
    main()
