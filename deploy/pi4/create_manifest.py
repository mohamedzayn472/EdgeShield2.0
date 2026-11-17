"""Record real local assets, never create weights or claim successful inference."""
import argparse
import hashlib
import json
from pathlib import Path
import os

REVISION = "985c1ceccc8bb8b6a32294f71aeb5d2f299562f7"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--runner", type=Path, required=True)
    p.add_argument("--model", type=Path, required=True)
    p.add_argument("--tokenizer", type=Path, required=True)
    p.add_argument("--library", type=Path, action="append", default=[])
    p.add_argument("--arch", choices=["aarch64", "x86_64"], required=True)
    p.add_argument("--output", type=Path, default=Path("configs/inference.json"))
    p.add_argument("--force", action="store_true", help="Overwrite an existing output manifest")
    args = p.parse_args()
    if args.model.suffix != ".pte" or args.tokenizer.name != "tokenizer.model":
        p.error("Expected exported .pte and matching Meta tokenizer.model; renaming formats does not convert them")
    if args.output.exists() and not args.force:
        p.error(f"Output already exists: {args.output}. Pass --force to overwrite.")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    def record(path):
        if not path.is_file() or not path.stat().st_size:
            p.error("A required nonempty artifact is missing")
        h = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(block)
        return {"path": os.path.relpath(path.resolve(), args.output.parent.resolve()).replace("\\", "/"), "sha256": h.hexdigest()}
    config = {"schema_version": 1, "executorch_revision": REVISION, "target_arch": args.arch,
              "model_family": "Llama-3.2-1B-Instruct", "tokenizer_format": "tiktoken_model",
              "seq_len": 768, "max_new_tokens": 48, "cpu_threads": 2,
              "timeout_seconds": 120, "max_output_bytes": 65536, "stdout_mode": "prompt_echo",
              "artifacts": {"runner": record(args.runner), "model": record(args.model),
                            "tokenizer": record(args.tokenizer), "shared_libraries": [record(x) for x in args.library]}}
    mode = "w" if args.force else "x"
    with args.output.open(mode, encoding="utf-8") as stream:
        json.dump(config, stream, indent=2)
    print("Manifest recorded. Confirm assets came from pinned export/build; hashing does not prove compatibility or provenance.")


if __name__ == "__main__":
    main()
