"""Clone a Pi 5 runtime manifest in the same directory changing only cpu_threads."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

EXPECTED_KEYS = {
    "schema_version",
    "executorch_revision",
    "target_arch",
    "model_family",
    "tokenizer_format",
    "seq_len",
    "timeout_seconds",
    "max_output_bytes",
    "artifacts",
    "stdout_mode",
    "max_new_tokens",
    "cpu_threads",
}
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base", type=Path, default=Path("configs/inference.json"), help="Base runtime manifest path")
    p.add_argument("--name", required=True, help="Trial manifest name suffix (writes trial-pi5-<name>.json)")
    p.add_argument("--cpu-threads", type=int, required=True, help="cpu_threads value (1..4)")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not _NAME_RE.fullmatch(args.name):
        parser.error("--name must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")
    if not 1 <= args.cpu_threads <= 4:
        parser.error("--cpu-threads must be between 1 and 4")
    if not args.base.is_file():
        print(f"Base manifest not found: {args.base}", file=sys.stderr)
        return 2

    try:
        base_data = json.loads(args.base.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"Failed to read base manifest {args.base}: {exc}", file=sys.stderr)
        return 2

    if not isinstance(base_data, dict) or set(base_data) != EXPECTED_KEYS or base_data.get("schema_version") != 1:
        print(f"Invalid base manifest schema in {args.base}", file=sys.stderr)
        return 2
    if not isinstance(base_data.get("artifacts"), dict):
        print(f"Invalid artifacts section in {args.base}", file=sys.stderr)
        return 2

    out_path = args.base.parent / f"trial-pi5-{args.name}.json"
    if out_path.resolve() == args.base.resolve():
        print(f"Refusing to overwrite base manifest: {out_path}", file=sys.stderr)
        return 2
    if out_path.exists():
        print(f"Refusing to overwrite existing manifest: {out_path}", file=sys.stderr)
        return 2

    cloned = copy.deepcopy(base_data)
    cloned["cpu_threads"] = args.cpu_threads
    if cloned["artifacts"] != base_data["artifacts"]:
        print("Internal error: artifact entries diverged", file=sys.stderr)
        return 2
    if {k: v for k, v in cloned.items() if k != "cpu_threads"} != {
        k: v for k, v in base_data.items() if k != "cpu_threads"
    }:
        print("Internal error: non-cpu_threads fields diverged", file=sys.stderr)
        return 2

    serialized = json.dumps(cloned, indent=2) + "\n"
    try:
        with out_path.open("x", encoding="utf-8") as handle:
            handle.write(serialized)
    except FileExistsError:
        print(f"Refusing to overwrite existing manifest: {out_path}", file=sys.stderr)
        return 2

    written_bytes = out_path.read_bytes()
    written_data = json.loads(written_bytes.decode("utf-8"))
    assert written_data["artifacts"] == base_data["artifacts"]
    assert written_data["cpu_threads"] == args.cpu_threads
    assert {k: v for k, v in written_data.items() if k != "cpu_threads"} == {
        k: v for k, v in base_data.items() if k != "cpu_threads"
    }

    digest = _sha256_bytes(written_bytes)
    print(f"{digest}  {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
