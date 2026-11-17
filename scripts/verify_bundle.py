"""Verify transferred bundle and optional private runtime files against trusted manifests."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath


def _verify_entries(root: Path, manifest_path: Path, *, allow_prefix: str = "") -> int:
    root = root.resolve()
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = data["entries"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("Empty or invalid manifest")
    seen = set()
    for item in entries:
        relative = PurePosixPath(item["path"])
        if relative.is_absolute() or ".." in relative.parts or "\\" in str(relative) or ":" in str(relative):
            raise ValueError("Unsafe manifest path")
        if allow_prefix and not str(relative).startswith(allow_prefix):
            raise ValueError("Unexpected manifest path prefix")
        target = (root / str(relative)).resolve()
        if not target.is_relative_to(root) or str(relative) in seen:
            raise ValueError("Escaping or duplicate manifest entry")
        seen.add(str(relative))
        if target.stat().st_size != item["bytes"]:
            raise ValueError("Bundle file size mismatch")
        with target.open("rb") as handle:
            digest = hashlib.sha256()
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != item["sha256"]:
            raise ValueError("Bundle file checksum mismatch")
    return len(entries)


def verify(root: Path) -> int:
    root = root.resolve()
    return _verify_entries(root, root / "BUNDLE_MANIFEST.json")


def verify_runtime(root: Path) -> int:
    root = root.resolve()
    return _verify_entries(root, root / "models" / "llama" / "RUNTIME_MANIFEST.json", allow_prefix="models/llama/")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--check-runtime", action="store_true", help="Also verify staged models/llama/RUNTIME_MANIFEST.json")
    args = p.parse_args(argv)
    try:
        count = verify(args.root)
    except (OSError, ValueError, KeyError, TypeError):
        print("FAILED: bundle manifest missing, unsafe or mismatched. Use a trusted, unmodified transfer archive.")
        return 1
    print(f"PASSED: {count} bundle files match manifest. This proves integrity, not authenticity or hardware compatibility.")
    if args.check_runtime:
        try:
            runtime_count = verify_runtime(args.root)
        except (OSError, ValueError, KeyError, TypeError):
            print("FAILED: runtime manifest missing, unsafe or mismatched in models/llama/.")
            return 1
        print(
            f"PASSED: {runtime_count} staged aarch64 runtime assets match models/llama/RUNTIME_MANIFEST.json. "
            "Integrity verified; hardware compatibility still requires device execution."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
