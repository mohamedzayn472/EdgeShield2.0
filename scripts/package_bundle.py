"""Build dual-target source bundles and the private licensed aarch64 Llama runtime archive."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DETECTOR_REL = "models/detector_v8.json"
REQUIRED_DEFAULT_FILES = (
    DEFAULT_DETECTOR_REL,
    f"{DEFAULT_DETECTOR_REL}.sha256",
)
TOP_FILES = {"README.md", "PROJECT_STATUS.md", "pyproject.toml", ".gitignore", ".gitattributes", "LICENSE"}
TOP_DIRS = {"src", "scripts", "tests", "requirements", "configs", "docs", "deploy", "executorch", "submission", "results", "wheelhouse"}
EXCLUDED_PARTS = {"__pycache__", ".pytest_cache", "raw", "processed", "llama", "licensed", "upstream"}

EXECUTORCH_REVISION = "985c1ceccc8bb8b6a32294f71aeb5d2f299562f7"
MODEL_PROVENANCE = {
    "repository": "meta-llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8",
    "revision": "b8c08c95d0476ccb6fc86e9410818d602ecca19d",
    "checkpoint_sha256": "c14adb6bf48fd9e81fdc14ebad5ef0ea9f98d50ca3419b28f0b788149c4ef2a5",
    "tokenizer_sha256": "82e9d31979e92ab929cd544440f129d9ecd797b69e327f80f17e1c50d5551b55",
    "executorch_revision": EXECUTORCH_REVISION,
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def included(path):
    rel = path.relative_to(ROOT)
    if any(part.startswith(".") and part not in {".gitignore", ".gitattributes"} for part in rel.parts):
        return False
    if any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in rel.parts):
        return False
    if path.suffix.lower() in {".pyc", ".pte", ".pth", ".pt", ".bin", ".gguf", ".onnx", ".safetensors", ".exe", ".dll", ".so", ".zip", ".log", ".key", ".pem"}:
        return False
    if path.name in {"tokenizer.model", "tokenizer.json", "llama_main"}:
        return False
    return (rel.parts[0] in TOP_DIRS or str(rel) in TOP_FILES or
            rel.parts[0] == "data" and (len(rel.parts) == 2 or rel.parts[1] == "synthetic") or
            rel.parts[0] == "models" and path.name in {
                "README.md",
                "detector_README.md",
                "detector.json",
                "detector.json.sha256",
                "detector_v2.json",
                "detector_v2.json.sha256",
                "detector_v3.json",
                "detector_v3.json.sha256",
                "detector_v4.json",
                "detector_v4.json.sha256",
                "detector_v5.json",
                "detector_v5.json.sha256",
                "detector_v6.json",
                "detector_v6.json.sha256",
                "detector_v7.json",
                "detector_v7.json.sha256",
                "detector_v8.json",
                "detector_v8.json.sha256",
                "url_detector_v1.json",
                "url_detector_v1.json.sha256",
            })


def validate_required_artifacts(paths: list[Path], root: Path = ROOT) -> None:
    """Fail packaging if any default detector artifact or its .sha256 sidecar is missing or mismatched."""
    rel_set = {p.relative_to(root).as_posix() for p in paths}
    for req in REQUIRED_DEFAULT_FILES:
        if req not in rel_set:
            raise RuntimeError(f"Required default artifact missing from bundle: {req}")
        target = root / req
        if not target.is_file():
            raise RuntimeError(f"Required default artifact missing on disk: {req}")
    model_path = root / DEFAULT_DETECTOR_REL
    checksum_path = root / f"{DEFAULT_DETECTOR_REL}.sha256"
    raw_sum = checksum_path.read_text(encoding="ascii").strip()
    expected_sha = raw_sum.split()[0] if raw_sum else ""
    actual_sha = sha256_file(model_path)
    if len(expected_sha) != 64 or expected_sha != actual_sha:
        raise RuntimeError(
            f"Default detector checksum mismatch for {DEFAULT_DETECTOR_REL}: expected {expected_sha!r}, got {actual_sha!r}"
        )


def _build_source_zip(archive: Path, paths: list[Path], manifest_text: str) -> dict:
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in paths:
            z.write(p, "edgeshield/" + p.relative_to(ROOT).as_posix())
        z.writestr("edgeshield/BUNDLE_MANIFEST.json", manifest_text)
    return {"file": archive.name, "bytes": archive.stat().st_size, "sha256": sha256_file(archive)}


def _runtime_provenance(rel: str) -> dict[str, str]:
    if rel == "models/llama/llama3_2.pte":
        return {"role": "model_pte", "provenance": f"Exported from {MODEL_PROVENANCE['repository']}@{MODEL_PROVENANCE['revision']} with ExecuTorch {EXECUTORCH_REVISION}"}
    if rel == "models/llama/tokenizer.model":
        return {"role": "tokenizer", "provenance": f"Official Meta tiktoken tokenizer from {MODEL_PROVENANCE['repository']}@{MODEL_PROVENANCE['revision']}"}
    if rel == "models/llama/LICENSE_AND_NOTICE.md":
        return {"role": "license_notice", "provenance": "Meta Llama 3.2 Community License Agreement and attribution notice"}
    if rel.startswith("models/llama/pi5-aarch64/") or rel in {"models/llama/llama_main", "models/llama/libllama_runner.so"}:
        return {"role": "pi5_native_bookworm_trixie", "provenance": "Cross-compiled Arm GNU 12.2.rel1 (-march=armv8.2-a+dotprod+fp16 -mtune=cortex-a76, GLIBC <= 2.34)"}
    if rel.startswith("models/llama/pi5-aarch64-glibc238/"):
        return {"role": "pi5_native_glibc238", "provenance": "Cross-compiled Arm GNU 14.3.rel1 (-march=armv8.2-a+dotprod+fp16 -mtune=cortex-a76, KleidiAI ON, GLIBC <= 2.38)"}
    if rel.endswith("-runtime-manifest.json"):
        return {"role": "profile_manifest", "provenance": "Target artifact SHA-256 reference manifest"}
    return {"role": "runtime_asset", "provenance": "Staged target runtime asset"}


def _build_private_runtime_bundle(dest: Path) -> tuple[dict, dict | None]:
    llama_dir = ROOT / "models" / "llama"
    expected_relpaths = [
        "models/llama/llama3_2.pte",
        "models/llama/tokenizer.model",
        "models/llama/LICENSE_AND_NOTICE.md",
        "models/llama/pi5-aarch64/llama_main",
        "models/llama/pi5-aarch64/libllama_runner.so",
        "models/llama/pi5-aarch64-glibc238/llama_main",
        "models/llama/pi5-aarch64-glibc238/libllama_runner.so",
        "models/llama/pi5-runtime-manifest.json",
    ]
    present = []
    missing = []
    for rel in expected_relpaths:
        p = ROOT / rel
        if p.is_file() and p.stat().st_size > 0:
            present.append((rel, p))
        else:
            missing.append(rel)

    entries = []
    binaries = {}
    for rel, p in present:
        digest = sha256_file(p)
        meta = _runtime_provenance(rel)
        entry = {"path": rel, "bytes": p.stat().st_size, "sha256": digest, **meta}
        entries.append(entry)
        if p.name == "llama_main":
            binaries[rel] = {"profile": p.parent.name, "sha256": digest, "bytes": p.stat().st_size}

    runtime_manifest = {
        "kind": "PRIVATE_LICENSED_AARCH64_LLAMA_RUNTIME_MANIFEST",
        "redistribution_note": "Licensed Meta Llama 3.2 derivative weights/tokenizer; private deployment only, retain LICENSE_AND_NOTICE.md, never publish.",
        "model_provenance": MODEL_PROVENANCE,
        "complete": len(missing) == 0,
        "missing": missing,
        "binaries": binaries,
        "entries": entries,
    }
    manifest_path = llama_dir / "RUNTIME_MANIFEST.json"
    manifest_path.write_text(json.dumps(runtime_manifest, indent=2), encoding="utf-8")

    archive_info = None
    runners_archive_info = None
    if present:
        archive = dest / "edgeshield-aarch64-llama-runtime-private.zip"
        with zipfile.ZipFile(archive, "w", allowZip64=True) as z:
            for rel, p in present:
                # Store large .pte uncompressed for fast packaging/extraction; deflate small binaries/text.
                comp = zipfile.ZIP_STORED if p.suffix == ".pte" else zipfile.ZIP_DEFLATED
                z.write(p, "edgeshield/" + rel, compress_type=comp)
            z.write(manifest_path, "edgeshield/models/llama/RUNTIME_MANIFEST.json", compress_type=zipfile.ZIP_DEFLATED)
        archive_info = {"file": archive.name, "bytes": archive.stat().st_size, "sha256": sha256_file(archive)}

        runners_archive = dest / "edgeshield-aarch64-runners-only.zip"
        with zipfile.ZipFile(runners_archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for rel, p in present:
                if p.suffix != ".pte":
                    z.write(p, "edgeshield/" + rel)
            z.write(manifest_path, "edgeshield/models/llama/RUNTIME_MANIFEST.json")
        runners_archive_info = {
            "file": runners_archive.name,
            "bytes": runners_archive.stat().st_size,
            "sha256": sha256_file(runners_archive),
        }
    return runtime_manifest, archive_info, runners_archive_info


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output-dir", type=Path, default=ROOT / "dist", help="Destination directory for built archives")
    ap.add_argument("--source-only", action="store_true", help="Build only the public source/detector bundles without private Llama archives")
    args = ap.parse_args(argv)

    candidates = [ROOT / name for name in TOP_FILES]
    for name in TOP_DIRS | {"data", "models"}:
        base = ROOT / name
        if base.exists():
            candidates.extend(base.rglob("*"))
    paths = sorted(p for p in candidates if p.is_file() and included(p))
    validate_required_artifacts(paths, ROOT)
    entries = [{"path": p.relative_to(ROOT).as_posix(), "bytes": p.stat().st_size,
                "sha256": sha256_file(p)} for p in paths]
    manifest = {
        "kind": "SOURCE_AND_DETECTOR_BUNDLE",
        "primary_target": "Raspberry Pi 5 Model B 16 GB (aarch64)",
        "default_detector": DEFAULT_DETECTOR_REL,
        "complete_llama_deployment": False,
        "missing": [
            "licensed Llama checkpoint (host-only, not transferred)",
            "exported .pte (staged in private runtime archive edgeshield-aarch64-llama-runtime-private.zip)",
            "matched tokenizer.model (staged in private runtime archive edgeshield-aarch64-llama-runtime-private.zip)",
            "aarch64 llama_main and libllama_runner.so (staged in private runtime archive edgeshield-aarch64-llama-runtime-private.zip)",
        ],
        "wheelhouse_targets": [
            "wheelhouse/pi5-cp313-aarch64/: CPython 3.13 aarch64 Linux (Raspberry Pi OS Trixie); cross-downloaded on Ubuntu, not executed on target",
        ],
        "entries": entries,
    }
    manifest_text = json.dumps(manifest, indent=2)

    dest = args.output_dir.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "BUNDLE_MANIFEST.json").write_text(manifest_text, encoding="utf-8")

    pi5_archive = _build_source_zip(dest / "edgeshield-pi5-preparation.zip", paths, manifest_text)
    if args.source_only:
        runtime_manifest = {"complete": False, "missing": ["skipped via --source-only"], "binaries": {}, "entries": []}
        runtime_archive = None
        runners_archive = None
    else:
        runtime_manifest, runtime_archive, runners_archive = _build_private_runtime_bundle(dest)

    if not args.source_only:
        private_inventory = {
            **runtime_manifest,
            "archive": runtime_archive,
            "runners_only_archive": runners_archive,
            "excludes": ["models/llama/host-x86_64/*", ".venv-host/*", "build/*", "data/raw/*", "data/processed/*"],
        }
        (dest / "PRIVATE_RUNTIME_INVENTORY.json").write_text(json.dumps(private_inventory, indent=2), encoding="utf-8")

    inventory = {
        **manifest,
        "archive": pi5_archive,
        "archives": {
            "pi5_source_bundle": pi5_archive,
            "private_aarch64_runtime_bundle": runtime_archive,
            "private_aarch64_runners_only_bundle": runners_archive,
        },
        "private_runtime_complete": runtime_manifest["complete"],
        "private_runtime_missing": runtime_manifest["missing"],
    }
    (dest / "ARTIFACT_INVENTORY.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    print(json.dumps({
        "files": len(entries),
        "pi5_archive": pi5_archive,
        "runtime_archive": runtime_archive,
        "runners_archive": runners_archive,
        "private_runtime_complete": runtime_manifest["complete"],
    }, indent=2))


if __name__ == "__main__":
    main()
