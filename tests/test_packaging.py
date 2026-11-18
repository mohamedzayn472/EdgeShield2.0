import importlib.util
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location("package_bundle", Path("scripts/package_bundle.py"))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


@pytest.mark.parametrize("name", [".venv/Scripts/python.exe", ".python/runtime", "data/raw/SMSCollection", "data/processed/test.jsonl",
                                  "models/llama/model.pte", "deploy/pi4/tokenizer.model", "configs/.env", "docs/secret.pem",
                                  "deploy/pi4/llama_main", "src/edgeshield/__pycache__/foo.pyc", "configs/tokenizer.json"])
def test_private_and_incompatible_assets_excluded(name):
    assert not bundle.included(bundle.ROOT / name)


@pytest.mark.parametrize("name", ["README.md", ".gitignore", "src/edgeshield/cli.py", "models/detector.json",
                                  "data/synthetic/examples.jsonl", "deploy/pi4/README.md", "deploy/pi5/setup.sh",
                                  "requirements/pi5.txt", "results/pi4/STATUS.json", "results/pi5/STATUS.json",
                                  "wheelhouse/pi5-cp313-aarch64/SHA256SUMS"])
def test_transfer_assets_included(name):
    assert bundle.included(bundle.ROOT / name)


@pytest.mark.parametrize("name", ["models/llama/RUNTIME_MANIFEST.json", "models/llama/pi5-aarch64/llama_main",
                                  "models/llama/host-x86_64/llama_main", "models/llama/pi5-aarch64/libllama_runner.so"])
def test_private_runtime_assets_excluded_from_source_bundle(name):
    assert not bundle.included(bundle.ROOT / name)


def test_bundle_verification_detects_tampering(tmp_path):
    import hashlib
    import json
    verify_spec = importlib.util.spec_from_file_location("verify_bundle", Path("scripts/verify_bundle.py"))
    module = importlib.util.module_from_spec(verify_spec)
    verify_spec.loader.exec_module(module)
    path = tmp_path / "asset.txt"
    path.write_bytes(b"trusted")
    manifest = {"entries": [{"path": "asset.txt", "bytes": 7, "sha256": hashlib.sha256(b"trusted").hexdigest()}]}
    (tmp_path / "BUNDLE_MANIFEST.json").write_text(json.dumps(manifest))
    assert module.verify(tmp_path) == 1
    path.write_bytes(b"changed")
    with pytest.raises(ValueError, match="checksum"):
        module.verify(tmp_path)
    manifest["entries"][0]["path"] = "../outside"
    (tmp_path / "BUNDLE_MANIFEST.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="Unsafe"):
        module.verify(tmp_path)


def test_runtime_manifest_verification_and_guards(tmp_path):
    import hashlib
    import json
    verify_spec = importlib.util.spec_from_file_location("verify_bundle", Path("scripts/verify_bundle.py"))
    module = importlib.util.module_from_spec(verify_spec)
    verify_spec.loader.exec_module(module)

    llama_dir = tmp_path / "models" / "llama"
    llama_dir.mkdir(parents=True)
    runner = llama_dir / "llama_main"
    runner.write_bytes(b"runner bytes")
    manifest = {
        "entries": [
            {"path": "models/llama/llama_main", "bytes": 12, "sha256": hashlib.sha256(b"runner bytes").hexdigest()}
        ]
    }
    (llama_dir / "RUNTIME_MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert module.verify_runtime(tmp_path) == 1

    runner.write_bytes(b"tampered!!!!")
    with pytest.raises(ValueError, match="models/llama/llama_main"):
        module.verify_runtime(tmp_path)

    manifest["entries"][0]["path"] = "src/edgeshield/cli.py"
    (llama_dir / "RUNTIME_MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="prefix"):
        module.verify_runtime(tmp_path)


def test_verify_and_repair_pte_split_check_patch_and_repair(tmp_path, monkeypatch):
    import hashlib
    import json
    import zipfile
    import zlib

    spec = importlib.util.spec_from_file_location("verify_and_repair_pte", Path("scripts/verify_and_repair_pte.py"))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    import sys
    sys.modules["verify_and_repair_pte"] = mod
    spec.loader.exec_module(mod)

    # Validate embedded DEFAULT_SPEC math for llama3_2.pte
    assert sum(p.size for p in mod.DEFAULT_SPEC.parts) == mod.DEFAULT_SPEC.total_bytes
    assert sum(b.size for b in mod.DEFAULT_SPEC.blocks) == mod.DEFAULT_SPEC.total_bytes
    assert len(mod.DEFAULT_SPEC.parts) == 17
    assert len(mod.DEFAULT_SPEC.blocks) == 65

    # Build synthetic model: 100 bytes -> part_size=64 (2 parts), block_size=16 (7 blocks)
    payload = bytes((i * 37) % 256 for i in range(100))
    part_size = 64
    block_size = 16
    parts = tuple(
        mod.ChunkSpec(i, off, min(part_size, len(payload) - off), hashlib.sha256(payload[off:off + part_size]).hexdigest())
        for i, off in enumerate(range(0, len(payload), part_size))
    )
    blocks = tuple(
        mod.ChunkSpec(i, off, min(block_size, len(payload) - off), hashlib.sha256(payload[off:off + block_size]).hexdigest())
        for i, off in enumerate(range(0, len(payload), block_size))
    )
    test_spec = mod.ModelSpec(
        filename="llama3_2.pte",
        total_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        crc32=f"{zlib.crc32(payload) & 0xffffffff:08x}",
        part_size=part_size,
        block_size=block_size,
        parts=parts,
        blocks=blocks,
    )
    monkeypatch.setattr(mod, "DEFAULT_SPEC", test_spec)

    good_pte = tmp_path / "good.pte"
    good_pte.write_bytes(payload)
    assert mod.main(["--check", str(good_pte)]) == 0

    chunks_dir = tmp_path / "chunks"
    assert mod.main(["--split", str(good_pte), str(chunks_dir)]) == 0
    assert (chunks_dir / "llama3_2.pte.part00").is_file()
    assert (chunks_dir / "llama3_2.pte.part01").is_file()
    assert (chunks_dir / "SHA256SUMS").is_file()

    # Corrupt block 1 (part 0) in a .pte and check + patch
    bad_pte_a = tmp_path / "bad_a.pte"
    corrupt_a = bytearray(payload)
    corrupt_a[20] ^= 0xFF
    bad_pte_a.write_bytes(corrupt_a)
    assert mod.main(["--check", str(bad_pte_a)]) == 1
    chk_a = mod.check_pte(bad_pte_a, test_spec)
    assert chk_a["bad_blocks"] == [1]
    assert chk_a["bad_parts"] == [0]
    assert mod.main(["--patch", str(bad_pte_a), str(chunks_dir)]) == 0
    assert bad_pte_a.read_bytes() == payload

    # Corrupt block 6 (last block in part 1) inside a ZIP_STORED zip, and corrupt block 0 in another copy
    zip_a = tmp_path / "zip_a.zip"
    with zipfile.ZipFile(zip_a, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("edgeshield/models/llama/llama3_2.pte", bytes(corrupt_a))

    corrupt_b = bytearray(payload)
    corrupt_b[98] ^= 0xFF
    zip_b = tmp_path / "zip_b.zip"
    with zipfile.ZipFile(zip_b, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("edgeshield/models/llama/llama3_2.pte", bytes(corrupt_b))

    chk_zip_b = mod.check_pte(zip_b, test_spec)
    assert chk_zip_b["valid"] is False
    assert chk_zip_b["bad_blocks"] == [6]
    assert chk_zip_b["bad_parts"] == [1]

    # Repair from the two differently corrupted zips!
    repaired = tmp_path / "repaired.pte"
    assert mod.main(["--repair", str(repaired), "--source", str(zip_a), "--source", str(zip_b)]) == 0
    assert repaired.read_bytes() == payload
