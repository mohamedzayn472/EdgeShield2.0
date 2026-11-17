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
    with pytest.raises(ValueError, match="checksum"):
        module.verify_runtime(tmp_path)

    manifest["entries"][0]["path"] = "src/edgeshield/cli.py"
    (llama_dir / "RUNTIME_MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="prefix"):
        module.verify_runtime(tmp_path)
