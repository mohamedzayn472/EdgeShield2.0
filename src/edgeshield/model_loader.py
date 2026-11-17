"""Load one of two explicitly supported, checksummed detector formats."""
import hashlib
import json
from pathlib import Path

_CACHE: dict[tuple[str, str], object] = {}
DEFAULT_DETECTOR_PATH = Path("models/detector_v2.json")


def resolve_default_detector(path: Path) -> Path:
    """Resolve the default relative detector against the repository root from any cwd."""
    if path == DEFAULT_DETECTOR_PATH and not path.exists():
        candidate = Path(__file__).resolve().parents[2] / DEFAULT_DETECTOR_PATH
        if candidate.exists():
            return candidate
    return path


def _verify_checksum(path: Path, fmt: int, digest: str) -> None:
    checksum = Path(str(path) + ".sha256")
    if fmt == 2:
        if checksum.stat().st_size > 256:
            raise ValueError("Invalid detector checksum")
        expected = checksum.read_text(encoding="ascii").strip()
    else:
        parts = checksum.read_text(encoding="ascii").split()
        expected = parts[0] if parts else ""
    if len(expected) != 64 or digest != expected:
        raise ValueError("Detector checksum mismatch")


def load_detector(path):
    """Load and checksum-verify a v1 or v2 detector in a single JSON pass with caching."""
    path = Path(path)
    size = path.stat().st_size
    if size > 30_000_000:
        raise ValueError("Detector artifact exceeds size limit")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    resolved = str(path.resolve())
    cache_entry = _CACHE.get((resolved, digest))
    if cache_entry is not None:
        fmt, detector = cache_entry
        _verify_checksum(path, fmt, digest)
        return detector
    artifact = json.loads(raw)
    if type(artifact) is not dict or type(artifact.get("format")) is not int:
        raise ValueError("Unsupported detector format")
    fmt = artifact["format"]
    if fmt not in (1, 2):
        raise ValueError("Unsupported detector format")
    if fmt == 1 and size > 20_000_000:
        raise ValueError("Detector artifact exceeds size limit")
    _verify_checksum(path, fmt, digest)
    if fmt == 1:
        from .detector import Detector
        detector = Detector(artifact)
    else:
        from .detector_v2 import DetectorV2
        detector = DetectorV2(artifact)
    _CACHE[(resolved, digest)] = (fmt, detector)
    return detector
