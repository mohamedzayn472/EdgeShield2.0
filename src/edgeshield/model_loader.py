"""Load supported, checksummed detector formats (v1, v2, v3, v4, v5, v6, v7, or v8)."""
import hashlib
import json
from pathlib import Path
import sys

_CACHE: dict[tuple[str, str], object] = {}
DEFAULT_DETECTOR_PATH = Path("models/detector_v8.json")


def resolve_default_detector(path: Path) -> Path:
    """Resolve the default relative detector against repo or venv bundle root from any cwd."""
    if path == DEFAULT_DETECTOR_PATH and not path.exists():
        candidates = [
            Path(__file__).resolve().parents[2] / DEFAULT_DETECTOR_PATH,
            Path(sys.prefix).parent / DEFAULT_DETECTOR_PATH,
            Path(sys.prefix).resolve().parent / DEFAULT_DETECTOR_PATH,
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
    return path


def _verify_checksum(path: Path, fmt: int, digest: str) -> None:
    checksum = Path(str(path) + ".sha256")
    if fmt in (2, 3, 4, 5, 6):
        if checksum.stat().st_size > 256:
            raise ValueError("Invalid detector checksum")
        expected = checksum.read_text(encoding="ascii").strip()
    else:
        parts = checksum.read_text(encoding="ascii").split()
        expected = parts[0] if parts else ""
    if len(expected) != 64 or digest != expected:
        raise ValueError("Detector checksum mismatch")


def load_detector(path):
    """Load and checksum-verify a v1..v6 detector in a single JSON pass with caching."""
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
    if fmt not in (1, 2, 3, 4, 5, 6, 7, 8):
        raise ValueError("Unsupported detector format")
    if fmt == 1 and size > 20_000_000:
        raise ValueError("Detector artifact exceeds size limit")
    _verify_checksum(path, fmt, digest)
    if fmt == 1:
        from .detector import Detector
        detector = Detector(artifact)
    elif fmt == 2:
        from .detector_v2 import DetectorV2
        detector = DetectorV2(artifact)
    elif fmt == 3:
        from .detector_v3 import DetectorV3
        detector = DetectorV3(artifact)
    elif fmt == 4:
        from .detector_v4 import DetectorV4
        detector = DetectorV4(artifact)
    elif fmt == 5:
        from .detector_v5 import DetectorV5
        detector = DetectorV5(artifact)
    elif fmt == 6:
        from .detector_v6 import DetectorV6
        detector = DetectorV6(artifact)
    elif fmt == 7:
        from .detector_v7 import DetectorV7
        detector = DetectorV7(artifact)
    else:
        from .detector_v8 import DetectorV8
        detector = DetectorV8(artifact)
    detector.artifact_sha256 = digest
    _CACHE[(resolved, digest)] = (fmt, detector)
    return detector
