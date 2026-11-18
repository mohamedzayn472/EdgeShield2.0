"""Verify, split, patch, and repair the exported SpinQuant llama3_2.pte model file."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile
import zlib


@dataclass(frozen=True)
class ChunkSpec:
    index: int
    offset: int
    size: int
    sha256: str


@dataclass(frozen=True)
class ModelSpec:
    filename: str
    total_bytes: int
    sha256: str
    crc32: str
    part_size: int
    block_size: int
    parts: tuple[ChunkSpec, ...]
    blocks: tuple[ChunkSpec, ...]


_RAW_PARTS = [
    {"index": 0, "offset": 0, "size": 67108864, "sha256": "0adf1bcaf9711970aaaf67317a10cfb01fc84ae37eb2a6c5fb8fc152dae05f5f"},
    {"index": 1, "offset": 67108864, "size": 67108864, "sha256": "f2c5d6ea2cc8bcf31a73319fda6a16c9a170f5957efe73fe182404aaaac19ae8"},
    {"index": 2, "offset": 134217728, "size": 67108864, "sha256": "e8956cc9c97dac6fdd01a560460eca677fa3914dd8352b70f28a8bcd4a61784e"},
    {"index": 3, "offset": 201326592, "size": 67108864, "sha256": "5a2c21bcfd1fe1e60448a88632efb0b29b0e2cae1f33aaaf7497d02a3599a0c9"},
    {"index": 4, "offset": 268435456, "size": 67108864, "sha256": "98e06c718eb8362ab263799d4e55e5a4ef8d9398007cbf8dbc58aaf2b2e4eedf"},
    {"index": 5, "offset": 335544320, "size": 67108864, "sha256": "aba8dfb35c3f2c6b375aebc020452061bbfea1ff940c04fb1475be59b07d0fe0"},
    {"index": 6, "offset": 402653184, "size": 67108864, "sha256": "eb2a7369dafdf4fcdd96f0fd941b22299e080d166d7115d9c7233982096f0c58"},
    {"index": 7, "offset": 469762048, "size": 67108864, "sha256": "eb82dc29ab338adfec0bb4657f72ae0a3b9561380a70de5eaae4617f893af620"},
    {"index": 8, "offset": 536870912, "size": 67108864, "sha256": "ea03357e90bed54c4ae89e84f1cc9cd6469f1324831161d6de9b4f1e8937398f"},
    {"index": 9, "offset": 603979776, "size": 67108864, "sha256": "bfee519bddb42e7dac8098600b8baf6eccadf6184572ee48ed71446d06d6a6ad"},
    {"index": 10, "offset": 671088640, "size": 67108864, "sha256": "04874ca8053403fe948d3b6838b050c93852409996b25af15f171be400cbdb34"},
    {"index": 11, "offset": 738197504, "size": 67108864, "sha256": "a840bd686ad759d18a3e390ee5f091f1d1416ecebc4ea982c11750242aa3c55c"},
    {"index": 12, "offset": 805306368, "size": 67108864, "sha256": "2e0e17a16742deacae70715f7e9b2a2b9a2c101bc8f3c89a11b5b52003e45bb8"},
    {"index": 13, "offset": 872415232, "size": 67108864, "sha256": "16b0a192ae3606fc6b077193dbf841b824e4591914a0eeb82dcdf267f44c118a"},
    {"index": 14, "offset": 939524096, "size": 67108864, "sha256": "a560e86614b41c15e194cbd9ecf5516c49f22b14514c584c6f6bf73f65703ca6"},
    {"index": 15, "offset": 1006632960, "size": 67108864, "sha256": "c32caae4d632d1d10ea41b9b64269df2bf6bbbc4b2f4f17c58a454844fbb88ba"},
    {"index": 16, "offset": 1073741824, "size": 1401088, "sha256": "279272e71877606b5672c71d73a3f9a690c62b2ae9b43c7d74c21639f3832a54"},
]

_RAW_BLOCKS = [
    {"index": 0, "offset": 0, "size": 16777216, "sha256": "d65502a2b309a855c4d97aab299fc4a7bd779d9726ddb07d6e24aa1635b06709"},
    {"index": 1, "offset": 16777216, "size": 16777216, "sha256": "abf9f4839ee1a756e5951bd5ff6f4a95a41064dcf069327263c786ebaf040d38"},
    {"index": 2, "offset": 33554432, "size": 16777216, "sha256": "1367c474c905f4f74eb868e40d752e033be147fdad0e31a66edfcf5469c5467b"},
    {"index": 3, "offset": 50331648, "size": 16777216, "sha256": "a1845d55fae78cc1cf80fb908bbed7de9e3f01c3aba2a705de84b390881a3303"},
    {"index": 4, "offset": 67108864, "size": 16777216, "sha256": "f4a41026384cc1fea15d5e77db32b49c44d6b4b7a0a6268360d01e0d0f564a4c"},
    {"index": 5, "offset": 83886080, "size": 16777216, "sha256": "4656f8a1c69593c7db33946c17a70bbae1048b961dc7edc8a9af71c727806731"},
    {"index": 6, "offset": 100663296, "size": 16777216, "sha256": "ff62b26cca8eead7a9a16229f3bae6e11694900631c0590cbac2e12dee5b6844"},
    {"index": 7, "offset": 117440512, "size": 16777216, "sha256": "97e6b3de8c2a57f10c0c229f1188dcf25776377fff9440b73373fa7ff7c04320"},
    {"index": 8, "offset": 134217728, "size": 16777216, "sha256": "9ca833fa2dc215fc217df295c3bd0eadf22e013032bf8dda44251ffc64cdd666"},
    {"index": 9, "offset": 150994944, "size": 16777216, "sha256": "7de85d3129c958f978a54de02ac63bde58cf055e29c2bd10c7b806cd4a1ac889"},
    {"index": 10, "offset": 167772160, "size": 16777216, "sha256": "63dcec0ed8f05f7a34444c676e8409169c64606928091616bb8d05c157d2b4e7"},
    {"index": 11, "offset": 184549376, "size": 16777216, "sha256": "1f583c2ad09055c3266946efeecc768a0b50511440da1bfc6a446ee8293761a7"},
    {"index": 12, "offset": 201326592, "size": 16777216, "sha256": "0dd1d53e7b59cf8616434378ad74c2820be89b18c7f8e59d4bf49a5b4913d2eb"},
    {"index": 13, "offset": 218103808, "size": 16777216, "sha256": "b038ce56733fcbc4d2fa9504e9e8e18f0131acf94e44646019282c5dcace1828"},
    {"index": 14, "offset": 234881024, "size": 16777216, "sha256": "485d463c837b78a8f82de9c3bf427ea5163f40e9a1b915d62aa48ba520bed57c"},
    {"index": 15, "offset": 251658240, "size": 16777216, "sha256": "f520a37a22c3540f0546c8a039cecb3bd09a8036a30966a221cf67d5d269694e"},
    {"index": 16, "offset": 268435456, "size": 16777216, "sha256": "a9fb0ca8e2bb9ef79738ff58e616be88dbfe509a0667585b269b698b5920d316"},
    {"index": 17, "offset": 285212672, "size": 16777216, "sha256": "91129a29af1bb714775e7b97d35fbf4399e0a8e7d43fbf292ab82d85d616acf8"},
    {"index": 18, "offset": 301989888, "size": 16777216, "sha256": "1136650f1f9ac3446e0f19b11139cb07807665b853b9a83c44d80698a9abd16c"},
    {"index": 19, "offset": 318767104, "size": 16777216, "sha256": "e81395ee16b0d7a17f666cd5331b35858225c1dea0593500cb6533a68e80c7e4"},
    {"index": 20, "offset": 335544320, "size": 16777216, "sha256": "d9eced1a3d046dda89d425cc718d6e6f0ed063b5486147bf589cf33a47153da2"},
    {"index": 21, "offset": 352321536, "size": 16777216, "sha256": "4ddcc52f79c578b8fcc4a7e75ea564d28e06dd9bd139733ef035fb495fbee502"},
    {"index": 22, "offset": 369098752, "size": 16777216, "sha256": "b168792bb97b11e8bdc0622cd6aaba851ab1fde305add80a699e01bfefa6639d"},
    {"index": 23, "offset": 385875968, "size": 16777216, "sha256": "b2fab84af8f6cbf81a733e47eb148dd71b3cf4ceaf66769028b33ea90891b987"},
    {"index": 24, "offset": 402653184, "size": 16777216, "sha256": "41cd154aa918e4314c818142ef8554d7037eaee33fc99452508dac6ddaf32ec8"},
    {"index": 25, "offset": 419430400, "size": 16777216, "sha256": "c0f4ef94cd2a1a579ac79b79019b80999ef31254fc1ac2ac01e6b7d2b26c9cef"},
    {"index": 26, "offset": 436207616, "size": 16777216, "sha256": "12e9848711630d77a2db89572fb05d6def0f752c45f9eb5bdb2338e3fe84cb6c"},
    {"index": 27, "offset": 452984832, "size": 16777216, "sha256": "de590796a016ea59b4b043b138c745086d178a0e0ad4a81a058b1bb392338010"},
    {"index": 28, "offset": 469762048, "size": 16777216, "sha256": "8d9158ecfc71a4abf9d340a5e05c38dc8ccae19db061aa241587a61b6e3a5139"},
    {"index": 29, "offset": 486539264, "size": 16777216, "sha256": "b6fd8a6a20d6a6367803dc062baab710b83a4913dc0574263a4a43847452fe52"},
    {"index": 30, "offset": 503316480, "size": 16777216, "sha256": "75a588debecd41ef0b7bc1f78d27f2780899f7afa9dcf0b665db82aac398bacd"},
    {"index": 31, "offset": 520093696, "size": 16777216, "sha256": "c8bda9aebb9ddbe4ed860d154e5c03b3e75e404148062f3d533419ad43e85eeb"},
    {"index": 32, "offset": 536870912, "size": 16777216, "sha256": "89ad6afda150d2b2acd9124fd093cdad0f38beb8b4738a051fb82dcdefdb01bc"},
    {"index": 33, "offset": 553648128, "size": 16777216, "sha256": "1f087f22c68bca9f208c708139f6b0b54e758fd3035c269be6a9eb8e717d9dc8"},
    {"index": 34, "offset": 570425344, "size": 16777216, "sha256": "28a7f6bb3839c80b18d3c1a74c19753cd3de7618ccca33a529782f54426f43a1"},
    {"index": 35, "offset": 587202560, "size": 16777216, "sha256": "247b904ac940d93c2897194e1e8d8f6321e6fbc56c5d1da2a38d4f60467b0420"},
    {"index": 36, "offset": 603979776, "size": 16777216, "sha256": "ad2d8c6496a7ce433e0ac43c0da0b27fe703dc0ac4d31d74097fc49ef9cf84c3"},
    {"index": 37, "offset": 620756992, "size": 16777216, "sha256": "98bd24ba03ec5e04279b136fa035eb2be7d2f6920e632ed50621d3818b34660b"},
    {"index": 38, "offset": 637534208, "size": 16777216, "sha256": "49d11613f427ab6ff1d1e4eeb8bfb01ccd1f021a172141a0481e05f51e3dfc44"},
    {"index": 39, "offset": 654311424, "size": 16777216, "sha256": "0b7529a1c34e672d0bf9f9a9eef46b021bfaaa1b573bc3b5da7f24ffc6a29d00"},
    {"index": 40, "offset": 671088640, "size": 16777216, "sha256": "661e455c0c6ca84ccedb33b0d67f6d1f9f6e256cdccfdb3d51749fe1a544712e"},
    {"index": 41, "offset": 687865856, "size": 16777216, "sha256": "81c4999c246da142a7b17c86ebb2ba6c56c219bc54b19f313d007e11feb348f0"},
    {"index": 42, "offset": 704643072, "size": 16777216, "sha256": "740715d3d3cd1deb9242bfaf5c69f1695dbf7aeff7b61e6f899d4b3594ad0bdd"},
    {"index": 43, "offset": 721420288, "size": 16777216, "sha256": "9d8815c2a43ec47bd621ad987efcb3af1f74b3ddfc3463dc80c50f691a470bf5"},
    {"index": 44, "offset": 738197504, "size": 16777216, "sha256": "fe35f159aa852918d3fa2aaa1343cb144b27457970b5335597a7532fd2562663"},
    {"index": 45, "offset": 754974720, "size": 16777216, "sha256": "e94956d351cb56b047ee15f0320402e5018b9cedb82b797961bddec1f890cb8f"},
    {"index": 46, "offset": 771751936, "size": 16777216, "sha256": "e05f464274aa3a74d383711471372148e143ac8ba256686f7e3176b3efa6a064"},
    {"index": 47, "offset": 788529152, "size": 16777216, "sha256": "0330f8e50997056843f64bda9b5aa140b1c1145c25737b7f2f08a9155b3ef2a7"},
    {"index": 48, "offset": 805306368, "size": 16777216, "sha256": "3d14c3d6442d3d54815aab7297a21dd628c85596246abff7300ce61b29ebfea7"},
    {"index": 49, "offset": 822083584, "size": 16777216, "sha256": "7aceacfa0d7f3071b99c958f53df8d110d7a2142af7f28b43a73985d92c817f1"},
    {"index": 50, "offset": 838860800, "size": 16777216, "sha256": "4a6122f87ddb3e415cc175bbf0d363e5d15ded0ebcea3a2aeb2bdd7dbdaf0c83"},
    {"index": 51, "offset": 855638016, "size": 16777216, "sha256": "d2b5f58cde2398f0a5e7e233996423146dedc87e8be80afb08692c39a672ea1b"},
    {"index": 52, "offset": 872415232, "size": 16777216, "sha256": "c98caeaba19767f44449e0617d040743a5169b3dcbe139b2c61e9a5ab7ea649a"},
    {"index": 53, "offset": 889192448, "size": 16777216, "sha256": "7ae2685778fcbfd4f8ec37995bfc0bb686ea2cede2383e1e09ff6baae3e68a14"},
    {"index": 54, "offset": 905969664, "size": 16777216, "sha256": "9266b02052d52e1536b3af28017ff70045288f8503ddb3b416d17966435c6f92"},
    {"index": 55, "offset": 922746880, "size": 16777216, "sha256": "1f6d26a237f93724f94db2f82d8bb3771949f9c675d163674039a4a547413f94"},
    {"index": 56, "offset": 939524096, "size": 16777216, "sha256": "014fab11bc93267df162452a443a8f1cabef676fc440b74f7cdee9a58c2924e3"},
    {"index": 57, "offset": 956301312, "size": 16777216, "sha256": "67125929f9b55626607ab9ae0dddaa556874143fa8834f99ab39020bb68f616a"},
    {"index": 58, "offset": 973078528, "size": 16777216, "sha256": "99ac894aa6c115d3d73d88939df87b089ddb61586c39d55b140b0fe77ab7980b"},
    {"index": 59, "offset": 989855744, "size": 16777216, "sha256": "7b1a63fbc1e12f0de3c0a4cfc5a2646866d2999bf9e745dffc7da3bc3c077164"},
    {"index": 60, "offset": 1006632960, "size": 16777216, "sha256": "301823f55925a0ebd86fe3de9a0bd2e0bf796039e0b9cb5f9f953c8175aa7f8a"},
    {"index": 61, "offset": 1023410176, "size": 16777216, "sha256": "e2d0fe036addb414cec1d41923d9e32b87d222ffad44975dce6e275db3b8edaa"},
    {"index": 62, "offset": 1040187392, "size": 16777216, "sha256": "6a37b03c56413007f86dfe23af2f8695bb9281cfdfc26e652ca8199125f6b1c6"},
    {"index": 63, "offset": 1056964608, "size": 16777216, "sha256": "ff55025152c92ebaee0846754445632e3a415618f16c44ab814e4769353a2647"},
    {"index": 64, "offset": 1073741824, "size": 1401088, "sha256": "279272e71877606b5672c71d73a3f9a690c62b2ae9b43c7d74c21639f3832a54"},
]

DEFAULT_SPEC = ModelSpec(
    filename="llama3_2.pte",
    total_bytes=1075142912,
    sha256="c31e4d376f349de85b4422a8c0405d88f21145709f0e17168b06d809ffe5e8a2",
    crc32="4e012699",
    part_size=64 * 1024 * 1024,
    block_size=16 * 1024 * 1024,
    parts=tuple(ChunkSpec(**item) for item in _RAW_PARTS),
    blocks=tuple(ChunkSpec(**item) for item in _RAW_BLOCKS),
)


def _read_exact(stream, size: int) -> bytes:
    """Read up to size bytes from stream across partial reads."""
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        try:
            piece = stream.read(remaining)
        except zipfile.BadZipFile:
            break
        if not piece:
            break
        chunks.append(piece)
        remaining -= len(piece)
    return b"".join(chunks)


def _find_zip_entry(zf: zipfile.ZipFile, filename: str) -> zipfile.ZipInfo:
    """Locate the target model entry inside a runtime zip archive."""
    matches = [
        info for info in zf.infolist()
        if not info.is_dir() and (info.filename == filename or info.filename.endswith("/" + filename))
    ]
    if not matches:
        raise FileNotFoundError(f"Zip archive does not contain {filename}")
    return matches[0]


def _digest_file(path: Path) -> tuple[int, str, str]:
    """Return (bytes, sha256, crc32_hex) for a file on disk."""
    sha = hashlib.sha256()
    crc = 0
    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(chunk)
            sha.update(chunk)
            crc = zlib.crc32(chunk, crc)
    return total, sha.hexdigest(), f"{crc & 0xffffffff:08x}"


class _BoundedFileStream:
    """Read-only view over a contiguous byte range of an underlying binary file."""

    def __init__(self, handle, offset: int, size: int) -> None:
        self._handle = handle
        self._remaining = size
        self._handle.seek(offset)

    def read(self, n: int = -1) -> bytes:
        if self._remaining <= 0:
            return b""
        to_read = self._remaining if n < 0 else min(n, self._remaining)
        data = self._handle.read(to_read)
        self._remaining -= len(data)
        return data

    def close(self) -> None:
        self._handle.close()


def _open_model_stream(path: Path, filename: str):
    """Context helper returning (container_to_close, stream, declared_size)."""
    if zipfile.is_zipfile(path):
        zf = zipfile.ZipFile(path, "r")
        info = _find_zip_entry(zf, filename)
        if info.compress_type == zipfile.ZIP_STORED and (info.flag_bits & 0x1) == 0:
            raw = path.open("rb")
            raw.seek(info.header_offset)
            hdr = raw.read(30)
            sig, _, _, _, _, _, _, _, _, fn_len, ex_len = struct.unpack("<IHHHHHIIIHH", hdr)
            if sig != 0x04034B50:
                raw.close()
                zf.close()
                raise zipfile.BadZipFile(f"Invalid local header for {info.filename}")
            data_offset = info.header_offset + 30 + fn_len + ex_len
            zf.close()
            stream = _BoundedFileStream(raw, data_offset, info.file_size)
            return stream, stream, info.file_size
        stream = zf.open(info, "r")
        return zf, stream, info.file_size
    handle = path.open("rb")
    return handle, handle, path.stat().st_size


def _close_quietly(cm, stream) -> None:
    """Close stream and parent container, ignoring zip EOF CRC mismatch."""
    for obj in (stream, cm):
        if obj is None or obj is stream and cm is stream:
            continue
        try:
            obj.close()
        except zipfile.BadZipFile:
            pass
    if cm is stream and stream is not None:
        try:
            stream.close()
        except zipfile.BadZipFile:
            pass


def check_pte(path: Path, spec: ModelSpec | None = None) -> dict:
    """Check a .pte file or zip archive against part (64 MiB) and block (16 MiB) hashes."""
    spec = DEFAULT_SPEC if spec is None else spec
    cm, stream, declared_size = _open_model_stream(path, spec.filename)
    bad_blocks: list[int] = []
    bad_parts_set: set[int] = set()
    whole_sha = hashlib.sha256()
    whole_crc = 0
    actual_size = 0
    try:
        for block in spec.blocks:
            data = _read_exact(stream, block.size)
            actual_size += len(data)
            whole_sha.update(data)
            whole_crc = zlib.crc32(data, whole_crc)
            digest = hashlib.sha256(data).hexdigest() if len(data) == block.size else f"SHORT({len(data)})"
            if digest != block.sha256:
                bad_blocks.append(block.index)
                bad_parts_set.add(block.offset // spec.part_size)
        # Drain any trailing bytes beyond expected EOF to compute actual size accurately.
        while True:
            extra = _read_exact(stream, 1024 * 1024)
            if not extra:
                break
            actual_size += len(extra)
            whole_sha.update(extra)
            whole_crc = zlib.crc32(extra, whole_crc)
    finally:
        _close_quietly(cm, stream)

    actual_sha = whole_sha.hexdigest()
    actual_crc = f"{whole_crc & 0xffffffff:08x}"
    valid = (
        actual_size == spec.total_bytes
        and declared_size == spec.total_bytes
        and actual_sha == spec.sha256
        and actual_crc == spec.crc32
        and not bad_blocks
    )
    return {
        "valid": valid,
        "path": str(path),
        "declared_bytes": declared_size,
        "actual_bytes": actual_size,
        "expected_bytes": spec.total_bytes,
        "actual_sha256": actual_sha,
        "expected_sha256": spec.sha256,
        "actual_crc32": actual_crc,
        "expected_crc32": spec.crc32,
        "bad_blocks": bad_blocks,
        "bad_parts": sorted(bad_parts_set),
    }


def split_pte(pte_path: Path, out_dir: Path, spec: ModelSpec | None = None) -> dict:
    """Split a verified .pte file into numbered 64 MiB parts and write SHA256SUMS."""
    spec = DEFAULT_SPEC if spec is None else spec
    report = check_pte(pte_path, spec)
    if not report["valid"]:
        raise ValueError(f"Refusing to split invalid {spec.filename}: bad_parts={report['bad_parts']}")
    out_dir.mkdir(parents=True, exist_ok=True)
    sum_lines: list[str] = []
    part_records: list[dict] = []
    with pte_path.open("rb") as src:
        for part in spec.parts:
            data = _read_exact(src, part.size)
            digest = hashlib.sha256(data).hexdigest()
            if len(data) != part.size or digest != part.sha256:
                raise ValueError(f"Part {part.index:02d} hash mismatch while splitting")
            part_name = f"{spec.filename}.part{part.index:02d}"
            part_path = out_dir / part_name
            part_path.write_bytes(data)
            written_bytes, written_sha, _ = _digest_file(part_path)
            if written_bytes != part.size or written_sha != part.sha256:
                raise ValueError(f"Verification failed after writing {part_name}")
            sum_lines.append(f"{part.sha256}  {part_name}")
            part_records.append({"name": part_name, "bytes": part.size, "sha256": part.sha256})
    (out_dir / "SHA256SUMS").write_text("\n".join(sum_lines) + "\n", encoding="utf-8")
    return {"out_dir": str(out_dir), "parts": len(part_records), "sha256sums": str(out_dir / "SHA256SUMS")}


def _collect_blocks_from_source(source: Path, recovered: dict[int, bytes], provenance: dict[int, str], spec: ModelSpec) -> None:
    """Inspect a .pte, .zip, .partXX, or directory of parts and store any valid blocks."""
    if source.is_dir():
        for child in sorted(source.iterdir()):
            if child.is_file() and f"{spec.filename}.part" in child.name:
                _collect_blocks_from_source(child, recovered, provenance, spec)
        return

    # Single .partXX file
    if f"{spec.filename}.part" in source.name:
        suffix = source.name.split(".part")[-1]
        if suffix.isdigit():
            part_idx = int(suffix)
            if 0 <= part_idx < len(spec.parts):
                part = spec.parts[part_idx]
                data = source.read_bytes()
                if len(data) == part.size and hashlib.sha256(data).hexdigest() == part.sha256:
                    for block in spec.blocks:
                        if part.offset <= block.offset < part.offset + part.size:
                            rel_off = block.offset - part.offset
                            bdata = data[rel_off:rel_off + block.size]
                            if hashlib.sha256(bdata).hexdigest() == block.sha256 and block.index not in recovered:
                                recovered[block.index] = bdata
                                provenance[block.index] = source.name
                return

    cm, stream, _ = _open_model_stream(source, spec.filename)
    try:
        for block in spec.blocks:
            bdata = _read_exact(stream, block.size)
            if len(bdata) != block.size:
                break
            if block.index not in recovered and hashlib.sha256(bdata).hexdigest() == block.sha256:
                recovered[block.index] = bdata
                provenance[block.index] = str(source)
    finally:
        _close_quietly(cm, stream)


def repair_pte(target_pte: Path, sources: list[Path], spec: ModelSpec | None = None) -> dict:
    """Reconstruct a verified target_pte using valid 16 MiB blocks across multiple sources."""
    spec = DEFAULT_SPEC if spec is None else spec
    recovered: dict[int, bytes] = {}
    provenance: dict[int, str] = {}
    for src in sources:
        if src.exists():
            _collect_blocks_from_source(src, recovered, provenance, spec)
        if len(recovered) == len(spec.blocks):
            break

    missing_blocks = [b.index for b in spec.blocks if b.index not in recovered]
    missing_parts = sorted({spec.blocks[idx].offset // spec.part_size for idx in missing_blocks})
    if missing_blocks:
        return {
            "repaired": False,
            "recovered_blocks": len(recovered),
            "total_blocks": len(spec.blocks),
            "missing_blocks": missing_blocks,
            "missing_parts": missing_parts,
        }

    target_pte.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target_pte.with_suffix(target_pte.suffix + ".tmp")
    with tmp_path.open("wb") as out:
        for block in spec.blocks:
            out.write(recovered[block.index])
    actual_bytes, actual_sha, actual_crc = _digest_file(tmp_path)
    if actual_bytes != spec.total_bytes or actual_sha != spec.sha256 or actual_crc != spec.crc32:
        tmp_path.unlink(missing_ok=True)
        raise ValueError("Assembled model failed whole-file SHA-256 or CRC-32 verification")
    tmp_path.replace(target_pte)
    return {
        "repaired": True,
        "target": str(target_pte),
        "bytes": actual_bytes,
        "sha256": actual_sha,
        "crc32": actual_crc,
        "recovered_blocks": len(recovered),
        "sources_used": sorted(set(provenance.values())),
    }


def patch_pte(target_pte: Path, parts_dir: Path, spec: ModelSpec | None = None) -> dict:
    """Replace any corrupted 64 MiB part(s) in target_pte using verified part files in parts_dir."""
    spec = DEFAULT_SPEC if spec is None else spec
    if not target_pte.is_file():
        raise FileNotFoundError(f"Target model not found: {target_pte}")
    current = check_pte(target_pte, spec)
    if current["valid"]:
        return {"patched": True, "replaced_parts": [], "sha256": spec.sha256, "crc32": spec.crc32}
    if target_pte.stat().st_size != spec.total_bytes:
        raise ValueError(
            f"Cannot patch in-place when size mismatches (expected {spec.total_bytes}, got {target_pte.stat().st_size}); use --repair"
        )

    replaced: list[int] = []
    with target_pte.open("r+b") as handle:
        for part_idx in current["bad_parts"]:
            part = spec.parts[part_idx]
            part_file = parts_dir / f"{spec.filename}.part{part.index:02d}"
            if not part_file.is_file():
                raise FileNotFoundError(f"Missing replacement part: {part_file}")
            data = part_file.read_bytes()
            if len(data) != part.size or hashlib.sha256(data).hexdigest() != part.sha256:
                raise ValueError(f"Replacement part failed SHA-256 verification: {part_file}")
            handle.seek(part.offset)
            handle.write(data)
            replaced.append(part.index)

    after = check_pte(target_pte, spec)
    if not after["valid"]:
        raise ValueError(f"Patched file still failed verification: bad_parts={after['bad_parts']}")
    return {"patched": True, "replaced_parts": replaced, "sha256": after["actual_sha256"], "crc32": after["actual_crc32"]}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", type=Path, metavar="PTE_OR_ZIP", help="Check .pte or zip and pinpoint bad 64 MiB parts / 16 MiB blocks")
    mode.add_argument("--split", nargs=2, type=Path, metavar=("PTE_PATH", "OUT_DIR"), help="Split verified .pte into 64 MiB parts + SHA256SUMS")
    mode.add_argument("--repair", type=Path, metavar="TARGET_PTE", help="Reconstruct verified .pte from one or more --source files/zips/parts")
    mode.add_argument("--patch", nargs=2, type=Path, metavar=("TARGET_PTE", "PARTS_DIR"), help="Patch bad 64 MiB part(s) in-place from PARTS_DIR")
    p.add_argument("--source", type=Path, action="append", default=[], help="Source .pte, .zip, .partXX, or parts directory for --repair")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.check:
            result = check_pte(args.check)
            print(json.dumps(result, indent=2))
            return 0 if result["valid"] else 1
        if args.split:
            result = split_pte(args.split[0], args.split[1])
            print(json.dumps(result, indent=2))
            return 0
        if args.repair:
            if not args.source:
                print("ERROR: --repair requires at least one --source argument", file=sys.stderr)
                return 2
            result = repair_pte(args.repair, args.source)
            print(json.dumps(result, indent=2))
            return 0 if result["repaired"] else 1
        if args.patch:
            result = patch_pte(args.patch[0], args.patch[1])
            print(json.dumps(result, indent=2))
            return 0
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
