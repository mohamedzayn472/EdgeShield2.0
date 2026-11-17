"""Target preflight. Run before install; --runtime adds artifact and loader checks."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys

KNOWN_RUNNERS = {
    "2dff99fe178ef105a178fd2b9e0fac84706181917b21ef18207cb5fcadc1dbd8": "pi4-aarch64",
    "4c3e62805c8f4ca63c19a10a3977d8f89e106e17abf5947dc725d4463e16ae39": "pi4-aarch64-glibc238",
    "6c84a84ddc9b1af7870dc769d9e054d22fb4010aae9311edaaa4b815d711005a": "host-x86_64",
}


def _parse_version_tuple(version_str: str) -> tuple[int, ...]:
    parts = [int(x) for x in re.findall(r"\d+", version_str or "")]
    return tuple(parts) if parts else (0,)


def _parse_os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    if not path.exists():
        return {}
    wanted = {"PRETTY_NAME", "NAME", "VERSION_ID", "VERSION_CODENAME", "ID"}
    result = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, val = line.split("=", 1)
        if key in wanted:
            result[key] = val.strip().strip('"').strip("'")
    return result


def _parse_meminfo() -> dict[str, int]:
    path = Path("/proc/meminfo")
    if not path.exists():
        return {}
    result = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        parts = rest.strip().split()
        if parts and parts[0].isdigit():
            result[key] = int(parts[0])
    return result


def _identify_runner_profile(runner: Path, runner_sha256: str, root: Path) -> str:
    if runner_sha256 in KNOWN_RUNNERS:
        return KNOWN_RUNNERS[runner_sha256]
    runtime_manifest = root / "models" / "llama" / "RUNTIME_MANIFEST.json"
    if runtime_manifest.exists():
        try:
            data = json.loads(runtime_manifest.read_text(encoding="utf-8"))
            for item in data.get("binaries", {}).values():
                if item.get("sha256") == runner_sha256 and item.get("profile"):
                    return item["profile"]
        except (OSError, ValueError, TypeError):
            pass
    parent = runner.parent.name
    if parent in {"pi5-aarch64", "pi5-aarch64-glibc238", "pi4-aarch64", "pi4-aarch64-glibc238", "host-x86_64"}:
        return parent
    return "custom"


def _readelf_max_glibc(paths: list[Path]) -> str | None:
    readelf = shutil.which("readelf")
    if not readelf:
        return None
    versions: list[tuple[tuple[int, ...], str]] = []
    for binary in paths:
        try:
            proc = subprocess.run([readelf, "-V", str(binary)], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0:
            return None
        for match in re.findall(r"GLIBC_(\d+(?:\.\d+)+)", proc.stdout):
            versions.append((_parse_version_tuple(match), f"GLIBC_{match}"))
    if not versions:
        return None
    return max(versions, key=lambda item: item[0])[1]


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--runtime", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--device", choices=("pi4", "pi5"), default="pi4")
    args = p.parse_args(argv)
    checks = {}
    checks["linux"] = platform.system() == "Linux"
    checks["aarch64_64bit"] = platform.machine() == "aarch64" and struct.calcsize("P") == 8
    if args.device == "pi4":
        checks["python_3_11_for_wheelhouse"] = sys.version_info[:2] == (3, 11)
    else:
        checks["python_supported_by_project"] = (3, 10) <= sys.version_info[:2] < (3, 14)
    libc, libc_version = platform.libc_ver()
    host_glibc_tuple = _parse_version_tuple(libc_version)
    checks["glibc_at_least_2_27"] = libc == "glibc" and host_glibc_tuple >= (2, 27)
    model_path = Path("/proc/device-tree/model")
    model = model_path.read_text(encoding="utf-8", errors="replace").strip("\x00") if model_path.exists() else "UNAVAILABLE"
    expected_model = "Raspberry Pi 5 Model B" if args.device == "pi5" else "Raspberry Pi 4 Model B"
    checks["expected_device_model"] = expected_model in model
    meminfo = _parse_meminfo()
    memory_kib = meminfo.get("MemTotal", 0)
    mem_available_kib = meminfo.get("MemAvailable")
    swap_total_kib = meminfo.get("SwapTotal")
    swap_free_kib = meminfo.get("SwapFree")
    # Provisioning thresholds only; a 4GB Pi5 still requires a real model memory test.
    minimum_gib = 3 if args.device == "pi5" else 6
    checks[f"ram_at_least_{minimum_gib}_gib"] = memory_kib >= minimum_gib * 1024 * 1024
    checks["free_disk_at_least_3_gib"] = shutil.disk_usage(Path.cwd()).free >= 3 * 1024**3
    runtime = "NOT_CHECKED"
    runner_profile = None
    runner_note = None
    runner_max_glibc = None
    if args.runtime:
        try:
            root = Path(__file__).resolve().parents[2]
            if str(root / "src") not in sys.path:
                sys.path.insert(0, str(root / "src"))
            from edgeshield.advisory import ExecuTorchAdvisor

            advisor = ExecuTorchAdvisor(args.runtime)
            checks["artifact_integrity"] = True
            runner, runner_sha = advisor.files["runner"]
            libraries = [path for path, _ in advisor.libraries]
            runner_profile = _identify_runner_profile(runner, runner_sha, root)
            if args.device == "pi4":
                checks["runner_compatible_with_device"] = not (
                    runner_profile.startswith("pi5-") or runner_profile == "host-x86_64"
                )
                if runner_profile.startswith("pi4-"):
                    runner_note = "Pi4 Cortex-A72 (armv8-a) runtime configured."
            else:
                checks["runner_compatible_with_device"] = runner_profile != "host-x86_64"
                if runner_profile.startswith("pi4-"):
                    runner_profile = "pi4-cortex-a72-runtime-on-pi5"
                    runner_note = (
                        "Pi4-built Cortex-A72 (armv8-a) runtime configured for Pi5 validation; "
                        "not compiled with Pi5 Cortex-A76 flags"
                    )
                elif runner_profile.startswith("pi5-"):
                    runner_profile = "pi5-cortex-a76-native"
                    runner_note = "Dedicated Pi5 Cortex-A76 (armv8.2-a+dotprod+fp16) runtime configured."
            env = dict(os.environ)
            env.pop("LD_PRELOAD", None)
            env["LD_LIBRARY_PATH"] = os.pathsep.join(sorted({str(path.parent) for path in libraries}))
            # Only inspect binaries after hash validation against the trusted manifest.
            ldd_ok = True
            for target_bin in [runner, *libraries]:
                result = subprocess.run(["ldd", str(target_bin)], capture_output=True, text=True, timeout=20, env=env)
                combined = (result.stdout + "\n" + result.stderr).lower()
                if result.returncode != 0 or "not found" in combined:
                    ldd_ok = False
                    break
            checks["dynamic_libraries_resolve"] = ldd_ok
            runner_max_glibc = _readelf_max_glibc([runner, *libraries])
            if runner_max_glibc and libc == "glibc":
                checks["runner_glibc_compatible"] = _parse_version_tuple(runner_max_glibc) <= host_glibc_tuple
            runtime = "INTEGRITY_AND_LOADER_CHECKED_NOT_INFERENCE"
        except Exception:
            checks["runtime_verification"] = False
            runtime = "FAILED"
    report = {
        "status": "PASSED" if all(checks.values()) else "FAILED",
        "checks": checks,
        "device": args.device,
        "machine": platform.machine(),
        "os": platform.platform(),
        "os_release": _parse_os_release(),
        "python": platform.python_version(),
        "device_model": model,
        "glibc": libc_version,
        "memory_kib": memory_kib,
        "mem_available_kib": mem_available_kib,
        "swap_total_kib": swap_total_kib,
        "swap_free_kib": swap_free_kib,
        "runtime": runtime,
        "runner_profile": runner_profile,
        "runner_max_glibc_required": runner_max_glibc,
        "runner_note": runner_note,
        "inference": "NOT_EXECUTED",
    }
    encoded = json.dumps(report, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded)
    return 0 if all(checks.values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
