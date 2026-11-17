"""Bounded local ExecuTorch runner adapter; no networking or SMS input API.

The manifest is a local trust anchor, not a signature. An attacker able to replace
both it and the executable is outside this integrity check's protection.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import threading


class AdvisoryError(RuntimeError):
    """Sanitized operational failure; never carries child output or prompt."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bounded_run(argv, *, timeout, max_bytes, env=None):
    """Drain both pipes with a shared byte budget; terminate on timeout/overflow."""
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=False, env=env)
    except OSError:
        raise AdvisoryError("RUNNER_START_FAILED") from None
    chunks = [bytearray(), bytearray()]
    lock = threading.Lock()
    overflow = threading.Event()
    total = 0

    def read_pipe(pipe, index):
        nonlocal total
        try:
            while True:
                chunk = pipe.read(1024)
                if not chunk:
                    break
                with lock:
                    total += len(chunk)
                    if total > max_bytes:
                        overflow.set()
                        proc.kill()
                        break
                    chunks[index].extend(chunk)
        finally:
            pipe.close()

    readers = [threading.Thread(target=read_pipe, args=(pipe, i), daemon=True)
               for i, pipe in enumerate((proc.stdout, proc.stderr))]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()
    for reader in readers:
        reader.join(timeout=2)
    if timed_out:
        raise AdvisoryError("RUNNER_TIMEOUT")
    if overflow.is_set() or any(reader.is_alive() for reader in readers):
        raise AdvisoryError("RUNNER_OUTPUT_LIMIT")
    if proc.returncode:
        raise AdvisoryError("RUNNER_FAILED")
    try:
        return bytes(chunks[0]).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise AdvisoryError("RUNNER_ENCODING") from None


class ExecuTorchAdvisor:
    """One process per generation. Startup cost is included in total runtime.

Input must be the already-framed, evidence-only prompt from build_prompt().
Model/runner/tokenizer hashes are checked on construction and before each call.
"""

    def __init__(self, config_path):
        self.config_path = Path(config_path).resolve()
        try:
            if self.config_path.stat().st_size > 65536:
                raise ValueError()
            c = json.loads(self.config_path.read_text(encoding="utf-8"))
            expected = {"schema_version", "executorch_revision", "target_arch", "model_family",
                        "tokenizer_format", "seq_len", "timeout_seconds", "max_output_bytes",
                        "artifacts", "stdout_mode", "max_new_tokens", "cpu_threads"}
            if set(c) != expected or c["schema_version"] != 1:
                raise ValueError()
            if not re.fullmatch(r"[0-9a-f]{40}", c["executorch_revision"]):
                raise ValueError()
            if c["model_family"] != "Llama-3.2-1B-Instruct" or c["tokenizer_format"] != "tiktoken_model":
                raise ValueError()
            if c["target_arch"] not in {"aarch64", "x86_64"}:
                raise ValueError()
            actual = {"AMD64": "x86_64", "arm64": "aarch64"}.get(platform.machine(), platform.machine())
            if actual != c["target_arch"]:
                raise AdvisoryError("RUNNER_ARCHITECTURE_MISMATCH")
            if type(c["seq_len"]) is not int or not 128 <= c["seq_len"] <= 2048:
                raise ValueError()
            if type(c["max_new_tokens"]) is not int or not 1 <= c["max_new_tokens"] <= 96:
                raise ValueError()
            if type(c["cpu_threads"]) is not int or not 1 <= c["cpu_threads"] <= 4:
                raise ValueError()
            if type(c["max_output_bytes"]) is not int or not 1024 <= c["max_output_bytes"] <= 262144:
                raise ValueError()
            if type(c["timeout_seconds"]) not in (int, float) or not math.isfinite(c["timeout_seconds"]) or not 0 < c["timeout_seconds"] <= 300:
                raise ValueError()
            if c["stdout_mode"] not in {"prompt_echo", "generated_only"}:
                raise ValueError()
            artifacts = c["artifacts"]
            if set(artifacts) != {"runner", "model", "tokenizer", "shared_libraries"} or not isinstance(artifacts["shared_libraries"], list):
                raise ValueError()
            if len(artifacts["shared_libraries"]) > 16:
                raise ValueError()
            self.files = {}
            for name in ("runner", "model", "tokenizer"):
                self.files[name] = self._artifact(artifacts[name])
            self.libraries = [self._artifact(item) for item in artifacts["shared_libraries"]]
            if self.files["model"][0].suffix != ".pte" or self.files["tokenizer"][0].name != "tokenizer.model":
                raise ValueError()
            self.config = c
            self.last_stats = None
            self.verify_integrity()
        except AdvisoryError:
            raise
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            raise AdvisoryError("RUNTIME_CONFIG_INVALID") from None

    def _artifact(self, item):
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ValueError()
        if not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise ValueError()
        path = (self.config_path.parent / item["path"]).resolve()
        if not path.is_file():
            raise AdvisoryError("RUNTIME_ARTIFACT_MISSING")
        return path, item["sha256"]

    def verify_integrity(self):
        for path, expected in [*self.files.values(), *self.libraries]:
            try:
                if sha256(path) != expected:
                    raise AdvisoryError("RUNTIME_INTEGRITY_FAILED")
            except OSError:
                raise AdvisoryError("RUNTIME_ARTIFACT_MISSING") from None

    def generate(self, prompt: str) -> str:
        self.last_stats = None
        if not isinstance(prompt, str) or not prompt or len(prompt.encode("utf-8")) > 8192 or "\x00" in prompt:
            raise AdvisoryError("RUNTIME_PROMPT_INVALID")
        self.verify_integrity()
        c = self.config
        argv = [str(self.files["runner"][0]), "--model_path", str(self.files["model"][0]),
                "--tokenizer_path", str(self.files["tokenizer"][0]), "--seq_len", str(c["seq_len"]),
                "--max_new_tokens", str(c["max_new_tokens"]), "--cpu_threads", str(c["cpu_threads"]),
                "--temperature", "0", "--prompt", prompt]
        env = dict(os.environ)
        # Do not inherit library injection variables into a trusted binary.
        for key in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "LD_LIBRARY_PATH"):
            env.pop(key, None)
        if self.libraries:
            env["LD_LIBRARY_PATH"] = os.pathsep.join(sorted({str(path.parent) for path, _ in self.libraries}))
        output = bounded_run(argv, timeout=c["timeout_seconds"], max_bytes=c["max_output_bytes"], env=env)
        if c["stdout_mode"] == "prompt_echo":
            if not output.startswith(prompt):
                raise AdvisoryError("RUNNER_OUTPUT_PROTOCOL")
            output = output[len(prompt):]
        elif prompt in output:
            raise AdvisoryError("RUNNER_OUTPUT_PROTOCOL")
        # Pinned stats.h prints exactly one terminal numeric JSON report to stdout.
        # Split only at the final marker; an invented marker inside generation remains
        # in the explanation and is rejected by the strict downstream validator.
        output, separator, report = output.rpartition("\nPyTorchObserver ")
        if not separator:
            raise AdvisoryError("RUNNER_STATS_PROTOCOL")
        try:
            stats = json.loads(report.strip())
            required = {"prompt_tokens", "generated_tokens", "SCALING_FACTOR_UNITS_PER_SECOND"}
            if not isinstance(stats, dict) or not required.issubset(stats) or len(stats) > 32:
                raise ValueError()
            if any(not isinstance(k, str) or not re.fullmatch(r"[A-Za-z_]+", k)
                   or type(v) not in (int, float) or not math.isfinite(v) or v < 0 for k, v in stats.items()):
                raise ValueError()
            if stats["SCALING_FACTOR_UNITS_PER_SECOND"] != 1000 or not 0 < stats["generated_tokens"] <= c["max_new_tokens"]:
                raise ValueError()
            self.last_stats = stats
        except (ValueError, TypeError):
            raise AdvisoryError("RUNNER_STATS_PROTOCOL") from None
        if stats["generated_tokens"] >= c["max_new_tokens"] - 1:
            raise AdvisoryError("RUNNER_TOKEN_LIMIT")
        # Never fish a WHY line out of mixed output: validator sees all generation.
        for ending in ("<|eot_id|>", "<|end_of_text|>"):
            if output.rstrip().endswith(ending):
                output = output.rstrip()[:-len(ending)]
        output = output.strip()
        if not output:
            raise AdvisoryError("RUNNER_EMPTY_OUTPUT")
        return output
