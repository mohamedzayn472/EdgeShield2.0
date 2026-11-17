> Ubuntu continuation (17 November 2026): model identity, `.pte` export (`llama3_2.pte`), native x86_64 `llama_main` execution (`10/10` benchmark, `20/20` comparison, `432/432` dev & `132/132` holdout prompt acceptance), and Bookworm-compatible `aarch64` cross-compilation (`arm-gnu-toolchain-12.2.rel1`, `GLIBC <= 2.34`) are now verified on the Ubuntu host. See [ARGON_COMPLETION_REPORT.md](ARGON_COMPLETION_REPORT.md), [OPUS_TO_ARGON_HANDOFF.md](OPUS_TO_ARGON_HANDOFF.md), and [UBUNTU_VERIFICATION.md](UBUNTU_VERIFICATION.md). Physical Pi 4 execution remains `PENDING_HARDWARE`. Earlier Windows blockers below are historical.

# ExecuTorch integration and outstanding gate

Status: adapter HOST TESTS passed (`176 passed, 1 skipped`); model export and genuine Ubuntu x86_64 host inference `VERIFIED`; Bookworm-compatible Pi 4 `aarch64` binaries cross-compiled and audited (`VERIFIED` on host); physical Pi 4 inference `PENDING_HARDWARE`. No checkpoint, tokenizer, `.pte`, runner binary, or Llama output has been fabricated.

Update, 16 November: the user now reports downloading Llama in this laptop's dual-boot Linux installation. The exact checkpoint name/path and approval state have not been inspected from Windows. Treat the earlier missing-download statement as historical; file compatibility, export and inference remain unverified. The Pi4 is available but setup must wait for the lab visit.

## Verified upstream configuration

Selected release/1.5 commit: `985c1ceccc8bb8b6a32294f71aeb5d2f299562f7`. The official GitHub API response and audited source copies are under `executorch/references/`; source copies retain upstream copyright and the upstream LICENSE is included there. Read [source findings](SOURCES_RUNTIME.md).

The selected upstream setup script accepts `pi4` and selects `-march=armv8-a -mtune=cortex-a72`. The Pi5 build uses newer CPU instructions and must not be substituted. This source verification does not establish that the resulting binary or its XNNPACK kernels actually run on a Pi4.

The selected export YAML uses prequantized SpinQuant, group size 32, 8-bit dynamic activations and 4-bit weights with separately configured embedding/output quantization. It enables XNNPACK extended operators, KV cache and a 2048-token context. The source is audited, but the actual supported operators, memory requirement and checkpoint compatibility remain untested until export and inference execute.

Target checkpoint is the official [Meta Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8](https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8). Its model card requires gated access and license acceptance. Obtain the matching original-format `consolidated.00.pth`, `params.json`, and `tokenizer.model` after approval, record their source revision and SHA-256, and inspect the actual parameter shapes. A base/non-Instruct model or ordinary unquantized checkpoint is not interchangeable with this prequantized export. Do not rename `tokenizer.json` to `.model`; format compatibility is not established by the filename.

## Reproduction on a separate Linux export host

Prerequisites: Linux x86_64, CMake 3.26+, git, a supported Python environment, compiler/build tools and sufficient disk/RAM for the upstream export. Upstream tools perform downloads during provisioning. No model acquisition occurs in the EdgeShield app.

```bash
git clone https://github.com/pytorch/executorch.git build/executorch
cd build/executorch
git checkout 985c1ceccc8bb8b6a32294f71aeb5d2f299562f7
git submodule update --init --recursive
python3 -m venv .venv
source .venv/bin/activate
./install_executorch.sh
# Capture pip freeze and build logs into a private build record.
export LLAMA_LICENSE_ACCEPTED=yes  # only after actual approval and license review
export LLAMA_QUANTIZED_CHECKPOINT=/absolute/approved/consolidated.00.pth
export LLAMA_PARAMS=/absolute/approved/params.json
bash /absolute/edgeshield/scripts/export_llama.sh
# Cross-build in a separate build tree from any native host runtime.
bash examples/raspberry_pi/setup.sh pi4
```

The export wrapper refuses a different commit, missing inputs or existing output. It checks the generated `.pte` exists and hashes it; this is not an inference test. Save checkpoint revision, export environment lock, command log and params alongside the deployment provenance record. This workflow has not been executed here because approved weights and the Linux toolchain are unavailable. Upstream downloads/toolchain checks may fail; never bypass a checksum failure. Verify the toolchain against Arm's official distribution metadata.

Copy the resulting `llama3_2.pte`, matching `tokenizer.model`, `cmake-out/examples/models/llama/llama_main` and `cmake-out/examples/models/llama/runner/libllama_runner.so` into the EdgeShield `models/llama/` directory. Include any additional required shared libraries only after inspecting the target loader dependencies and distribution terms. `libextension_module.a` is linked during build; it is not a runtime shared library. Retain all model notices and the applicable license when distributing Llama materials; the current bundle excludes them.

## Runner contract and safety

`ExecuTorchAdvisor(config_path).generate(prompt)` receives the already-framed evidence-only Llama3 prompt. It does not inspect raw SMS or add a second chat template. The audited main accepts `--model_path`, `--tokenizer_path`, `--max_new_tokens`, `--cpu_threads`, `--temperature` and `--prompt`. Default settings request 48 new tokens, two CPU threads and greedy sampling. The exported model context is 2048; `seq_len` is retained for compatibility but upstream prioritizes `max_new_tokens`. Measure actual tokenizer length before deploying any enlarged prompt.

The pinned runner echoes the prompt, writes generation, then emits a terminal `PyTorchObserver` numeric JSON report. The adapter requires an exact prompt prefix and valid final report. It never extracts a plausible WHY line from arbitrary output. All generated text reaches the validator. A missing/changed protocol, invalid UTF-8, timeout, child failure, exhausted generation budget or excessive combined stdout/stderr causes sanitized failure and the application falls back. Numeric report data are exposed as `last_stats`; they are not proof of correctness. No runtime stdout/stderr is written to disk by the adapter.

Manifest hashes are checked before every launch. The manifest itself must be trusted and protected alongside the executable. It is not a signed provenance attestation, and cannot protect against an attacker who changes both the manifest and artifacts. Shared-library loading is restricted to declared local directories and inherited preload variables are removed; system libraries still belong to the OS trust boundary. A hostile binary can do anything the local user can; hashes do not sandbox native code. The adapter assumes the verified upstream runner does not spawn descendants: timeout kills the direct process, not arbitrary descendant trees.

One runner process is started per message. It reloads model weights each time. The measured Llama wall time therefore includes startup, integrity checks, loading, prefill and decode. Persistent inference is deferred until a measured bottleneck justifies a supported integration. Detector verdict/advice are printed before this blocking advisory call; the terminal cannot accept another message during generation. No claimed responsiveness beyond that sequence.

## Actual verification (updated 17 November 2026)

- `bash scripts/host_python.sh -m pytest tests/test_runtime.py -q` exercises real child-process timeout, output bounding, error sanitization, and adapter protocol tests (`VERIFIED`).
- Genuine Ubuntu x86_64 `.pte` export (`build/executorch/llama3_2.pte`, `1,075,142,912` bytes, SHA-256 `c31e4d376f349de85b4422a8c0405d88f21145709f0e17168b06d809ffe5e8a2`) and pybind/native `llama_main` inference verified (`results/host/ubuntu/llama_host_smoke_v2.json`, `llama_prompt_v2_development.json` `432/432`, `llama_prompt_v2_holdout.json` `132/132`, `twenty_case_llama_vs_template.json` `20/20`, `benchmark_llama_threads2.json` `10/10`, `benchmark_argon_llama.json` `5/5`, `cli_llama_smoke.jsonl`, `demo_ubuntu_llama.txt`) (`VERIFIED` on Ubuntu x86_64).
- Bookworm-compatible Pi 4 `aarch64` cross-compilation verified with Arm GNU Toolchain `12.2.rel1` (`-march=armv8-a -mtune=cortex-a72`, KleidiAI & Armv8.2+/Armv9 extensions disabled; `pi4_bookworm_cross_build.log` & `pi4_bookworm_binary_audit.json`, max `GLIBC_2.34` and `GLIBCXX_3.4.30`, zero `GLIBC > 2.36` symbols). Note that upstream `setup.sh` with `14.3.rel1` produced `GLIBC_2.38` binaries (`models/llama/pi4-aarch64-glibc238/`, `pi4_binary_audit.json`) which would fail on Bookworm.
- Physical Pi 4 execution, `vcgencmd` thermal/throttled behavior, and disconnected Pi 4 `strace` verification remain `PENDING_HARDWARE`.

Arm-Examples LLM-Runner was reviewed as a reference, but is not used. Its current README pins a different ExecuTorch release and defaults to another backend; adopting it without an explicit ExecuTorch configuration would not satisfy this project's chosen integration.
