EDGESHIELD V8 - RASPBERRY PI 5 HANDOVER
=======================================

1. VERIFIED HARDWARE
Board: Raspberry Pi 5 Model B Rev 1.1
CPU: Quad-core ARM Cortex-A76
Architecture: aarch64
RAM: 16 GiB
OS: Debian GNU/Linux 13 (Trixie)
Python: 3.13.5
Temperature at final check: 62 C
Throttling status: 0x0

2. DETECTOR
Model: edgeshield-word-char-lr-v8
Model file: models/detector_v8.json
SHA256:
4d3481555460d2bf5dfaf5e28fc107786f38ea34400358e4637b5bd9b0afd365

Quality status:
EXPERIMENTAL_SYNTHETIC_TRAINED

Important:
The model's risk scores are not calibrated against real-world data.
The test results are functional experiments, not real-world accuracy measurements.

3. INSTALLATION
On a compatible Raspberry Pi 5, extract the project and run:

cd edgeshield
bash deploy/pi5/setup.sh --offline

4. RUN A SINGLE MESSAGE
printf '%s\n' 'Your bank account will be blocked. Share your OTP.' \
  | .venv/bin/python -m edgeshield.cli --stdin --json

5. RUN THE BATCH TEST
.venv/bin/python batch_test.py

6. TEST RECORD
Five batch runs were completed.
Each run processed 10 messages.
Total detections: 50

Classification totals:
SCAM: 25
LEGITIMATE: 20
UNCERTAIN: 5

Average detector latency: 2.4321 ms
Minimum detector latency: 2.2172 ms
Maximum detector latency: 5.0981 ms

Detailed logs are in test_logs/run_1.txt through run_5.txt.

7. KNOWN LIMITATION
The Llama explanation runtime is not configured.
The CLI currently uses template fallback explanations:
RUNTIME_NOT_CONFIGURED

The detector works without the Llama runtime.

8. IMPORTANT
The five batches repeat the same 10 synthetic test messages.
They do not represent 50 independent real-world samples.
The new recipient should independently verify the hardware setup,
model checksum, and test results on their own device.
