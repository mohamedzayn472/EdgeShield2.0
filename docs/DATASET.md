# Dataset and model card

The baseline is trained on UCI SMS Spam Collection, attributed to Almeida, T. & Hidalgo, J. (2011), DOI 10.24432/C5CC84. The official dataset page identifies CC BY 4.0 licensing. The downloaded archive and processed partitions are local development data, excluded from the distributable application and source bundle; reacquire with the documented public URL. UCI contains historical public messages that can include identifiers. Do not use it as demo SMS or put its raw contents into logs.

`scripts/prepare_dataset.py` reads only the named ZIP member, normalizes input and constructs group-exclusive partitions. SHA-256 of the actual archive, observed row counts, and partition class counts are in `data/processed/manifest.json`. Do not substitute the website's advertised row count for the parsed count. Normalization failures are counted and skipped.

The TF-IDF vocabulary is learned solely from the training split. Serialized weights are plain JSON, not pickle, and loading verifies a SHA-256 sidecar. This catches accidental changes, not malicious replacement of both files; distribute a trusted release manifest. Model vocabulary may retain source corpus tokens, so it is not a private-data anonymization technique. No live user SMS is stored or used for training.

`data/synthetic/indian_sms.jsonl` has 36 fictional, AI-assisted project-written cases across 18 families: eight development examples and 28 heldout examples (24 binary-labeled, four ambiguous/adversarial with null labels). It uses reserved `.example` domains, fictional organization names and dummy OTPs. Language and family labels are explicit. This is a small challenge set, not independent human ground truth and not evidence of real-world Indian or Hinglish accuracy. None is used for training or threshold selection. Families do not cross development/test. Ambiguous cases cannot honestly be assigned a supervised binary outcome.

This implementation reports UCI and synthetic results separately; it does not claim a synthetic-augmented trained detector. A future augmented model requires an independently frozen protocol and heldout set. The current classifier detects a historical spam proxy, not authenticated fraud, sender identity, malware, URL reputation or network intrusion.

Reproduce from repository root:

```powershell
New-Item -ItemType Directory -Force data/raw | Out-Null
Invoke-WebRequest -Uri 'https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip' -OutFile data/raw/uci_sms.zip
.venv\Scripts\python.exe scripts/prepare_dataset.py
.venv\Scripts\python.exe scripts/train_detector.py
```

Linux uses `.venv/bin/python` for these commands. Training requires scikit-learn 1.7.2, NumPy 2.2.6 and SciPy 1.15.3 in this tested host environment. Target installation uses its own compatible wheels, not a copied Windows virtual environment.
