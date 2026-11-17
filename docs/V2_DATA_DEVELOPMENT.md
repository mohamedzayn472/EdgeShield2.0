# V2 synthetic development data

`data/synthetic/v2_development.jsonl` contains **432 AI-assisted synthetic messages** written for development. They are not collected SMS, team-verified examples of real fraud, or an independent test set. The authoring script does not open the original corpus or any fresh holdout.

## How the examples were made

`scripts/create_v2_development.py` defines 72 explicit families. Each has a stable context and six controlled variations, such as different reasons given for a transaction notice or a request to reveal a secret. Variations stay together; changing a reason does not make a message an independent observation. Company names are fictional, links use `.example`, and codes are synthetic.

There are 48 training families, eight calibration families and sixteen validation families. Every split contains equal numbers of English and Romanized Hindi/English messages, and equal legitimate/scam labels within each language. That gives 288 training, 48 calibration and 96 validation rows. Family IDs are unique across splits.

The legitimate examples include receipts, OTP notifications, completed payments, branch-based KYC reminders, parcel updates, recruitment scheduling and security warnings. The scam examples contain explicit secret-sharing requests, payment approvals falsely presented as receiving money, personal-wallet advance fees, credential collection, remote banking control or coercive transfers. We avoided labelling short ambiguous reminders as confirmed fraud. No null-labelled examples are included in this version.

Some legitimate notices mention the same terms as scam requests. Examples include warnings not to share an OTP, requests not to approve unknown collect payments, and delivery-code sharing limited to a verified package handover. This is intentional. A bank or OTP keyword should not decide the label by itself.

## Schema and reproducibility

Each JSONL record contains `id`, `text`, `label`, `language`, `family`, `split` and `source`. Labels are `0` for authored legitimate scenarios and `1` for authored scam scenarios. Languages are `english` and `hinglish`. The source is always `synthetic_ai_assisted`.

Run from the repository root:

```powershell
.venv\Scripts\python.exe scripts/create_v2_development.py
```

On Linux, use the active environment's `python` command with the same script. The script writes only the v2 development JSONL and prints its checksum and counts. It rejects duplicate family names, exact canonical duplicate texts, oversized messages and unexpected split balance. The training pipeline must also run its cross-split near-duplicate checker; family separation alone does not prove lexical independence.

## Use and limitations

Use train rows to fit the candidate detector, calibration rows only for the stated calibration procedure, and validation rows for model/threshold decisions. These roles are fixed in the records. Do not silently reshuffle families or use fresh holdout results to revise this corpus.

The balanced composition is a development choice, not an estimate of message prevalence. Repeated sentence structures, shared author style and deliberately explicit scam mechanics make this corpus easier and narrower than real messages. Hinglish wording does not cover all dialects, scripts or code-switching patterns. Validation performance here can guide development but cannot establish real-world scam accuracy or replace a genuinely separate evaluation.
