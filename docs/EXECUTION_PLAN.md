# Execution plan — 15 November 2026

The newer master build request supersedes the older prompt's proposal-only installments.
Preserve both source prompts; implement terminal-first with no automatic SMS actions.

1. Inspect repository and verify official requirements. Initial workspace: architecture prompt only, no Git repository or source.
2. Provision isolated Python; implement detector/data pipeline, evidence firewall, strict explanation validation, CLI and tests.
3. Verify ExecuTorch upstream interfaces; prepare bounded local runner and deployment scripts. Licensed model and physical Pi are external gates.
4. Train using training data; compare calibration and select thresholds without test access. Freeze code before a single final heldout evaluation.
5. Run adversarial/privacy/integration tests and host benchmark. Package only verified local artifacts and document missing assets.
6. Reconcile status, report, demo and submission content with actual results.

## Device schedule and owners

- 15–16 Nov: AI student owns detector and validation; VLSI students own runtime/export and Pi OS provisioning.
- 17 Nov: genuine host ExecuTorch inference after licensed checkpoint and Linux host become available.
- 18–19 Nov: Pi4 compatibility, end-to-end inference, offline trace and sustained performance.
- 20 Nov: intended submission code freeze; any changes require a new evaluation version, not silent retuning on heldout results.
- 21 Nov: report, clarity study and video using real device outputs.
- 22 Nov: internal submission, preceding verified official 23 Nov deadline.

Cut order: dashboard; URL/network extensions; cosmetic work; performance optimizations beyond reliable inference.
Do not cut actual Arm ExecuTorch inference, offline evidence, evaluation, report, video or source repository.
