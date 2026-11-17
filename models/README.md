# Model artifacts

The default is now `detector_v2.json` with its checksum sidecar. It combines word and character features, UCI training data and explicitly synthetic examples. Read `docs/V2_RESULTS.md`; passing synthetic checks does not establish real-world protection. The original `detector.json` is retained as v1.

`detector.json` is the trained text detector in non-executable JSON form; its adjacent
SHA-256 file detects accidental changes when compared against a trusted copy.
It estimates a spam-derived risk proxy, not real-world scam probability.

Llama weights, tokenizer, `.pte`, runner and shared libraries are not included.
The user confirmed on 15 November 2026 that no approved checkpoint/tokenizer is downloaded.
See `docs/EXECUTORCH.md` for acquisition and export steps. Never substitute dummy weights.
Preserve the applicable Llama license and attribution when acquiring or redistributing artifacts.

Host virtual environments and compiled Windows packages cannot be copied to a Pi as dependencies.
