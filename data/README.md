# Data handling

`raw/` and `processed/` are local-only development data; exclude from source publication and deployment archives. Raw UCI data may contain historic personal identifiers. Live user SMS is never written here.

Download: https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip

Attribution: Almeida, T. & Hidalgo, J. (2011). SMS Spam Collection. UCI Machine Learning Repository. https://doi.org/10.24432/C5CC84. Official page declares CC BY 4.0: https://creativecommons.org/licenses/by/4.0/ . Preparation normalizes and partitions the source; these are modifications.

The synthetic JSONL is AI-assisted project-written fictional test data and can accompany the project. See docs/DATASET.md and docs/EVALUATION.md. Test-set access during split integrity checking does not execute classifier evaluation; final metrics require a code freeze.
