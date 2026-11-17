# Data and ML primary sources

Accessed 2026-11-15 (research), implementation/evaluation protocol written 2026-11-16.

- [VERIFIED] UCI SMS Spam Collection dataset 228: https://archive.ics.uci.edu/dataset/228/sms+spam+collection . Describes binary spam/ham research corpus, attribution and CC BY 4.0 license. Public download https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip . Downloaded locally through root agent. Parsed counts and checksum are measured, not copied from website.
- [VERIFIED] TF-IDF API: https://scikit-learn.org/stable/modules/generated/sklearn.feature_extraction.text.TfidfVectorizer.html . Supports word n-grams, sublinear TF, vocabulary and learned IDF. Stable page retrieved version 1.9.1; host implementation tested against installed 1.7.2, not presumed identical for every API.
- [VERIFIED] Logistic regression API: https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html . Balanced class weighting, solver and regularization settings supported by host tests.
- [VERIFIED] Grouped stratification: https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.StratifiedGroupKFold.html . Keeps groups disjoint while attempting class balance.
- [VERIFIED] Probability calibration: https://scikit-learn.org/stable/modules/calibration . Logistic regression does not guarantee calibrated probabilities; calibration needs distinct fitting data and appropriate evaluation. Brier loss combines calibration and discrimination effects.
- [REASONED] Train sigmoid calibration on a separate partition and retain only if both validation Brier/log loss improve. Use validation-only selective thresholds. These are project decisions, not official competition mandates.
- [UNVERIFIED] Real-world modern Indian scam prevalence, domain generalization and effectiveness: no representative dataset or user study exists in this project.
