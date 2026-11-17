"""Reproducible grouped data splits and explicit leakage checks."""
import hashlib
import json
import re
from pathlib import Path
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.neighbors import NearestNeighbors
from .privacy import normalize_sms

SEED = 20261115


def canonical(text):
    text = normalize_sms(text).casefold()
    text = re.sub(r"https?://\S+|www\.\S+", " URL ", text)
    text = re.sub(r"\d+", " N ", text)
    return " ".join(re.findall(r"\w+", text))


def group_near_duplicates(rows, similarity=0.90):
    normalized = [canonical(row["text"]) for row in rows]
    parent = list(range(len(rows)))
    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    def join(a, b):
        parent[find(b)] = find(a)
    seen = {}
    for i, text in enumerate(normalized):
        if text in seen:
            join(i, seen[text])
        seen[text] = i
    matrix = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=50000).fit_transform(normalized)
    neighbors = NearestNeighbors(metric="cosine", algorithm="brute", n_jobs=1).fit(matrix)
    for start in range(0, len(rows), 128):
        matches = neighbors.radius_neighbors(matrix[start:start+128], radius=1-similarity, return_distance=False)
        for offset, indices in enumerate(matches):
            for j in indices:
                join(start+offset, int(j))
    return [find(i) for i in range(len(rows))]


def split_rows(rows):
    groups = group_near_duplicates(rows)
    y = [row["label"] for row in rows]
    folds = StratifiedGroupKFold(n_splits=10, shuffle=True, random_state=SEED)
    for fold, (_, indices) in enumerate(folds.split(np.zeros(len(rows)), y, groups)):
        split = "test" if fold < 2 else "validation" if fold < 4 else "calibration" if fold == 4 else "train"
        for i in indices:
            rows[i]["split"] = split
            rows[i]["group"] = str(groups[i])
    check_leakage(rows)
    return rows


def check_leakage(rows):
    groups, texts, families = {}, {}, {}
    for row in rows:
        for bucket, key in ((groups, row.get("group")), (texts, canonical(row["text"])), (families, row.get("family"))):
            if key is None:
                continue
            if key in bucket and bucket[key] != row["split"]:
                raise ValueError("Cross-split leakage detected")
            bucket[key] = row["split"]


def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line]


def write_jsonl(path, rows):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
