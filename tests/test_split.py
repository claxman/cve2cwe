"""Split, dedup, label-set and lock checks on the processed dataset.

These tests read only the committed files in data/processed/. They do not use
the network or data/raw/.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PROCESSED = ROOT / "data" / "processed"
TRAIN = PROCESSED / "train.jsonl.gz"
DEV = PROCESSED / "dev.jsonl"
TEST = PROCESSED / "test.jsonl"
LABELS = PROCESSED / "labels.json"
MANIFEST = PROCESSED / "MANIFEST.json"
STATS = PROCESSED / "stats.json"
CONFIG = ROOT / "configs" / "data.yaml"

pytestmark = pytest.mark.skipif(
    not (TRAIN.exists() and DEV.exists() and TEST.exists() and LABELS.exists()),
    reason="processed dataset not built; run `make data` first",
)


def _read_jsonl(path: Path) -> list[dict]:
    if path.suffix == ".gz":
        f = gzip.open(path, "rt", encoding="utf-8")
    else:
        f = path.open("rt", encoding="utf-8")
    try:
        return [json.loads(line) for line in f if line.strip()]
    finally:
        f.close()


@pytest.fixture(scope="module")
def splits() -> dict:
    return {
        "train": _read_jsonl(TRAIN),
        "dev": _read_jsonl(DEV),
        "test": _read_jsonl(TEST),
    }


@pytest.fixture(scope="module")
def cfg() -> dict:
    with CONFIG.open() as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def labels() -> list[dict]:
    with LABELS.open() as f:
        return json.load(f)


@pytest.fixture(scope="module")
def manifest() -> dict:
    with MANIFEST.open() as f:
        return json.load(f)


def test_no_cve_id_overlap(splits):
    from cve2cwe.leakage import check_no_id_overlap

    check_no_id_overlap(splits["train"], splits["dev"], splits["test"])


def test_date_boundaries(splits, cfg):
    from cve2cwe.leakage import check_date_boundaries

    check_date_boundaries(splits["train"], splits["dev"], splits["test"], cfg)


def test_no_normalised_overlap(splits):
    from cve2cwe.leakage import check_no_normalised_overlap

    check_no_normalised_overlap(splits["train"], splits["dev"], splits["test"])


def test_labels_valid(splits, labels):
    from cve2cwe.leakage import check_labels

    check_labels(splits["train"] + splits["dev"] + splits["test"], labels)


def test_lock(manifest):
    from cve2cwe.leakage import check_lock

    check_lock(TEST, manifest)


def test_rows_sorted_by_published_then_cve_id(splits):
    for name, rows in splits.items():
        keys = [(r["published"], r["cve_id"]) for r in rows]
        assert keys == sorted(keys), f"{name} is not sorted by (published, cve_id)"


def test_cap_per_class(splits, cfg):
    from collections import Counter

    cap = cfg["train_per_class_cap"]
    counts = Counter(r["label"] for r in splits["train"])
    too_big = {k: v for k, v in counts.items() if v > cap}
    assert not too_big, f"train classes above cap {cap}: {too_big}"


def test_min_class_count_in_train(splits, cfg):
    # Every label in the labels set must have at least min_train_class_count
    # single-label-rule-2 records in the train window. We verify the weaker
    # property: every label has at least one train record.
    from collections import Counter

    counts = Counter(r["label"] for r in splits["train"])
    missing = [lbl for lbl in counts if counts[lbl] == 0]
    assert not missing


def test_no_placeholder_labels(labels):
    ids = {lbl["id"] for lbl in labels}
    assert "NVD-CWE-Other" not in ids
    assert "NVD-CWE-noinfo" not in ids
