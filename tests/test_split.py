"""Split, dedup, label-set and lock checks.

The first group are unit tests on a small synthetic fixture: no files, no
network. They exercise `split_by_date`, `pick_label_set`, `dedup` and
`cap_train` and must always run.

The second group reads the committed files in `data/processed/` and is
skipped when the dataset has not been built yet.
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

needs_processed = pytest.mark.skipif(
    not (TRAIN.exists() and DEV.exists() and TEST.exists() and LABELS.exists()),
    reason="processed dataset not built; run `make data` first",
)


# ---------------------------------------------------------------------------
# Unit tests on a synthetic in-memory fixture.
# ---------------------------------------------------------------------------


def _rec(cve_id: str, published: str, description: str, label: str) -> dict:
    """Minimal record shaped like what the pipeline passes between stages."""
    return {
        "cve_id": cve_id,
        "published": published,
        "description": description,
        "label": label,
    }


def test_split_by_date_puts_records_in_the_right_window():
    from cve2cwe.data import split_by_date

    cfg = {"train_end": "2025-10-01", "test_start": "2026-04-15"}
    records = [
        _rec("CVE-A", "2025-01-01T00:00:00", "a", "CWE-1"),  # train
        _rec("CVE-B", "2025-09-30T23:59:59", "b", "CWE-1"),  # train
        _rec("CVE-C", "2025-10-01T00:00:00", "c", "CWE-1"),  # dev (boundary)
        _rec("CVE-D", "2026-04-14T23:59:59", "d", "CWE-1"),  # dev
        _rec("CVE-E", "2026-04-15T00:00:00", "e", "CWE-1"),  # test (boundary)
        _rec("CVE-F", "2026-06-01T00:00:00", "f", "CWE-1"),  # test
    ]
    train, dev, test = split_by_date(records, cfg)
    assert [r["cve_id"] for r in train] == ["CVE-A", "CVE-B"]
    assert [r["cve_id"] for r in dev] == ["CVE-C", "CVE-D"]
    assert [r["cve_id"] for r in test] == ["CVE-E", "CVE-F"]


def test_pick_label_set_excludes_classes_below_minimum():
    from cve2cwe.data import pick_label_set

    cfg = {"min_train_class_count": 2}
    train = [
        _rec("T1", "2025-01-01", "x", "CWE-1"),
        _rec("T2", "2025-01-02", "x", "CWE-1"),
        _rec("T3", "2025-01-03", "x", "CWE-2"),  # only one of CWE-2: excluded
        _rec("T4", "2025-01-04", "x", "CWE-3"),
        _rec("T5", "2025-01-05", "x", "CWE-3"),
        _rec("T6", "2025-01-06", "x", "CWE-3"),
    ]
    assert pick_label_set(train, cfg) == ["CWE-1", "CWE-3"]


def test_dedup_rules_cross_and_within_split():
    from cve2cwe.data import dedup

    train = [
        # Within-train duplicate: same normalised description as T2.
        # T2 is more recent, so T2 is kept and T1 is dropped.
        _rec("T1", "2025-01-01", "Use after free in parser", "CWE-416"),
        _rec("T2", "2025-06-01", "Use after free in parser", "CWE-416"),
        # Matches a test record: must be dropped from train.
        _rec("T3", "2025-03-01", "SQL injection in login form", "CWE-89"),
        # Unique to train: must survive.
        _rec("T4", "2025-04-01", "Path traversal in asset loader", "CWE-22"),
        # Matches a dev record: must be dropped from train.
        _rec("T5", "2025-05-01", "Buffer overflow in audio decoder", "CWE-120"),
    ]
    dev = [
        # Same normalised text as a test record: dev drops this.
        _rec("D1", "2025-12-01", "Command injection in setup script", "CWE-77"),
        # Shared with T5 in train: dev keeps it (train is the side that drops).
        _rec("D2", "2025-11-01", "Buffer overflow in audio decoder", "CWE-120"),
        # Unique to dev: survives.
        _rec("D3", "2025-11-15", "Only in dev split", "CWE-78"),
    ]
    test = [
        # Matches D1 in dev: test keeps it.
        _rec("TE1", "2026-05-01", "Command injection in setup script", "CWE-77"),
        # Matches T3 in train: test keeps it.
        _rec("TE2", "2026-06-01", "SQL injection in login form", "CWE-89"),
        # Unique to test.
        _rec("TE3", "2026-06-15", "Only in test split", "CWE-22"),
    ]

    train_out, dev_out, test_out, counts = dedup(train, dev, test)

    train_ids = {r["cve_id"] for r in train_out}
    dev_ids = {r["cve_id"] for r in dev_out}
    test_ids = {r["cve_id"] for r in test_out}

    # Test never loses a record in dedup.
    assert test_ids == {"TE1", "TE2", "TE3"}

    # Dev drops only the record that matches a test record.
    assert dev_ids == {"D2", "D3"}

    # Train drops cross-split matches (T3 vs TE2, T5 vs D2) and the older
    # within-train duplicate (T1, kept T2 since it is newer).
    assert train_ids == {"T2", "T4"}

    assert counts["rule_5_dev_dropped_equals_test"] == 1
    assert counts["rule_5_train_dropped_equals_dev_or_test"] == 2
    assert counts["rule_5_train_within_dropped"] == 1


def test_cap_train_keeps_the_most_recent_per_class():
    from cve2cwe.data import cap_train

    train = [
        _rec("A1", "2025-01-01", "a1", "CWE-1"),
        _rec("A2", "2025-02-01", "a2", "CWE-1"),
        _rec("A3", "2025-03-01", "a3", "CWE-1"),
        _rec("A4", "2025-04-01", "a4", "CWE-1"),  # most recent of CWE-1
        _rec("B1", "2025-05-01", "b1", "CWE-2"),  # only one of CWE-2
    ]
    kept, dropped = cap_train(train, cap=2)
    kept_ids = {r["cve_id"] for r in kept}
    # CWE-1: the two most recent are A3 and A4. CWE-2: B1 kept.
    assert kept_ids == {"A3", "A4", "B1"}
    assert dropped == 2


# ---------------------------------------------------------------------------
# Integration tests over the committed dataset.
# ---------------------------------------------------------------------------


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


@needs_processed
def test_no_cve_id_overlap(splits):
    from cve2cwe.leakage import check_no_id_overlap

    check_no_id_overlap(splits["train"], splits["dev"], splits["test"])


@needs_processed
def test_date_boundaries(splits, cfg):
    from cve2cwe.leakage import check_date_boundaries

    check_date_boundaries(splits["train"], splits["dev"], splits["test"], cfg)


@needs_processed
def test_no_normalised_overlap(splits):
    from cve2cwe.leakage import check_no_normalised_overlap

    check_no_normalised_overlap(splits["train"], splits["dev"], splits["test"])


@needs_processed
def test_labels_valid(splits, labels, cfg):
    from cve2cwe.leakage import check_labels

    check_labels(splits["train"] + splits["dev"] + splits["test"], labels, cfg)


@needs_processed
def test_lock(manifest):
    from cve2cwe.leakage import check_lock

    check_lock(TEST, manifest)


@needs_processed
def test_rows_sorted_by_published_then_cve_id(splits):
    for name, rows in splits.items():
        keys = [(r["published"], r["cve_id"]) for r in rows]
        assert keys == sorted(keys), f"{name} is not sorted by (published, cve_id)"


@needs_processed
def test_cap_per_class(splits, cfg):
    from collections import Counter

    cap = cfg["train_per_class_cap"]
    counts = Counter(r["label"] for r in splits["train"])
    too_big = {k: v for k, v in counts.items() if v > cap}
    assert not too_big, f"train classes above cap {cap}: {too_big}"


@needs_processed
def test_no_placeholder_labels(labels, cfg):
    placeholders = set(cfg.get("placeholder_labels", []))
    ids = {lbl["id"] for lbl in labels}
    assert not (ids & placeholders), f"labels contain placeholders: {ids & placeholders}"
