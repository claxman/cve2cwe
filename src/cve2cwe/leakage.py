"""Leakage and lock checks for the processed dataset (DESIGN.md section 4.4)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cve2cwe.data import normalise


class LeakageError(RuntimeError):
    pass


def check_no_id_overlap(train: list[dict], dev: list[dict], test: list[dict]) -> None:
    sets = {
        "train": {r["cve_id"] for r in train},
        "dev": {r["cve_id"] for r in dev},
        "test": {r["cve_id"] for r in test},
    }
    pairs = [("train", "dev"), ("train", "test"), ("dev", "test")]
    for a, b in pairs:
        shared = sets[a] & sets[b]
        if shared:
            example = next(iter(shared))
            raise LeakageError(
                f"cve_id overlap between {a} and {b}: {len(shared)} ids; example {example}"
            )


def check_date_boundaries(
    train: list[dict], dev: list[dict], test: list[dict], cfg: dict[str, Any] | None = None
) -> None:
    if cfg is None:
        with (Path(__file__).resolve().parents[2] / "configs" / "data.yaml").open() as f:
            import yaml

            cfg = yaml.safe_load(f)
    if train:
        newest_train = max(r["published"][:10] for r in train)
    else:
        newest_train = cfg["train_end"]
    if dev:
        oldest_dev = min(r["published"][:10] for r in dev)
        newest_dev = max(r["published"][:10] for r in dev)
    else:
        oldest_dev = cfg["train_end"]
        newest_dev = cfg["train_end"]
    if test:
        oldest_test = min(r["published"][:10] for r in test)
    else:
        oldest_test = cfg["test_start"]

    if not (newest_train < oldest_dev):
        raise LeakageError(
            f"date boundary train/dev: newest train {newest_train} >= oldest dev {oldest_dev}"
        )
    if not (newest_dev < oldest_test):
        raise LeakageError(
            f"date boundary dev/test: newest dev {newest_dev} >= oldest test {oldest_test}"
        )
    if oldest_dev != cfg["train_end"]:
        # Boundary might be reached only approximately if no record exists at the first day.
        if oldest_dev < cfg["train_end"]:
            raise LeakageError(
                f"dev starts before configured train_end: {oldest_dev} < {cfg['train_end']}"
            )
    if oldest_test < cfg["test_start"]:
        raise LeakageError(
            f"test starts before configured test_start: {oldest_test} < {cfg['test_start']}"
        )


def check_no_normalised_overlap(
    train: list[dict], dev: list[dict], test: list[dict]
) -> None:
    def norms(xs: list[dict]) -> set[str]:
        return {normalise(r["description"]) for r in xs}

    t_norms = norms(train)
    d_norms = norms(dev)
    te_norms = norms(test)
    for a, A, b, B in [
        ("train", t_norms, "dev", d_norms),
        ("train", t_norms, "test", te_norms),
        ("dev", d_norms, "test", te_norms),
    ]:
        shared = A & B
        if shared:
            raise LeakageError(
                f"normalised-text overlap between {a} and {b}: {len(shared)} items"
            )


def check_labels(
    records: list[dict], labels: list[dict], cfg: dict[str, Any] | None = None
) -> None:
    if cfg is None:
        with (Path(__file__).resolve().parents[2] / "configs" / "data.yaml").open() as f:
            import yaml

            cfg = yaml.safe_load(f)
    placeholders = set(cfg.get("placeholder_labels", []))
    ids = {lbl["id"] for lbl in labels}
    if ids & placeholders:
        raise LeakageError(f"labels contain placeholders: {ids & placeholders}")
    for r in records:
        if r["label"] in placeholders:
            raise LeakageError(f"record {r['cve_id']} carries placeholder label {r['label']}")
        if r["label"] not in ids:
            raise LeakageError(f"record {r['cve_id']} label {r['label']} not in labels.json")


def check_lock(test_path: Path, manifest: dict | None = None) -> None:
    if manifest is None:
        with (test_path.parent / "MANIFEST.json").open() as f:
            manifest = json.load(f)
    expected = manifest["processed"]["test.jsonl"]["sha256"]
    h = hashlib.sha256()
    with test_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    got = h.hexdigest()
    if got != expected:
        raise LeakageError(
            f"test.jsonl sha256 mismatch: manifest={expected} actual={got}"
        )


def run_all(
    train: list[dict],
    dev: list[dict],
    test: list[dict],
    labels: list[dict],
    test_path: Path,
    manifest: dict,
    cfg: dict[str, Any],
) -> None:
    check_no_id_overlap(train, dev, test)
    check_date_boundaries(train, dev, test, cfg)
    check_no_normalised_overlap(train, dev, test)
    check_labels(train + dev + test, labels, cfg)
    check_lock(test_path, manifest)
    print("[leakage] all checks passed")
