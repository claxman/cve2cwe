"""Scoring. Reads prediction files only, never calls a model.

DESIGN section 5. One parser for the whole repo. Invalid counts as wrong in
every metric. All intervals come from the same bootstrap (10,000 resamples,
fixed seed) so runs are reproducible across machines.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

import numpy as np

from cve2cwe import runinfo
from cve2cwe.prompts import REPO_ROOT, load_systems_cfg

# DESIGN section 5: strict parser. Nothing else, no fallbacks.
_CWE_RE = re.compile(r"^CWE-[0-9]+$")


# ---------------------------------------------------------------------------
# Parser and label set helpers.


def load_label_set(path: Path | None = None) -> set[str]:
    path = path or (REPO_ROOT / "data" / "processed" / "labels.json")
    with path.open() as f:
        return {row["id"] for row in json.load(f)}


def parse(raw: str, label_set: set[str]) -> str | None:
    """Return a valid CWE id or None.

    Valid only if, after stripping whitespace, the string matches
    ``^CWE-[0-9]+$`` and is present in ``label_set``. This is the only CWE
    parser in the repo.
    """
    if not isinstance(raw, str):
        return None
    stripped = raw.strip()
    if not _CWE_RE.match(stripped):
        return None
    if stripped not in label_set:
        return None
    return stripped


# ---------------------------------------------------------------------------
# File I/O.


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("rt", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rows.append(json.loads(line))
    return rows


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_split(split: str) -> list[dict]:
    """Return the ordered split rows with cve_id, label, is_kernel, adp_cwes."""
    if split == "dev":
        rows = _read_jsonl(REPO_ROOT / "data" / "processed" / "dev.jsonl")
    elif split == "test":
        rows = _read_jsonl(REPO_ROOT / "data" / "processed" / "test.jsonl")
    else:
        raise ValueError(f"unknown split: {split!r}")
    out = []
    for r in rows:
        out.append(
            {
                "cve_id": r["cve_id"],
                "label": r["label"],
                "is_kernel": bool(r.get("is_kernel", False)),
                "adp_cwes": list(r.get("adp_cwes", [])),
            }
        )
    return out


# ---------------------------------------------------------------------------
# Coverage and lock checks.


def check_coverage(pred_cve_ids: Sequence[str], split_cve_ids: Sequence[str]) -> None:
    """Raise if the prediction set does not exactly match the split set.

    Every cve_id in the split must appear exactly once in the prediction file;
    no duplicates, no extras.
    """
    pred_list = list(pred_cve_ids)
    split_set = set(split_cve_ids)
    pred_set = set(pred_list)
    dupes: list[str] = []
    seen: set[str] = set()
    for cid in pred_list:
        if cid in seen:
            dupes.append(cid)
        seen.add(cid)
    missing = sorted(split_set - pred_set)
    extra = sorted(pred_set - split_set)
    msgs: list[str] = []
    if missing:
        msgs.append(f"missing cve_ids ({len(missing)}): {missing[:5]}")
    if extra:
        msgs.append(f"extra cve_ids ({len(extra)}): {extra[:5]}")
    if dupes:
        msgs.append(f"duplicate cve_ids ({len(dupes)}): {sorted(set(dupes))[:5]}")
    if msgs:
        raise ValueError("prediction coverage failed: " + "; ".join(msgs))


def check_test_lock() -> None:
    """Check data/processed/test.jsonl sha256 against MANIFEST.json."""
    manifest_path = REPO_ROOT / "data" / "processed" / "MANIFEST.json"
    test_path = REPO_ROOT / "data" / "processed" / "test.jsonl"
    with manifest_path.open() as f:
        manifest = json.load(f)
    expected = manifest["processed"]["test.jsonl"]["sha256"]
    actual = _sha256_file(test_path)
    if expected != actual:
        raise ValueError(
            f"test.jsonl sha256 mismatch: expected {expected} got {actual}"
        )


# ---------------------------------------------------------------------------
# Metrics.


def _per_class_prf(gold: np.ndarray, pred: np.ndarray, class_name: str) -> dict:
    """Precision, recall, F1 for one class. Invalid pred (empty string) is
    never counted as a positive prediction for any class, so it contributes
    only to false negatives for the gold class."""
    gold_mask = gold == class_name
    pred_mask = pred == class_name
    tp = int((gold_mask & pred_mask).sum())
    fp = int((~gold_mask & pred_mask).sum())
    fn = int((gold_mask & ~pred_mask).sum())
    support = int(gold_mask.sum())
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "support": support,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _accuracy(correct: np.ndarray) -> float:
    return float(correct.mean()) if correct.size > 0 else 0.0


def compute_metrics(
    predictions: list[dict],
    split_rows: list[dict],
    label_set: set[str],
    macro_f1_min_support: int,
) -> dict:
    """Return the full metrics dict for one (predictions x split) pair.

    ``predictions`` must already be ordered to match ``split_rows`` by
    ``cve_id``. Invalid predictions are counted as wrong everywhere.
    """
    assert len(predictions) == len(split_rows)
    gold = np.array([r["label"] for r in split_rows])
    pred = np.array([(p["parsed"] if p["parsed"] is not None else "") for p in predictions])
    correct = (pred == gold).astype(np.int32)
    invalid = np.array([p["parsed"] is None for p in predictions])

    is_kernel = np.array([r["is_kernel"] for r in split_rows])
    adp = [r["adp_cwes"] for r in split_rows]
    adp_equals = np.array(
        [bool(a) and list(a) == [g] for a, g in zip(adp, gold.tolist(), strict=True)]
    )
    adp_empty = np.array([not a for a in adp])
    adp_diff = ~(adp_equals | adp_empty)

    # Per-class table. Every label in label_set gets a row, even if unseen.
    per_class: dict[str, dict] = {}
    for cls in sorted(label_set):
        per_class[cls] = _per_class_prf(gold, pred, cls)

    # Macro-F1 over classes with support >= threshold in this split.
    kept = [m["f1"] for m in per_class.values() if m["support"] >= macro_f1_min_support]
    macro_f1 = float(np.mean(kept)) if kept else 0.0
    kept_classes = sorted(
        cls for cls, m in per_class.items() if m["support"] >= macro_f1_min_support
    )

    return {
        "n": int(len(predictions)),
        "accuracy": _accuracy(correct),
        "invalid_rate": float(invalid.mean()) if invalid.size > 0 else 0.0,
        "macro_f1": macro_f1,
        "macro_f1_classes": kept_classes,
        "kernel_accuracy": {
            "true": {
                "n": int(is_kernel.sum()),
                "accuracy": _accuracy(correct[is_kernel]),
            },
            "false": {
                "n": int((~is_kernel).sum()),
                "accuracy": _accuracy(correct[~is_kernel]),
            },
        },
        "adp_slices": {
            "equals_label": {
                "n": int(adp_equals.sum()),
                "accuracy": _accuracy(correct[adp_equals]),
            },
            "non_empty_different": {
                "n": int(adp_diff.sum()),
                "accuracy": _accuracy(correct[adp_diff]),
            },
            "empty": {
                "n": int(adp_empty.sum()),
                "accuracy": _accuracy(correct[adp_empty]),
            },
        },
        "per_class": per_class,
        # Useful for the paired bootstrap when two systems share split order.
        "_correct_vector": correct.tolist(),
    }


# ---------------------------------------------------------------------------
# Bootstrap.


def bootstrap_accuracy_ci(
    correct: Sequence[int], n_resamples: int, seed: int
) -> tuple[float, float]:
    """95% bootstrap percentile interval for the mean of ``correct``."""
    arr = np.asarray(correct, dtype=np.int32)
    n = arr.size
    if n == 0:
        return (0.0, 0.0)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, n, size=(n_resamples, n))
    means = arr[idx].mean(axis=1)
    lo = float(np.percentile(means, 2.5))
    hi = float(np.percentile(means, 97.5))
    return (lo, hi)


def paired_bootstrap_diff_ci(
    correct_a: Sequence[int],
    correct_b: Sequence[int],
    n_resamples: int,
    seed: int,
) -> tuple[float, float]:
    """95% paired bootstrap interval for ``mean(correct_a) - mean(correct_b)``.

    The same resampling indices are applied to both systems, so two
    identical systems always return (0.0, 0.0).
    """
    a = np.asarray(correct_a, dtype=np.int32)
    b = np.asarray(correct_b, dtype=np.int32)
    if a.shape != b.shape:
        raise ValueError(f"paired bootstrap shape mismatch: {a.shape} vs {b.shape}")
    n = a.size
    if n == 0:
        return (0.0, 0.0)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, n, size=(n_resamples, n))
    diff = a[idx].mean(axis=1) - b[idx].mean(axis=1)
    lo = float(np.percentile(diff, 2.5))
    hi = float(np.percentile(diff, 97.5))
    return (lo, hi)


# ---------------------------------------------------------------------------
# Prediction directories.


def _load_prediction_dir(pred_dir: Path) -> tuple[dict, list[dict]]:
    """Return (run.json dict, list of prediction dicts) for a directory."""
    run_path = pred_dir / "run.json"
    preds_path = pred_dir / "predictions.jsonl"
    with run_path.open() as f:
        run = json.load(f)
    preds = _read_jsonl(preds_path)
    return run, preds


def _aligned_predictions(preds: list[dict], split_rows: list[dict]) -> list[dict]:
    """Return predictions reordered to match ``split_rows`` by cve_id."""
    by_id = {p["cve_id"]: p for p in preds}
    return [by_id[r["cve_id"]] for r in split_rows]


def assert_reparse_matches(predictions: list[dict], label_set: set[str]) -> None:
    """Re-parse each prediction's ``raw_output`` with the canonical parser and
    fail if the stored ``parsed`` value disagrees.

    The scorer never trusts a stored ``parsed`` field blindly: every system
    (baselines, llm_eval, frontier) is cross-checked against ``parse()`` on
    the raw output it recorded. A disagreement means either the system used
    a non-canonical parser or the file was edited by hand.
    """
    for p in predictions:
        raw = p.get("raw_output", "")
        stored = p.get("parsed")
        expected = parse(raw if isinstance(raw, str) else "", label_set)
        if stored != expected:
            raise ValueError(
                f"predictions.jsonl stored parsed={stored!r} disagrees with "
                f"re-parsing raw_output={raw!r} -> {expected!r} "
                f"(cve_id={p.get('cve_id')!r})"
            )


def _scoring_cfg() -> dict:
    cfg = load_systems_cfg()["scoring"]
    return {
        "bootstrap_resamples": int(cfg["bootstrap_resamples"]),
        "bootstrap_seed": int(cfg["bootstrap_seed"]),
        "macro_f1_min_support": int(cfg["macro_f1_min_support"]),
    }


def score_prediction_dir(
    pred_dir: Path,
    results_root: Path | None = None,
    info: runinfo.RunInfo | None = None,
) -> dict:
    """Score one prediction directory and write
    ``results/<system>/<split>/<run_id>.json``. Return the summary dict.

    ``info`` is the process-level RunInfo snapshot captured at startup. If
    not given, one is captured here (standalone CLI entry).
    """
    info = info or runinfo.capture()
    start = info.started_utc
    run, preds = _load_prediction_dir(pred_dir)
    system = run["system"]
    split = run["split"]
    run_id = run["run_id"]
    if split == "test":
        check_test_lock()
    split_rows = _load_split(split)
    check_coverage([p["cve_id"] for p in preds], [r["cve_id"] for r in split_rows])
    aligned = _aligned_predictions(preds, split_rows)
    label_set = load_label_set()
    assert_reparse_matches(aligned, label_set)
    cfg = _scoring_cfg()
    metrics = compute_metrics(aligned, split_rows, label_set, cfg["macro_f1_min_support"])
    correct_vec = metrics.pop("_correct_vector")
    lo, hi = bootstrap_accuracy_ci(correct_vec, cfg["bootstrap_resamples"], cfg["bootstrap_seed"])
    metrics["accuracy_ci95"] = [lo, hi]
    end = runinfo.now_iso()

    out = {
        "system": system,
        "split": split,
        "run_id": run_id,
        "prediction_dir": (
            str(pred_dir.relative_to(REPO_ROOT))
            if pred_dir.is_absolute()
            else str(pred_dir)
        ),
        "scoring": cfg,
        "git_commit": info.git_commit,
        "git_dirty": info.git_dirty,
        "package_versions": info.package_versions,
        "start": start,
        "end": end,
        "metrics": metrics,
    }
    out_root = results_root or (REPO_ROOT / "results")
    out_dir = out_root / system / split
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{run_id}.json"
    with out_path.open("w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    out["_result_path"] = str(out_path)
    return out


def score_paired(
    pred_dir_a: Path,
    pred_dir_b: Path,
    results_root: Path | None = None,
    info: runinfo.RunInfo | None = None,
) -> dict:
    """Paired bootstrap of accuracy_a - accuracy_b on the same split.

    Writes ``results/paired/<split>/<a>__minus__<b>.json``.
    """
    info = info or runinfo.capture()
    run_a, preds_a = _load_prediction_dir(pred_dir_a)
    run_b, preds_b = _load_prediction_dir(pred_dir_b)
    if run_a["split"] != run_b["split"]:
        raise ValueError(
            f"paired bootstrap split mismatch: {run_a['split']} vs {run_b['split']}"
        )
    split = run_a["split"]
    if split == "test":
        check_test_lock()
    split_rows = _load_split(split)
    for preds in (preds_a, preds_b):
        check_coverage([p["cve_id"] for p in preds], [r["cve_id"] for r in split_rows])
    label_set = load_label_set()
    aligned_a = _aligned_predictions(preds_a, split_rows)
    aligned_b = _aligned_predictions(preds_b, split_rows)
    assert_reparse_matches(aligned_a, label_set)
    assert_reparse_matches(aligned_b, label_set)
    gold = np.array([r["label"] for r in split_rows])
    pred_a = np.array([(p["parsed"] if p["parsed"] is not None else "") for p in aligned_a])
    pred_b = np.array([(p["parsed"] if p["parsed"] is not None else "") for p in aligned_b])
    correct_a = (pred_a == gold).astype(np.int32)
    correct_b = (pred_b == gold).astype(np.int32)
    cfg = _scoring_cfg()
    lo, hi = paired_bootstrap_diff_ci(
        correct_a.tolist(), correct_b.tolist(), cfg["bootstrap_resamples"], cfg["bootstrap_seed"]
    )
    out = {
        "split": split,
        "a": {
            "system": run_a["system"],
            "run_id": run_a["run_id"],
            "accuracy": float(correct_a.mean()),
        },
        "b": {
            "system": run_b["system"],
            "run_id": run_b["run_id"],
            "accuracy": float(correct_b.mean()),
        },
        "diff_accuracy": float(correct_a.mean() - correct_b.mean()),
        "diff_accuracy_ci95": [lo, hi],
        "scoring": cfg,
        "git_commit": info.git_commit,
        "git_dirty": info.git_dirty,
        "package_versions": info.package_versions,
        "finished_utc": runinfo.now_iso(),
    }
    out_root = results_root or (REPO_ROOT / "results")
    out_dir = out_root / "paired" / split
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"{run_a['system']}-{run_a['run_id']}__minus__{run_b['system']}-{run_b['run_id']}.json"
    out_path = out_dir / name
    with out_path.open("w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    out["_result_path"] = str(out_path)
    return out


# ---------------------------------------------------------------------------
# CLI: run alone on one prediction dir, or on two dirs for paired bootstrap.


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score prediction files written by any system")
    ap.add_argument(
        "pred_dir",
        type=Path,
        help="directory holding predictions.jsonl and run.json",
    )
    ap.add_argument(
        "--paired",
        type=Path,
        default=None,
        help="second prediction directory; report paired bootstrap of a-b",
    )
    args = ap.parse_args(list(argv) if argv is not None else None)
    try:
        summary = score_prediction_dir(args.pred_dir)
    except Exception as exc:
        sys.stderr.write(f"scorer: {exc}\n")
        return 2
    m = summary["metrics"]
    lo, hi = m["accuracy_ci95"]
    print(
        f"[{summary['system']}/{summary['split']}] "
        f"n={m['n']} acc={m['accuracy']:.4f} ({lo:.4f}, {hi:.4f}) "
        f"invalid={m['invalid_rate']:.4f} macro-F1={m['macro_f1']:.4f}"
    )
    if args.paired is not None:
        try:
            summary_b = score_prediction_dir(args.paired)
            diff = score_paired(args.pred_dir, args.paired)
        except Exception as exc:
            sys.stderr.write(f"scorer: paired: {exc}\n")
            return 2
        lo, hi = diff["diff_accuracy_ci95"]
        print(
            f"[{diff['a']['system']} minus {diff['b']['system']}] "
            f"split={diff['split']} diff={diff['diff_accuracy']:+.4f} "
            f"({lo:+.4f}, {hi:+.4f})"
        )
        _ = summary_b
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "parse",
    "load_label_set",
    "check_coverage",
    "check_test_lock",
    "compute_metrics",
    "bootstrap_accuracy_ci",
    "paired_bootstrap_diff_ci",
    "score_prediction_dir",
    "score_paired",
    "main",
]
