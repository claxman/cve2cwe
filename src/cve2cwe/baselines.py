"""CPU baselines (DESIGN section 6, systems 1-3).

Three systems, fit on train only, scored on dev and test. Each one goes
through ``prompts.cut_description`` so the input it sees matches every other
system in the repo. The predictions file layout and run metadata are the
same as every other system, so the scorer treats them identically.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import time
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion
from sklearn.preprocessing import normalize
from sklearn.svm import LinearSVC

from cve2cwe import runinfo
from cve2cwe.prompts import REPO_ROOT, cut_description, load_systems_cfg
from cve2cwe.scorer import score_paired, score_prediction_dir

# Fit everything with the same seed so identical configs produce identical
# predictions (matches DESIGN "every run writes a run.json with seed").
SEED = 20261124


# ---------------------------------------------------------------------------
# Data loading. All three baselines take only the cut description plus label.


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("rt", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rows.append(json.loads(line))
    return rows


def _read_jsonl_gz(path: Path) -> list[dict]:
    rows: list[dict] = []
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rows.append(json.loads(line))
    return rows


def _load_labels_ordered() -> list[str]:
    """Labels in labels.json file order. Used for majority tie-breaking."""
    path = REPO_ROOT / "data" / "processed" / "labels.json"
    with path.open() as f:
        return [row["id"] for row in json.load(f)]


def _load_split_descs(split: str, max_chars: int) -> list[dict]:
    """Return rows with cve_id, label and cut description for one split."""
    if split == "train":
        path = REPO_ROOT / "data" / "processed" / "train.jsonl.gz"
        raw = _read_jsonl_gz(path)
    elif split == "dev":
        raw = _read_jsonl(REPO_ROOT / "data" / "processed" / "dev.jsonl")
    elif split == "test":
        raw = _read_jsonl(REPO_ROOT / "data" / "processed" / "test.jsonl")
    else:
        raise ValueError(f"unknown split: {split!r}")
    return [
        {
            "cve_id": r["cve_id"],
            "label": r["label"],
            "description": cut_description(r["description"], max_chars),
        }
        for r in raw
    ]


# ---------------------------------------------------------------------------
# Majority baseline.


def fit_majority(train_rows: list[dict], labels_order: list[str]) -> str:
    """Most frequent label in train. Ties -> first in ``labels_order``."""
    counts = Counter(r["label"] for r in train_rows)
    top = max(counts.values())
    tied = {lbl for lbl, c in counts.items() if c == top}
    for lbl in labels_order:
        if lbl in tied:
            return lbl
    # Unreachable: every train label is in labels.json.
    raise RuntimeError("majority baseline could not break tie")


def predict_majority(label: str, rows: list[dict]) -> list[dict]:
    """Every row gets the same label with confidence None."""
    return [
        {"cve_id": r["cve_id"], "raw_output": label, "parsed": label, "confidence": None}
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Keyword baseline.


def compile_keyword_rules(rules: dict[str, str]) -> list[tuple[str, re.Pattern[str]]]:
    """Return a list of (CWE, compiled regex) pairs. Case-insensitive."""
    return [(cwe, re.compile(pattern, re.IGNORECASE)) for cwe, pattern in rules.items()]


def predict_keyword(
    compiled: list[tuple[str, re.Pattern[str]]], rows: list[dict]
) -> list[dict]:
    """One hit -> that CWE, confidence 1.0. Zero or more than one hit ->
    raw_output "" and invalid (parsed None, confidence None)."""
    preds: list[dict] = []
    for r in rows:
        hits = [cwe for cwe, pat in compiled if pat.search(r["description"])]
        if len(hits) == 1:
            preds.append(
                {"cve_id": r["cve_id"], "raw_output": hits[0], "parsed": hits[0], "confidence": 1.0}
            )
        else:
            preds.append(
                {"cve_id": r["cve_id"], "raw_output": "", "parsed": None, "confidence": None}
            )
    return preds


# ---------------------------------------------------------------------------
# TF-IDF + LinearSVC baseline.


def _make_tfidf_union() -> FeatureUnion:
    """Word 1-2 grams (min_df=2) plus char_wb 3-5 grams (min_df=3)."""
    word_vec = TfidfVectorizer(
        ngram_range=(1, 2),
        min_df=2,
        sublinear_tf=True,
        lowercase=True,
        analyzer="word",
    )
    char_vec = TfidfVectorizer(
        ngram_range=(3, 5),
        min_df=3,
        sublinear_tf=True,
        lowercase=True,
        analyzer="char_wb",
    )
    return FeatureUnion([("word", word_vec), ("char", char_vec)])


def fit_tfidf_svm(
    train_rows: list[dict],
    dev_rows: list[dict],
    c_values: list[float],
    seed: int,
) -> tuple[FeatureUnion, LinearSVC, float, dict[float, float]]:
    """Fit features on train, grid-search C on dev accuracy. Returns the
    fitted vectorizer, the SVM at the chosen C, that C, and every C's dev
    accuracy for the run.json log.
    """
    union = _make_tfidf_union()
    X_train = union.fit_transform([r["description"] for r in train_rows])
    y_train = np.array([r["label"] for r in train_rows])
    X_dev = union.transform([r["description"] for r in dev_rows])
    y_dev = np.array([r["label"] for r in dev_rows])
    dev_scores: dict[float, float] = {}
    best_c = c_values[0]
    best_acc = -1.0
    for c in c_values:
        svm = LinearSVC(C=c, random_state=seed)
        svm.fit(X_train, y_train)
        acc = float((svm.predict(X_dev) == y_dev).mean())
        dev_scores[c] = acc
        # Ties prefer the smaller C (less regularisation we don't need).
        if acc > best_acc:
            best_acc = acc
            best_c = c
    best_svm = LinearSVC(C=best_c, random_state=seed)
    best_svm.fit(X_train, y_train)
    return union, best_svm, best_c, dev_scores


def predict_tfidf_svm(
    union: FeatureUnion, svm: LinearSVC, rows: list[dict]
) -> list[dict]:
    """Return predictions with confidence = top decision score - second."""
    X = union.transform([r["description"] for r in rows])
    scores = svm.decision_function(X)
    preds_idx = scores.argmax(axis=1)
    labels = np.asarray(svm.classes_)
    preds_label = labels[preds_idx]
    # top1 minus top2 margin
    sorted_desc = np.sort(scores, axis=1)[:, ::-1]
    margins = (sorted_desc[:, 0] - sorted_desc[:, 1]).astype(float)
    out: list[dict] = []
    for r, lbl, conf in zip(rows, preds_label.tolist(), margins.tolist(), strict=True):
        out.append(
            {
                "cve_id": r["cve_id"],
                "raw_output": str(lbl),
                "parsed": str(lbl),
                "confidence": float(conf),
            }
        )
    return out


# ---------------------------------------------------------------------------
# Retrieval table for the next step.


def build_retrieval_tables(
    train_rows: list[dict],
    other_splits: dict[str, list[dict]],
    k: int,
    out_dir: Path,
) -> dict[str, Path]:
    """Write ``outputs/retrieval/<split>.jsonl`` with the top-k train
    neighbours by cosine similarity on word 1-2 gram TF-IDF vectors.

    Only descriptions are used, never a dev or test label.
    """
    word_vec = TfidfVectorizer(
        ngram_range=(1, 2),
        min_df=2,
        sublinear_tf=True,
        lowercase=True,
        analyzer="word",
    )
    X_train = word_vec.fit_transform([r["description"] for r in train_rows])
    X_train_n = normalize(X_train)
    train_ids = [r["cve_id"] for r in train_rows]

    out_dir.mkdir(parents=True, exist_ok=True)
    out_paths: dict[str, Path] = {}
    for split, rows in other_splits.items():
        X = word_vec.transform([r["description"] for r in rows])
        X_n = normalize(X)
        path = out_dir / f"{split}.jsonl"
        batch = 256
        with path.open("w", encoding="utf-8") as f:
            for start in range(0, X_n.shape[0], batch):
                end = min(start + batch, X_n.shape[0])
                sims = (X_n[start:end] @ X_train_n.T).toarray()
                for i, row_sims in enumerate(sims):
                    # top-k by similarity, descending
                    if k < row_sims.size:
                        top_idx = np.argpartition(-row_sims, k)[:k]
                    else:
                        top_idx = np.arange(row_sims.size)
                    top_idx = top_idx[np.argsort(-row_sims[top_idx])]
                    neighbours = [
                        [train_ids[j], float(row_sims[j])] for j in top_idx.tolist()
                    ]
                    rec = {"cve_id": rows[start + i]["cve_id"], "neighbours": neighbours}
                    f.write(json.dumps(rec) + "\n")
        out_paths[split] = path
    return out_paths


# ---------------------------------------------------------------------------
# Write predictions and run.json.


def _run_id(start_iso: str, commit: str) -> str:
    # 20261124T110532Z from "2026-11-24T11:05:32Z"
    ts = start_iso.replace("-", "").replace(":", "")
    short = commit[:7] if commit else "nogit"
    return f"{ts}-{short}"


def _write_prediction_dir(
    system: str,
    split: str,
    run_id: str,
    predictions: list[dict],
    run_meta: dict,
    outputs_root: Path,
) -> Path:
    out_dir = outputs_root / system / split / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    pred_path = out_dir / "predictions.jsonl"
    with pred_path.open("w", encoding="utf-8") as f:
        for p in predictions:
            f.write(json.dumps(p) + "\n")
    with (out_dir / "run.json").open("w") as f:
        json.dump(run_meta, f, indent=2, sort_keys=True)
        f.write("\n")
    return out_dir


# ---------------------------------------------------------------------------
# One command runs the three systems on dev and test, then scores them.


def run(outputs_root: Path | None = None, results_root: Path | None = None) -> int:
    outputs_root = outputs_root or (REPO_ROOT / "outputs")
    results_root = results_root or (REPO_ROOT / "results")

    # Capture clean-tree state once, before any output file exists.
    info = runinfo.capture()

    systems_cfg = load_systems_cfg()
    max_chars = int(systems_cfg["max_description_chars"])
    scoring_cfg = systems_cfg["scoring"]
    keyword_rules = systems_cfg["keyword_rules"]

    print("[baselines] loading splits")
    t0 = time.perf_counter()
    train_rows = _load_split_descs("train", max_chars)
    dev_rows = _load_split_descs("dev", max_chars)
    test_rows = _load_split_descs("test", max_chars)
    t_load = time.perf_counter() - t0
    print(
        f"[baselines] loaded train={len(train_rows)} dev={len(dev_rows)} "
        f"test={len(test_rows)} in {t_load:.2f}s"
    )

    labels_order = _load_labels_ordered()
    commit = info.git_commit
    pkg = dict(info.package_versions)

    # ---- Majority ----
    print("[baselines] majority: fit")
    t0 = time.perf_counter()
    majority_label = fit_majority(train_rows, labels_order)
    fit_t_majority = time.perf_counter() - t0
    print(f"[baselines] majority label: {majority_label}")

    # ---- Keyword ----
    print("[baselines] keyword: compile rules")
    t0 = time.perf_counter()
    compiled = compile_keyword_rules(keyword_rules)
    fit_t_keyword = time.perf_counter() - t0

    # ---- TF-IDF SVM ----
    print("[baselines] tfidf_svm: fit + C grid on dev")
    t0 = time.perf_counter()
    c_values = [0.25, 0.5, 1.0]
    union, svm, best_c, dev_scores_by_c = fit_tfidf_svm(
        train_rows, dev_rows, c_values, SEED
    )
    fit_t_svm = time.perf_counter() - t0
    print(
        f"[baselines] tfidf_svm best C={best_c} dev_scores="
        + ", ".join(f"C={c}:{a:.4f}" for c, a in dev_scores_by_c.items())
    )

    # ---- Predict + write per split ----
    split_rows = {"dev": dev_rows, "test": test_rows}
    paths: dict[str, dict[str, Path]] = {"majority": {}, "keyword": {}, "tfidf_svm": {}}

    for split, rows in split_rows.items():
        start_iso = runinfo.now_iso()
        run_id = _run_id(start_iso, commit)

        # majority
        t0 = time.perf_counter()
        preds = predict_majority(majority_label, rows)
        pred_t = time.perf_counter() - t0
        meta = {
            "system": "majority",
            "split": split,
            "run_id": run_id,
            "seed": SEED,
            "config": {"label": majority_label},
            "git_commit": commit,
            "git_dirty": info.git_dirty,
            "package_versions": pkg,
            "fit_seconds": round(fit_t_majority, 4),
            "predict_seconds": round(pred_t, 4),
            "start": start_iso,
            "end": runinfo.now_iso(),
        }
        paths["majority"][split] = _write_prediction_dir(
            "majority", split, run_id, preds, meta, outputs_root
        )
        print(f"[baselines] majority {split}: predicted in {pred_t:.2f}s")

        # keyword
        start_iso = runinfo.now_iso()
        run_id = _run_id(start_iso, commit)
        t0 = time.perf_counter()
        preds = predict_keyword(compiled, rows)
        pred_t = time.perf_counter() - t0
        meta = {
            "system": "keyword",
            "split": split,
            "run_id": run_id,
            "seed": SEED,
            "config": {"rules": dict(keyword_rules)},
            "git_commit": commit,
            "git_dirty": info.git_dirty,
            "package_versions": pkg,
            "fit_seconds": round(fit_t_keyword, 4),
            "predict_seconds": round(pred_t, 4),
            "start": start_iso,
            "end": runinfo.now_iso(),
        }
        paths["keyword"][split] = _write_prediction_dir(
            "keyword", split, run_id, preds, meta, outputs_root
        )
        print(f"[baselines] keyword {split}: predicted in {pred_t:.2f}s")

        # tfidf_svm
        start_iso = runinfo.now_iso()
        run_id = _run_id(start_iso, commit)
        t0 = time.perf_counter()
        preds = predict_tfidf_svm(union, svm, rows)
        pred_t = time.perf_counter() - t0
        meta = {
            "system": "tfidf_svm",
            "split": split,
            "run_id": run_id,
            "seed": SEED,
            "config": {
                "c_values": c_values,
                "dev_scores_by_c": {str(c): dev_scores_by_c[c] for c in c_values},
                "best_c": best_c,
                "word_ngram_range": [1, 2],
                "word_min_df": 2,
                "char_wb_ngram_range": [3, 5],
                "char_min_df": 3,
                "sublinear_tf": True,
                "lowercase": True,
                "classifier": "LinearSVC",
                "max_description_chars": max_chars,
            },
            "git_commit": commit,
            "git_dirty": info.git_dirty,
            "package_versions": pkg,
            "fit_seconds": round(fit_t_svm, 4),
            "predict_seconds": round(pred_t, 4),
            "start": start_iso,
            "end": runinfo.now_iso(),
        }
        paths["tfidf_svm"][split] = _write_prediction_dir(
            "tfidf_svm", split, run_id, preds, meta, outputs_root
        )
        print(f"[baselines] tfidf_svm {split}: predicted in {pred_t:.2f}s")

    # ---- Retrieval table for the next step ----
    print("[baselines] building retrieval table (top-5 cosine on word 1-2 grams)")
    t0 = time.perf_counter()
    retrieval_dir = outputs_root / "retrieval"
    build_retrieval_tables(
        train_rows,
        {"dev": dev_rows, "test": test_rows},
        k=5,
        out_dir=retrieval_dir,
    )
    print(f"[baselines] retrieval: wrote {retrieval_dir} in {time.perf_counter() - t0:.2f}s")

    # ---- Score ----
    print("[baselines] scoring")
    for system, by_split in paths.items():
        for split, pdir in by_split.items():
            summary = score_prediction_dir(pdir, results_root=results_root, info=info)
            m = summary["metrics"]
            lo, hi = m["accuracy_ci95"]
            print(
                f"  {system}/{split}: n={m['n']} acc={m['accuracy']:.4f} "
                f"({lo:.4f}, {hi:.4f}) invalid={m['invalid_rate']:.4f} "
                f"macroF1={m['macro_f1']:.4f}"
            )

    # Paired bootstrap of tfidf_svm minus keyword on test.
    print("[baselines] paired bootstrap: tfidf_svm - keyword on test")
    diff = score_paired(
        paths["tfidf_svm"]["test"],
        paths["keyword"]["test"],
        results_root=results_root,
        info=info,
    )
    lo, hi = diff["diff_accuracy_ci95"]
    print(
        f"  tfidf_svm - keyword test diff={diff['diff_accuracy']:+.4f} "
        f"({lo:+.4f}, {hi:+.4f})"
    )

    _ = scoring_cfg  # recorded in each result file via the scorer
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CPU baselines: majority, keyword, tfidf_svm")
    ap.parse_args(list(argv) if argv is not None else None)
    return run()


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "fit_majority",
    "predict_majority",
    "compile_keyword_rules",
    "predict_keyword",
    "fit_tfidf_svm",
    "predict_tfidf_svm",
    "build_retrieval_tables",
    "run",
    "main",
]

