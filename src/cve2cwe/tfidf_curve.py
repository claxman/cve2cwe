"""TF-IDF + linear SVM on the ablation training subsets. Dev only.

The command has no test path. It does not read the test split.
"""

from __future__ import annotations

import gzip
import json

from cve2cwe import baselines, runinfo
from cve2cwe.ablations import ablation_path, load_override, sample_train_fraction
from cve2cwe.baselines import _load_split_descs, _run_id, _write_prediction_dir
from cve2cwe.prompts import REPO_ROOT, cut_description, load_systems_cfg

# The three fractions that have a fine-tuned ablation. The full-data TF-IDF
# run already exists and is not repeated here.
CURVE_NAMES = ("frac05", "frac10", "frac30")


def load_raw_train_rows() -> list[dict]:
    """Train rows in file order, the same order the trainer samples."""
    path = REPO_ROOT / "data" / "processed" / "train.jsonl.gz"
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def subset_rows(name: str) -> tuple[list[dict], dict]:
    """Rows for one ablation override, sampled before any description cut."""
    if name not in CURVE_NAMES:
        raise SystemExit(f"tfidf-curve: {name} is not a subset run")
    override = load_override(ablation_path(name))
    if "train_fraction" not in override or "fraction_seed" not in override:
        raise SystemExit(f"tfidf-curve: {name} has no train fraction")
    sampled = sample_train_fraction(
        load_raw_train_rows(),
        float(override["train_fraction"]),
        int(override["fraction_seed"]),
    )
    return sampled, override


def subset_cve_ids(name: str) -> list[str]:
    rows, _override = subset_rows(name)
    return [row["cve_id"] for row in rows]


def run(argv: list[str] | None = None) -> int:
    if argv:
        raise SystemExit("tfidf-curve: this command takes no arguments and has no test path")
    info = runinfo.capture()
    if info.git_dirty:
        raise SystemExit(
            "tfidf-curve: git tree is dirty outside outputs/ and results/. "
            "Refusing to write a run."
        )
    systems = load_systems_cfg()
    max_chars = int(systems["max_description_chars"])
    tfidf_cfg = systems["tfidf"]
    c_values = [float(c) for c in tfidf_cfg["c_values"]]
    dev_rows = _load_split_descs("dev", max_chars)
    # The fraction seed only picks rows. C is chosen with the baseline seed,
    # so a subset is comparable with the full-data TF-IDF run.
    seed = int(baselines.SEED)
    outputs_root = REPO_ROOT / "outputs"
    for name in CURVE_NAMES:
        sampled, override = subset_rows(name)
        train_rows = [
            {
                "cve_id": row["cve_id"],
                "label": row["label"],
                "description": cut_description(row["description"], max_chars),
            }
            for row in sampled
        ]
        started = runinfo.now_iso()
        _union, _svm, best_c, dev_scores = baselines.fit_tfidf_svm(
            train_rows, dev_rows, c_values, seed, tfidf_cfg
        )
        predictions = baselines.predict_tfidf_svm(_union, _svm, dev_rows)
        finished = runinfo.now_iso()
        system = f"ablation_tfidf_{name}"
        run_id = _run_id(started, info.git_commit)
        meta = {
            "system": system,
            "split": "dev",
            "run_id": run_id,
            "started_utc": started,
            "finished_utc": finished,
            "train_fraction": float(override["train_fraction"]),
            "fraction_seed": int(override["fraction_seed"]),
            "train_row_count": len(sampled),
            "chosen_c": best_c,
            "dev_scores_by_c": {str(c): dev_scores[c] for c in c_values},
            "random_state": seed,
            "git_commit": info.git_commit,
            "git_dirty": info.git_dirty,
            "package_versions": info.to_dict()["package_versions"],
        }
        out_dir = _write_prediction_dir(
            system, "dev", run_id, predictions, meta, outputs_root
        )
        scores = ", ".join(f"C={c}:{dev_scores[c]:.4f}" for c in c_values)
        print(
            f"[tfidf-curve] {system} rows={len(sampled)} "
            f"fraction={override['train_fraction']} seed={override['fraction_seed']} "
            f"chosen_c={best_c} dev={dev_scores[best_c]:.4f} {scores} -> {out_dir}"
        )
    return 0
