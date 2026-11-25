"""The TF-IDF subset uses the trainer's rows."""

import gzip
import json

from cve2cwe.ablations import ablation_path, load_override, sample_train_fraction
from cve2cwe.prompts import REPO_ROOT
from cve2cwe.tfidf_curve import subset_cve_ids


def test_frac10_subset_matches_trainer_sample() -> None:
    path = REPO_ROOT / "data" / "processed" / "train.jsonl.gz"
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        raw = [json.loads(line) for line in handle if line.strip()]
    override = load_override(ablation_path("frac10"))
    expected = [
        row["cve_id"]
        for row in sample_train_fraction(
            raw,
            float(override["train_fraction"]),
            int(override["fraction_seed"]),
        )
    ]
    assert subset_cve_ids("frac10") == expected
    assert len(expected) == round(float(override["train_fraction"]) * len(raw))
