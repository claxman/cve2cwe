"""Unit tests for scorer and baselines (Work Order 5 part C).

Covers the parser, invalid handling, macro-F1 threshold, bootstrap
reproducibility, coverage checks and the keyword baseline.
"""

from __future__ import annotations

import pytest

from cve2cwe.baselines import compile_keyword_rules, predict_keyword
from cve2cwe.scorer import (
    bootstrap_accuracy_ci,
    check_coverage,
    compute_metrics,
    paired_bootstrap_diff_ci,
    parse,
)

LABEL_SET = {"CWE-79", "CWE-89", "CWE-416", "CWE-476"}


# ---------------------------------------------------------------------------
# parse()


def test_parse_valid_cwe_id() -> None:
    assert parse("CWE-79", LABEL_SET) == "CWE-79"


def test_parse_strips_whitespace() -> None:
    assert parse(" CWE-79\n", LABEL_SET) == "CWE-79"


def test_parse_rejects_lowercase() -> None:
    # The regex is anchored and case-sensitive. Lowercase is not a CWE id.
    assert parse("cwe-79", LABEL_SET) is None


def test_parse_rejects_trailing_punctuation() -> None:
    assert parse("CWE-79.", LABEL_SET) is None


def test_parse_rejects_multiple_tokens() -> None:
    assert parse("CWE-79 CWE-89", LABEL_SET) is None


def test_parse_rejects_empty_string() -> None:
    assert parse("", LABEL_SET) is None


def test_parse_rejects_unknown_label() -> None:
    # Matches the regex but is not in the label set.
    assert parse("CWE-99999", LABEL_SET) is None


def test_parse_rejects_non_string() -> None:
    # Prediction files may carry `null` for parsed; parse should never crash.
    assert parse(None, LABEL_SET) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# compute_metrics(): invalid counts as wrong; invalid_rate is right;
# macro-F1 ignores a class under the support threshold.


def _rows(cve_ids: list[str], labels: list[str]) -> list[dict]:
    return [
        {"cve_id": cid, "label": lbl, "is_kernel": False, "adp_cwes": []}
        for cid, lbl in zip(cve_ids, labels, strict=True)
    ]


def _preds(cve_ids: list[str], parsed: list[str | None]) -> list[dict]:
    return [
        {
            "cve_id": cid,
            "raw_output": (p or ""),
            "parsed": p,
            "confidence": None,
        }
        for cid, p in zip(cve_ids, parsed, strict=True)
    ]


def test_invalid_counted_as_wrong_and_invalid_rate() -> None:
    # 4 records: 2 correct, 1 wrong, 1 invalid. accuracy = 2/4 = 0.5,
    # invalid_rate = 1/4 = 0.25.
    rows = _rows(["A", "B", "C", "D"], ["CWE-79", "CWE-79", "CWE-89", "CWE-416"])
    preds = _preds(["A", "B", "C", "D"], ["CWE-79", "CWE-79", "CWE-476", None])
    m = compute_metrics(preds, rows, LABEL_SET, macro_f1_min_support=1)
    assert m["n"] == 4
    assert m["accuracy"] == pytest.approx(0.5)
    assert m["invalid_rate"] == pytest.approx(0.25)


def test_macro_f1_ignores_classes_below_support() -> None:
    # Build 25 records of CWE-79 (all correct) and 5 of CWE-89 (all wrong).
    # Threshold 20 -> only CWE-79 counts in macro-F1.
    cve_ids = [f"C{i}" for i in range(30)]
    labels = ["CWE-79"] * 25 + ["CWE-89"] * 5
    parsed: list[str | None] = ["CWE-79"] * 25 + ["CWE-476"] * 5
    rows = _rows(cve_ids, labels)
    preds = _preds(cve_ids, parsed)
    m = compute_metrics(preds, rows, LABEL_SET, macro_f1_min_support=20)
    # Only CWE-79 kept, perfect precision and recall -> F1 = 1.0.
    assert m["macro_f1_classes"] == ["CWE-79"]
    assert m["macro_f1"] == pytest.approx(1.0)
    # With threshold 1, CWE-89 kept too (F1 = 0). Macro = (1 + 0)/2 = 0.5.
    m2 = compute_metrics(preds, rows, LABEL_SET, macro_f1_min_support=1)
    assert set(m2["macro_f1_classes"]) == {"CWE-79", "CWE-89"}
    assert m2["macro_f1"] == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Bootstrap: same seed -> same interval; identical systems -> paired diff 0.


def test_bootstrap_is_deterministic() -> None:
    correct = [1, 0, 1, 1, 0, 1, 0, 1, 1, 1]
    lo1, hi1 = bootstrap_accuracy_ci(correct, n_resamples=10_000, seed=20261124)
    lo2, hi2 = bootstrap_accuracy_ci(correct, n_resamples=10_000, seed=20261124)
    assert (lo1, hi1) == (lo2, hi2)
    # And actually a real interval, not a point.
    assert lo1 < hi1


def test_paired_bootstrap_identical_systems_is_zero() -> None:
    correct = [1, 0, 1, 1, 0, 1, 0, 1, 1, 1]
    lo, hi = paired_bootstrap_diff_ci(
        correct, correct, n_resamples=10_000, seed=20261124
    )
    assert lo == 0.0
    assert hi == 0.0


# ---------------------------------------------------------------------------
# Coverage.


def test_check_coverage_passes_on_exact_match() -> None:
    check_coverage(["A", "B", "C"], ["C", "A", "B"])  # order independent


def test_check_coverage_missing_raises() -> None:
    with pytest.raises(ValueError, match="missing"):
        check_coverage(["A", "B"], ["A", "B", "C"])


def test_check_coverage_extra_raises() -> None:
    with pytest.raises(ValueError, match="extra"):
        check_coverage(["A", "B", "C", "D"], ["A", "B", "C"])


def test_check_coverage_duplicate_raises() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        check_coverage(["A", "B", "B"], ["A", "B", "C"])


# ---------------------------------------------------------------------------
# Keyword baseline rule semantics.


def test_keyword_single_hit_labels() -> None:
    rules = {"CWE-416": r"use[- ]after[- ]free|\buaf\b", "CWE-89": r"sql injection"}
    compiled = compile_keyword_rules(rules)
    preds = predict_keyword(
        compiled,
        [{"cve_id": "X", "description": "A classic use-after-free in the kernel"}],
    )
    assert preds[0]["parsed"] == "CWE-416"
    assert preds[0]["raw_output"] == "CWE-416"
    assert preds[0]["confidence"] == 1.0


def test_keyword_zero_hits_invalid() -> None:
    rules = {"CWE-416": r"use[- ]after[- ]free|\buaf\b"}
    compiled = compile_keyword_rules(rules)
    preds = predict_keyword(
        compiled,
        [{"cve_id": "X", "description": "An unrelated authentication bug"}],
    )
    assert preds[0]["parsed"] is None
    assert preds[0]["raw_output"] == ""


def test_keyword_two_hits_invalid() -> None:
    rules = {
        "CWE-416": r"use[- ]after[- ]free|\buaf\b",
        "CWE-89": r"sql injection",
    }
    compiled = compile_keyword_rules(rules)
    preds = predict_keyword(
        compiled,
        [
            {
                "cve_id": "X",
                "description": "A SQL injection bug combined with a use after free",
            }
        ],
    )
    assert preds[0]["parsed"] is None
    assert preds[0]["raw_output"] == ""
