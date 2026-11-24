"""Routing arithmetic on a fixed synthetic example."""

from __future__ import annotations

from cve2cwe.report import (
    break_even_records_per_month,
    cascade_cost_per_1000,
    cost_per_1000_records,
    invalid_output_reason,
    routing_row,
)


def test_cost_per_1000_records() -> None:
    # 3600 USD/hour at 1 record/second is 1000 USD per 1,000 records.
    assert cost_per_1000_records(3600.0, 1.0) == 1000.0


def test_cascade_cost_and_break_even() -> None:
    # Small model on every record, Claude on the 75% that were not auto-labelled.
    assert cascade_cost_per_1000(2.0, 4.0, 0.25) == 5.0
    # 2 USD/hour * 10 hours = 20 USD. At 0.5 USD/record that is 40 records.
    assert break_even_records_per_month(2.0, 10.0, 0.5) == 40.0


def test_routing_row_on_four_records() -> None:
    # Records: auto, auto, rest, rest. Small model is right, wrong, right, wrong.
    # Fallback is right on every record. Cascade is right on 1, wrong on 2, right on 3 and 4.
    correct_small = [True, False, True, False]
    correct_fallback = [True, True, True, True]
    auto = [True, True, False, False]
    row = routing_row(correct_small, correct_fallback, auto)
    assert row["n"] == 4
    assert row["n_auto"] == 2
    assert row["n_rest"] == 2
    assert row["auto_label_rate"] == 0.5
    assert row["accuracy_auto"] == 0.5
    assert row["accuracy_rest"] == 0.5
    assert row["cascade_accuracy"] == 0.75
    assert cascade_cost_per_1000(1.0, 4.0, row["auto_label_rate"]) == 3.0


def test_invalid_output_reasons() -> None:
    labels = {"CWE-79", "CWE-89"}
    assert invalid_output_reason("CWE-79", labels) is None
    assert invalid_output_reason("  CWE-79\n", labels) is None
    assert invalid_output_reason("", labels) == "empty"
    assert invalid_output_reason("   ", labels) == "empty"
    assert invalid_output_reason("CWE-999", labels) == "clean_id_outside_the_label_set"
    assert (
        invalid_output_reason("answer: CWE-999", labels)
        == "extra_text_with_an_id_outside_the_set"
    )
    assert (
        invalid_output_reason("answer: CWE-79", labels)
        == "extra_text_around_an_id_in_the_set"
    )
    assert invalid_output_reason("no idea", labels) == "no_cwe_id"
