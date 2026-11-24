"""Gate decisions on synthetic inputs. No model and no real result files."""

from __future__ import annotations

from cve2cwe.gate import (
    GAIN,
    INVALID_MAX,
    MUST_PASS_MIN,
    choose_champion,
    judge,
    lowest_confidence_threshold,
    must_pass_ids,
    render_acceptance,
)


def _run(system: str, accuracy: float, run_id: str, n: int, complete: bool) -> dict:
    return {
        "system": system,
        "run_id": run_id,
        "split": "test",
        "prediction_dir": f"outputs/{system}/test/{run_id}",
        "metrics": {"accuracy": accuracy, "n": n if complete else n - 1},
    }


def test_champion_ignores_candidates_and_incomplete_runs(tmp_path, monkeypatch) -> None:
    # Every run has a prediction file. The candidate is ignored by name. The
    # keyword run is ignored because its n is short of the test split.
    monkeypatch.setattr("cve2cwe.gate.REPO_ROOT", tmp_path)
    records = [
        _run("candidate_e2-seed1", 0.99, "run-z", 10, True),
        _run("tfidf_svm", 0.70, "run-a", 10, True),
        _run("keyword", 0.95, "run-c", 10, False),
        _run("claude", 0.72, "run-b", 10, True),
    ]
    for record in records:
        path = tmp_path / record["prediction_dir"] / "predictions.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
    chosen = choose_champion(records, 10)
    assert chosen["system"] == "claude"
    assert chosen["run_id"] == "run-b"


def test_champion_keeps_the_higher_accuracy_when_a_system_has_two_runs(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr("cve2cwe.gate.REPO_ROOT", tmp_path)
    records = [
        _run("tfidf_svm", 0.70, "run-new", 10, True),
        _run("tfidf_svm", 0.71, "run-old", 10, True),
    ]
    for record in records:
        path = tmp_path / record["prediction_dir"] / "predictions.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
    chosen = choose_champion(records, 10)
    assert chosen["run_id"] == "run-old"
    assert chosen["metrics"]["accuracy"] == 0.71


def _seed(**overrides: object) -> dict:
    row = {
        "system": "s1",
        "accuracy": 0.80,
        "paired_lo": 0.01,
        "must_pass_accuracy": 0.99,
        "invalid_rate": 0.0,
    }
    row.update(overrides)
    return row


def test_all_four_checks_promote() -> None:
    seeds = [
        _seed(system="s1", accuracy=0.80, paired_lo=0.01),
        _seed(system="s2", accuracy=0.81, paired_lo=0.02, invalid_rate=0.001),
        _seed(
            system="s3",
            accuracy=0.82,
            paired_lo=0.03,
            must_pass_accuracy=1.0,
            invalid_rate=0.004,
        ),
    ]
    decision = judge(seeds, champion_accuracy=0.70)
    assert decision["g1"] is True
    assert decision["verdict"] == "PROMOTE"
    assert decision["pass_line"] == 0.70 + GAIN


def test_g1_failure_rejects() -> None:
    seeds = [_seed(system=name, accuracy=0.71) for name in ("s1", "s2", "s3")]
    decision = judge(seeds, champion_accuracy=0.70)
    assert decision["g1"] is False
    assert decision["verdict"] == "REJECT"


def test_g2_failure_rejects() -> None:
    # A lower bound of 0 is not above 0, so G2 fails on its own.
    seeds = [
        _seed(system="s1"),
        _seed(system="s2", paired_lo=0.0),
        _seed(system="s3"),
    ]
    decision = judge(seeds, champion_accuracy=0.70)
    assert decision["seeds"][1]["g2"] is False
    assert decision["verdict"] == "REJECT"


def test_g3_failure_rejects() -> None:
    seeds = [
        _seed(system="s1"),
        _seed(system="s2", must_pass_accuracy=MUST_PASS_MIN - 0.01),
        _seed(system="s3"),
    ]
    decision = judge(seeds, champion_accuracy=0.70)
    assert decision["seeds"][1]["g3"] is False
    assert decision["verdict"] == "REJECT"


def test_g4_failure_rejects() -> None:
    seeds = [
        _seed(system="s1"),
        _seed(system="s2", invalid_rate=INVALID_MAX + 0.001),
        _seed(system="s3"),
    ]
    decision = judge(seeds, champion_accuracy=0.70)
    assert decision["seeds"][1]["g4"] is False
    assert decision["verdict"] == "REJECT"


def test_lowest_threshold_drops_low_confidence_errors() -> None:
    # Five records. Null confidence is a correct record that stays in the
    # denominator and out of the auto-labelled set. The two low scores are
    # wrong, so the lowest t at 95% is 0.5 and covers 2 of 5.
    rows = [
        (0.1, False),
        (0.2, False),
        (0.5, True),
        (0.6, True),
        (None, True),
    ]
    found = lowest_confidence_threshold(rows, 0.95)
    assert found["threshold"] == 0.5
    assert found["n"] == 2
    assert found["coverage"] == 2 / 5


def test_must_pass_requires_keyword_label_gold_and_champion() -> None:
    ids = must_pass_ids(
        ["a", "b", "c", "d"],
        ["CWE-79", "CWE-89", "CWE-79", "CWE-89"],
        ["CWE-79", None, "CWE-89", "CWE-89"],
        ["CWE-79", "CWE-89", "CWE-79", "CWE-416"],
    )
    # a: keyword and champion right. b: keyword gave no label. c: keyword
    # label is not gold. d: keyword right, champion wrong.
    assert ids == ["a"]


def test_acceptance_renders_numbers_from_the_document() -> None:
    doc = {
        "prepared_utc": "2026-11-24T00:00:00Z",
        "champion": {"system": "tfidf_svm", "run_id": "run-1", "accuracy": 0.5},
        "thresholds": {"gain": GAIN, "must_pass": MUST_PASS_MIN, "invalid": INVALID_MAX},
        "g1_pass_line": 0.5 + GAIN,
        "candidate": {
            "chosen_epochs": 2,
            "chosen_systems": ["candidate_e2-seed1", "candidate_e2-seed2", "candidate_e2-seed3"],
            "one_epoch_mean": 0.11,
            "two_epoch_mean": 0.22,
            "rule": "Higher mean. A tie goes to 1 epoch.",
            "shipped": "candidate_e2-seed1",
            "shipped_dev_accuracy": 0.21,
        },
        "must_pass": {"count": 7, "sha256": "abc", "path": "data/processed/must_pass.json"},
        "routing": {
            "candidate_e2-seed1": {
                "run_id": "dev-1",
                "at_0.95": {"threshold": 0.4, "accuracy": 0.96, "coverage": 0.5, "n": 4},
                "at_0.97": {"threshold": 0.8, "accuracy": 0.98, "coverage": 0.25, "n": 2},
            }
        },
    }
    text = render_acceptance(doc)
    assert "\nStatus: final\n" in text
    assert "0.11" in text
    assert "0.22" in text
    assert "candidate_e2-seed1" in text
    assert "abc" in text
    sentence = (
        "No fine-tuned checkpoint has been evaluated on the test split "
        "before this commit."
    )
    assert sentence in text
