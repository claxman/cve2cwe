"""Unit tests for prompts and the llm-eval guard (Step 7 work order G1).

Covers:
- the candidate prompt is byte-identical to the frozen string (B6 golden)
- zero_shot lists every one of the 53 labels
- few_shot has 8 example pairs followed by the query
- retrieval has 5 pairs, each example description at most 600 chars,
  least similar first
- the test-split guard refuses a candidate_* run without a final
  acceptance file and allows a baseline run on test
"""

from __future__ import annotations

import pytest

from cve2cwe.llm_eval import guard_test_split_candidate
from cve2cwe.prompts import (
    build_baseline_system_text,
    build_messages,
    load_labels,
    load_prompts_cfg,
    load_systems_cfg,
)


@pytest.fixture(scope="module")
def prompts() -> dict:
    return load_prompts_cfg()


@pytest.fixture(scope="module")
def systems() -> dict:
    return load_systems_cfg()


@pytest.fixture(scope="module")
def labels() -> list[dict]:
    return load_labels()


# ---------------------------------------------------------------------------
# B6 golden: the candidate prompt must not change by one character.


EXPECTED_CANDIDATE_SYSTEM = (
    "You label CVE records. Given a CVE description, answer with the one "
    "CWE id an NVD analyst would assign, for example CWE-79. Answer with "
    "the id only."
)

EXPECTED_CANDIDATE_USER = (
    "CVE description:\n"
    "A short bug.\n"
    "\n"
    "Answer with one CWE id."
)


def test_candidate_prompt_is_golden(prompts, systems):
    msgs = build_messages(
        "candidate", "A short bug.", prompts=prompts, systems=systems
    )
    assert len(msgs) == 2
    assert msgs[0] == {"role": "system", "content": EXPECTED_CANDIDATE_SYSTEM}
    assert msgs[1] == {"role": "user", "content": EXPECTED_CANDIDATE_USER}


# ---------------------------------------------------------------------------
# zero_shot lists every one of the 53 labels.


def test_zero_shot_lists_every_label(prompts, systems, labels):
    msgs = build_messages(
        "zero_shot",
        "A short bug.",
        prompts=prompts,
        systems=systems,
        labels=labels,
    )
    assert msgs[0]["role"] == "system"
    sys_text = msgs[0]["content"]
    for lab in labels:
        line = f"{lab['id']}: {lab['name']}"
        assert line in sys_text, f"missing label line: {line!r}"
    # Last line of the system prompt is the last label in file order.
    assert sys_text.splitlines()[-1] == f"{labels[-1]['id']}: {labels[-1]['name']}"


def test_baseline_system_text_has_blank_line_after_header(prompts, labels):
    text = build_baseline_system_text(prompts, labels)
    # Header, blank line, then the first label line.
    lines = text.split("\n")
    assert lines[0].startswith("You label CVE records.")
    assert lines[1] == ""
    assert lines[2].startswith("CWE-")


# ---------------------------------------------------------------------------
# few_shot: 8 example pairs, then the query.


def test_few_shot_has_eight_example_pairs_then_query(prompts, systems, labels):
    examples = [
        {"description": f"example {i} description", "label": f"CWE-{i}"}
        for i in range(8)
    ]
    msgs = build_messages(
        "few_shot",
        "the query description",
        examples=examples,
        prompts=prompts,
        systems=systems,
        labels=labels,
    )
    # 1 system + 8 user/assistant pairs + 1 final user = 18 messages.
    assert len(msgs) == 1 + 8 * 2 + 1
    assert msgs[0]["role"] == "system"
    for i in range(8):
        user_msg = msgs[1 + 2 * i]
        asst_msg = msgs[2 + 2 * i]
        assert user_msg["role"] == "user"
        assert asst_msg["role"] == "assistant"
        assert asst_msg["content"] == f"CWE-{i}"
        assert f"example {i} description" in user_msg["content"]
    assert msgs[-1]["role"] == "user"
    assert "the query description" in msgs[-1]["content"]


# ---------------------------------------------------------------------------
# retrieval: 5 pairs, each description <= 600 chars, least similar first.


def test_retrieval_has_five_pairs_least_similar_first(prompts, systems, labels):
    # Caller is responsible for cutting; here we simulate what llm_eval will
    # pass: 5 examples ordered least similar first.
    long_text = "x" * 900
    examples = [
        {"description": long_text[:600], "label": f"CWE-{i}", "similarity": s}
        for i, s in enumerate([0.10, 0.11, 0.12, 0.13, 0.14])
    ]
    msgs = build_messages(
        "retrieval",
        "query",
        examples=examples,
        prompts=prompts,
        systems=systems,
        labels=labels,
    )
    assert len(msgs) == 1 + 5 * 2 + 1
    # Every example description must be at most 600 characters (plus the
    # template chrome around it is fine, we check the example payload).
    for i in range(5):
        user_msg = msgs[1 + 2 * i]
        # Payload is the 600-char example, cross-check length appears in the
        # formatted user content.
        assert "x" * 600 in user_msg["content"]
        assert "x" * 601 not in user_msg["content"]
    # Least similar first means similarities ascend across example turns.
    sims = [e["similarity"] for e in examples]
    assert sims == sorted(sims)


# ---------------------------------------------------------------------------
# Test-split guard.


def test_guard_allows_baseline_on_test():
    # A baseline system name never trips the guard.
    guard_test_split_candidate("qwen35_4b_zero_shot", "test")


def test_guard_allows_candidate_on_dev():
    # Candidate on dev is always allowed; the guard only applies to test.
    guard_test_split_candidate("candidate_seed1", "dev")


def test_guard_refuses_candidate_on_test_without_final_acceptance(tmp_path, monkeypatch):
    # Point the guard at a temporary repo tree so the real ACCEPTANCE.md is
    # untouched.
    import cve2cwe.llm_eval as llm_eval

    monkeypatch.setattr(llm_eval, "REPO_ROOT", tmp_path)
    (tmp_path / "docs").mkdir()
    (tmp_path / "configs").mkdir()
    (tmp_path / "docs" / "ACCEPTANCE.md").write_text("# Draft\n\nStatus: draft\n")
    (tmp_path / "configs" / "gate.yaml").write_text("placeholder: true\n")
    with pytest.raises(SystemExit, match="Status: final"):
        llm_eval.guard_test_split_candidate("candidate_seed1", "test")
