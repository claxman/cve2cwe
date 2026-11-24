"""Smoke test: the package imports and the dispatcher lists every stage."""

from __future__ import annotations

import subprocess
import sys

import cve2cwe
from cve2cwe.__main__ import STAGES


def test_package_has_version() -> None:
    assert isinstance(cve2cwe.__version__, str)
    assert cve2cwe.__version__


def test_dispatcher_lists_every_stage() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "cve2cwe"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    usage = result.stderr
    for stage in STAGES:
        assert stage in usage, f"stage {stage} missing from usage output"


def test_cut_description_applies_max_chars() -> None:
    """DESIGN section 3: every system uses the first 2,000 characters of the
    description. A 3,000-character input must come out at 2,000 characters.
    """
    from cve2cwe.prompts import build_messages, cut_description

    assert len(cut_description("a" * 3000, 2000)) == 2000

    systems = {"max_description_chars": 2000}
    prompts = {
        "candidate": {
            "system": "sys",
            "user_template": "CVE description:\n{description}\n\nAnswer with one CWE id.",
        }
    }
    msgs = build_messages("candidate", "a" * 3000, prompts=prompts, systems=systems)
    user_content = msgs[1]["content"]
    assert "a" * 2000 in user_content
    assert "a" * 2001 not in user_content


def test_each_unbuilt_stage_reports_not_built() -> None:
    # Stages implemented so far; skip them here (they have their own tests).
    # train, merge and llm-eval are pod-only stages (unsloth / openai client);
    # the dispatcher must not be executed for them in CI.
    built = {"data", "baselines", "train", "merge", "llm-eval", "frontier", "gate"}
    for stage in STAGES:
        if stage in built:
            continue
        result = subprocess.run(
            [sys.executable, "-m", "cve2cwe", stage],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "not built yet" in result.stdout
