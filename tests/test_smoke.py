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


def test_each_stage_runs_and_reports_not_built() -> None:
    for stage in STAGES:
        result = subprocess.run(
            [sys.executable, "-m", "cve2cwe", stage],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "not built yet" in result.stdout
