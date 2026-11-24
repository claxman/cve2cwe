"""Shared run info: git commit, dirty flag, package versions, UTC time.

DESIGN "A clean-tree rule for every stage" (added in Step 7):

- git_dirty is any modified or untracked file outside ``outputs/`` and
  ``results/``. Those two directories hold artefacts a run itself writes,
  so if we counted them the flag would always flip to true the moment we
  wrote anything.
- The snapshot is captured once at process start, before anything is
  written, and reused for every file that process writes. baselines.py,
  scorer.py, llm_eval.py and merge.py all go through here. train.py keeps
  its own capture (snapshot taken before any Unsloth/TRL side effects).
"""

from __future__ import annotations

import importlib.metadata as md
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Default list of packages whose versions are recorded. llm_eval and merge
# extend this when they import heavier libraries (openai, torch, vllm).
_DEFAULT_PACKAGES: tuple[str, ...] = (
    "numpy",
    "scipy",
    "scikit-learn",
    "pyyaml",
)


def _git_commit() -> str:
    try:
        r = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        return r.stdout.strip()
    except FileNotFoundError:
        return ""


def _parse_porcelain_paths(stdout: str) -> list[str]:
    """Return the path on each porcelain line.

    porcelain v1 format: ``XY <path>`` for tracked changes, or
    ``XY <old> -> <new>`` for renames, or ``?? <path>`` for untracked.
    """
    paths: list[str] = []
    for line in stdout.splitlines():
        if len(line) < 4:
            continue
        payload = line[3:]
        if " -> " in payload:
            payload = payload.split(" -> ", 1)[1]
        payload = payload.strip().strip('"')
        if payload:
            paths.append(payload)
    return paths


def _git_dirty_outside_artefacts(ignore_prefixes: tuple[str, ...]) -> bool:
    """True if any status entry sits outside the artefact directories."""
    try:
        r = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return False
    for path in _parse_porcelain_paths(r.stdout):
        if any(path.startswith(p) for p in ignore_prefixes):
            continue
        return True
    return False


def _package_versions(names: tuple[str, ...]) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for name in names:
        try:
            out[name] = md.version(name)
        except md.PackageNotFoundError:
            out[name] = None
    return out


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# Artefact prefixes ignored by the clean-tree check. A tuple so it can be
# appended to in tests without touching callers.
ARTEFACT_PREFIXES: tuple[str, ...] = ("outputs/", "results/")


@dataclass(frozen=True)
class RunInfo:
    """Immutable snapshot captured once at process start."""

    git_commit: str
    git_dirty: bool
    started_utc: str
    package_versions: dict[str, str | None] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "git_commit": self.git_commit,
            "git_dirty": self.git_dirty,
            "started_utc": self.started_utc,
            "package_versions": dict(self.package_versions),
        }


def capture(packages: tuple[str, ...] = _DEFAULT_PACKAGES) -> RunInfo:
    """Capture the process-level run snapshot. Call once at startup."""
    return RunInfo(
        git_commit=_git_commit(),
        git_dirty=_git_dirty_outside_artefacts(ARTEFACT_PREFIXES),
        started_utc=_now_iso(),
        package_versions=_package_versions(packages),
    )


def now_iso() -> str:
    """UTC timestamp for a per-file ``end`` or ``finished_utc`` field."""
    return _now_iso()


__all__ = [
    "RunInfo",
    "ARTEFACT_PREFIXES",
    "capture",
    "now_iso",
]
