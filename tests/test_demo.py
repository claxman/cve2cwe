"""Demo decision rules. No server."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_PATH = Path(__file__).resolve().parents[1] / "demo" / "app.py"
_spec = importlib.util.spec_from_file_location("cve2cwe_demo_app", _PATH)
assert _spec is not None and _spec.loader is not None
demo_app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo_app)


def test_missing_confidence_goes_to_review() -> None:
    decision, note = demo_app.decide(None, 0.74)
    assert decision == "send to review"
    assert note == demo_app.NO_CONFIDENCE


def test_threshold_splits_auto_label_and_review() -> None:
    assert demo_app.decide(0.80, 0.74)[0] == "auto-label"
    assert demo_app.decide(0.70, 0.74)[0] == "send to review"
    assert demo_app.decide(0.74, 0.74)[0] == "auto-label"


def test_sample_is_stable() -> None:
    rows = [{"cve_id": f"CVE-{i}"} for i in range(50)]
    a = demo_app.sample_dev(rows, 10, 20261124)
    b = demo_app.sample_dev(rows, 10, 20261124)
    assert [r["cve_id"] for r in a] == [r["cve_id"] for r in b]
    assert len(a) == 10
