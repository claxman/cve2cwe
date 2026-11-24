"""Backlog filter: the same CWE-source flags as the coverage table."""

from __future__ import annotations

from cve2cwe.data import coverage_flags, is_unlabelled_backlog

CFG = {
    "nvd_source": "nvd@nist.gov",
    "adp_source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
    "kernel_source": "416baaa9-dc9f-4396-8d5f-8c081fb06d67",
    "placeholder_labels": ["NVD-CWE-Other", "NVD-CWE-noinfo"],
    "earliest_published": "2021-01-01",
    "test_start": "2026-04-15",
}
NVD = CFG["nvd_source"]
ADP = CFG["adp_source"]
CNA = "cna-1"


def _weakness(source: str, value: str) -> dict:
    return {"source": source, "description": [{"lang": "en", "value": value}]}


def _cve(*weaknesses: dict, published: str = "2026-04-15T00:00:00.000") -> dict:
    return {
        "id": "CVE-2026-0001",
        "vulnStatus": "Published",
        "published": published,
        "sourceIdentifier": CNA,
        "descriptions": [{"lang": "en", "value": "A bug in a parser."}],
        "weaknesses": list(weaknesses),
    }


def test_no_cwe_source_is_backlog() -> None:
    cve = _cve()
    flags = coverage_flags(cve, CFG)
    assert flags["has_nvd_analyst"] is False
    assert flags["has_cna"] is False
    assert flags["has_adp"] is False
    assert is_unlabelled_backlog(cve, CFG) is True


def test_nvd_analyst_cwe_is_not_backlog() -> None:
    cve = _cve(_weakness(NVD, "CWE-79"))
    assert coverage_flags(cve, CFG)["has_nvd_analyst"] is True
    assert is_unlabelled_backlog(cve, CFG) is False


def test_nvd_placeholder_does_not_count() -> None:
    for placeholder in ("NVD-CWE-Other", "NVD-CWE-noinfo"):
        cve = _cve(_weakness(NVD, placeholder))
        flags = coverage_flags(cve, CFG)
        assert flags["has_nvd_analyst"] is False
        assert is_unlabelled_backlog(cve, CFG) is True


def test_cna_cwe_is_not_backlog() -> None:
    cve = _cve(_weakness(CNA, "CWE-89"))
    assert coverage_flags(cve, CFG)["has_cna"] is True
    assert is_unlabelled_backlog(cve, CFG) is False


def test_adp_cwe_is_not_backlog() -> None:
    cve = _cve(_weakness(ADP, "CWE-22"))
    assert coverage_flags(cve, CFG)["has_adp"] is True
    assert is_unlabelled_backlog(cve, CFG) is False


def test_unrelated_source_does_not_count_as_cna() -> None:
    cve = _cve(_weakness("someone-else", "CWE-79"))
    flags = coverage_flags(cve, CFG)
    assert flags["has_cna"] is False
    assert is_unlabelled_backlog(cve, CFG) is True


def test_outside_test_window_is_not_backlog() -> None:
    cve = _cve(published="2026-04-14T23:59:59.000")
    assert is_unlabelled_backlog(cve, CFG) is False


def test_rejected_is_not_backlog() -> None:
    cve = _cve()
    cve["vulnStatus"] = "Rejected"
    assert is_unlabelled_backlog(cve, CFG) is False
