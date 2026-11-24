"""Display format for the generated README. No result files."""

from cve2cwe.report import fmt_count, fmt_pct, fmt_usd


def test_percentages_use_one_decimal() -> None:
    assert fmt_pct(0.7590467784642542) == "75.9%"
    assert fmt_pct(0.7268314210061783) == "72.7%"


def test_usd_uses_three_significant_digits() -> None:
    assert fmt_usd(0.013302520044043196) == "$0.0133"
    assert fmt_usd(0.08703051885416498) == "$0.0870"
    assert fmt_usd(5.000064430714915) == "$5.00"
    assert fmt_usd(36.951610826722224) == "$37.0"
    assert fmt_usd(19.494535) == "$19.5"


def test_counts_use_thousands_separators() -> None:
    assert fmt_count(6180) == "6,180"
    assert fmt_count(868) == "868"
