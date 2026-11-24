"""Unlabelled CVE backlog: the test-window records no source assigned a CWE to.

The filter is ``data.is_unlabelled_backlog``, which uses the same rule-1
checks and coverage flags as the pre-rule-2 table in stats.json. A row
count that does not match that table's "none of the three" cell is a bug.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

import yaml

from cve2cwe import runinfo
from cve2cwe.data import (
    REPO_ROOT,
    _english_description,
    _load_config,
    coverage_flags,
    is_unlabelled_backlog,
    iter_records,
    rule1_drop,
)
from cve2cwe.prompts import load_labels

_UNLABELLED = REPO_ROOT / "data" / "processed" / "unlabelled.jsonl"
_STATS = REPO_ROOT / "data" / "processed" / "stats.json"


def _raw_paths(cfg: dict) -> tuple[str, dict[int, Path]]:
    manifest_path = REPO_ROOT / "data" / "processed" / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    source = manifest["source"]
    raw_root = REPO_ROOT / cfg["raw_dir"]
    paths: dict[int, Path] = {}
    for year in cfg["years"]:
        if source == "official":
            path = raw_root / "official" / f"nvdcve-2.0-{year}.json.gz"
        elif source == "mirror":
            path = raw_root / "mirror" / f"CVE-{year}.json.xz"
        else:
            raise SystemExit(f"backlog: unknown feed source {source!r}")
        if not path.is_file():
            raise SystemExit(f"backlog: missing raw feed {path}")
        paths[year] = path
    return source, paths


def _stats_test_window() -> dict:
    stats = json.loads(_STATS.read_text())
    return stats["coverage_pre_rule_2"]["test_window"]


def build_unlabelled(cfg: dict | None = None) -> tuple[int, int]:
    """Write unlabelled.jsonl. Returns (rows written, has_none counted)."""
    cfg = cfg or _load_config()
    source, paths = _raw_paths(cfg)
    rows: list[dict] = []
    has_none = 0
    window_records = 0
    for year in sorted(paths):
        print(f"[backlog] {year}: {paths[year].name}", flush=True)
        for cve in iter_records(source, paths[year]):
            if rule1_drop(cve, cfg) is not None:
                continue
            published = cve["published"]
            if published[:10] < cfg["test_start"]:
                continue
            window_records += 1
            flags = coverage_flags(cve, cfg)
            if flags["has_nvd_analyst"] or flags["has_cna"] or flags["has_adp"]:
                continue
            has_none += 1
            if not is_unlabelled_backlog(cve, cfg):
                raise SystemExit("backlog: coverage flags and backlog filter disagree")
            rows.append(
                {
                    "cve_id": cve.get("id"),
                    "published": published,
                    "source_identifier": flags["source_identifier"],
                    "description": _description(cve),
                    "is_kernel": flags["is_kernel"],
                }
            )
    rows.sort(key=lambda r: r["cve_id"] or "")
    _UNLABELLED.parent.mkdir(parents=True, exist_ok=True)
    with _UNLABELLED.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    tw = _stats_test_window()
    share = round(has_none / window_records, 6) if window_records else 0.0
    print(f"[backlog] rows written: {len(rows)}")
    print(f"[backlog] test-window has_none (this scan): {has_none}")
    print(
        f"[backlog] stats.json test_window records: {tw['records']} "
        f"none_share: {tw['none_share']}"
    )
    print(f"[backlog] this scan test-window records: {window_records} none_share: {share}")
    if len(rows) != has_none:
        raise SystemExit("backlog: row count does not equal has_none")
    if window_records != tw["records"] or share != tw["none_share"]:
        raise SystemExit(
            "backlog: test-window coverage does not match stats.json "
            f"({window_records} records, none_share {share} vs "
            f"{tw['records']} records, none_share {tw['none_share']})"
        )
    return len(rows), has_none


def _description(cve: dict) -> str:
    text = _english_description(cve)
    if text is None:
        raise SystemExit(f"backlog: rule 1 kept {cve.get('id')} with no description")
    return text


def _read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _gate_thresholds() -> dict[str, float]:
    with (REPO_ROOT / "configs" / "gate.yaml").open() as f:
        gate = yaml.safe_load(f)
    block = gate["routing"]["candidate_e2-seed1"]
    return {
        "at_0.95": float(block["at_0.95"]["threshold"]),
        "at_0.97": float(block["at_0.97"]["threshold"]),
    }


def _serve_price() -> float:
    with (REPO_ROOT / "configs" / "serve.yaml").open() as f:
        cfg = yaml.safe_load(f)
    return float(cfg["gpu_price_usd_per_hour"])


def write_labels(pred_dir: Path) -> Path:
    """Write outputs/backlog/<run_id>/labels.csv and summary.json."""
    pred_dir = pred_dir.resolve()
    preds = _read_jsonl(pred_dir / "predictions.jsonl")
    records = _read_jsonl(_UNLABELLED)
    by_id = {r["cve_id"]: r for r in records}
    if len(by_id) != len(records):
        raise SystemExit("backlog: duplicate cve_id in unlabelled.jsonl")
    pred_ids = [p["cve_id"] for p in preds]
    if len(pred_ids) != len(set(pred_ids)):
        raise SystemExit("backlog: duplicate cve_id in predictions")
    missing = [cid for cid in pred_ids if cid not in by_id]
    extra = sorted(set(by_id) - set(pred_ids))
    if missing or extra or len(preds) != len(records):
        raise SystemExit(
            f"backlog: predictions do not match unlabelled.jsonl "
            f"(missing {len(missing)}, extra {len(extra)}, "
            f"preds {len(preds)}, rows {len(records)})"
        )

    names = {row["id"]: row["name"] for row in load_labels()}
    thresholds = _gate_thresholds()
    t95 = thresholds["at_0.95"]
    t97 = thresholds["at_0.97"]
    run_meta = json.loads((pred_dir / "run.json").read_text())
    wall = float(run_meta["wall_seconds"])
    price = _serve_price()
    gpu_cost = wall / 3600.0 * price

    run_id = pred_dir.name
    out_dir = REPO_ROOT / "outputs" / "backlog" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "labels.csv"

    n_above_95 = 0
    n_above_97 = 0
    n_invalid = 0
    n_kernel = 0
    cwe_counts: Counter[str] = Counter()

    # One row per unlabelled record, in cve_id order, so the file is stable.
    pred_by_id = {p["cve_id"]: p for p in preds}
    ordered = [by_id[cid] for cid in sorted(by_id)]

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "cve_id",
                "published",
                "is_kernel",
                "predicted_cwe",
                "cwe_name",
                "confidence",
                "auto_95",
                "auto_97",
            ],
        )
        writer.writeheader()
        for rec in ordered:
            pred = pred_by_id[rec["cve_id"]]
            parsed = pred.get("parsed") or ""
            conf = pred.get("confidence")
            auto_95 = conf is not None and conf >= t95
            auto_97 = conf is not None and conf >= t97
            if auto_95:
                n_above_95 += 1
            if auto_97:
                n_above_97 += 1
            if not parsed:
                n_invalid += 1
            else:
                cwe_counts[parsed] += 1
            if rec["is_kernel"]:
                n_kernel += 1
            writer.writerow(
                {
                    "cve_id": rec["cve_id"],
                    "published": rec["published"],
                    "is_kernel": rec["is_kernel"],
                    "predicted_cwe": parsed,
                    "cwe_name": names.get(parsed, ""),
                    "confidence": "" if conf is None else repr(conf),
                    "auto_95": auto_95,
                    "auto_97": auto_97,
                }
            )

    n = len(ordered)
    summary = {
        "run_id": run_id,
        "prediction_dir": str(pred_dir.relative_to(REPO_ROOT)),
        "rows": n,
        "share_at_or_above": {
            "at_0.95": n_above_95 / n if n else 0.0,
            "at_0.97": n_above_97 / n if n else 0.0,
        },
        "thresholds": thresholds,
        "invalid_count": n_invalid,
        "top_predicted_cwes": [
            {"cwe": cwe, "name": names.get(cwe, ""), "count": count}
            for cwe, count in cwe_counts.most_common(10)
        ],
        "kernel_share": n_kernel / n if n else 0.0,
        "wall_seconds": wall,
        "gpu_price_usd_per_hour": price,
        "gpu_cost_usd": gpu_cost,
        "git_commit": run_meta.get("git_commit"),
        "git_dirty": run_meta.get("git_dirty"),
    }
    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(f"[backlog] wrote {csv_path}")
    print(f"[backlog] wrote {summary_path}")
    print(
        f"[backlog] rows={n} invalid={n_invalid} "
        f"share_0.95={summary['share_at_or_above']['at_0.95']} "
        f"share_0.97={summary['share_at_or_above']['at_0.97']} "
        f"kernel_share={summary['kernel_share']} "
        f"wall_seconds={wall} gpu_cost_usd={gpu_cost}"
    )
    return out_dir


def main(argv: list[str] | None = None) -> int:
    # Snapshot before the scan writes unlabelled.jsonl.
    info = runinfo.capture()
    ap = argparse.ArgumentParser(description="Unlabelled backlog and its labels")
    ap.add_argument(
        "--predictions",
        type=Path,
        default=None,
        help="prediction dir of a backlog llm-eval run; writes labels.csv",
    )
    args = ap.parse_args(argv)
    if args.predictions is not None:
        write_labels(args.predictions)
        return 0
    print(
        f"[backlog] git {info.git_commit} dirty={info.git_dirty}",
        flush=True,
    )
    build_unlabelled()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
