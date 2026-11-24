"""Routing, error analysis and the spend ledger. Reads files a run already wrote."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import yaml

from cve2cwe import runinfo
from cve2cwe.prompts import REPO_ROOT, load_systems_cfg
from cve2cwe.scorer import _read_jsonl, compute_metrics, load_label_set, parse

_CWE_ID = re.compile(r"CWE-[0-9]+")
_CLEAN_ID = re.compile(r"^CWE-[0-9]+$")
_CPU_SYSTEMS = {"majority", "keyword", "tfidf_svm"}

# Reason labels for an output the scorer rejected. parse() is unchanged;
# this only describes why it returned None.
INVALID_REASONS = (
    "empty",
    "clean_id_outside_the_label_set",
    "extra_text_with_an_id_outside_the_set",
    "extra_text_around_an_id_in_the_set",
    "no_cwe_id",
)


def cost_per_1000_records(price_usd_per_hour: float, records_per_second: float) -> float:
    """price / (records per second * 3600) * 1000."""
    return price_usd_per_hour / (records_per_second * 3600.0) * 1000.0


def cascade_cost_per_1000(
    small_per_1000: float, claude_per_1000: float, auto_label_rate: float
) -> float:
    """Small model on every record, Claude on the records that were not auto-labelled."""
    return small_per_1000 + (1.0 - auto_label_rate) * claude_per_1000


def break_even_records_per_month(
    price_usd_per_hour: float, hours_per_month: float, cost_per_record: float
) -> float:
    """Monthly volume at which an always-on GPU costs the same as one Claude system."""
    return (price_usd_per_hour * hours_per_month) / cost_per_record


def routing_row(
    correct_small: list[bool],
    correct_fallback: list[bool],
    auto: list[bool],
) -> dict:
    """Auto-label rate, accuracy on each part, and cascade accuracy.

    ``auto[i]`` is true when the small model would label record i itself.
    The cascade uses the small model there and the fallback elsewhere.
    """
    n = len(auto)
    if n == 0 or len(correct_small) != n or len(correct_fallback) != n:
        raise ValueError("routing_row: the three lists must be the same non-zero length")
    n_auto = sum(auto)
    n_rest = n - n_auto
    auto_correct = sum(c for c, a in zip(correct_small, auto, strict=True) if a)
    rest_correct = sum(c for c, a in zip(correct_small, auto, strict=True) if not a)
    cascade_correct = sum(
        (c_s if a else c_f)
        for c_s, c_f, a in zip(correct_small, correct_fallback, auto, strict=True)
    )
    return {
        "n": n,
        "n_auto": n_auto,
        "n_rest": n_rest,
        "auto_label_rate": n_auto / n,
        "accuracy_auto": (auto_correct / n_auto) if n_auto else None,
        "accuracy_rest": (rest_correct / n_rest) if n_rest else None,
        "cascade_accuracy": cascade_correct / n,
    }


def invalid_output_reason(raw: str, label_set: set[str]) -> str | None:
    """Why parse() rejected ``raw``, or None when the output is valid."""
    if parse(raw, label_set) is not None:
        return None
    if not isinstance(raw, str) or raw.strip() == "":
        return "empty"
    stripped = raw.strip()
    if _CLEAN_ID.match(stripped):
        return "clean_id_outside_the_label_set"
    ids = _CWE_ID.findall(raw)
    if not ids:
        return "no_cwe_id"
    if any(cwe_id in label_set for cwe_id in ids):
        return "extra_text_around_an_id_in_the_set"
    return "extra_text_with_an_id_outside_the_set"


def _load_yaml(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def _parse_utc(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _result_files(system: str) -> list[Path]:
    return sorted((REPO_ROOT / "results" / system / "test").glob("*.json"))


def _prediction_dir(result: dict) -> Path:
    return REPO_ROOT / result["prediction_dir"]


def _aligned(pred_dir: Path, rows: list[dict]) -> list[dict]:
    preds = _read_jsonl(pred_dir / "predictions.jsonl")
    by_id = {p["cve_id"]: p for p in preds}
    if len(by_id) != len(preds):
        raise SystemExit(f"report: duplicate cve_id in {pred_dir}")
    missing = [r["cve_id"] for r in rows if r["cve_id"] not in by_id]
    if missing or len(preds) != len(rows):
        raise SystemExit(f"report: {pred_dir} does not cover the test split")
    return [by_id[r["cve_id"]] for r in rows]


def _correct(preds: list[dict], rows: list[dict]) -> list[bool]:
    return [p.get("parsed") == r["label"] for p, r in zip(preds, rows, strict=True)]


def _best_claude(results: list[tuple[str, dict]]) -> tuple[str, dict]:
    def key(item: tuple[str, dict]) -> tuple[float, str]:
        system, doc = item
        return (float(doc["metrics"]["accuracy"]), system)

    return max(results, key=key)


def _claude_test_results() -> list[tuple[str, dict]]:
    out = []
    root = REPO_ROOT / "results"
    for path in sorted(root.glob("claude_*/test/*.json")):
        doc = json.loads(path.read_text())
        out.append((doc["system"], doc))
    if not out:
        raise SystemExit("report: no Claude test results")
    return out


def _slice_block(metrics: dict) -> dict:
    kernel = metrics["kernel_accuracy"]
    adp = metrics["adp_slices"]
    return {
        "n": metrics["n"],
        "accuracy": metrics["accuracy"],
        "kernel": kernel["true"]["accuracy"],
        "kernel_n": kernel["true"]["n"],
        "non_kernel": kernel["false"]["accuracy"],
        "non_kernel_n": kernel["false"]["n"],
        "adp_equals_label": adp["equals_label"]["accuracy"],
        "adp_equals_label_n": adp["equals_label"]["n"],
        "adp_disagrees": adp["non_empty_different"]["accuracy"],
        "adp_disagrees_n": adp["non_empty_different"]["n"],
        "adp_empty": adp["empty"]["accuracy"],
        "adp_empty_n": adp["empty"]["n"],
    }


def _matches_adp(preds: list[dict], rows: list[dict]) -> dict:
    """On records where CISA ADP is non-empty and is not exactly the NVD label."""
    n = 0
    match_adp = 0
    match_nvd = 0
    for pred, row in zip(preds, rows, strict=True):
        adp = list(row.get("adp_cwes") or [])
        gold = row["label"]
        if not adp or adp == [gold]:
            continue
        n += 1
        parsed = pred.get("parsed")
        if parsed == gold:
            match_nvd += 1
        if parsed is not None and parsed in adp:
            match_adp += 1
    return {
        "n": n,
        "matches_nvd": match_nvd,
        "matches_nvd_rate": (match_nvd / n) if n else None,
        "matches_adp": match_adp,
        "matches_adp_rate": (match_adp / n) if n else None,
        "definition": (
            "CISA ADP disagrees with NVD when adp_cwes is non-empty and is not "
            "exactly [label]. matches_adp counts a prediction that is one of adp_cwes."
        ),
    }


def _confusions(preds: list[dict], rows: list[dict], top_n: int) -> list[dict]:
    counts: Counter[tuple[str, str]] = Counter()
    for pred, row in zip(preds, rows, strict=True):
        parsed = pred.get("parsed") or ""
        if parsed == row["label"]:
            continue
        counts[(row["label"], parsed)] += 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
    return [
        {"gold": gold, "predicted": predicted, "count": count}
        for (gold, predicted), count in ranked[:top_n]
    ]


def _examples(
    preds: list[dict], rows: list[dict], n_examples: int, n_chars: int
) -> list[dict]:
    wrong = []
    for pred, row in zip(preds, rows, strict=True):
        parsed = pred.get("parsed")
        if parsed == row["label"]:
            continue
        wrong.append(
            {
                "cve_id": row["cve_id"],
                "gold": row["label"],
                "predicted": parsed,
                "confidence": pred.get("confidence"),
                "adp_cwes": list(row.get("adp_cwes") or []),
                "description": (row.get("description") or "")[:n_chars],
            }
        )
    wrong.sort(
        key=lambda item: (
            item["confidence"] is None,
            -(item["confidence"] if item["confidence"] is not None else 0.0),
            item["cve_id"],
        )
    )
    return wrong[:n_examples]


def _per_class(candidate: dict, champion: dict, min_support: int) -> list[dict]:
    rows = []
    for cwe in sorted(candidate["per_class"]):
        support = candidate["per_class"][cwe]["support"]
        if support < min_support:
            continue
        rows.append(
            {
                "cwe": cwe,
                "support": support,
                "candidate_recall": candidate["per_class"][cwe]["recall"],
                "champion_recall": champion["per_class"][cwe]["recall"],
            }
        )
    return rows


def _llm_invalid_reasons(label_set: set[str]) -> dict:
    table = {}
    root = REPO_ROOT / "results"
    for path in sorted(root.glob("*/test/*.json")):
        if path.parent.parent.name == "paired":
            continue
        doc = json.loads(path.read_text())
        system = doc.get("system")
        if system in _CPU_SYSTEMS:
            continue
        preds = _read_jsonl(_prediction_dir(doc) / "predictions.jsonl")
        counts = {reason: 0 for reason in INVALID_REASONS}
        for pred in preds:
            if pred.get("parsed") is not None:
                continue
            reason = invalid_output_reason(pred.get("raw_output") or "", label_set)
            if reason not in counts:
                raise SystemExit(
                    f"report: unclassified invalid output for {system}: "
                    f"{pred.get('raw_output')!r}"
                )
            counts[reason] += 1
        table[system] = {
            "run_id": doc.get("run_id"),
            "prediction_dir": doc["prediction_dir"],
            "n": len(preds),
            "invalid": sum(counts.values()),
            "reasons": counts,
        }
    return table


def write_analysis() -> None:
    info = runinfo.capture()
    if info.git_dirty:
        raise SystemExit("report: refusing --analysis because git_dirty is true")
    systems = load_systems_cfg()
    report_cfg = systems["report"]
    min_support = int(systems["scoring"]["macro_f1_min_support"])
    gate = _load_yaml(REPO_ROOT / "configs" / "gate.yaml")
    rows = _read_jsonl(REPO_ROOT / "data" / "processed" / "test.jsonl")
    label_set = load_label_set()

    shipped = gate["candidate"]["shipped"]
    champion_name = gate["champion"]["system"]
    claude_name, claude_doc = _best_claude(_claude_test_results())

    champion_path = (
        REPO_ROOT
        / "results"
        / champion_name
        / "test"
        / f"{gate['champion']['run_id']}.json"
    )
    wanted = {
        "candidate": (shipped, _result_files(shipped)[0]),
        "champion": (champion_name, champion_path),
        "best_claude": (claude_name, None),
    }
    # Resolve result docs.
    systems_out = {}
    metrics_by_role = {}
    preds_by_role = {}
    for role, (name, path) in wanted.items():
        if role == "best_claude":
            doc = claude_doc
        else:
            doc = json.loads(Path(path).read_text())
        preds = _aligned(_prediction_dir(doc), rows)
        metrics = compute_metrics(preds, rows, label_set, min_support)
        # Drop the vector; it is only for the bootstrap and is large.
        metrics.pop("_correct_vector", None)
        preds_by_role[role] = preds
        metrics_by_role[role] = metrics
        systems_out[role] = {
            "system": name,
            "run_id": doc.get("run_id"),
            "prediction_dir": doc["prediction_dir"],
            "slices": _slice_block(metrics),
            "where_adp_disagrees": _matches_adp(preds, rows),
        }

    doc = {
        "split": "test",
        "git_commit": info.git_commit,
        "git_dirty": info.git_dirty,
        "systems": systems_out,
        "candidate_confusions": _confusions(
            preds_by_role["candidate"],
            rows,
            int(report_cfg["confusion_top_n"]),
        ),
        "per_class_recall": _per_class(
            metrics_by_role["candidate"],
            metrics_by_role["champion"],
            min_support,
        ),
        "per_class_min_support": min_support,
        "candidate_high_confidence_errors": _examples(
            preds_by_role["candidate"],
            rows,
            int(report_cfg["example_errors"]),
            int(report_cfg["example_description_chars"]),
        ),
        "invalid_reasons": _llm_invalid_reasons(label_set),
    }
    out = REPO_ROOT / "results" / "error_analysis.json"
    out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"[report] wrote {out}")


def _bench_concurrency(concurrency: int) -> tuple[dict, dict]:
    paths = sorted((REPO_ROOT / "outputs" / "bench").glob("*/bench.json"))
    chosen = None
    for path in paths:
        run_doc = json.loads((path.parent / "run.json").read_text())
        if run_doc.get("git_dirty"):
            continue
        chosen = path
    if chosen is None:
        raise SystemExit("report: no bench.json with git_dirty false")
    doc = json.loads(chosen.read_text())
    for level in doc["levels"]:
        if int(level["concurrency"]) == concurrency:
            return doc, level
    raise SystemExit(f"report: {chosen} has no concurrency {concurrency}")


def _run_json_for(result: dict) -> dict:
    return json.loads((_prediction_dir(result) / "run.json").read_text())


def write_routing() -> None:
    info = runinfo.capture()
    if info.git_dirty:
        raise SystemExit("report: refusing --routing because git_dirty is true")
    gate = _load_yaml(REPO_ROOT / "configs" / "gate.yaml")
    serve = _load_yaml(REPO_ROOT / "configs" / "serve.yaml")
    rows = _read_jsonl(REPO_ROOT / "data" / "processed" / "test.jsonl")
    bench_doc, level = _bench_concurrency(32)
    small_per_1000 = float(level["cost_per_1000_usd"])
    price = float(serve["gpu_price_usd_per_hour"])
    hours = float(serve["hours_per_month"])

    claude_results = _claude_test_results()
    best_name, best_doc = _best_claude(claude_results)
    best_run = _run_json_for(best_doc)
    best_n = int(best_run["counts"]["total"])
    best_cost = float(best_run["cost_usd"])
    best_per_record = best_cost / best_n
    best_per_1000 = best_per_record * 1000.0
    best_preds = _aligned(_prediction_dir(best_doc), rows)
    correct_fallback = _correct(best_preds, rows)

    systems_out = {}
    for name in (gate["candidate"]["shipped"], gate["champion"]["system"]):
        result_path = _result_files(name)[0]
        result = json.loads(result_path.read_text())
        preds = _aligned(_prediction_dir(result), rows)
        correct = _correct(preds, rows)
        block = {}
        for key, spec in gate["routing"][name].items():
            if not key.startswith("at_"):
                continue
            threshold = float(spec["threshold"])
            auto = [
                p.get("confidence") is not None and p["confidence"] >= threshold
                for p in preds
            ]
            row = routing_row(correct, correct_fallback, auto)
            row["threshold"] = threshold
            row["cost_per_1000_usd"] = {
                "small_only": small_per_1000,
                "claude_only": best_per_1000,
                "cascade": cascade_cost_per_1000(
                    small_per_1000, best_per_1000, row["auto_label_rate"]
                ),
            }
            block[key] = row
        systems_out[name] = {
            "prediction_dir": result["prediction_dir"],
            "run_id": result.get("run_id"),
            "thresholds": block,
        }

    break_even = {}
    claude_costs = {}
    for name, doc in claude_results:
        run_doc = _run_json_for(doc)
        n = int(run_doc["counts"]["total"])
        cost = float(run_doc["cost_usd"])
        per_record = cost / n
        claude_costs[name] = {
            "run_id": doc.get("run_id"),
            "n": n,
            "cost_usd": cost,
            "cost_per_record_usd": per_record,
            "cost_per_1000_usd": per_record * 1000.0,
            "test_accuracy": doc["metrics"]["accuracy"],
        }
        break_even[name] = break_even_records_per_month(price, hours, per_record)

    out_doc = {
        "split": "test",
        "git_commit": info.git_commit,
        "git_dirty": info.git_dirty,
        "best_claude": best_name,
        "small_model_cost_per_1000_usd": small_per_1000,
        "small_model_cost_source": {
            "bench_run_id": bench_doc["run_id"],
            "concurrency": 32,
            "records_per_second": level["records_per_second"],
            "gpu_price_usd_per_hour": price,
        },
        "cascade_cost_formula": (
            "small_per_1000 + (1 - auto_label_rate) * claude_per_1000"
        ),
        "hours_per_month": hours,
        "hours_per_month_basis": "24 * 365 / 12",
        "gpu_price_usd_per_hour": price,
        "gpu_price_source": serve["gpu_price_source"],
        "systems": systems_out,
        "claude_costs": claude_costs,
        "break_even_records_per_month": break_even,
    }
    out = REPO_ROOT / "results" / "routing.json"
    out.write_text(json.dumps(out_doc, indent=2) + "\n")
    print(f"[report] wrote {out}")


def _seconds_from_run(doc: dict) -> float | None:
    if "wall_seconds" in doc:
        return float(doc["wall_seconds"])
    start = doc.get("started_utc") or doc.get("start")
    end = doc.get("finished_utc") or doc.get("end")
    if start and end:
        return (_parse_utc(end) - _parse_utc(start)).total_seconds()
    return None


def _purpose(rel: str, doc: dict) -> str:
    system = str(doc.get("system") or "")
    if rel.startswith("outputs/train/"):
        return "training"
    if "gguf" in rel:
        return "gguf_export"
    if rel.startswith("outputs/merge/"):
        return "merge"
    if rel.startswith("outputs/bench/"):
        return "benchmark"
    if "backlog" in rel or system.endswith("_backlog"):
        return "backlog"
    if "cost_usd" in doc or system.startswith("claude_"):
        return "claude"
    if system in _CPU_SYSTEMS:
        return "cpu_baseline"
    if "wall_seconds" in doc and ("served_model" in doc or "base_url" in doc):
        return "evaluation"
    return "unclassified"


def write_spend() -> None:
    info = runinfo.capture()
    if info.git_dirty:
        raise SystemExit("report: refusing --spend because git_dirty is true")
    pod = json.loads((REPO_ROOT / "results" / "pod.json").read_text())
    serve = _load_yaml(REPO_ROOT / "configs" / "serve.yaml")
    price = float(pod["price_usd_per_hour"]["total"])
    started = _parse_utc(pod["started_utc"])
    now = datetime.now(UTC)
    hours = (now - started).total_seconds() / 3600.0

    by_purpose: dict[str, list[dict]] = {}
    claude_runs = []
    missing_seconds = []
    for path in sorted((REPO_ROOT / "outputs").rglob("run.json")):
        doc = json.loads(path.read_text())
        rel = str(path.relative_to(REPO_ROOT))
        purpose = _purpose(rel, doc)
        seconds = _seconds_from_run(doc)
        entry = {
            "path": rel,
            "system": doc.get("system") or doc.get("run_name"),
            "split": doc.get("split"),
            "seconds": seconds,
            "git_commit": doc.get("git_commit"),
            "git_dirty": doc.get("git_dirty"),
        }
        by_purpose.setdefault(purpose, []).append(entry)
        if seconds is None:
            missing_seconds.append(rel)
        if purpose == "claude":
            claude_runs.append(
                {
                    "path": rel,
                    "system": doc.get("system"),
                    "cost_usd": doc.get("cost_usd"),
                    "records": (doc.get("counts") or {}).get("total"),
                }
            )

    gpu_purposes = ("training", "merge", "evaluation", "benchmark", "backlog", "gguf_export")
    purpose_totals = {}
    recorded = 0.0
    for purpose in gpu_purposes:
        rows = by_purpose.get(purpose, [])
        total = sum(row["seconds"] or 0.0 for row in rows)
        recorded += total
        purpose_totals[purpose] = {"seconds": total, "runs": rows}

    out_doc = {
        "git_commit": info.git_commit,
        "git_dirty": info.git_dirty,
        "written_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gpu": {
            "provider": pod["provider"],
            "cloud": pod["cloud"],
            "gpu": serve["gpu_name"],
            "started_utc": pod["started_utc"],
            "price_usd_per_hour": price,
            "price_source": serve["gpu_price_source"],
            "hours_so_far": hours,
            "total_usd": hours * price,
            "serve_yaml_price_usd_per_hour": float(serve["gpu_price_usd_per_hour"]),
            "seconds_by_purpose": purpose_totals,
            "recorded_gpu_seconds": recorded,
            "recorded_gpu_hours": recorded / 3600.0,
            "billed_minus_recorded_hours": hours - (recorded / 3600.0),
        },
        "claude": {
            "runs": claude_runs,
            "total_usd": sum(row["cost_usd"] or 0.0 for row in claude_runs),
        },
        "cpu_baselines": by_purpose.get("cpu_baseline", []),
        "unclassified_run_json": by_purpose.get("unclassified", []),
        "run_json_missing_seconds": missing_seconds,
        "not_recorded": [
            "The 30-record sanity calls have no run.json and are not in this ledger.",
            "Failed attempts that wrote no run.json are not in this ledger.",
            "Model-load time and idle time between runs are in the billed GPU hours "
            "and not in seconds_by_purpose. billed_minus_recorded_hours is that gap.",
            "CPU baselines (majority, keyword, tfidf_svm) are listed separately and "
            "are not GPU time.",
        ],
    }
    out = REPO_ROOT / "results" / "spend.json"
    out.write_text(json.dumps(out_doc, indent=2) + "\n")
    print(f"[report] wrote {out}")
    print(
        f"[report] gpu hours={hours} total_usd={hours * price} "
        f"recorded_gpu_seconds={recorded} claude_usd={out_doc['claude']['total_usd']}"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Routing, error analysis, spend")
    ap.add_argument("--analysis", action="store_true")
    ap.add_argument("--routing", action="store_true")
    ap.add_argument("--spend", action="store_true")
    args = ap.parse_args(argv)
    if not (args.analysis or args.routing or args.spend):
        ap.error("pass --analysis, --routing, --spend, or a combination")
    if args.analysis:
        write_analysis()
    if args.routing:
        write_routing()
    if args.spend:
        write_spend()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
