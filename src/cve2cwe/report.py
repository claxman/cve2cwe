"""Routing, error analysis and the spend ledger. Reads files a run already wrote."""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

import yaml

from cve2cwe import runinfo
from cve2cwe.prompts import REPO_ROOT, load_systems_cfg
from cve2cwe.scorer import _read_jsonl, compute_metrics, load_label_set, parse

_CWE_ID = re.compile(r"CWE-[0-9]+")
_CLEAN_ID = re.compile(r"^CWE-[0-9]+$")
_CPU_SYSTEMS = {"majority", "keyword", "tfidf_svm"}
_CPU_COST_NOTE = "CPU, not measured"

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
            # The linear model runs on CPU. The GPU figure is the fine-tuned
            # checkpoint only, so it is not stored against tfidf_svm.
            if name in _CPU_SYSTEMS:
                row["cost_per_1000_usd"] = {
                    "small_only": None,
                    "claude_only": best_per_1000,
                    "cascade": None,
                    "note": _CPU_COST_NOTE,
                }
            else:
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


def fmt_pct(value: float) -> str:
    """One decimal place. 0.7590... is 75.9%."""
    return f"{100.0 * value:.1f}%"


def fmt_points(value: float) -> str:
    """An accuracy difference, in percentage points, with a sign."""
    return f"{100.0 * value:+.1f}"


def fmt_count(value: int) -> str:
    return f"{value:,}"


def fmt_usd(value: float) -> str:
    """Three significant digits, half up."""
    dec = Decimal(str(value))
    if dec == 0:
        return "$0.00"
    sign = "-" if dec < 0 else ""
    dec = abs(dec)
    quantum = Decimal(f"1e{dec.adjusted() - 2}")
    rounded = dec.quantize(quantum, rounding=ROUND_HALF_UP)
    return f"{sign}${format(rounded, 'f')}"


def fmt_sig(value: float, digits: int = 4) -> str:
    dec = Decimal(str(value))
    if dec == 0:
        return "0"
    sign = "-" if dec < 0 else ""
    dec = abs(dec)
    quantum = Decimal(f"1e{dec.adjusted() - (digits - 1)}")
    rounded = dec.quantize(quantum, rounding=ROUND_HALF_UP)
    return sign + format(rounded, "f")


def _md(headers: list[str], rows: list[list[str]]) -> str:
    head = "| " + " | ".join(headers) + " |"
    rule = "|" + "|".join("---" for _ in headers) + "|"
    body = ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join([head, rule, *body])


def _cve_link(cve_id: str) -> str:
    return f"[{cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id})"


def _one_result(system: str, split: str) -> dict:
    paths = sorted((REPO_ROOT / "results" / system / split).glob("*.json"))
    if len(paths) != 1:
        raise SystemExit(f"report: {system} {split} has {len(paths)} result files")
    return json.loads(paths[0].read_text())


def _test_results() -> list[dict]:
    out = []
    root = REPO_ROOT / "results"
    for path in sorted(root.glob("*/test/*.json")):
        if path.parent.parent.name == "paired":
            continue
        out.append(json.loads(path.read_text()))
    return out


def _dev_accuracy(system: str) -> float | None:
    folder = REPO_ROOT / "results" / system / "dev"
    if not folder.is_dir():
        return None
    return float(_one_result(system, "dev")["metrics"]["accuracy"])


def _n_invalid(system: str, run_id: str) -> int:
    path = REPO_ROOT / "outputs" / system / "test" / run_id / "predictions.jsonl"
    return sum(1 for row in _read_jsonl(path) if row.get("parsed") is None)


def _acceptance() -> tuple[str, str]:
    """Commit that set the acceptance file to final, and its UTC time.

    The parent has to be present. A shallow checkout has no parent, and git
    then treats the tip as the commit that added the line.
    """
    proc = subprocess.run(
        [
            "git",
            "log",
            "-S",
            "Status: final",
            "--reverse",
            "--format=%H%x09%cI",
            "--",
            "docs/ACCEPTANCE.md",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    for line in proc.stdout.splitlines():
        sha, iso = line.split("\t")
        parent = subprocess.run(
            ["git", "rev-parse", "--verify", f"{sha}^"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        if parent.returncode != 0:
            continue
        diff = subprocess.run(
            ["git", "diff", "-U0", f"{sha}^", sha, "--", "docs/ACCEPTANCE.md"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        if "+Status: final" not in diff.stdout:
            continue
        stamp = datetime.fromisoformat(iso).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        return sha, stamp
    raise SystemExit(
        "report: the commit that set docs/ACCEPTANCE.md to final is not in this checkout"
    )


def _first_candidate_test_utc(gate: dict) -> str:
    times = []
    for seed in gate["seeds"]:
        path = (
            REPO_ROOT
            / "outputs"
            / seed["system"]
            / "test"
            / seed["run_id"]
            / "run.json"
        )
        times.append(json.loads(path.read_text())["started_utc"])
    return min(times)


def _fix_cpu_routing_cost() -> None:
    """Drop the GPU price from the linear model without rewriting other fields.

    A full json dump would reformat every float in the file. This replaces
    only the two tfidf cost objects and leaves the recorded git commit as it was.
    """
    path = REPO_ROOT / "results" / "routing.json"
    text = path.read_text()
    start = text.index('"tfidf_svm"')
    end = text.index('"claude_costs"')
    mid = text[start:end]
    if mid.count(f'"note": "{_CPU_COST_NOTE}"') == 2 and '"small_only": null' in mid:
        return
    pattern = re.compile(
        r'"cost_per_1000_usd": \{\n'
        r'            "small_only": [0-9.eE+-]+,\n'
        r'            "claude_only": ([0-9.eE+-]+),\n'
        r'            "cascade": [0-9.eE+-]+\n'
        r"          \}"
    )

    def _repl(match: re.Match) -> str:
        claude = match.group(1)
        return (
            '"cost_per_1000_usd": {\n'
            '            "small_only": null,\n'
            f'            "claude_only": {claude},\n'
            '            "cascade": null,\n'
            f'            "note": "{_CPU_COST_NOTE}"\n'
            "          }"
        )

    new_mid, n = pattern.subn(_repl, mid)
    if n != 2:
        raise SystemExit(f"report: expected 2 tfidf cost blocks, rewrote {n}")
    path.write_text(text[:start] + new_mid + text[end:])
    print("[report] updated tfidf costs in results/routing.json")


def _route_view(gate_cfg: dict, routing: dict) -> dict:
    """Test routing rows plus Claude accuracy on the records left over.

    The stored row is checked against a fresh pass over the prediction files.
    """
    rows = _read_jsonl(REPO_ROOT / "data" / "processed" / "test.jsonl")
    dev_rows = _read_jsonl(REPO_ROOT / "data" / "processed" / "dev.jsonl")
    best_name = routing["best_claude"]
    best_doc = _one_result(best_name, "test")
    correct_fallback = _correct(_aligned(_prediction_dir(best_doc), rows), rows)
    shipped = gate_cfg["candidate"]["shipped"]
    names = (shipped, gate_cfg["champion"]["system"])
    out = {}
    for name in names:
        result = _one_result(name, "test")
        preds = _aligned(_prediction_dir(result), rows)
        correct = _correct(preds, rows)
        dev_result = _one_result(name, "dev")
        dev_preds = _aligned(_prediction_dir(dev_result), dev_rows)
        dev_correct = _correct(dev_preds, dev_rows)
        thresholds = {}
        for key, spec in gate_cfg["routing"][name].items():
            if not str(key).startswith("at_"):
                continue
            threshold = float(spec["threshold"])
            auto = [
                p.get("confidence") is not None and float(p["confidence"]) >= threshold
                for p in preds
            ]
            fresh = routing_row(correct, correct_fallback, auto)
            stored = routing["systems"][name]["thresholds"][key]
            if fresh["n_auto"] != stored["n_auto"] or fresh["n_rest"] != stored["n_rest"]:
                raise SystemExit(f"report: {name} {key} does not match routing.json")
            n_rest = fresh["n_rest"]
            claude_rest = sum(
                c for c, flag in zip(correct_fallback, auto, strict=True) if not flag
            )
            dev_auto = [
                p.get("confidence") is not None and float(p["confidence"]) >= threshold
                for p in dev_preds
            ]
            dev_n_auto = sum(dev_auto)
            dev_hit = sum(
                c for c, flag in zip(dev_correct, dev_auto, strict=True) if flag
            )
            if dev_n_auto != int(spec["n"]) or dev_hit != int(spec["n_correct"]):
                raise SystemExit(f"report: {name} {key} dev counts do not match gate.yaml")
            thresholds[key] = {
                "threshold": threshold,
                "dev_coverage": dev_n_auto / len(dev_rows),
                "dev_precision": dev_hit / dev_n_auto,
                "auto_label_rate": fresh["auto_label_rate"],
                "accuracy_auto": fresh["accuracy_auto"],
                "accuracy_rest": fresh["accuracy_rest"],
                "claude_rest": claude_rest / n_rest,
                "cascade_accuracy": fresh["cascade_accuracy"],
                "cost": stored["cost_per_1000_usd"],
            }
        out[name] = thresholds
    return out


def _block_headline(
    gate: dict, gate_cfg: dict, routing: dict, view: dict, bench: dict
) -> str:
    champ = gate["champion"]
    best = routing["best_claude"]
    best_acc = routing["claude_costs"][best]["test_accuracy"]
    shipped = gate_cfg["candidate"]["shipped"]
    level = next(row for row in bench["levels"] if int(row["concurrency"]) == 32)
    ship = view[shipped]["at_0.95"]
    linear = view[gate["champion"]["system"]]["at_0.95"]
    gains = []
    musts = []
    invalids = []
    for seed in gate["seeds"]:
        gains.append(
            f"{seed['system']} {fmt_points(seed['paired_diff'])} points "
            f"(lower bound {fmt_points(seed['paired_lo'])})"
        )
        musts.append(f"{fmt_count(seed['must_pass_correct'])}/{fmt_count(seed['must_pass_n'])}")
        invalids.append(fmt_count(_n_invalid(seed["system"], seed["run_id"])))
    summary, labels = _backlog_rows()
    n95 = sum(1 for row in labels if row["auto_95"] == "True")
    label_path = f"outputs/backlog/{summary['run_id']}/labels.csv"
    return "\n".join(
        [
            (
                f"- Verdict {gate['verdict']}. Fine-tuned mean test accuracy "
                f"{fmt_pct(gate['mean_accuracy'])}. Champion {champ['system']} "
                f"{fmt_pct(champ['accuracy'])}. Best Claude run {best} "
                f"{fmt_pct(best_acc)}. Pass line {fmt_pct(gate['g1_pass_line'])}."
            ),
            (
                "- Per-seed gains: "
                + "; ".join(gains)
                + f". Must-pass counts: {', '.join(musts)}. "
                + f"Invalid outputs: {', '.join(invalids)}."
            ),
            (
                f"- At the dev 95% threshold on test, {shipped} auto-labels "
                f"{fmt_pct(ship['auto_label_rate'])} of records at "
                f"{fmt_pct(ship['accuracy_auto'])} precision. "
                f"{champ['system']} auto-labels {fmt_pct(linear['auto_label_rate'])} "
                f"at {fmt_pct(linear['accuracy_auto'])} precision."
            ),
            (
                f"- On the records {shipped} does not auto-label, its accuracy is "
                f"{fmt_pct(ship['accuracy_rest'])} and {best} on those same records "
                f"is {fmt_pct(ship['claude_rest'])}."
            ),
            (
                f"- Cost per 1,000 records: {shipped} at concurrency 32 is "
                f"{fmt_usd(level['cost_per_1000_usd'])}, and {best} is "
                f"{fmt_usd(routing['claude_costs'][best]['cost_per_1000_usd'])}. "
                f"Prices read on {bench['gpu']['price_read_utc']}."
            ),
            (
                f"- Backlog: {fmt_count(summary['rows'])} rows in "
                f"{summary['wall_seconds']:.2f} seconds, GPU cost "
                f"{fmt_usd(summary['gpu_cost_usd'])}, "
                f"{fmt_count(n95)} rows at or above the dev 95% threshold. "
                f"[labels.csv]({label_path})."
            ),
        ]
    )


def _block_coverage(stats: dict) -> str:
    cov = stats["coverage_pre_rule_2"]
    rows = []
    for year in sorted(key for key in cov if key != "test_window"):
        block = cov[year]
        rows.append(
            [
                year,
                fmt_count(block["records"]),
                fmt_pct(block["nvd_analyst_cwe_share"]),
            ]
        )
    window = cov["test_window"]
    sentence = (
        f"In the test window, {fmt_pct(window['none_share'])} of "
        f"{fmt_count(window['records'])} CVEs have no CWE from any source. "
        f"{fmt_pct(window['none_kernel_share'])} of those are kernel CVEs."
    )
    table = _md(["Publication year", "Records", "NVD analyst CWE"], rows)
    return table + "\n\n" + sentence


def _block_data(stats: dict) -> str:
    rows = []
    for name in ("train", "dev", "test"):
        block = stats["splits"][name]
        start, end = block["date_range"]
        rows.append(
            [
                name,
                fmt_count(block["rows"]),
                start,
                end,
                fmt_pct(block["kernel_share"]),
            ]
        )
    funnel = stats["funnel"]
    line = (
        f"{fmt_count(funnel['rule_1_input'])} feed records, "
        f"{fmt_count(funnel['rule_1_dropped_rejected'])} rejected, "
        f"{fmt_count(funnel['rule_2_dropped_no_label'])} with no label, "
        f"{fmt_count(funnel['rule_2_dropped_placeholder'])} placeholder, "
        f"{fmt_count(funnel['rule_2_dropped_multi_label'])} with more than one CWE, "
        f"{fmt_count(funnel['rule_2_kept'])} with a single NVD CWE, then "
        f"{fmt_count(funnel['final_train'])} train, "
        f"{fmt_count(funnel['final_dev'])} dev and "
        f"{fmt_count(funnel['final_test'])} test."
    )
    test = stats["splits"]["test"]
    near_bits = []
    for key, value in stats["near_duplicate_test_to_train"].items():
        cut = key.removeprefix("share_ge_").replace("_", ".")
        near_bits.append(f"{fmt_pct(value)} at or above {cut}")
    near = "Near-duplicate share of test against train: " + ", ".join(near_bits) + "."
    adp = (
        f"{fmt_pct(test['adp_nonempty_share'])} of test records have a CISA ADP label. "
        f"Where CISA labelled the record, it agrees with NVD on "
        f"{fmt_pct(test['adp_agree_share'])}."
    )
    table = _md(["Split", "Rows", "From", "To", "Kernel share"], rows)
    return "\n\n".join(
        [
            table,
            f"Label set size: {fmt_count(funnel['label_set_size'])}.",
            line,
            adp,
            near,
        ]
    )


def _block_training(gate_cfg: dict) -> str:
    groups = (
        ("1 epoch", gate_cfg["candidate"]["one_epoch_systems"]),
        ("2 epochs", gate_cfg["candidate"]["two_epoch_systems"]),
    )
    rows = []
    means = {}
    for label, systems in groups:
        accs = []
        for system in systems:
            folder = system.removeprefix("candidate_")
            run = json.loads((REPO_ROOT / "outputs" / "train" / folder / "run.json").read_text())
            dev_acc = _dev_accuracy(system)
            if dev_acc is None:
                raise SystemExit(f"report: {system} has no dev result")
            accs.append(dev_acc)
            minutes = float(run["training_seconds"]) / 60.0
            last_loss = float(run["dev_losses"][-1]["loss"])
            epochs = int(run["full_config"]["num_train_epochs"])
            rows.append(
                [folder, str(epochs), f"{minutes:.1f}", fmt_sig(last_loss), fmt_pct(dev_acc)]
            )
        means[label] = sum(accs) / len(accs)
    one = means["1 epoch"]
    two = means["2 epochs"]
    chosen = 2 if two > one else 1
    if int(gate_cfg["candidate"]["chosen_epochs"]) != chosen:
        raise SystemExit("report: chosen length does not match the dev means")
    table = _md(
        ["Run", "Epochs", "Training minutes", "Last dev loss", "Dev accuracy"],
        rows,
    )
    note = (
        f"Mean dev accuracy, 1 epoch: {fmt_pct(one)}. "
        f"2 epochs: {fmt_pct(two)}. Chosen length: {chosen} epochs."
    )
    return table + "\n\n" + note


def _block_serving(bench: dict) -> str:
    rows = []
    for level in bench["levels"]:
        rows.append(
            [
                str(level["concurrency"]),
                fmt_sig(level["records_per_second"]),
                fmt_sig(level["latency_ms_p50"]),
                fmt_sig(level["latency_ms_p95"]),
                fmt_usd(level["cost_per_1000_usd"]),
            ]
        )
    gpu = bench["gpu"]
    note = (
        f"GPU: {gpu['name']}. Price {fmt_usd(gpu['price_usd_per_hour'])} per hour, "
        f"read on {gpu['price_read_utc']}. {gpu['price_source']}."
    )
    table = _md(
        ["Concurrency", "Records per second", "Latency p50 ms", "Latency p95 ms", "USD per 1,000"],
        rows,
    )
    return table + "\n\n" + note


def _block_gate(gate: dict) -> str:
    seeds = gate["seeds"]
    headers = ["Gate", "Bar", *[seed["system"] for seed in seeds]]
    bar = gate["g1_pass_line"]

    def _flag(ok: bool) -> str:
        return "PASS" if ok else "FAIL"

    g1 = ["G1 test accuracy", f">= {fmt_pct(bar)}"]
    for seed in seeds:
        g1.append(f"{fmt_pct(seed['accuracy'])} {_flag(seed['accuracy'] >= bar)}")
    g2 = ["G2 invalid rate", f"<= {fmt_pct(gate['thresholds']['invalid'])}"]
    for seed in seeds:
        g2.append(f"{fmt_pct(seed['invalid_rate'])} {_flag(seed['g2'])}")
    g3 = ["G3 must-pass", f">= {fmt_pct(gate['thresholds']['must_pass'])}"]
    for seed in seeds:
        g3.append(
            f"{fmt_pct(seed['must_pass_accuracy'])} "
            f"({fmt_count(seed['must_pass_correct'])}/{fmt_count(seed['must_pass_n'])}) "
            f"{_flag(seed['g3'])}"
        )
    bound = float(gate["thresholds"]["paired_lower_bound_above"])
    g4_bar = "above 0" if bound == 0 else f"above {fmt_points(bound)}"
    g4 = ["G4 paired lower bound", g4_bar]
    for seed in seeds:
        g4.append(f"{fmt_points(seed['paired_lo'])} points {_flag(seed['g4'])}")
    sha, when = _acceptance()
    started = _first_candidate_test_utc(gate)
    official = _flag(gate["g1"])
    note = (
        f"Mean test accuracy {fmt_pct(gate['mean_accuracy'])}. "
        f"G1 on that mean: {official}. Verdict: {gate['verdict']}. "
        f"Acceptance commit {sha} at {when}. "
        f"First candidate test run started {started}."
    )
    return _md(headers, [g1, g2, g3, g4]) + "\n\n" + note


def _acc_cell(acc: float, ci: list | None) -> str:
    if not ci:
        return fmt_pct(acc)
    return f"{fmt_pct(acc)} ({fmt_pct(ci[0])} to {fmt_pct(ci[1])})"


def _dev_cell(system: str) -> str:
    acc = _dev_accuracy(system)
    if acc is not None:
        return fmt_pct(acc)
    if system.startswith("claude_"):
        return "test only"
    return "not run"


def _block_main(gate: dict, gate_cfg: dict) -> str:
    chosen = list(gate_cfg["candidate"]["chosen_systems"])
    shipped = gate_cfg["candidate"]["shipped"]
    batched = [
        doc["system"]
        for doc in _test_results()
        if doc["system"].startswith(shipped) and doc["system"].endswith("_batched")
    ]
    grouped = set(chosen) | set(batched)
    others = []
    by_system = {doc["system"]: doc for doc in _test_results()}
    for doc in by_system.values():
        if doc["system"] in grouped:
            continue
        others.append(doc)
    others.sort(key=lambda doc: float(doc["metrics"]["accuracy"]), reverse=True)
    mean_acc = float(gate["mean_accuracy"])
    devs = [_dev_accuracy(system) for system in chosen]
    if any(item is None for item in devs):
        raise SystemExit("report: a chosen seed has no dev accuracy")
    mean_dev = sum(devs) / len(devs)

    def _row(
        name: str, dev: str, acc: float, ci: list | None, invalid: float, f1: float
    ) -> list[str]:
        return [name, dev, _acc_cell(acc, ci), fmt_pct(invalid), fmt_pct(f1)]

    invalid_mean = sum(
        float(by_system[system]["metrics"]["invalid_rate"]) for system in chosen
    ) / len(chosen)
    block = [
        _row(
            "fine-tuned mean",
            fmt_pct(mean_dev),
            mean_acc,
            None,
            invalid_mean,
            _mean_macro(chosen),
        ),
    ]
    for system in chosen:
        doc = by_system[system]
        metrics = doc["metrics"]
        block.append(
            _row(
                system,
                _dev_cell(system),
                metrics["accuracy"],
                metrics["accuracy_ci95"],
                metrics["invalid_rate"],
                metrics["macro_f1"],
            )
        )
    for system in batched:
        doc = by_system[system]
        metrics = doc["metrics"]
        block.append(
            _row(
                system,
                _dev_cell(system),
                metrics["accuracy"],
                metrics["accuracy_ci95"],
                metrics["invalid_rate"],
                metrics["macro_f1"],
            )
        )
    rest = []
    for doc in others:
        metrics = doc["metrics"]
        rest.append(
            _row(
                doc["system"],
                _dev_cell(doc["system"]),
                metrics["accuracy"],
                metrics["accuracy_ci95"],
                metrics["invalid_rate"],
                metrics["macro_f1"],
            )
        )
    insert = 0
    while insert < len(rest):
        system = rest[insert][0]
        acc = float(by_system[system]["metrics"]["accuracy"])
        if acc <= mean_acc:
            break
        insert += 1
    rows = rest[:insert] + block + rest[insert:]
    table = _md(
        ["System", "Dev accuracy", "Test accuracy", "Test invalid rate", "Test macro-F1"],
        rows,
    )
    return table + "\n\nClaude runs are test only. The fine-tuned mean has no stored interval."


def _mean_macro(systems: list[str]) -> float:
    docs = [_one_result(system, "test") for system in systems]
    return sum(float(doc["metrics"]["macro_f1"]) for doc in docs) / len(docs)


def _block_slices(analysis: dict) -> str:
    order = ("candidate", "champion", "best_claude")
    systems = [analysis["systems"][key] for key in order]
    headers = ["Slice", "n", *[item["system"] for item in systems]]

    def _rate(item: dict, key: str) -> str:
        return fmt_pct(item["slices"][key])

    def _n(key: str) -> str:
        return fmt_count(systems[0]["slices"][key])

    disagree = ["CISA disagrees", _n("adp_disagrees_n")]
    for item in systems:
        disagree.append(
            f"{fmt_pct(item['slices']['adp_disagrees'])} match NVD, "
            f"{fmt_pct(item['where_adp_disagrees']['matches_adp_rate'])} match CISA"
        )
    rows = [
        ["kernel", _n("kernel_n"), *[_rate(item, "kernel") for item in systems]],
        ["non-kernel", _n("non_kernel_n"), *[_rate(item, "non_kernel") for item in systems]],
        [
            "CISA agrees",
            _n("adp_equals_label_n"),
            *[_rate(item, "adp_equals_label") for item in systems],
        ],
        disagree,
        ["CISA absent", _n("adp_empty_n"), *[_rate(item, "adp_empty") for item in systems]],
    ]
    return _md(headers, rows)


def _block_routing(view: dict, gate_cfg: dict) -> str:
    shipped = gate_cfg["candidate"]["shipped"]
    names = (shipped, gate_cfg["champion"]["system"])
    rows = []
    for name in names:
        for key in sorted(view[name]):
            row = view[name][key]
            rows.append(
                [
                    name,
                    key,
                    fmt_pct(row["dev_coverage"]),
                    fmt_pct(row["dev_precision"]),
                    fmt_pct(row["auto_label_rate"]),
                    fmt_pct(row["accuracy_auto"]),
                    fmt_pct(row["accuracy_rest"]),
                    fmt_pct(row["claude_rest"]),
                    fmt_pct(row["cascade_accuracy"]),
                ]
            )
    return _md(
        [
            "System",
            "Threshold",
            "Dev coverage",
            "Dev precision",
            "Test auto-label rate",
            "Test precision",
            "Accuracy on the rest",
            "Best Claude on the rest",
            "Cascade accuracy",
        ],
        rows,
    )


def _block_cost(routing: dict, view: dict, gate_cfg: dict, bench: dict) -> str:
    shipped = gate_cfg["candidate"]["shipped"]
    level = next(row for row in bench["levels"] if int(row["concurrency"]) == 32)
    rows = [[f"{shipped} concurrency 32", fmt_usd(level["cost_per_1000_usd"])]]
    for name, doc in routing["claude_costs"].items():
        rows.append([name, fmt_usd(doc["cost_per_1000_usd"])])
    for key in sorted(view[shipped]):
        cost = view[shipped][key]["cost"]["cascade"]
        rows.append([f"{shipped} cascade {key}", fmt_usd(cost)])
    rows.append([gate_cfg["champion"]["system"], _CPU_COST_NOTE])
    price = routing["gpu_price_usd_per_hour"]
    hours = routing["hours_per_month"]
    even_rows = []
    for name, volume in routing["break_even_records_per_month"].items():
        whole = Decimal(str(volume)).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
        even_rows.append([name, fmt_count(int(whole))])
    summary, _labels = _backlog_rows()
    note = (
        f"Break-even is the monthly volume at which a GPU left on for {fmt_sig(hours, 3)} "
        f"hours at {fmt_usd(price)} per hour costs the same as that Claude run. "
        f"Backlog batch GPU cost: {fmt_usd(summary['gpu_cost_usd'])}."
    )
    return (
        _md(["System", "USD per 1,000"], rows)
        + "\n\n"
        + _md(["Claude run", "Break-even records per month"], even_rows)
        + "\n\n"
        + note
    )


def _backlog_rows() -> tuple[dict, list[dict]]:
    paths = sorted((REPO_ROOT / "outputs" / "backlog").glob("*/summary.json"))
    if len(paths) != 1:
        raise SystemExit(f"report: expected one backlog summary, found {len(paths)}")
    summary = json.loads(paths[0].read_text())
    with (paths[0].parent / "labels.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != int(summary["rows"]):
        raise SystemExit("report: labels.csv row count does not match the backlog summary")
    return summary, rows


def _block_backlog() -> str:
    summary, rows = _backlog_rows()
    n = len(rows)
    n95 = sum(1 for row in rows if row["auto_95"] == "True")
    n97 = sum(1 for row in rows if row["auto_97"] == "True")
    n_kernel = sum(1 for row in rows if row["is_kernel"] == "True")
    counts: Counter[str] = Counter(row["predicted_cwe"] for row in rows)
    names: dict[str, str] = {}
    for row in rows:
        names.setdefault(row["predicted_cwe"], row["cwe_name"])
    top = counts.most_common(10)
    stored = [(item["cwe"], item["count"]) for item in summary["top_predicted_cwes"]]
    if top != stored:
        raise SystemExit("report: top predicted CWEs do not match the backlog summary")
    top_rows = [[cwe, names[cwe], fmt_count(count)] for cwe, count in top]
    lead = (
        f"{fmt_count(n)} rows. "
        f"At the dev 95% threshold: {fmt_count(n95)} ({fmt_pct(n95 / n)}). "
        f"At the dev 97% threshold: {fmt_count(n97)} ({fmt_pct(n97 / n)}). "
        f"Kernel share: {fmt_count(n_kernel)} ({fmt_pct(n_kernel / n)})."
    )
    return lead + "\n\n" + _md(["CWE", "Name", "Rows"], top_rows)


def _block_errors(analysis: dict) -> str:
    conf_rows = []
    for item in analysis["candidate_confusions"][:10]:
        conf_rows.append([item["gold"], item["predicted"], fmt_count(item["count"])])
    err_rows = []
    for item in analysis["candidate_high_confidence_errors"][:6]:
        adp = item.get("adp_cwes") or []
        cisa = ", ".join(adp) if adp else "none"
        err_rows.append(
            [
                _cve_link(item["cve_id"]),
                item["gold"],
                item["predicted"],
                fmt_pct(item["confidence"]),
                cisa,
            ]
        )
    return (
        _md(["Gold", "Predicted", "Count"], conf_rows)
        + "\n\n"
        + _md(["CVE", "Gold", "Predicted", "Confidence", "CISA label"], err_rows)
    )


def _block_demo() -> str:
    paths = sorted((REPO_ROOT / "outputs" / "demo_check").glob("*/summary.json"))
    if not paths:
        return "No demo check has been written yet."
    summary = json.loads(paths[-1].read_text())
    rows = [
        [
            fmt_count(summary["n"]),
            fmt_pct(summary["agreement_with_bf16"]),
            fmt_pct(summary["accuracy"]),
            fmt_count(summary["n_with_confidence"]),
        ]
    ]
    note = f"Run {summary['run_id']}. The demo model is the 4-bit file."
    if int(summary["n_with_confidence"]) == 0:
        note += " The server returned no token probabilities, so this check has no confidence."
    table = _md(
        ["Records", "Agreement with bf16", "Accuracy", "Records with confidence"],
        rows,
    )
    return table + "\n\n" + note


def _block_spend(spend: dict) -> str:
    gpu = spend["gpu"]
    idle = float(gpu["billed_minus_recorded_hours"]) / float(gpu["hours_so_far"])
    purpose_rows = []
    for name, block in gpu["seconds_by_purpose"].items():
        seconds = f"{float(block['seconds']):,.2f}"
        purpose_rows.append([name, seconds, fmt_count(len(block["runs"]))])
    claude_rows = []
    for run in spend["claude"]["runs"]:
        claude_rows.append([run["system"], fmt_usd(run["cost_usd"])])
    total = float(gpu["total_usd"]) + float(spend["claude"]["total_usd"])
    lead = (
        f"GPU {gpu['gpu']}: {float(gpu['hours_so_far']):.3f} hours, "
        f"{fmt_usd(gpu['total_usd'])}. "
        f"Share of billed hours with no recorded run: {fmt_pct(idle)}."
    )
    tail = (
        f"Claude total {fmt_usd(spend['claude']['total_usd'])}. "
        f"GPU plus Claude: {fmt_usd(total)}."
    )
    return (
        lead
        + "\n\n"
        + _md(["Purpose", "Seconds", "Runs"], purpose_rows)
        + "\n\n"
        + _md(["Claude run", "USD"], claude_rows)
        + "\n\n"
        + tail
    )


_README_BLOCKS = (
    "headline",
    "facts:coverage",
    "facts:data",
    "table:training",
    "table:serving",
    "table:demo",
    "table:gate",
    "table:main",
    "table:slices",
    "table:routing",
    "table:cost",
    "table:backlog",
    "table:errors",
    "table:spend",
)


def _readme_blocks() -> dict[str, str]:
    gate = json.loads((REPO_ROOT / "results" / "gate.json").read_text())
    gate_cfg = _load_yaml(REPO_ROOT / "configs" / "gate.yaml")
    routing = json.loads((REPO_ROOT / "results" / "routing.json").read_text())
    analysis = json.loads((REPO_ROOT / "results" / "error_analysis.json").read_text())
    spend = json.loads((REPO_ROOT / "results" / "spend.json").read_text())
    stats = json.loads((REPO_ROOT / "data" / "processed" / "stats.json").read_text())
    _bench, _level = _bench_concurrency(32)
    view = _route_view(gate_cfg, routing)
    return {
        "headline": _block_headline(gate, gate_cfg, routing, view, _bench),
        "facts:coverage": _block_coverage(stats),
        "facts:data": _block_data(stats),
        "table:training": _block_training(gate_cfg),
        "table:serving": _block_serving(_bench),
        "table:gate": _block_gate(gate),
        "table:main": _block_main(gate, gate_cfg),
        "table:slices": _block_slices(analysis),
        "table:routing": _block_routing(view, gate_cfg),
        "table:cost": _block_cost(routing, view, gate_cfg, _bench),
        "table:backlog": _block_backlog(),
        "table:errors": _block_errors(analysis),
        "table:demo": _block_demo(),
        "table:spend": _block_spend(spend),
    }


def _fill_readme(text: str, blocks: dict[str, str]) -> str:
    begins = re.findall(r"<!-- BEGIN (.+?) -->", text)
    if begins != list(_README_BLOCKS):
        raise SystemExit(f"report: README markers are {begins}")

    def _repl(match: re.Match) -> str:
        name = match.group(1)
        body = blocks[name].strip("\n")
        return f"<!-- BEGIN {name} -->\n{body}\n<!-- END {name} -->"

    pattern = re.compile(
        r"<!-- BEGIN (.+?) -->\n.*?<!-- END \1 -->",
        re.S,
    )
    new, n = pattern.subn(_repl, text)
    if n != len(_README_BLOCKS):
        raise SystemExit(f"report: filled {n} blocks, expected {len(_README_BLOCKS)}")
    return new


def write_readme() -> int:
    _fix_cpu_routing_cost()
    path = REPO_ROOT / "README.md"
    path.write_text(_fill_readme(path.read_text(), _readme_blocks()))
    print("[report] wrote README.md")
    return 0


def check_readme() -> int:
    path = REPO_ROOT / "README.md"
    text = path.read_text()
    new = _fill_readme(text, _readme_blocks())
    if new != text:
        sys.stderr.write("report: README.md is out of date\n")
        import difflib

        diff = difflib.unified_diff(
            text.splitlines(),
            new.splitlines(),
            fromfile="README.md",
            tofile="rendered",
            lineterm="",
        )
        shown = 0
        for line in diff:
            sys.stderr.write(line + "\n")
            shown += 1
            if shown >= 80:
                sys.stderr.write("report: diff truncated\n")
                break
        return 1
    print("[report] README.md is up to date")
    return 0


def _wandb_key() -> str:
    for line in (REPO_ROOT / ".env").read_text().splitlines():
        if line.startswith("WANDB_API_KEY="):
            return line.split("=", 1)[1].strip().strip('"')
    raise SystemExit("report: WANDB_API_KEY is not in .env")


def _wandb(query: str, variables: dict | None, key: str) -> dict:
    import requests

    resp = requests.post(
        "https://api.wandb.ai/graphql",
        json={"query": query, "variables": variables or {}},
        headers={"Authorization": f"Bearer {key}"},
        timeout=90,
    )
    doc = resp.json()
    if "errors" in doc:
        raise SystemExit(f"report: wandb query failed: {doc['errors'][0]['message']}")
    return doc["data"]


def export_curves() -> int:
    """Train and dev loss for the six full runs, from the W&B history API."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    gate_cfg = _load_yaml(REPO_ROOT / "configs" / "gate.yaml")
    folders = [
        name.removeprefix("candidate_")
        for name in (
            gate_cfg["candidate"]["one_epoch_systems"]
            + gate_cfg["candidate"]["two_epoch_systems"]
        )
    ]
    key = _wandb_key()
    out_dir = REPO_ROOT / "results" / "curves"
    out_dir.mkdir(parents=True, exist_ok=True)
    series: dict[str, list[dict]] = {}
    for folder in folders:
        run_doc = json.loads((REPO_ROOT / "outputs" / "train" / folder / "run.json").read_text())
        wandb = run_doc["wandb"]
        parts = wandb["run_url"].split("/wandb/", 1)[1].split("/")
        entity, project, run_id = parts[0], parts[1], wandb["run_id"]
        data = _wandb(
            """query($entity: String!, $project: String!, $run: String!) {
              project(name: $project, entityName: $entity) {
                run(name: $run) { history(samples: 5000) }
              }
            }""",
            {"entity": entity, "project": project, "run": run_id},
            key,
        )
        history = data["project"]["run"]["history"]
        rows = []
        for item in history:
            point = json.loads(item) if isinstance(item, str) else item
            step = point.get("train/global_step")
            if step is None:
                continue
            if "train/loss" not in point and "eval/loss" not in point:
                continue
            rows.append(
                {
                    "step": int(step),
                    "train_loss": point.get("train/loss"),
                    "eval_loss": point.get("eval/loss"),
                }
            )
        rows.sort(key=lambda row: (row["step"], row["train_loss"] is None))
        path = out_dir / f"{folder}.csv"
        with path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["step", "train_loss", "eval_loss"])
            writer.writeheader()
            writer.writerows(rows)
        series[folder] = rows
        print(f"[report] wrote {path} ({len(rows)} rows)")

    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for folder, rows in series.items():
        train = [(row["step"], row["train_loss"]) for row in rows if row["train_loss"] is not None]
        dev = [(row["step"], row["eval_loss"]) for row in rows if row["eval_loss"] is not None]
        axes[0].plot([s for s, _ in train], [v for _, v in train], label=folder)
        axes[1].plot([s for s, _ in dev], [v for _, v in dev], marker="o", label=folder)
    axes[0].set_title("Train loss")
    axes[1].set_title("Dev loss")
    for axis in axes:
        axis.set_xlabel("Step")
        axis.legend(fontsize=8)
    fig.tight_layout()
    png = out_dir / "loss.png"
    fig.savefig(png)
    print(f"[report] wrote {png}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="README, routing, error analysis, spend")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--curves", action="store_true")
    ap.add_argument("--analysis", action="store_true")
    ap.add_argument("--routing", action="store_true")
    ap.add_argument("--spend", action="store_true")
    args = ap.parse_args(argv)
    if args.curves:
        return export_curves()
    if args.check:
        return check_readme()
    wrote = False
    if args.analysis:
        write_analysis()
        wrote = True
    if args.routing:
        write_routing()
        wrote = True
    if args.spend:
        write_spend()
        wrote = True
    if not wrote:
        return write_readme()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
