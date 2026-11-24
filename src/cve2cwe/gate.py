"""Acceptance gate. DESIGN section 9. Reads prediction files only.

``gate --prepare`` names the champion, writes the must-pass set, the routing
thresholds and docs/ACCEPTANCE.md. ``gate`` with no flag scores the three
shipped seeds against that bar and prints PROMOTE or REJECT. Neither command
calls a model.

The numeric bar is the Step 9 protocol: gain 0.020, paired-interval lower
bound above 0, must-pass accuracy 0.98, invalid rate 0.005. ACCEPTANCE.md is
rendered from the files this command writes, so the numbers in it are the
numbers just computed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import yaml

from cve2cwe.prompts import REPO_ROOT, load_systems_cfg
from cve2cwe.scorer import (
    assert_reparse_matches,
    bootstrap_accuracy_ci,
    check_coverage,
    compute_metrics,
    load_label_set,
    paired_bootstrap_diff_ci,
)

# Step 9 protocol. Written into configs/gate.yaml by --prepare. The acceptance
# page copies them back out of that file.
GAIN = 0.020
PAIRED_LOWER_BOUND_ABOVE = 0.0
MUST_PASS_MIN = 0.98
INVALID_MAX = 0.005
ROUTE_TARGETS = (0.95, 0.97)

ONE_EPOCH = ("candidate_seed1", "candidate_seed2", "candidate_seed3")
TWO_EPOCH = ("candidate_e2-seed1", "candidate_e2-seed2", "candidate_e2-seed3")

LENGTH_RULE = (
    "The candidate is the length with the higher mean dev accuracy "
    "over its three seeds. A tie goes to 1 epoch."
)


def _num(value: float) -> str:
    """Render a float the same way the JSON files do, so the page is not a
    second rounding of the stored number."""
    return json.dumps(value)


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _load_split(split: str) -> list[dict]:
    path = REPO_ROOT / "data" / "processed" / f"{split}.jsonl"
    rows = []
    for row in _read_jsonl(path):
        rows.append(
            {
                "cve_id": row["cve_id"],
                "label": row["label"],
                "is_kernel": bool(row.get("is_kernel", False)),
                "adp_cwes": row.get("adp_cwes") or [],
            }
        )
    return rows


def _result_records(results_root: Path) -> list[dict]:
    """Every scored run under results/, skipping paired output and gate.json."""
    records = []
    if not results_root.exists():
        return records
    for path in sorted(results_root.rglob("*.json")):
        if "paired" in path.parts or path.name in {"gate.json", "pod.json"}:
            continue
        data = json.loads(path.read_text())
        if "metrics" not in data or "system" not in data:
            continue
        records.append(data)
    return records


def _prediction_file(record: dict) -> Path:
    return REPO_ROOT / record["prediction_dir"] / "predictions.jsonl"


def is_complete_test_run(record: dict, test_n: int) -> bool:
    """A test run is complete when it scored every test record and the
    prediction file is still on disk."""
    if record.get("split") != "test":
        return False
    metrics = record.get("metrics") or {}
    if metrics.get("n") != test_n:
        return False
    return _prediction_file(record).is_file()


def choose_champion(records: list[dict], test_n: int) -> dict:
    """The complete non-candidate test run with the highest accuracy.

    An accuracy tie breaks on run_id, then system name, so a later clean
    rerun wins when the number is the same and directory order does not.
    """
    eligible = [
        record
        for record in records
        if not record["system"].startswith("candidate_")
        and is_complete_test_run(record, test_n)
    ]
    if not eligible:
        raise SystemExit("gate: no complete non-candidate test run to name as champion")
    return max(
        eligible,
        key=lambda row: (row["metrics"]["accuracy"], row["run_id"], row["system"]),
    )


def _latest_dev(records: list[dict], system: str) -> dict:
    found = [
        row
        for row in records
        if row.get("system") == system and row.get("split") == "dev" and "metrics" in row
    ]
    if not found:
        raise SystemExit(f"gate: no dev result for {system}")
    return max(found, key=lambda row: row["run_id"])


def _dev_accuracy(records: list[dict], system: str) -> float:
    return float(_latest_dev(records, system)["metrics"]["accuracy"])


def choose_length(records: list[dict]) -> dict:
    """Apply the DESIGN section 7 length rule to the stored dev accuracies."""
    one = [_dev_accuracy(records, name) for name in ONE_EPOCH]
    two = [_dev_accuracy(records, name) for name in TWO_EPOCH]
    mean_one = sum(one) / len(one)
    mean_two = sum(two) / len(two)
    # Tie goes to 1 epoch.
    chosen = TWO_EPOCH if mean_two > mean_one else ONE_EPOCH
    accuracies = two if chosen is TWO_EPOCH else one
    # Middle of the sorted accuracies. An accuracy tie breaks on the system
    # name, which is the median seed the protocol ships.
    ranked = sorted(zip(chosen, accuracies, strict=True), key=lambda item: (item[1], item[0]))
    shipped, shipped_accuracy = ranked[len(ranked) // 2]
    return {
        "one_epoch_systems": list(ONE_EPOCH),
        "two_epoch_systems": list(TWO_EPOCH),
        "one_epoch_accuracies": one,
        "two_epoch_accuracies": two,
        "one_epoch_mean": mean_one,
        "two_epoch_mean": mean_two,
        "chosen_systems": list(chosen),
        "chosen_epochs": 2 if chosen is TWO_EPOCH else 1,
        "rule": LENGTH_RULE,
        "shipped": shipped,
        "shipped_dev_accuracy": shipped_accuracy,
    }


def lowest_confidence_threshold(
    rows: Sequence[tuple[float | None, bool]], target: float
) -> dict:
    """Lowest confidence t such that records with confidence >= t are at
    least ``target`` accurate.

    Null confidences stay out of the auto-labelled set. Coverage uses every
    dev record, including those, as the denominator.
    """
    n = len(rows)
    scored = [(conf, ok) for conf, ok in rows if conf is not None]
    if n == 0 or not scored:
        raise SystemExit("gate: routing threshold has no scored dev records")
    for threshold in sorted({conf for conf, _ in scored}):
        chosen = [(conf, ok) for conf, ok in scored if conf >= threshold]
        correct = sum(1 for _, ok in chosen if ok)
        accuracy = correct / len(chosen)
        if accuracy >= target:
            return {
                "threshold": threshold,
                "accuracy": accuracy,
                "coverage": len(chosen) / n,
                "n": len(chosen),
                "n_correct": correct,
                "n_dev": n,
            }
    raise SystemExit(f"gate: no confidence threshold reaches accuracy {target}")


def must_pass_ids(
    cve_ids: Sequence[str],
    gold: Sequence[str],
    keyword_parsed: Sequence[str | None],
    champion_parsed: Sequence[str | None],
) -> list[str]:
    """Test ids where keyword gave a label, that label is gold, and the
    champion is also right."""
    chosen = []
    for cve_id, label, keyword, champion in zip(
        cve_ids, gold, keyword_parsed, champion_parsed, strict=True
    ):
        if keyword is not None and keyword == label and champion == label:
            chosen.append(cve_id)
    return chosen


def must_pass_sha256(cve_ids: Sequence[str]) -> str:
    """Hash the canonical count and id list. The hash field itself is not
    part of the hashed bytes, so the value can live in the file."""
    payload = {"count": len(cve_ids), "cve_ids": list(cve_ids)}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _aligned(preds: list[dict], rows: list[dict], label_set: set[str]) -> list[dict]:
    check_coverage([p["cve_id"] for p in preds], [r["cve_id"] for r in rows])
    by_id = {p["cve_id"]: p for p in preds}
    ordered = [by_id[r["cve_id"]] for r in rows]
    assert_reparse_matches(ordered, label_set)
    return ordered


def _correct_flags(preds: list[dict], rows: list[dict]) -> list[tuple[float | None, bool]]:
    out = []
    for pred, row in zip(preds, rows, strict=True):
        parsed = pred.get("parsed")
        out.append((pred.get("confidence"), parsed == row["label"]))
    return out


def judge(
    seed_rows: list[dict],
    champion_accuracy: float,
    gain: float = GAIN,
    must_min: float = MUST_PASS_MIN,
    invalid_max: float = INVALID_MAX,
) -> dict:
    """Apply G1-G4. ``seed_rows`` carry accuracy, paired_lo, must_pass_accuracy
    and invalid_rate. PROMOTE only when every check passes."""
    if not seed_rows:
        raise SystemExit("gate: no candidate seeds to judge")
    mean_accuracy = sum(row["accuracy"] for row in seed_rows) / len(seed_rows)
    pass_line = champion_accuracy + gain
    g1 = mean_accuracy >= pass_line
    per_seed = []
    for row in seed_rows:
        g2 = row["paired_lo"] > PAIRED_LOWER_BOUND_ABOVE
        g3 = row["must_pass_accuracy"] >= must_min
        g4 = row["invalid_rate"] <= invalid_max
        per_seed.append({**row, "g2": g2, "g3": g3, "g4": g4})
    passed = g1 and all(row["g2"] and row["g3"] and row["g4"] for row in per_seed)
    return {
        "mean_accuracy": mean_accuracy,
        "pass_line": pass_line,
        "g1": g1,
        "seeds": per_seed,
        "verdict": "PROMOTE" if passed else "REJECT",
    }


def _routing_block(preds: list[dict], rows: list[dict]) -> dict:
    flags = _correct_flags(preds, rows)
    block = {}
    for target in ROUTE_TARGETS:
        block[f"at_{target}"] = lowest_confidence_threshold(flags, target)
    return block


def _write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=False)


def render_acceptance(gate_doc: dict) -> str:
    """docs/ACCEPTANCE.md from the prepared document. No number is typed here."""
    length = gate_doc["candidate"]
    champion = gate_doc["champion"]
    thresholds = gate_doc["thresholds"]
    must = gate_doc["must_pass"]
    route = gate_doc["routing"]
    names = ", ".join(length["chosen_systems"])
    lines = [
        "# Acceptance bar",
        "",
        "Status: final",
        "",
        f"Prepared: {gate_doc['prepared_utc']}",
        "",
        "## Candidate",
        "",
        f"The candidate is the {length['chosen_epochs']}-epoch set ({names}).",
        f"Dev mean accuracy, 1 epoch: {_num(length['one_epoch_mean'])}.",
        f"Dev mean accuracy, 2 epochs: {_num(length['two_epoch_mean'])}.",
        length["rule"],
        f"Chosen length: {length['chosen_epochs']} epoch"
        + ("s" if length["chosen_epochs"] != 1 else "")
        + ".",
        (
            f"Shipped checkpoint: {length['shipped']} "
            f"(median dev accuracy {_num(length['shipped_dev_accuracy'])})."
        ),
        "",
        "## Champion",
        "",
        f"Champion: {champion['system']}.",
        f"Run id: {champion['run_id']}.",
        f"Test accuracy: {_num(champion['accuracy'])}.",
        "",
        "## Gates",
        "",
        (
            f"G1 gain: the mean test accuracy over the three seeds is at least "
            f"{_num(gate_doc['g1_pass_line'])} "
            f"(champion accuracy {_num(champion['accuracy'])} plus {_num(thresholds['gain'])})."
        ),
        (
            "G2 noise: for every seed, the lower bound of the 95% paired-bootstrap "
            "interval of candidate minus champion is above 0."
        ),
        (
            f"G3 must-pass: every seed is at least {_num(thresholds['must_pass'])} "
            f"accurate on the pinned set."
        ),
        (
            f"G4 validity: the invalid rate is at most {_num(thresholds['invalid'])} "
            f"for every seed."
        ),
        "",
        "## Must-pass set",
        "",
        f"Count: {must['count']}.",
        f"sha256: {must['sha256']}.",
        "The sha256 is of the canonical JSON object with keys count and cve_ids.",
        f"File: {must['path']}.",
        "",
        "## Routing thresholds",
        "",
        (
            "Lowest dev confidence at which records at or above it are at least "
            "95% accurate, and the same for 97%. Coverage is the share of all "
            "dev records at or above the threshold."
        ),
        "",
    ]
    for system, block in route.items():
        lines.append(f"{system}, dev run {block['run_id']}:")
        for key in ("at_0.95", "at_0.97"):
            row = block[key]
            lines.append(
                f"- {key}: threshold {_num(row['threshold'])}, "
                f"accuracy {_num(row['accuracy'])}, "
                f"coverage {_num(row['coverage'])}, n {row['n']}."
            )
        lines.append("")
    lines.extend(
        [
            "## Serving",
            "",
            (
                "Gate runs use the deterministic serving mode in D1: "
                "--enforce-eager, --no-enable-prefix-caching, and one request at a time."
            ),
            "",
            (
                "No fine-tuned checkpoint has been evaluated on the test split before "
                "this commit. llm_eval.py refuses to do so until this file is final "
                "and committed."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def prepare(results_root: Path | None = None) -> dict:
    """Read results/ and write gate.yaml, must_pass.json and ACCEPTANCE.md."""
    results_root = results_root or (REPO_ROOT / "results")
    records = _result_records(results_root)
    test_rows = _load_split("test")
    dev_rows = _load_split("dev")
    label_set = load_label_set()
    champion_row = choose_champion(records, len(test_rows))
    length = choose_length(records)

    keyword_row = _latest_complete(records, "keyword", len(test_rows))
    keyword_preds = _aligned(
        _read_jsonl(_prediction_file(keyword_row)), test_rows, label_set
    )
    champion_preds = _aligned(
        _read_jsonl(_prediction_file(champion_row)), test_rows, label_set
    )
    ids = must_pass_ids(
        [row["cve_id"] for row in test_rows],
        [row["label"] for row in test_rows],
        [pred["parsed"] for pred in keyword_preds],
        [pred["parsed"] for pred in champion_preds],
    )
    digest = must_pass_sha256(ids)
    must_doc = {"count": len(ids), "cve_ids": ids, "sha256": digest}
    must_path = REPO_ROOT / "data" / "processed" / "must_pass.json"
    must_path.write_text(json.dumps(must_doc, indent=2) + "\n")

    shipped_row = _latest_dev(records, length["shipped"])
    tfidf_row = _latest_dev(records, "tfidf_svm")
    routing = {}
    for row in (shipped_row, tfidf_row):
        preds = _aligned(_read_jsonl(_prediction_file(row)), dev_rows, label_set)
        routing[row["system"]] = {
            "run_id": row["run_id"],
            **_routing_block(preds, dev_rows),
        }

    prepared_utc = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    champion_accuracy = float(champion_row["metrics"]["accuracy"])
    gate_doc = {
        "prepared_utc": prepared_utc,
        "champion": {
            "system": champion_row["system"],
            "run_id": champion_row["run_id"],
            "accuracy": champion_accuracy,
            "prediction_dir": champion_row["prediction_dir"],
        },
        "thresholds": {
            "gain": GAIN,
            "paired_lower_bound_above": PAIRED_LOWER_BOUND_ABOVE,
            "must_pass": MUST_PASS_MIN,
            "invalid": INVALID_MAX,
        },
        "g1_pass_line": champion_accuracy + GAIN,
        "candidate": length,
        "must_pass": {
            "path": "data/processed/must_pass.json",
            "count": len(ids),
            "sha256": digest,
        },
        "routing": routing,
        "deterministic_serving": {
            "enforce_eager": True,
            "prefix_caching": False,
            "concurrency": 1,
        },
    }
    gate_path = REPO_ROOT / "configs" / "gate.yaml"
    _write_yaml(gate_path, gate_doc)
    # The page is rendered from the files just written, so a number in
    # ACCEPTANCE.md is a number that survived the yaml and json round trip.
    stored = yaml.safe_load(gate_path.read_text())
    if stored != gate_doc:
        raise SystemExit("gate: yaml round-trip changed configs/gate.yaml")
    stored_must = json.loads(must_path.read_text())
    if stored_must["sha256"] != digest or stored_must["cve_ids"] != ids:
        raise SystemExit("gate: must_pass.json round-trip changed the id list")
    text = render_acceptance(stored)
    (REPO_ROOT / "docs" / "ACCEPTANCE.md").write_text(text)
    print(f"[gate] champion {champion_row['system']} accuracy {_num(champion_accuracy)}")
    print(f"[gate] must-pass count {len(ids)} sha256 {digest}")
    print(f"[gate] shipped {length['shipped']}")
    print("[gate] wrote configs/gate.yaml docs/ACCEPTANCE.md data/processed/must_pass.json")
    return gate_doc


def _latest_complete(records: list[dict], system: str, test_n: int) -> dict:
    found = [
        row
        for row in records
        if row.get("system") == system and is_complete_test_run(row, test_n)
    ]
    if not found:
        raise SystemExit(f"gate: no complete test run for {system}")
    return max(found, key=lambda row: row["run_id"])


def _latest_test_result(system: str) -> dict:
    folder = REPO_ROOT / "results" / system / "test"
    files = sorted(folder.glob("*.json")) if folder.is_dir() else []
    if not files:
        raise SystemExit(f"gate: no test result for {system}")
    return json.loads(files[-1].read_text())


def _seed_measurements(
    system: str,
    champion_preds: list[dict],
    test_rows: list[dict],
    must_ids: set[str],
    label_set: set[str],
    resamples: int,
    seed: int,
    macro_min: int,
) -> dict:
    result = _latest_test_result(system)
    pred_dir = REPO_ROOT / result["prediction_dir"]
    preds = _aligned(_read_jsonl(pred_dir / "predictions.jsonl"), test_rows, label_set)
    metrics = compute_metrics(preds, test_rows, label_set, macro_min)
    correct = metrics.pop("_correct_vector")
    lo, hi = bootstrap_accuracy_ci(correct, resamples, seed)
    champion_correct = [
        1 if pred.get("parsed") == row["label"] else 0
        for pred, row in zip(champion_preds, test_rows, strict=True)
    ]
    diff_lo, diff_hi = paired_bootstrap_diff_ci(correct, champion_correct, resamples, seed)
    by_id = {pred["cve_id"]: pred for pred in preds}
    gold = {row["cve_id"]: row["label"] for row in test_rows}
    must_correct = sum(1 for cve_id in must_ids if by_id[cve_id].get("parsed") == gold[cve_id])
    must_n = len(must_ids)
    return {
        "system": system,
        "run_id": result["run_id"],
        "accuracy": metrics["accuracy"],
        "accuracy_ci95": [lo, hi],
        "invalid_rate": metrics["invalid_rate"],
        "macro_f1": metrics["macro_f1"],
        "kernel_accuracy": metrics["kernel_accuracy"]["true"]["accuracy"],
        "non_kernel_accuracy": metrics["kernel_accuracy"]["false"]["accuracy"],
        "paired_diff": sum(correct) / len(correct) - sum(champion_correct) / len(champion_correct),
        "paired_lo": diff_lo,
        "paired_hi": diff_hi,
        "must_pass_correct": must_correct,
        "must_pass_n": must_n,
        "must_pass_accuracy": must_correct / must_n,
    }


def _print_report(champion: dict, decision: dict) -> None:
    print(
        f"champion: {champion['system']} run={champion['run_id']} "
        f"accuracy={_num(champion['accuracy'])}"
    )
    print(f"G1 pass line: {_num(decision['pass_line'])}")
    for row in decision["seeds"]:
        print(f"seed {row['system']} run={row['run_id']}")
        print(
            f"  accuracy={_num(row['accuracy'])} "
            f"interval=[{_num(row['accuracy_ci95'][0])}, {_num(row['accuracy_ci95'][1])}]"
        )
        print(f"  invalid_rate={_num(row['invalid_rate'])}")
        print(
            f"  paired_diff={_num(row['paired_diff'])} "
            f"interval=[{_num(row['paired_lo'])}, {_num(row['paired_hi'])}]"
        )
        print(
            f"  must_pass={_num(row['must_pass_accuracy'])} "
            f"({row['must_pass_correct']}/{row['must_pass_n']})"
        )
        print(f"  G2: {'PASS' if row['g2'] else 'FAIL'}")
        print(f"  G3: {'PASS' if row['g3'] else 'FAIL'}")
        print(f"  G4: {'PASS' if row['g4'] else 'FAIL'}")
    print(f"mean_accuracy={_num(decision['mean_accuracy'])}")
    print(f"G1: {'PASS' if decision['g1'] else 'FAIL'}")
    print(decision["verdict"])


def run_gate() -> int:
    """Score the shipped seeds. Writes results/gate.json. Never calls a model."""
    gate_path = REPO_ROOT / "configs" / "gate.yaml"
    if not gate_path.is_file():
        raise SystemExit("gate: configs/gate.yaml is missing. Run gate --prepare first.")
    gate_doc = yaml.safe_load(gate_path.read_text())
    must_doc = json.loads((REPO_ROOT / gate_doc["must_pass"]["path"]).read_text())
    if must_doc["sha256"] != must_pass_sha256(must_doc["cve_ids"]):
        raise SystemExit("gate: must_pass.json sha256 does not match its id list")
    if must_doc["sha256"] != gate_doc["must_pass"]["sha256"]:
        raise SystemExit("gate: must_pass.json sha256 does not match configs/gate.yaml")

    test_rows = _load_split("test")
    label_set = load_label_set()
    scoring = load_systems_cfg()["scoring"]
    champion_preds = _aligned(
        _read_jsonl(REPO_ROOT / gate_doc["champion"]["prediction_dir"] / "predictions.jsonl"),
        test_rows,
        label_set,
    )
    must_ids = set(must_doc["cve_ids"])
    seed_rows = [
        _seed_measurements(
            system,
            champion_preds,
            test_rows,
            must_ids,
            label_set,
            int(scoring["bootstrap_resamples"]),
            int(scoring["bootstrap_seed"]),
            int(scoring["macro_f1_min_support"]),
        )
        for system in gate_doc["candidate"]["chosen_systems"]
    ]
    thresholds = gate_doc["thresholds"]
    decision = judge(
        seed_rows,
        float(gate_doc["champion"]["accuracy"]),
        float(thresholds["gain"]),
        float(thresholds["must_pass"]),
        float(thresholds["invalid"]),
    )
    _print_report(gate_doc["champion"], decision)
    out = {
        "champion": gate_doc["champion"],
        "thresholds": thresholds,
        "g1_pass_line": decision["pass_line"],
        "mean_accuracy": decision["mean_accuracy"],
        "g1": decision["g1"],
        "seeds": decision["seeds"],
        "verdict": decision["verdict"],
    }
    out_path = REPO_ROOT / "results" / "gate.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(f"[gate] wrote {out_path.relative_to(REPO_ROOT)}")
    return 0 if decision["verdict"] == "PROMOTE" else 1


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Acceptance gate. Does not call a model.")
    parser.add_argument(
        "--prepare",
        action="store_true",
        help="name the champion and write the acceptance bar",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.prepare:
        prepare()
        return 0
    return run_gate()


__all__ = [
    "GAIN",
    "MUST_PASS_MIN",
    "INVALID_MAX",
    "choose_champion",
    "choose_length",
    "is_complete_test_run",
    "judge",
    "lowest_confidence_threshold",
    "must_pass_ids",
    "must_pass_sha256",
    "prepare",
    "render_acceptance",
    "run_gate",
    "main",
]
