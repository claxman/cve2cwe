"""Full LLM evaluation runs against an OpenAI-compatible server.

DESIGN section 8 (Inference and serving) and Step 7 work order, section C.

- Every LLM run (baseline or candidate, Qwen or Claude) goes through this
  one client, so the evaluated artifact is the one that would ship.
- Parsing goes only through ``scorer.parse``. The old lenient parser and
  the Step 5 smoke command are deleted.
- 32 concurrent requests; temperature 0; max 8 new tokens; logprobs on;
  thinking disabled via ``chat_template_kwargs``.
- Context-length rejections are recorded as invalid and counted. Any other
  error is retried three times with backoff; if it still fails the run
  exits non-zero and leaves no ``predictions.jsonl``.
- Predictions are written to a temporary file and renamed at the end.
- A ``--repeat-check 300`` sends the first N records twice and fails the
  run if any raw output differs.

Guard: a system named ``candidate_*`` is refused on the test split unless
``docs/ACCEPTANCE.md`` contains a ``Status: final`` line, ``configs/gate.yaml``
exists, and both are committed and unmodified (DESIGN section 9).
"""

from __future__ import annotations

import argparse
import gzip
import json
import math
import os
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import yaml

from cve2cwe import runinfo
from cve2cwe.prompts import (
    REPO_ROOT,
    build_messages,
    cut_description,
    load_labels,
    load_prompts_cfg,
    load_systems_cfg,
)
from cve2cwe.scorer import load_label_set, parse

# vLLM / OpenAI rejections for prompts over the server context length look
# like "This model's maximum context length is X tokens, however you requested
# Y tokens". We treat any of these substrings as a context-length failure.
_CTX_PATTERNS = (
    "context length",
    "max context length",
    "maximum context length",
    "max model length",
    "maximum model length",
    "max_model_len",
)


# ---------------------------------------------------------------------------
# Data loading. Baselines load the splits; we reuse the same files directly.


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("rt", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rows.append(json.loads(line))
    return rows


def _read_jsonl_gz(path: Path) -> list[dict]:
    rows: list[dict] = []
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rows.append(json.loads(line))
    return rows


def _load_split(split: str) -> list[dict]:
    if split == "dev":
        return _read_jsonl(REPO_ROOT / "data" / "processed" / "dev.jsonl")
    if split == "test":
        return _read_jsonl(REPO_ROOT / "data" / "processed" / "test.jsonl")
    raise ValueError(f"unknown split: {split!r}")


def _load_train_rows() -> list[dict]:
    return _read_jsonl_gz(REPO_ROOT / "data" / "processed" / "train.jsonl.gz")


def _load_retrieval_table(split: str) -> dict[str, list[tuple[str, float]]]:
    path = REPO_ROOT / "outputs" / "retrieval" / f"{split}.jsonl"
    if not path.exists():
        raise FileNotFoundError(
            f"retrieval table missing: {path}. Run `python -m cve2cwe baselines` first."
        )
    out: dict[str, list[tuple[str, float]]] = {}
    for row in _read_jsonl(path):
        out[row["cve_id"]] = [(tcid, float(sim)) for tcid, sim in row["neighbours"]]
    return out


# ---------------------------------------------------------------------------
# Example resolvers (few-shot and retrieval).


def resolve_few_shot_examples(
    train_rows: list[dict], labels_order: list[str], cfg: dict
) -> list[dict]:
    """8 most frequent train classes; for each, the most recent train record
    whose description is strictly under ``max_example_chars``. Ties in
    frequency break by ``labels.json`` file order.

    Returns a list of dicts: ``cve_id``, ``description``, ``label``.
    """
    n = int(cfg["num_examples"])
    max_chars = int(cfg["max_example_chars"])
    label_pos = {lab: i for i, lab in enumerate(labels_order)}
    counts = Counter(r["label"] for r in train_rows)
    # Highest count first, then earlier in labels.json.
    top_labels = sorted(
        counts.keys(), key=lambda label: (-counts[label], label_pos.get(label, 1 << 30))
    )[:n]
    by_label: dict[str, list[dict]] = defaultdict(list)
    short_target = set(top_labels)
    for r in train_rows:
        if r["label"] in short_target and len(r["description"]) < max_chars:
            by_label[r["label"]].append(r)
    examples: list[dict] = []
    for lab in top_labels:
        cands = by_label.get(lab, [])
        if not cands:
            raise ValueError(
                f"no train record for {lab} with len(description) < {max_chars}"
            )
        cands.sort(key=lambda r: r["published"], reverse=True)
        pick = cands[0]
        examples.append(
            {
                "cve_id": pick["cve_id"],
                "description": pick["description"],
                "label": pick["label"],
            }
        )
    return examples


def resolve_retrieval_examples(
    retrieval_table: dict[str, list[tuple[str, float]]],
    train_by_id: dict[str, dict],
    cve_id: str,
    cfg: dict,
) -> list[dict]:
    """Top-k neighbours for one query, cut to ``max_example_chars``, in
    least-similar-first order."""
    n = int(cfg["num_examples"])
    max_chars = int(cfg["max_example_chars"])
    neighbours = retrieval_table[cve_id][:n]
    # retrieval file lists descending similarity; reverse for least-first.
    neighbours = list(reversed(neighbours))
    out: list[dict] = []
    for tcid, sim in neighbours:
        r = train_by_id[tcid]
        out.append(
            {
                "cve_id": tcid,
                "description": cut_description(r["description"], max_chars),
                "label": r["label"],
                "similarity": float(sim),
            }
        )
    return out


# ---------------------------------------------------------------------------
# Guard: candidate_* on test requires final acceptance + gate.


def guard_test_split_candidate(name: str, split: str) -> None:
    """Raise SystemExit if a candidate_* system is run on the test split
    before the acceptance bar and gate config are committed as final.
    """
    if not name.startswith("candidate_"):
        return
    if split != "test":
        return
    acc_path = REPO_ROOT / "docs" / "ACCEPTANCE.md"
    gate_path = REPO_ROOT / "configs" / "gate.yaml"
    if not acc_path.exists():
        raise SystemExit(
            "llm-eval: docs/ACCEPTANCE.md is missing; a candidate_* run on "
            "the test split is refused until the acceptance bar is committed as final."
        )
    acc_text = acc_path.read_text()
    has_final = any(line.strip() == "Status: final" for line in acc_text.splitlines())
    if not has_final:
        raise SystemExit(
            "llm-eval: docs/ACCEPTANCE.md does not contain a 'Status: final' line; "
            "a candidate_* run on the test split is refused."
        )
    if not gate_path.exists():
        raise SystemExit(
            "llm-eval: configs/gate.yaml is missing; a candidate_* run on the "
            "test split is refused until the gate is committed."
        )
    # Both must be committed.
    r = subprocess.run(
        ["git", "ls-tree", "-r", "HEAD", "--name-only"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    committed = set(r.stdout.splitlines())
    for rel in ("docs/ACCEPTANCE.md", "configs/gate.yaml"):
        if rel not in committed:
            raise SystemExit(
                f"llm-eval: {rel} is not committed; a candidate_* run on the "
                "test split is refused."
            )
    # Both must be unmodified.
    r = subprocess.run(
        ["git", "status", "--porcelain", "--", "docs/ACCEPTANCE.md", "configs/gate.yaml"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if r.stdout.strip():
        raise SystemExit(
            "llm-eval: docs/ACCEPTANCE.md or configs/gate.yaml has uncommitted "
            "changes; a candidate_* run on the test split is refused.\n" + r.stdout
        )


# ---------------------------------------------------------------------------
# Client call: one record, with retries. Context-length rejections are
# flagged as invalid; every other failure is retried, then raised.


class ContextLengthRejection(Exception):
    """Raised when the server refused the prompt as too long."""


def _is_context_length_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(p in msg for p in _CTX_PATTERNS)


def _confidence_from_logprobs(
    logprobs_content: list,
) -> tuple[float | None, list[tuple[str, float]]]:
    if not logprobs_content:
        return None, []
    pairs: list[tuple[str, float]] = []
    product = 1.0
    for item in logprobs_content:
        token = getattr(item, "token", None)
        lp = getattr(item, "logprob", None)
        if token is None or lp is None:
            return None, []
        p = math.exp(lp)
        pairs.append((token, p))
        product *= p
    return product, pairs


def _label_token_product(
    token_probs: list[tuple[str, float]], parsed: str
) -> float | None:
    """Product of token probabilities over the contiguous run of tokens that
    reconstructs the parsed CWE id. DESIGN: "confidence of a prediction:
    the product of the token probabilities of the generated label."
    """
    if not token_probs or not parsed:
        return None
    for i in range(len(token_probs)):
        joined = ""
        prod = 1.0
        for tok, p in token_probs[i:]:
            joined += tok
            prod *= p
            if parsed in joined:
                return prod
    return None


def predict_one(
    client,
    model: str,
    msgs: list[dict],
    label_set: set[str],
    max_new_tokens: int,
    temperature: float,
    max_retries: int,
    backoff_seconds: float,
) -> dict:
    """Returns a prediction dict with raw_output, parsed, confidence,
    token_usage, and an ``invalid_reason`` field (``None`` or
    ``"context_length"``)."""
    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=msgs,
                temperature=temperature,
                max_tokens=max_new_tokens,
                logprobs=True,
                extra_body={"chat_template_kwargs": {"enable_thinking": False}},
            )
            choice = resp.choices[0]
            raw = choice.message.content or ""
            parsed = parse(raw, label_set)
            lp_content = (
                getattr(getattr(choice, "logprobs", None), "content", None) or []
            )
            _, token_probs = _confidence_from_logprobs(lp_content)
            conf = _label_token_product(token_probs, parsed or "")
            usage = getattr(resp, "usage", None)
            return {
                "raw_output": raw,
                "parsed": parsed,
                "confidence": conf,
                "prompt_tokens": getattr(usage, "prompt_tokens", 0) or 0,
                "completion_tokens": getattr(usage, "completion_tokens", 0) or 0,
                "invalid_reason": None,
            }
        except Exception as exc:
            if _is_context_length_error(exc):
                return {
                    "raw_output": "",
                    "parsed": None,
                    "confidence": None,
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "invalid_reason": "context_length",
                }
            last_exc = exc
            if attempt < max_retries:
                time.sleep(backoff_seconds * (2 ** (attempt - 1)))
    assert last_exc is not None
    raise last_exc


# ---------------------------------------------------------------------------
# One-record message builder dispatcher.


def _build_messages_for_record(
    system_name: str,
    record: dict,
    *,
    prompts: dict,
    systems: dict,
    labels: list[dict],
    few_shot_examples: list[dict] | None,
    retrieval_table: dict | None,
    train_by_id: dict | None,
    retrieval_cfg: dict | None,
) -> list[dict]:
    if system_name == "candidate":
        return build_messages(
            "candidate", record["description"], prompts=prompts, systems=systems
        )
    if system_name == "zero_shot":
        return build_messages(
            "zero_shot",
            record["description"],
            prompts=prompts,
            systems=systems,
            labels=labels,
        )
    if system_name == "few_shot":
        return build_messages(
            "few_shot",
            record["description"],
            examples=few_shot_examples,
            prompts=prompts,
            systems=systems,
            labels=labels,
        )
    if system_name == "retrieval":
        examples = resolve_retrieval_examples(
            retrieval_table, train_by_id, record["cve_id"], retrieval_cfg
        )
        return build_messages(
            "retrieval",
            record["description"],
            examples=examples,
            prompts=prompts,
            systems=systems,
            labels=labels,
        )
    raise ValueError(f"unknown system: {system_name}")


# ---------------------------------------------------------------------------
# Full run.


def run(
    name: str,
    system: str,
    split: str,
    model: str,
    base_url: str,
    concurrency: int,
    max_new_tokens: int,
    temperature: float,
    repeat_check: int,
    outputs_root: Path,
) -> int:
    guard_test_split_candidate(name, split)

    info = runinfo.capture(
        packages=("numpy", "scipy", "scikit-learn", "pyyaml", "openai", "httpx")
    )

    # Lazy-load openai so unit tests that only exercise the guard do not
    # require the package.
    try:
        from openai import OpenAI
    except ImportError:
        print("llm-eval: openai package not installed", file=sys.stderr)
        return 2

    prompts = load_prompts_cfg()
    systems = load_systems_cfg()
    labels = load_labels()
    labels_order = [lab["id"] for lab in labels]
    label_set = load_label_set()
    rows = _load_split(split)
    print(f"[llm-eval] system={system} name={name} split={split} n={len(rows)}")

    # Pre-build per-system state.
    few_shot_examples = None
    retrieval_table = None
    train_by_id = None
    if system == "few_shot":
        train_rows = _load_train_rows()
        few_shot_examples = resolve_few_shot_examples(
            train_rows, labels_order, systems["few_shot"]
        )
        print(
            "[llm-eval] few-shot examples: "
            + ", ".join(f"{e['cve_id']}->{e['label']}" for e in few_shot_examples)
        )
    if system == "retrieval":
        retrieval_table = _load_retrieval_table(split)
        train_by_id = {r["cve_id"]: r for r in _load_train_rows()}

    # One client per worker thread. A shared OpenAI client under a thread
    # pool has been observed to send a request the server answers 404
    # ("model does not exist") while the same model name succeeds serially.
    thread_clients = threading.local()

    def _client():
        client = getattr(thread_clients, "client", None)
        if client is None:
            client = OpenAI(
                base_url=base_url,
                api_key=os.environ.get("OPENAI_API_KEY", "EMPTY"),
            )
            thread_clients.client = client
        return client

    # Build messages up front so repeat-check compares the exact same
    # messages we send during the main pass.
    msg_sets = [
        _build_messages_for_record(
            system,
            r,
            prompts=prompts,
            systems=systems,
            labels=labels,
            few_shot_examples=few_shot_examples,
            retrieval_table=retrieval_table,
            train_by_id=train_by_id,
            retrieval_cfg=systems.get("retrieval"),
        )
        for r in rows
    ]

    # Output paths. Write to a temporary filename and rename at the end.
    run_id_ts = info.started_utc.replace("-", "").replace(":", "")
    short = info.git_commit[:7] if info.git_commit else "nogit"
    run_id = f"{run_id_ts}-{short}"
    out_dir = outputs_root / name / split / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    pred_tmp = out_dir / "predictions.jsonl.tmp"
    pred_final = out_dir / "predictions.jsonl"
    run_json = out_dir / "run.json"

    counts = {
        "total": len(rows),
        "valid": 0,
        "invalid_total": 0,
        "invalid_context_length": 0,
        "errors_retried_but_failed": 0,
    }
    token_usage = {"prompt_tokens": 0, "completion_tokens": 0}
    predictions: list[dict | None] = [None] * len(rows)
    wall_start = time.perf_counter()

    def _run_one(idx: int) -> tuple[int, dict]:
        pred = predict_one(
            _client(),
            model,
            msg_sets[idx],
            label_set,
            max_new_tokens=max_new_tokens,
            temperature=temperature,
            max_retries=3,
            backoff_seconds=1.0,
        )
        pred["cve_id"] = rows[idx]["cve_id"]
        return idx, pred

    try:
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = {ex.submit(_run_one, i): i for i in range(len(rows))}
            for fut in as_completed(futures):
                idx, pred = fut.result()
                predictions[idx] = pred
                token_usage["prompt_tokens"] += pred["prompt_tokens"]
                token_usage["completion_tokens"] += pred["completion_tokens"]
                if pred["parsed"] is None:
                    counts["invalid_total"] += 1
                    if pred["invalid_reason"] == "context_length":
                        counts["invalid_context_length"] += 1
                else:
                    counts["valid"] += 1
    except Exception as exc:
        counts["errors_retried_but_failed"] += 1
        # Nothing is written. pred_tmp (if any) is removed. No run.json.
        if pred_tmp.exists():
            pred_tmp.unlink()
        print(
            f"llm-eval: aborting; unrecoverable error after retries: {exc}",
            file=sys.stderr,
        )
        return 2

    # Repeat-check: send the first N records again and compare raw outputs.
    # Runs serially (concurrency=1) so the server sees a batch size of one
    # per request and vLLM's batch-order non-determinism does not contaminate
    # the check. The check asserts "same prompt -> same raw output", not
    # "same batching order -> same raw output".
    repeat_result: dict[str, Any] = {"count": 0, "passed": True, "mismatches": []}
    if repeat_check > 0:
        rc_n = min(repeat_check, len(rows))
        print(
            f"[llm-eval] repeat-check: resending first {rc_n} records "
            "(concurrency=1 for determinism)"
        )
        second: list[dict | None] = [None] * rc_n
        try:
            for i in range(rc_n):
                _, pred = _run_one(i)
                second[i] = pred
        except Exception as exc:
            print(
                f"llm-eval: aborting; repeat-check failed with an unrecoverable error: {exc}",
                file=sys.stderr,
            )
            return 2
        for i in range(rc_n):
            if second[i]["raw_output"] != predictions[i]["raw_output"]:
                repeat_result["mismatches"].append(
                    {
                        "cve_id": rows[i]["cve_id"],
                        "first": predictions[i]["raw_output"],
                        "second": second[i]["raw_output"],
                    }
                )
        repeat_result["count"] = rc_n
        repeat_result["passed"] = len(repeat_result["mismatches"]) == 0
        if not repeat_result["passed"]:
            print(
                f"llm-eval: repeat-check failed on {len(repeat_result['mismatches'])} "
                "records; writing no predictions file.",
                file=sys.stderr,
            )
            return 2

    wall_seconds = time.perf_counter() - wall_start

    # Write predictions to a temp file, then rename.
    with pred_tmp.open("w", encoding="utf-8") as f:
        for pred in predictions:
            out = {
                "cve_id": pred["cve_id"],
                "raw_output": pred["raw_output"],
                "parsed": pred["parsed"],
                "confidence": pred["confidence"],
            }
            f.write(json.dumps(out) + "\n")
    pred_tmp.rename(pred_final)

    # Record run metadata.
    train_cfg_path = REPO_ROOT / "configs" / "train.yaml"
    base_revision = None
    base_model_cfg = None
    if train_cfg_path.exists():
        with train_cfg_path.open() as f:
            tc = yaml.safe_load(f)
        base_model_cfg = tc.get("base_model")
        base_revision = tc.get("revision")

    run_meta = {
        "system": name,
        "prompt_name": system,
        "split": split,
        "run_id": run_id,
        "served_model": model,
        "base_model": base_model_cfg,
        "base_revision": base_revision,
        "base_url": base_url,
        "request_settings": {
            "temperature": temperature,
            "max_tokens": max_new_tokens,
            "logprobs": True,
            "concurrency": concurrency,
            "chat_template_kwargs": {"enable_thinking": False},
        },
        "systems_config": {
            "max_description_chars": int(systems["max_description_chars"]),
            "few_shot": systems.get("few_shot"),
            "retrieval": systems.get("retrieval"),
        },
        "few_shot_examples": (
            [{"cve_id": e["cve_id"], "label": e["label"]} for e in few_shot_examples]
            if few_shot_examples
            else None
        ),
        "counts": counts,
        "token_usage": token_usage,
        "wall_seconds": round(wall_seconds, 2),
        "repeat_check": repeat_result,
        "git_commit": info.git_commit,
        "git_dirty": info.git_dirty,
        "package_versions": info.package_versions,
        "started_utc": info.started_utc,
        "finished_utc": runinfo.now_iso(),
    }
    with run_json.open("w") as f:
        json.dump(run_meta, f, indent=2, sort_keys=True)
        f.write("\n")

    print(
        f"[llm-eval] done: wrote {pred_final}  valid={counts['valid']}/"
        f"{counts['total']} invalid_ctx={counts['invalid_context_length']} "
        f"wall={wall_seconds:.1f}s"
    )
    return 0


# ---------------------------------------------------------------------------
# CLI


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run an LLM system on a split")
    ap.add_argument(
        "--system",
        required=True,
        choices=("candidate", "zero_shot", "few_shot", "retrieval"),
        help="which prompt to render",
    )
    ap.add_argument("--split", required=True, choices=("dev", "test"))
    ap.add_argument(
        "--model",
        required=True,
        help="served model id to send in the request (matches `vllm serve --served-model-name`)",
    )
    ap.add_argument(
        "--name",
        required=True,
        help="output system name (e.g. qwen35_4b_zero_shot, candidate_seed1)",
    )
    ap.add_argument(
        "--base-url",
        default=os.environ.get("VLLM_BASE_URL", "http://127.0.0.1:8000/v1"),
    )
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--max-new-tokens", type=int, default=8)
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument(
        "--repeat-check",
        type=int,
        default=300,
        help="resend the first N records and fail if any raw output differs (0 to skip)",
    )
    args = ap.parse_args(list(argv) if argv is not None else None)

    return run(
        name=args.name,
        system=args.system,
        split=args.split,
        model=args.model,
        base_url=args.base_url,
        concurrency=args.concurrency,
        max_new_tokens=args.max_new_tokens,
        temperature=args.temperature,
        repeat_check=args.repeat_check,
        outputs_root=REPO_ROOT / "outputs",
    )


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ContextLengthRejection",
    "guard_test_split_candidate",
    "resolve_few_shot_examples",
    "resolve_retrieval_examples",
    "predict_one",
    "run",
    "main",
]
