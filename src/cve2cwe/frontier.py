"""Claude reference runs (DESIGN section 6, system 7; Step 7 work order part 2).

Uses the installed anthropic SDK (checked against the version pinned in
``.venv``). Every request goes through the same ``build_messages`` as the
open-weight baselines; the baseline system prompt is lifted out of the chat
and sent in Anthropic's ``system`` parameter so the message list is
user/assistant only, which is what the Messages API expects.

- Models: Claude Haiku 5.5 and Claude Sonnet 5.5. Exact ids are looked up at
  startup via ``client.models.list`` and recorded in run.json.
- Request settings: ``max_tokens=16``, ``temperature=0``, no extended
  thinking (we never pass the ``thinking`` parameter, which is "off" by
  default; see Anthropic docs for this SDK version).
- The SDK handles retries on rate-limit and server errors (``max_retries=5``,
  with exponential backoff). If a request still fails after retries, the
  run stops with a non-zero exit code and no ``predictions.jsonl`` is
  written. A ``.partial.jsonl`` under the system/split directory is appended
  to as each response arrives, so a restarted run continues and nothing is
  paid for twice.
- Cost in USD is computed from ``configs/systems.yaml::claude_prices`` using
  the prompts-<=100k rate (every CVE prompt is well under 100k tokens).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from cve2cwe import runinfo
from cve2cwe.llm_eval import (
    _build_messages_for_record,
    _load_retrieval_table,
    _load_split,
    _load_train_rows,
)
from cve2cwe.prompts import (
    REPO_ROOT,
    load_labels,
    load_prompts_cfg,
    load_systems_cfg,
)
from cve2cwe.scorer import load_label_set, parse

# Model nickname -> hub id prefix we expect to find via models.list(). We
# pick the newest 5.5 revision for each. The exact id is recorded in
# run.json so a later reader can tell which revision answered.
_MODEL_PREFIXES = {
    "sonnet": "claude-sonnet-5-5",
    "haiku": "claude-haiku-5-5",
}

# Internal name shown in outputs/<system name>/.
_OUTPUT_NAMES = {
    ("sonnet", "zero_shot"): "claude_sonnet_5_5_zero_shot",
    ("sonnet", "retrieval"): "claude_sonnet_5_5_retrieval",
    ("haiku", "zero_shot"): "claude_haiku_5_5_zero_shot",
    ("haiku", "retrieval"): "claude_haiku_5_5_retrieval",
}

# How to turn extended thinking OFF, per model (API constraint).
# Haiku 5.5 accepts ``{"type": "disabled"}``.
# Sonnet 5.5 rejects "disabled" and requires ``{"type": "between_tools"}`` --
# that value documents "the model does not think before responding", which is
# the behaviour we want here.
_THINKING_OFF = {
    "haiku": {"type": "disabled"},
    "sonnet": {"type": "between_tools"},
}

# Anthropic rate-limit header names (SDK 2.x; see docs/).
_RL_HEADERS = (
    "anthropic-ratelimit-requests-limit",
    "anthropic-ratelimit-requests-remaining",
    "anthropic-ratelimit-requests-reset",
    "anthropic-ratelimit-input-tokens-limit",
    "anthropic-ratelimit-input-tokens-remaining",
    "anthropic-ratelimit-input-tokens-reset",
    "anthropic-ratelimit-output-tokens-limit",
    "anthropic-ratelimit-output-tokens-remaining",
)


def _anthropic_client(max_retries: int = 5):
    import anthropic

    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise SystemExit("frontier: ANTHROPIC_API_KEY not set (put it in .env)")
    return anthropic.Anthropic(api_key=key, max_retries=max_retries)


def resolve_model_ids(client) -> dict[str, str]:
    """Map nickname -> exact model id for Haiku 5.5 and Sonnet 5.5.

    Uses ``models.list``; picks the first model whose id starts with the
    expected prefix. Sorted descending so the newest revision wins if
    Anthropic lists several.
    """
    page = client.models.list(limit=100)
    ids = sorted((m.id for m in page.data), reverse=True)
    out: dict[str, str] = {}
    for nick, prefix in _MODEL_PREFIXES.items():
        for mid in ids:
            if mid.startswith(prefix):
                out[nick] = mid
                break
    missing = [n for n in _MODEL_PREFIXES if n not in out]
    if missing:
        raise SystemExit(
            f"frontier: could not resolve model ids for {missing} via models.list; "
            f"ids seen (first 10): {ids[:10]}"
        )
    return out


def probe_rate_limits(client, model_id: str, thinking_off: dict) -> dict[str, str | None]:
    """Send one tiny request and return the rate-limit headers it reports."""
    raw = client.messages.with_raw_response.create(
        model=model_id,
        max_tokens=1,
        messages=[{"role": "user", "content": "hi"}],
        thinking=thinking_off,
    )
    # raw.parse() returns the Message; we discard it, we only want headers.
    _ = raw.parse()
    return {k: raw.headers.get(k) for k in _RL_HEADERS}


def _concurrency_from_limits(rpm: int | None, cap: int = 32) -> int:
    """Stay under 80 % of the requests-per-minute limit.

    Conservative: concurrency = 0.8 * rpm / 60 (requests per second), rounded
    down, with a floor of 1 and a ceiling of ``cap``.
    """
    if not rpm or rpm <= 0:
        return 1
    rps_cap = 0.8 * rpm / 60.0
    return max(1, min(cap, int(rps_cap)))


def _price_for(model_nick: str, prices_cfg: dict) -> tuple[float, float]:
    key = {"haiku": "haiku_5_5", "sonnet": "sonnet_5_5"}[model_nick]
    row = prices_cfg[key]
    return float(row["input_usd_per_mtok"]), float(row["output_usd_per_mtok"])


def _usd_cost(
    input_tokens: int, output_tokens: int, in_per_mtok: float, out_per_mtok: float
) -> float:
    return (input_tokens * in_per_mtok + output_tokens * out_per_mtok) / 1_000_000.0


# ---------------------------------------------------------------------------
# Record-level call, with a partial file to make restarts idempotent.


def _call_one(
    client, model_id: str, system_text: str, msgs: list[dict], thinking_off: dict
) -> tuple[str, int, int, str]:
    """Return (raw_output_text, input_tokens, output_tokens, response_id).

    Notes on request shape (per Messages API docs read on 2026-11-24 for
    anthropic SDK 2.13.0):
    - ``temperature`` is not a public parameter on this SDK revision; the
      API is deterministic by default. We record this in ``run.json``.
    - ``thinking_off`` is the model-specific "extended thinking off"
      config (see ``_THINKING_OFF``). For the user's request "no extended
      thinking", Haiku 5.5 uses ``{"type": "disabled"}`` and Sonnet 5.5
      uses ``{"type": "between_tools"}`` (API-enforced naming).
    """
    resp = client.messages.create(
        model=model_id,
        max_tokens=16,
        system=system_text,
        messages=msgs,
        thinking=thinking_off,
    )
    text_parts: list[str] = []
    for block in resp.content:
        t = getattr(block, "text", None)
        if t:
            text_parts.append(t)
    raw = "".join(text_parts)
    usage = resp.usage
    return raw, int(usage.input_tokens or 0), int(usage.output_tokens or 0), resp.id


def _split_system_and_messages(msgs: list[dict]) -> tuple[str, list[dict]]:
    assert msgs and msgs[0]["role"] == "system", msgs[:1]
    return msgs[0]["content"], msgs[1:]


def _load_partial(path: Path) -> dict[str, dict]:
    """Return already-collected responses keyed by cve_id."""
    if not path.exists():
        return {}
    out: dict[str, dict] = {}
    with path.open("rt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            out[r["cve_id"]] = r
    return out


def _append_partial(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("at", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Runs.


def run(
    model_nick: str,
    system: str,
    split: str,
    limit: int | None = None,
    cost_cap_usd: float = 40.0,
) -> int:
    name = _OUTPUT_NAMES[(model_nick, system)]
    info = runinfo.capture(packages=("anthropic", "numpy", "pyyaml"))

    systems = load_systems_cfg()
    prompts = load_prompts_cfg()
    labels = load_labels()
    label_set = load_label_set()
    prices_cfg = systems["claude_prices"]
    in_per, out_per = _price_for(model_nick, prices_cfg)

    client = _anthropic_client(max_retries=5)
    print("[frontier] listing models via API")
    model_ids = resolve_model_ids(client)
    model_id = model_ids[model_nick]
    thinking_off = _THINKING_OFF[model_nick]
    print(f"[frontier] {model_nick} -> {model_id}  thinking={thinking_off}")
    print(f"[frontier] probing {model_id} for rate-limit headers")
    headers = probe_rate_limits(client, model_id, thinking_off)
    for k, v in headers.items():
        print(f"  {k}: {v}")
    rpm = int(headers.get("anthropic-ratelimit-requests-limit") or 0)
    concurrency = _concurrency_from_limits(rpm)
    print(f"[frontier] concurrency = {concurrency} (80% of {rpm} rpm)")
    if model_nick == "sonnet" and rpm and rpm < 300:
        print(
            f"[frontier] WARNING: Sonnet 5.5 rpm limit is {rpm} < 300. "
            "A full test run of 2266 records will take longer than expected.",
            file=sys.stderr,
        )

    # Rows and messages.
    rows = _load_split(split)
    if limit is not None:
        rows = rows[:limit]

    train_by_id = None
    retrieval_table = None
    if system == "retrieval":
        retrieval_table = _load_retrieval_table(split)
        train_by_id = {r["cve_id"]: r for r in _load_train_rows()}

    out_dir_root = REPO_ROOT / "outputs" / name / split
    out_dir_root.mkdir(parents=True, exist_ok=True)
    partial_path = out_dir_root / ".partial.jsonl"

    # Build messages once; the partial file lets us skip already-done ones.
    full_msgs: list[tuple[str, list[dict]]] = []
    for r in rows:
        msgs = _build_messages_for_record(
            system,
            r,
            prompts=prompts,
            systems=systems,
            labels=labels,
            few_shot_examples=None,
            retrieval_table=retrieval_table,
            train_by_id=train_by_id,
            retrieval_cfg=systems.get("retrieval"),
        )
        system_text, user_msgs = _split_system_and_messages(msgs)
        full_msgs.append((system_text, user_msgs))

    collected = _load_partial(partial_path)
    todo_idx = [i for i, r in enumerate(rows) if r["cve_id"] not in collected]
    print(
        f"[frontier] {name}/{split}: {len(rows)} rows total; "
        f"{len(collected)} already in partial, {len(todo_idx)} to send"
    )

    # Cost estimate before sending (just the to-do records).
    sum_input_so_far = sum(int(c["input_tokens"]) for c in collected.values())
    sum_output_so_far = sum(int(c["output_tokens"]) for c in collected.values())
    cost_so_far = _usd_cost(sum_input_so_far, sum_output_so_far, in_per, out_per)
    print(f"[frontier] cost already spent (collected records): ${cost_so_far:.4f}")

    wall_start = time.perf_counter()
    cost_lock_breach: float | None = None

    def _run_idx(i: int) -> tuple[int, dict]:
        system_text, user_msgs = full_msgs[i]
        raw, in_tok, out_tok, rid = _call_one(
            client, model_id, system_text, user_msgs, thinking_off
        )
        parsed = parse(raw, label_set)
        rec = {
            "cve_id": rows[i]["cve_id"],
            "raw_output": raw,
            "parsed": parsed,
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "model_id": model_id,
            "response_id": rid,
        }
        _append_partial(partial_path, rec)
        return i, rec

    try:
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = {ex.submit(_run_idx, i): i for i in todo_idx}
            done = 0
            for fut in as_completed(futures):
                i, rec = fut.result()
                collected[rec["cve_id"]] = rec
                sum_input_so_far += rec["input_tokens"]
                sum_output_so_far += rec["output_tokens"]
                done += 1
                if done % 200 == 0 or done == len(todo_idx):
                    cost = _usd_cost(
                        sum_input_so_far, sum_output_so_far, in_per, out_per
                    )
                    print(
                        f"  {done}/{len(todo_idx)}  spent=${cost:.4f}  "
                        f"in={sum_input_so_far}  out={sum_output_so_far}"
                    )
                    if cost > cost_cap_usd and cost_lock_breach is None:
                        cost_lock_breach = cost
                        for f in futures:
                            f.cancel()
                        raise SystemExit(
                            f"frontier: cost cap ${cost_cap_usd} exceeded "
                            f"(${cost:.4f}); stopping. Partial preserved at {partial_path}."
                        )
    except SystemExit:
        raise
    except Exception as exc:
        print(
            f"frontier: a request failed after retries; stopping. "
            f"Partial preserved at {partial_path}. Error: {exc}",
            file=sys.stderr,
        )
        return 2

    wall_seconds = time.perf_counter() - wall_start

    # Everything is in. Assemble the final predictions in split order.
    aligned = [collected[r["cve_id"]] for r in rows]
    input_tokens = sum(int(r["input_tokens"]) for r in aligned)
    output_tokens = sum(int(r["output_tokens"]) for r in aligned)
    usd = _usd_cost(input_tokens, output_tokens, in_per, out_per)
    invalid = sum(1 for r in aligned if r["parsed"] is None)

    run_id_ts = info.started_utc.replace("-", "").replace(":", "")
    short = info.git_commit[:7] if info.git_commit else "nogit"
    run_id = f"{run_id_ts}-{short}"
    final_dir = out_dir_root / run_id
    final_dir.mkdir(parents=True, exist_ok=True)
    pred_path = final_dir / "predictions.jsonl"
    with pred_path.open("w", encoding="utf-8") as f:
        for rec in aligned:
            f.write(
                json.dumps(
                    {
                        "cve_id": rec["cve_id"],
                        "raw_output": rec["raw_output"],
                        "parsed": rec["parsed"],
                        "confidence": None,
                    }
                )
                + "\n"
            )

    run_meta = {
        "system": name,
        "prompt_name": system,
        "split": split,
        "run_id": run_id,
        "served_model": model_id,
        "model_nick": model_nick,
        "request_settings": {
            "max_tokens": 16,
            # anthropic SDK 2.13.0 removed the `temperature` parameter; the
            # Messages API is deterministic by default.
            "temperature": "not accepted by SDK 2.13.0 (deterministic default)",
            "thinking": thinking_off,
            "concurrency": concurrency,
            "max_retries": 5,
        },
        "systems_config": {
            "max_description_chars": int(systems["max_description_chars"]),
            "retrieval": systems.get("retrieval"),
        },
        "rate_limit_headers_probe": headers,
        "counts": {
            "total": len(rows),
            "valid": int(len(rows) - invalid),
            "invalid_total": int(invalid),
        },
        "token_usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        },
        "cost_usd": round(usd, 6),
        "price_source": {
            "price_read_on": prices_cfg["price_read_on"],
            "url": prices_cfg["url"],
            "input_usd_per_mtok": in_per,
            "output_usd_per_mtok": out_per,
        },
        "wall_seconds": round(wall_seconds, 2),
        "git_commit": info.git_commit,
        "git_dirty": info.git_dirty,
        "package_versions": info.package_versions,
        "started_utc": info.started_utc,
        "finished_utc": runinfo.now_iso(),
    }
    with (final_dir / "run.json").open("w") as f:
        json.dump(run_meta, f, indent=2, sort_keys=True)
        f.write("\n")

    # Clean up partial file now that the final predictions exist.
    partial_path.unlink()

    print(
        f"[frontier] {name}/{split}: done. valid={len(rows) - invalid}/{len(rows)} "
        f"input={input_tokens} output={output_tokens} cost=${usd:.4f} "
        f"wall={wall_seconds:.1f}s -> {pred_path}"
    )
    return 0


def sanity(model_nick: str, system: str, n: int = 30) -> int:
    """30-record sanity run on dev. Prints invalid count and 5 raw outputs.
    Not a reported run; writes under outputs/<name>/dev-sanity/ so the
    final scorer never confuses it with the real run."""
    name = _OUTPUT_NAMES[(model_nick, system)]
    client = _anthropic_client(max_retries=5)
    model_ids = resolve_model_ids(client)
    model_id = model_ids[model_nick]
    thinking_off = _THINKING_OFF[model_nick]
    systems = load_systems_cfg()
    prompts = load_prompts_cfg()
    labels = load_labels()
    label_set = load_label_set()
    rows = _load_split("dev")[:n]

    train_by_id = None
    retrieval_table = None
    if system == "retrieval":
        retrieval_table = _load_retrieval_table("dev")
        train_by_id = {r["cve_id"]: r for r in _load_train_rows()}

    invalid = 0
    raws: list[tuple[str, str]] = []
    print(f"[frontier-sanity] {name} on dev, n={n}, model={model_id}")
    for r in rows:
        msgs = _build_messages_for_record(
            system,
            r,
            prompts=prompts,
            systems=systems,
            labels=labels,
            few_shot_examples=None,
            retrieval_table=retrieval_table,
            train_by_id=train_by_id,
            retrieval_cfg=systems.get("retrieval"),
        )
        system_text, user_msgs = _split_system_and_messages(msgs)
        raw, _in, _out, _rid = _call_one(
            client, model_id, system_text, user_msgs, thinking_off
        )
        parsed = parse(raw, label_set)
        if parsed is None:
            invalid += 1
        if len(raws) < 5:
            raws.append((r["cve_id"], raw))

    print(f"[frontier-sanity] invalid: {invalid}/{n}")
    for cid, raw in raws:
        print(f"  {cid}: {raw!r}")
    return 0


# ---------------------------------------------------------------------------
# CLI


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run Claude baselines on a split")
    ap.add_argument("--model", choices=("sonnet", "haiku"), required=True)
    ap.add_argument("--system", choices=("zero_shot", "retrieval"), required=True)
    ap.add_argument(
        "--split",
        choices=("dev", "test"),
        default="test",
        help="split to run on (dev for sanity, test for the reported run)",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=None,
        help="restrict to the first N records (used for cost probes)",
    )
    ap.add_argument(
        "--sanity",
        action="store_true",
        help="30-record sanity run on dev; prints 5 raw outputs; not a reported run",
    )
    ap.add_argument(
        "--cost-cap-usd",
        type=float,
        default=40.0,
        help="stop if cumulative spend passes this cap",
    )
    args = ap.parse_args(list(argv) if argv is not None else None)
    if args.sanity:
        return sanity(args.model, args.system, n=(args.limit or 30))
    return run(args.model, args.system, args.split, args.limit, args.cost_cap_usd)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "resolve_model_ids",
    "probe_rate_limits",
    "run",
    "sanity",
    "main",
]
