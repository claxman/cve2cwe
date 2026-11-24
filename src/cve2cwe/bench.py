"""Serving benchmark for the shipped checkpoint.

Measures the request that would ship: thinking disabled, temperature 0,
at most 8 new tokens, logprobs on. The server is the caller's: no
``--enforce-eager``, prefix caching left at vLLM's default. Warm-up
requests are not included in any total.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np
import yaml

from cve2cwe import runinfo
from cve2cwe.llm_eval import predict_one
from cve2cwe.prompts import REPO_ROOT, build_messages, load_prompts_cfg, load_systems_cfg
from cve2cwe.report import cost_per_1000_records
from cve2cwe.scorer import _read_jsonl, load_label_set


def _load_serve() -> dict:
    with (REPO_ROOT / "configs" / "serve.yaml").open() as f:
        return yaml.safe_load(f)


def _sample(rows: list[dict], seed: int, warmup: int, sample_size: int) -> tuple[list, list]:
    if len(rows) < warmup + sample_size:
        raise SystemExit(
            f"bench: dev has {len(rows)} rows, need {warmup + sample_size} "
            "for a disjoint warm-up and measured sample"
        )
    rng = np.random.default_rng(seed)
    order = rng.permutation(len(rows))
    warm = [rows[int(i)] for i in order[:warmup]]
    measured = [rows[int(i)] for i in order[warmup : warmup + sample_size]]
    return warm, measured


def _messages(rows: list[dict], prompts: dict, systems: dict) -> list[list[dict]]:
    return [
        build_messages(
            "candidate", row["description"], prompts=prompts, systems=systems
        )
        for row in rows
    ]


def _run_level(
    client_factory,
    model: str,
    messages: list[list[dict]],
    label_set: set[str],
    concurrency: int,
    max_new_tokens: int,
    temperature: float,
) -> dict:
    n = len(messages)
    latencies = [0.0] * n
    prompt_tokens = 0
    completion_tokens = 0

    def _one(idx: int) -> tuple[int, float, dict]:
        start = time.perf_counter()
        pred = predict_one(
            client_factory(),
            model,
            messages[idx],
            label_set,
            max_new_tokens=max_new_tokens,
            temperature=temperature,
            max_retries=3,
            backoff_seconds=1.0,
        )
        return idx, time.perf_counter() - start, pred

    wall_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = [ex.submit(_one, i) for i in range(n)]
        for fut in as_completed(futures):
            idx, seconds, pred = fut.result()
            latencies[idx] = seconds
            prompt_tokens += int(pred["prompt_tokens"])
            completion_tokens += int(pred["completion_tokens"])
    wall_seconds = time.perf_counter() - wall_start
    ms = np.asarray(latencies, dtype=np.float64) * 1000.0
    rps = n / wall_seconds
    return {
        "concurrency": concurrency,
        "n": n,
        "wall_seconds": wall_seconds,
        "records_per_second": rps,
        "latency_ms_p50": float(np.percentile(ms, 50)),
        "latency_ms_p95": float(np.percentile(ms, 95)),
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
    }


def run(
    base_url: str,
    model: str,
    max_num_seqs: int,
    enforce_eager: bool,
    prefix_caching: str,
) -> int:
    info = runinfo.capture(packages=("numpy", "pyyaml", "openai", "httpx"))
    print(f"[bench] git {info.git_commit} dirty={info.git_dirty}", flush=True)
    if info.git_dirty:
        print("[bench] refusing: git_dirty is true", file=sys.stderr)
        return 2

    try:
        from openai import OpenAI
    except ImportError:
        print("bench: openai package not installed", file=sys.stderr)
        return 2

    serve = _load_serve()
    bench_cfg = serve["bench"]
    price = float(serve["gpu_price_usd_per_hour"])
    seed = int(bench_cfg["seed"])
    warmup_n = int(bench_cfg["warmup_requests"])
    sample_n = int(bench_cfg["sample_size"])
    concurrencies = [int(c) for c in bench_cfg["concurrencies"]]
    max_new_tokens = int(bench_cfg["max_new_tokens"])
    temperature = float(bench_cfg["temperature"])

    dev = _read_jsonl(REPO_ROOT / "data" / "processed" / "dev.jsonl")
    warm_rows, measured_rows = _sample(dev, seed, warmup_n, sample_n)
    prompts = load_prompts_cfg()
    systems = load_systems_cfg()
    label_set = load_label_set()
    warm_msgs = _messages(warm_rows, prompts, systems)
    measured_msgs = _messages(measured_rows, prompts, systems)

    import threading

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

    print(f"[bench] warm-up {warmup_n} requests (not counted)", flush=True)
    _run_level(
        _client,
        model,
        warm_msgs,
        label_set,
        concurrency=1,
        max_new_tokens=max_new_tokens,
        temperature=temperature,
    )

    levels = []
    for conc in concurrencies:
        print(f"[bench] concurrency {conc}", flush=True)
        level = _run_level(
            _client,
            model,
            measured_msgs,
            label_set,
            concurrency=conc,
            max_new_tokens=max_new_tokens,
            temperature=temperature,
        )
        level["cost_per_1000_usd"] = cost_per_1000_records(
            price, level["records_per_second"]
        )
        levels.append(level)
        print(
            f"[bench] concurrency {conc}: wall={level['wall_seconds']} "
            f"rps={level['records_per_second']} "
            f"p50={level['latency_ms_p50']} p95={level['latency_ms_p95']} "
            f"cost_per_1000={level['cost_per_1000_usd']}",
            flush=True,
        )

    short = info.git_commit[:7] if info.git_commit else "nogit"
    run_id_ts = info.started_utc.replace("-", "").replace(":", "")
    run_id = f"{run_id_ts}-{short}"
    out_dir = REPO_ROOT / "outputs" / "bench" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    bench_doc = {
        "run_id": run_id,
        "served_model": model,
        "base_url": base_url,
        "checkpoint": "candidate_e2-seed1",
        "sample_size": sample_n,
        "warmup_requests": warmup_n,
        "seed": seed,
        "measured_cve_ids": [r["cve_id"] for r in measured_rows],
        "warmup_cve_ids": [r["cve_id"] for r in warm_rows],
        "gpu": {
            "name": serve["gpu_name"],
            "price_usd_per_hour": price,
            "price_source": serve["gpu_price_source"],
            "price_read_utc": serve["gpu_price_read_utc"],
        },
        "server": {
            "enforce_eager": enforce_eager,
            "prefix_caching": prefix_caching,
            "max_num_seqs": max_num_seqs,
        },
        "request": {
            "temperature": temperature,
            "max_tokens": max_new_tokens,
            "logprobs": True,
            "chat_template_kwargs": {"enable_thinking": False},
        },
        "cost_formula": "price_usd_per_hour / (records_per_second * 3600) * 1000",
        "levels": levels,
    }
    run_doc = {
        "run_id": run_id,
        "git_commit": info.git_commit,
        "git_dirty": info.git_dirty,
        "package_versions": info.package_versions,
        "started_utc": info.started_utc,
        "finished_utc": runinfo.now_iso(),
        "served_model": model,
        "base_url": base_url,
    }
    (out_dir / "bench.json").write_text(json.dumps(bench_doc, indent=2) + "\n")
    (out_dir / "run.json").write_text(json.dumps(run_doc, indent=2, sort_keys=True) + "\n")
    print(f"[bench] wrote {out_dir / 'bench.json'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    serve = _load_serve()
    ap = argparse.ArgumentParser(description="Serving benchmark")
    ap.add_argument("--base-url", default=os.environ.get("VLLM_BASE_URL", "http://127.0.0.1:8000/v1"))
    ap.add_argument("--model", required=True, help="served model name")
    ap.add_argument(
        "--max-num-seqs",
        type=int,
        default=int(serve["bench"]["max_num_seqs"]),
        help="max_num_seqs the server was started with",
    )
    ap.add_argument(
        "--enforce-eager",
        action="store_true",
        help="record that the server was started with --enforce-eager",
    )
    ap.add_argument(
        "--prefix-caching",
        default="default",
        choices=("default", "off"),
        help="what the server was started with; default means the flag was not passed",
    )
    args = ap.parse_args(argv)
    return run(
        base_url=args.base_url,
        model=args.model,
        max_num_seqs=args.max_num_seqs,
        enforce_eager=args.enforce_eager,
        prefix_caching=args.prefix_caching,
    )


if __name__ == "__main__":
    raise SystemExit(main())
