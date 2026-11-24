"""Laptop demo. Paste a CVE description, get a CWE.

The page talks to any OpenAI-compatible server. The default is llama-server
on this machine. The prompt is the candidate prompt, and the only parser is
scorer.parse. A missing token-probability field is shown as no confidence:
the page then sends the record to review.
"""

from __future__ import annotations

import argparse
import json
import time

import numpy as np
import yaml
from openai import OpenAI

from cve2cwe import runinfo
from cve2cwe.llm_eval import predict_one
from cve2cwe.prompts import (
    REPO_ROOT,
    build_messages,
    cut_description,
    load_prompts_cfg,
    load_systems_cfg,
)
from cve2cwe.scorer import parse

NO_CONFIDENCE = (
    "The server did not return token probabilities, so there is no confidence."
)


def load_serve_cfg() -> dict:
    with (REPO_ROOT / "configs" / "serve.yaml").open() as f:
        return yaml.safe_load(f)


def load_gate_cfg() -> dict:
    with (REPO_ROOT / "configs" / "gate.yaml").open() as f:
        return yaml.safe_load(f)


def label_names() -> dict[str, str]:
    with (REPO_ROOT / "data" / "processed" / "labels.json").open() as f:
        return {row["id"]: row["name"] for row in json.load(f)}


def dev95_threshold(gate_cfg: dict) -> float:
    block = gate_cfg["routing"]["candidate_e2-seed1"]["at_0.95"]
    return float(block["threshold"])


def decide(confidence: float | None, threshold: float) -> tuple[str, str]:
    """Return the routing decision and a note. No confidence means review."""
    if confidence is None:
        return "send to review", NO_CONFIDENCE
    if confidence >= threshold:
        return "auto-label", ""
    return "send to review", ""


def label_one(
    client: OpenAI,
    description: str,
    *,
    model: str,
    prompts: dict,
    systems: dict,
    label_set: set[str],
    max_new_tokens: int,
    temperature: float,
    max_retries: int,
    backoff_seconds: float,
) -> dict:
    text = cut_description(description, int(systems["max_description_chars"]))
    messages = build_messages(
        "candidate", text, prompts=prompts, systems=systems
    )
    t0 = time.perf_counter()
    pred = predict_one(
        client,
        model,
        messages,
        label_set,
        max_new_tokens,
        temperature,
        max_retries,
        backoff_seconds,
    )
    pred["latency_seconds"] = time.perf_counter() - t0
    # parse is applied inside predict_one. Call it again so this page's
    # contract does not depend on that helper keeping the same parser.
    pred["parsed"] = parse(pred.get("raw_output") or "", label_set)
    return pred


def format_result(pred: dict, names: dict[str, str], threshold: float) -> str:
    parsed = pred.get("parsed")
    name = names.get(parsed, "") if parsed else ""
    conf = pred.get("confidence")
    decision, note = decide(conf, threshold)
    latency_ms = 1000.0 * float(pred.get("latency_seconds") or 0.0)
    lines = [
        f"CWE: {parsed or '(not a label)'}",
        f"Name: {name or '(none)'}",
    ]
    if conf is None:
        lines.append(f"Confidence: (none). {note}")
    else:
        lines.append(f"Confidence: {conf:.4f}")
    lines.append(f"Latency: {latency_ms:.0f} ms")
    lines.append(f"Decision: {decision}")
    return "\n".join(lines)


def build_page(base_url: str | None = None):
    import gradio as gr

    serve = load_serve_cfg()
    demo_cfg = serve["demo"]
    gate = load_gate_cfg()
    prompts = load_prompts_cfg()
    systems = load_systems_cfg()
    names = label_names()
    label_set = set(names)
    threshold = dev95_threshold(gate)
    url = base_url or demo_cfg["base_url"]
    model = demo_cfg["model"]
    client = OpenAI(base_url=url, api_key="local")

    def _go(description: str) -> str:
        if not (description or "").strip():
            return "Paste a CVE description."
        pred = label_one(
            client,
            description,
            model=model,
            prompts=prompts,
            systems=systems,
            label_set=label_set,
            max_new_tokens=int(demo_cfg["max_new_tokens"]),
            temperature=float(demo_cfg["temperature"]),
            max_retries=int(demo_cfg["max_retries"]),
            backoff_seconds=float(demo_cfg["backoff_seconds"]),
        )
        return format_result(pred, names, threshold)

    return gr.Interface(
        fn=_go,
        inputs=gr.Textbox(lines=14, label="CVE description"),
        outputs=gr.Textbox(lines=8, label="CWE"),
        title="cve2cwe demo",
        description=(
            "Candidate prompt, parsed by the shared scorer. "
            "Auto-label uses the dev 95% threshold from configs/gate.yaml. "
            f"Server: {url}"
        ),
    )


def _dev_rows() -> list[dict]:
    rows = []
    with (REPO_ROOT / "data" / "processed" / "dev.jsonl").open() as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _bf16_by_id() -> dict[str, dict]:
    """Dev predictions of the shipped bf16 checkpoint."""
    root = REPO_ROOT / "results" / "candidate_e2-seed1" / "dev"
    files = sorted(root.glob("*.json"))
    if len(files) != 1:
        raise SystemExit(f"expected one dev result, found {len(files)}")
    with files[0].open() as f:
        result = json.load(f)
    pred_path = REPO_ROOT / result["prediction_dir"] / "predictions.jsonl"
    out = {}
    with pred_path.open() as f:
        for line in f:
            if line.strip():
                row = json.loads(line)
                out[row["cve_id"]] = row
    return out


def sample_dev(rows: list[dict], n: int, seed: int) -> list[dict]:
    rng = np.random.default_rng(seed)
    order = rng.permutation(len(rows))
    return [rows[int(i)] for i in order[:n]]


def run_check(base_url: str | None = None) -> int:
    serve = load_serve_cfg()
    demo_cfg = serve["demo"]
    prompts = load_prompts_cfg()
    systems = load_systems_cfg()
    names = label_names()
    label_set = set(names)
    url = base_url or demo_cfg["base_url"]
    model = demo_cfg["model"]
    n = int(demo_cfg["check_records"])
    seed = int(demo_cfg["seed"])
    client = OpenAI(base_url=url, api_key="local")

    info = runinfo.capture()
    started = runinfo.now_iso()
    run_id = started.replace("-", "").replace(":", "") + "-" + info.git_commit[:7]
    out_dir = REPO_ROOT / "outputs" / "demo_check" / run_id
    out_dir.mkdir(parents=True, exist_ok=False)

    chosen = sample_dev(_dev_rows(), n, seed)
    bf16 = _bf16_by_id()
    preds = []
    n_agree = 0
    n_correct = 0
    n_conf = 0
    for i, row in enumerate(chosen, start=1):
        pred = label_one(
            client,
            row["description"],
            model=model,
            prompts=prompts,
            systems=systems,
            label_set=label_set,
            max_new_tokens=int(demo_cfg["max_new_tokens"]),
            temperature=float(demo_cfg["temperature"]),
            max_retries=int(demo_cfg["max_retries"]),
            backoff_seconds=float(demo_cfg["backoff_seconds"]),
        )
        ref = bf16[row["cve_id"]]
        agree = pred["parsed"] == ref.get("parsed")
        correct = pred["parsed"] is not None and pred["parsed"] == row["label"]
        n_agree += int(agree)
        n_correct += int(correct)
        n_conf += int(pred["confidence"] is not None)
        preds.append(
            {
                "cve_id": row["cve_id"],
                "label": row["label"],
                "raw_output": pred["raw_output"],
                "parsed": pred["parsed"],
                "confidence": pred["confidence"],
                "latency_seconds": pred["latency_seconds"],
                "bf16_parsed": ref.get("parsed"),
                "agrees_with_bf16": agree,
            }
        )
        if i % 25 == 0 or i == n:
            print(f"[demo check] {i}/{n} agree={n_agree} correct={n_correct}", flush=True)

    summary = {
        "run_id": run_id,
        "n": n,
        "seed": seed,
        "n_agree_with_bf16": n_agree,
        "agreement_with_bf16": n_agree / n,
        "n_correct": n_correct,
        "accuracy": n_correct / n,
        "n_with_confidence": n_conf,
        "bf16_prediction_dir": str(
            (REPO_ROOT / "results" / "candidate_e2-seed1" / "dev").relative_to(REPO_ROOT)
        ),
        "model": model,
        "base_url": url,
        "note": (
            "This server is the Q4_K_M GGUF. Reported scores in the README "
            "come from the bf16 checkpoint."
        ),
    }
    with (out_dir / "predictions.jsonl").open("w") as f:
        for row in preds:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    with (out_dir / "summary.json").open("w") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    finished = runinfo.now_iso()
    run_doc = {
        "stage": "demo_check",
        "run_id": run_id,
        "seed": seed,
        "n": n,
        "git_commit": info.git_commit,
        "git_dirty": info.git_dirty,
        "package_versions": info.package_versions,
        "started_utc": started,
        "finished_utc": finished,
        "summary": summary,
    }
    with (out_dir / "run.json").open("w") as f:
        json.dump(run_doc, f, indent=2)
        f.write("\n")
    print(json.dumps(summary, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cve2cwe demo")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--base-url", default=None)
    args = parser.parse_args(argv)
    if args.check:
        return run_check(args.base_url)
    page = build_page(args.base_url)
    page.launch()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
