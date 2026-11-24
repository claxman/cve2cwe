"""Client for an OpenAI-compatible endpoint (DESIGN.md section 8).

Every LLM evaluation, base and fine-tuned, goes through this one client so
the evaluated artifact is the one that would ship. The server side is
`scripts/serve.sh` (vLLM). This file also hosts a small smoke command used
by the Step 5 work order: it sends the first N dev records to the server
and prints raw output, parsed label, gold label and confidence.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from cve2cwe.prompts import build_messages, load_prompts_cfg, load_systems_cfg

REPO_ROOT = Path(__file__).resolve().parents[2]

# CWE ids look like CWE-<digits>. We parse the first match out of the raw
# completion. Nothing else, no fallbacks.
CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


@dataclass
class Prediction:
    cve_id: str
    gold: str
    raw: str
    parsed: str | None
    confidence: float | None
    # Debug: the per-token (token_text, prob) pairs for the generated tokens.
    token_probs: list[tuple[str, float]]


def parse_cwe(raw: str) -> str | None:
    m = CWE_RE.search(raw)
    if not m:
        return None
    body = m.group(0).upper()
    # Canonicalise to "CWE-<digits>".
    return body


def _confidence_from_logprobs(
    logprobs_content: list,
) -> tuple[float | None, list[tuple[str, float]]]:
    """Return (product of token probabilities, [(token, prob), ...]).

    OpenAI-compatible `logprobs.content` is a list of one object per generated
    token. Each object has `token` (str) and `logprob` (float). We take the
    probability of the chosen token (exp(logprob)) and multiply across tokens.
    If any item is missing, we return (None, [])."""
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


def _extract_label_token_probs(
    token_probs: list[tuple[str, float]], parsed: str
) -> tuple[float | None, list[tuple[str, float]]]:
    """Restrict the product to the tokens that reconstruct the parsed label.

    vLLM's chat template may emit a thinking preamble or spaces. We want the
    product over the tokens that belong to the CWE id itself, matching
    DESIGN.md: "confidence of a prediction: the product of the token
    probabilities of the generated label."
    """
    if not token_probs or not parsed:
        return None, []
    joined = ""
    chosen: list[tuple[str, float]] = []
    # Find the first contiguous run of tokens whose concatenation contains the
    # parsed label.
    for i in range(len(token_probs)):
        joined = ""
        chosen = []
        for tok, p in token_probs[i:]:
            joined += tok
            chosen.append((tok, p))
            if parsed in joined:
                prod = 1.0
                for _, q in chosen:
                    prod *= q
                return prod, chosen
    return None, []


def predict_one(
    client,
    model: str,
    description: str,
    prompts: dict,
    systems: dict,
    max_new_tokens: int = 8,
    temperature: float = 0.0,
) -> tuple[str, str | None, float | None, list[tuple[str, float]]]:
    """Return (raw text, parsed label, confidence, token_probs)."""
    msgs = build_messages(description, prompts, systems)
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
    parsed = parse_cwe(raw)
    lp_content = getattr(getattr(choice, "logprobs", None), "content", None) or []
    _, token_probs = _confidence_from_logprobs(lp_content)
    label_prod, _ = _extract_label_token_probs(token_probs, parsed or "")
    return raw, parsed, label_prod, token_probs


# ---------------------------------------------------------------------------
# Smoke: send the first N dev records and print the result for each.


def _read_jsonl(path: Path, limit: int | None = None) -> list[dict]:
    rows: list[dict] = []
    with path.open("rt", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rows.append(json.loads(line))
            if limit is not None and len(rows) >= limit:
                break
    return rows


def smoke(
    base_url: str,
    model: str,
    n: int,
    dev_path: Path,
    out_path: Path | None,
) -> int:
    try:
        from openai import OpenAI
    except ImportError:
        print("llm_eval: openai package not installed; `uv pip install openai`", file=sys.stderr)
        return 2
    # Any non-empty api_key value is fine for a local vLLM server.
    client = OpenAI(base_url=base_url, api_key="EMPTY")
    prompts = load_prompts_cfg()
    systems = load_systems_cfg()
    rows = _read_jsonl(dev_path, limit=n)
    print(f"[llm-eval] serving at {base_url}, model={model}, n={len(rows)}")
    print(f"[llm-eval] max_description_chars: {systems['max_description_chars']}")

    predictions: list[Prediction] = []
    invalid = 0
    agree = 0
    for r in rows:
        try:
            raw, parsed, conf, token_probs = predict_one(
                client, model, r["description"], prompts, systems
            )
        except Exception as exc:
            # Section 8: a request that is still too long (or any server
            # error) is recorded as invalid output. It does not crash the run.
            msg = str(exc).splitlines()[0][:200]
            print(f"- {r['cve_id']} | gold={r['label']} | INVALID: {msg}")
            predictions.append(
                Prediction(
                    cve_id=r["cve_id"],
                    gold=r["label"],
                    raw="",
                    parsed=None,
                    confidence=None,
                    token_probs=[],
                )
            )
            invalid += 1
            continue
        pred = Prediction(
            cve_id=r["cve_id"],
            gold=r["label"],
            raw=raw,
            parsed=parsed,
            confidence=conf,
            token_probs=token_probs,
        )
        predictions.append(pred)
        if parsed is not None and parsed == pred.gold:
            agree += 1
        print(
            f"- {pred.cve_id} | gold={pred.gold} | parsed={pred.parsed} | "
            f"conf={pred.confidence if pred.confidence is not None else 'n/a'} | "
            f"raw={pred.raw!r}"
        )

    print(f"\n[llm-eval] agree: {agree}/{len(rows)}  invalid: {invalid}/{len(rows)}")
    if out_path is not None:
        payload = [
            {
                "cve_id": p.cve_id,
                "gold": p.gold,
                "raw": p.raw,
                "parsed": p.parsed,
                "confidence": p.confidence,
                "token_probs": [[t, round(pr, 6)] for t, pr in p.token_probs],
            }
            for p in predictions
        ]
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w") as f:
            json.dump(
                {
                    "base_url": base_url,
                    "model": model,
                    "n": len(predictions),
                    "agree": agree,
                    "invalid": invalid,
                    "predictions": payload,
                },
                f,
                indent=2,
            )
            f.write("\n")
        print(f"[llm-eval] wrote {out_path}")
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="OpenAI-compatible client / smoke runner")
    ap.add_argument("--base-url", default=os.environ.get("VLLM_BASE_URL", "http://127.0.0.1:8000/v1"))
    ap.add_argument(
        "--model",
        default=os.environ.get("VLLM_MODEL", "/workspace/checkpoints/smoke-merged"),
        help="model id to send in the request (must match `vllm serve`)",
    )
    ap.add_argument("--n", type=int, default=20, help="number of dev records to send")
    ap.add_argument(
        "--dev",
        default=str(REPO_ROOT / "data" / "processed" / "dev.jsonl"),
        help="path to dev.jsonl (never test.jsonl)",
    )
    ap.add_argument(
        "--out",
        default=str(REPO_ROOT / "outputs" / "llm_eval" / "smoke.json"),
        help="where to write the per-record predictions",
    )
    args = ap.parse_args(list(argv) if argv is not None else None)
    return smoke(
        base_url=args.base_url,
        model=args.model,
        n=args.n,
        dev_path=Path(args.dev),
        out_path=Path(args.out) if args.out else None,
    )


if __name__ == "__main__":
    raise SystemExit(main())
