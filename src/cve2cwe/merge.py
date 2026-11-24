"""Merge a LoRA adapter into the base weights and save a bf16 checkpoint.

DESIGN.md section 8: the shipped checkpoint is the base weights with the
adapter merged in, saved as a standalone bf16 directory that vLLM can serve.
Runs inside the .venv-train environment on the GPU pod.
"""

from __future__ import annotations

# ruff: noqa: I001
import unsloth  # noqa: F401 (keep first)

import argparse
import sys
from pathlib import Path

import yaml
from unsloth import FastLanguageModel

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_cfg(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def run(
    adapter_dir: Path,
    out_dir: Path,
    revision: str,
    base_model: str,
    max_seq_length: int,
) -> int:
    if not adapter_dir.exists():
        print(f"merge: adapter dir not found: {adapter_dir}", file=sys.stderr)
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)

    # Load the adapter folder directly; Unsloth reads adapter_config.json and
    # resolves the pinned base model ({base_model} @ {revision}). This is the
    # path required by save_pretrained_merged (loading the base and attaching
    # with peft.load_adapter is explicitly rejected).
    print(f"[merge] loading adapter {adapter_dir} (base: {base_model} @ {revision})")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=str(adapter_dir),
        max_seq_length=max_seq_length,
        load_in_4bit=False,
        load_in_16bit=True,
        full_finetuning=False,
    )

    print(f"[merge] saving merged bf16 to {out_dir}")
    model.save_pretrained_merged(str(out_dir), tokenizer, save_method="merged_16bit")
    print("[merge] done")
    return 0


def main(argv: list[str] | None = None) -> int:
    train_cfg = _load_cfg(REPO_ROOT / "configs" / "train.yaml")
    smoke_cfg = train_cfg["smoke"]

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--adapter",
        default=str(Path(smoke_cfg["output_dir"]) / "lora"),
        help="directory holding the LoRA adapter (default: smoke output)",
    )
    ap.add_argument(
        "--out",
        default=smoke_cfg["merged_dir"],
        help="directory to write the merged bf16 checkpoint (default: smoke merged)",
    )
    args = ap.parse_args(argv)
    return run(
        adapter_dir=Path(args.adapter),
        out_dir=Path(args.out),
        revision=train_cfg["revision"],
        base_model=train_cfg["base_model"],
        max_seq_length=int(train_cfg["max_seq_length"]),
    )


if __name__ == "__main__":
    raise SystemExit(main())
