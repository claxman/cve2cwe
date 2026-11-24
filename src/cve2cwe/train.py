"""LoRA fine-tune of Qwen3.5-4B with Unsloth + TRL.

DESIGN section 7 is the spec. Four modes are exposed on the command line:

  --profile-lengths   tokenise train+dev after the input cut, print p50/p90/
                      p99/max and the total train tokens; no training.
  --memory-check      build the model, run one training step on the longest
                      N train examples (default 32), report peak memory;
                      no W&B run; useful for sizing per-device-batch-size.
  --probe             run 100 steps on a random 3,200-row train sample with
                      the final settings. W&B run name: "probe". Used to
                      decide epochs per the rule in configs/train.yaml.
  --seed N            full training run on seed N using configs/train.yaml.
                      Writes run.json at the start and completes it at the
                      end. Saves the adapter at the end of every epoch.

All modes share the exact same data path, tokeniser, prompt construction
and loss mask.  Runs on the GPU pod inside the .venv-train environment.
"""

from __future__ import annotations

# ruff: noqa: I001
# Unsloth must be imported before transformers/trl so its kernels and patches
# take effect. See the Unsloth Qwen3.5 fine-tune guide.
import unsloth  # noqa: F401 (keep first)

import argparse
import gzip
import json
import os
import random
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import torch
import yaml
from datasets import Dataset
from transformers import TrainerCallback
from trl import SFTConfig, SFTTrainer
from unsloth import FastLanguageModel
from unsloth.chat_templates import train_on_responses_only

from cve2cwe.prompts import (
    load_prompts_cfg,
    load_systems_cfg,
    render_inference_prompt,
    render_training_text,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
# Allow the pod launcher to redirect outputs/ to a stable location (so later
# pushes to /workspace/cve2cwe cannot clobber in-progress run artefacts).
OUTPUT_DIR = Path(os.environ.get("CVE2CWE_OUTPUT_DIR", REPO_ROOT / "outputs"))


# ---------------------------------------------------------------------------
# Utilities.


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git_commit() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return ""


def _git_dirty() -> bool:
    try:
        out = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=REPO_ROOT, stderr=subprocess.DEVNULL
        )
        return bool(out.strip())
    except Exception:
        return False


def _package_versions() -> dict[str, str]:
    mods = [
        "torch",
        "transformers",
        "trl",
        "peft",
        "accelerate",
        "unsloth",
        "unsloth_zoo",
        "bitsandbytes",
        "wandb",
        "datasets",
    ]
    out: dict[str, str] = {}
    for m in mods:
        try:
            mod = __import__(m)
            out[m] = getattr(mod, "__version__", "unknown")
        except Exception:
            out[m] = "missing"
    return out


def _wandb_info(project: str, run_name: str) -> dict:
    out: dict = {"project": project, "run_name": run_name, "run_id": None, "run_url": None}
    try:
        import wandb  # type: ignore

        if wandb.run is not None:
            out["run_id"] = getattr(wandb.run, "id", None)
            out["run_url"] = getattr(wandb.run, "url", None)
    except Exception:
        pass
    return out


def _read_jsonl_gz(path: Path) -> list[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _read_jsonl(path: Path) -> list[dict]:
    with path.open("rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _load_cfg(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def _text_tokenizer(tokenizer):
    """Qwen3.5 is a VLM, so `tokenizer` may be a processor. Fall back to the
    inner text tokenizer when present so calls take a plain string."""
    return getattr(tokenizer, "tokenizer", tokenizer)


# ---------------------------------------------------------------------------
# Prompt + token-length probe.


def _render_split(
    tokenizer, rows: list[dict], prompts: dict, systems: dict, with_label: bool
) -> list[str]:
    texts: list[str] = []
    for r in rows:
        if with_label:
            texts.append(
                render_training_text(tokenizer, r["description"], r["label"], prompts, systems)
            )
        else:
            texts.append(render_inference_prompt(tokenizer, r["description"], prompts, systems))
    return texts


def _token_lengths(tokenizer, texts: list[str]) -> list[int]:
    text_tok = _text_tokenizer(tokenizer)
    return [len(text_tok.encode(t, add_special_tokens=False)) for t in texts]


def _percentile(xs: list[int], q: float) -> int:
    if not xs:
        return 0
    return int(np.percentile(np.asarray(xs), q))


def _length_stats(xs: list[int]) -> dict[str, int]:
    return {
        "count": len(xs),
        "p50": _percentile(xs, 50),
        "p90": _percentile(xs, 90),
        "p99": _percentile(xs, 99),
        "max": max(xs) if xs else 0,
        "total": sum(xs),
    }


def _round_up_to_multiple(x: int, m: int) -> int:
    return ((x + m - 1) // m) * m


# ---------------------------------------------------------------------------
# Data loading.


def _load_data() -> tuple[list[dict], list[dict]]:
    train_path = REPO_ROOT / "data" / "processed" / "train.jsonl.gz"
    dev_path = REPO_ROOT / "data" / "processed" / "dev.jsonl"
    return _read_jsonl_gz(train_path), _read_jsonl(dev_path)


# ---------------------------------------------------------------------------
# Model build.


def _load_base(train_cfg: dict, max_seq_length: int):
    print(
        f"[train] loading base {train_cfg['base_model']} @ {train_cfg['revision']} "
        f"(max_seq_length={max_seq_length})"
    )
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=train_cfg["base_model"],
        revision=train_cfg["revision"],
        max_seq_length=max_seq_length,
        load_in_4bit=False,
        load_in_16bit=True,
        full_finetuning=False,
    )
    return model, tokenizer


def _attach_lora(model, train_cfg: dict, seed: int, max_seq_length: int):
    lora = train_cfg["lora"]
    # Section B3 of the work order: language model only. With FastLanguageModel
    # the adapter attaches only to the language stack; the vision tower is
    # skipped (verified below via _count_vision_lora_modules).
    model = FastLanguageModel.get_peft_model(
        model,
        r=int(lora["r"]),
        target_modules=list(lora["target_modules"]),
        lora_alpha=int(lora["alpha"]),
        lora_dropout=float(lora["dropout"]),
        bias=lora["bias"],
        use_gradient_checkpointing=lora["use_gradient_checkpointing"],
        random_state=seed,  # seed controls adapter initialisation
        max_seq_length=max_seq_length,
    )
    return model


_VISION_NAME_RE = re.compile(r"(^|\.)(vision|visual)(\.|$)", re.IGNORECASE)


def _count_vision_lora_modules(model) -> int:
    n = 0
    for name, module in model.named_modules():
        cls = type(module).__name__.lower()
        if "lora" in cls and _VISION_NAME_RE.search(name):
            n += 1
    return n


def _trainable_param_counts(model) -> tuple[int, int]:
    total = sum(p.numel() for p in model.parameters())
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    return trainable, total


# ---------------------------------------------------------------------------
# Trainer build.


def _build_dataset(
    tokenizer, rows: list[dict], prompts: dict, systems: dict
) -> Dataset:
    """Return a dataset with the rendered training text and a `length` column
    for HuggingFace's LengthGroupedSampler (group_by_length=True)."""
    texts = _render_split(tokenizer, rows, prompts, systems, with_label=True)
    lens = _token_lengths(tokenizer, texts)
    return Dataset.from_dict({"text": texts, "length": lens})


class _DevLossProbe(TrainerCallback):
    """Collects every eval/loss as (step, loss)."""

    def __init__(self) -> None:
        self.losses: list[dict[str, float]] = []

    def on_log(self, args, state, control, logs=None, **kwargs):
        if not logs or "eval_loss" not in logs:
            return
        self.losses.append({"step": int(state.global_step), "loss": float(logs["eval_loss"])})


class _TrainLossProbe(TrainerCallback):
    def __init__(self) -> None:
        self.first: float | None = None
        self.last: float | None = None

    def on_log(self, args, state, control, logs=None, **kwargs):
        if not logs or "loss" not in logs:
            return
        loss = float(logs["loss"])
        if self.first is None:
            self.first = loss
        self.last = loss


def _apply_response_mask(trainer, train_cfg: dict):
    mask_cfg = train_cfg["loss_mask"]
    return train_on_responses_only(
        trainer,
        instruction_part=mask_cfg["instruction_part"],
        response_part=mask_cfg["response_part"],
    )


def _restore_length_column(trainer, length_column: str = "length") -> None:
    """SFTTrainer tokenises the ``text`` column and drops the pre-computed
    ``length`` column, so transformers' LengthGroupedSampler falls back to
    the processor's first input name (``pixel_values`` for Qwen3.5) and
    crashes with "Can only automatically infer lengths...".

    Re-add ``length`` to the tokenised train and eval datasets from the real
    ``input_ids`` length, after preparation."""
    for attr in ("train_dataset", "eval_dataset"):
        ds = getattr(trainer, attr, None)
        if ds is None:
            continue
        if length_column in ds.column_names:
            continue
        if "input_ids" not in ds.column_names:
            continue
        lens = [len(x) for x in ds["input_ids"]]
        setattr(trainer, attr, ds.add_column(length_column, lens))


def _dev_sample(dev_rows: list[dict], n: int, sample_seed: int) -> list[dict]:
    """Deterministic 500-record dev sample. The sample seed is in the config
    (same for every training seed), so dev loss is comparable across runs."""
    rng = random.Random(sample_seed)
    idx = list(range(len(dev_rows)))
    rng.shuffle(idx)
    return [dev_rows[i] for i in idx[: min(n, len(dev_rows))]]


def _make_sft_config(
    train_cfg: dict,
    seed: int,
    max_steps: int | None,
    num_train_epochs: int | None,
    output_dir: Path,
    run_name: str,
    eval_steps: int | None,
    logging_steps: int,
    save_strategy: str,
    total_steps_hint: int | None,
) -> SFTConfig:
    opt = train_cfg["optim"]
    batch = train_cfg["batch"]
    # transformers 5.17 and trl 1.15 dropped `warmup_ratio`; only
    # `warmup_steps` is a field. Compute it here from `warmup_ratio` in the
    # config and the known total steps (max_steps or epochs x steps/epoch).
    warmup_steps = 0
    if total_steps_hint and total_steps_hint > 0:
        warmup_steps = max(1, int(float(opt["warmup_ratio"]) * total_steps_hint))
    kwargs: dict[str, Any] = {
        "output_dir": str(output_dir),
        "per_device_train_batch_size": int(batch["per_device_train_batch_size"]),
        "per_device_eval_batch_size": int(batch["per_device_eval_batch_size"]),
        "gradient_accumulation_steps": int(batch["gradient_accumulation_steps"]),
        "warmup_steps": warmup_steps,
        "learning_rate": float(opt["learning_rate"]),
        "weight_decay": float(opt["weight_decay"]),
        "lr_scheduler_type": opt["lr_scheduler_type"],
        "optim": opt["optimizer"],
        "logging_steps": logging_steps,
        "seed": seed,
        "data_seed": seed,  # seed controls data order via LengthGroupedSampler
        "report_to": ["wandb"],
        "run_name": run_name,
        "max_length": int(train_cfg["max_seq_length"]),
        "bf16": True,
        "fp16": False,
        "dataset_num_proc": 1,
        "save_strategy": save_strategy,
        # Length-grouped sampling: shuffle, then within each mega-batch sort
        # by length, then yield batches. transformers' LengthGroupedSampler
        # reads the column named by `length_column_name`; SFTTrainer drops
        # non-signature columns during preparation, so train.py re-adds a
        # `length` column from `input_ids` after the trainer is built.
        "train_sampling_strategy": "group_by_length",
        "length_column_name": "length",
        "remove_unused_columns": False,
    }
    if max_steps is not None:
        kwargs["max_steps"] = int(max_steps)
    if num_train_epochs is not None:
        kwargs["num_train_epochs"] = int(num_train_epochs)
    if eval_steps is not None:
        kwargs["eval_strategy"] = "steps"
        kwargs["eval_steps"] = int(eval_steps)
    return SFTConfig(**kwargs)


# ---------------------------------------------------------------------------
# Loss-mask printout.


def _print_loss_carrying_tokens(label_name: str, tokenizer, trainer, example_text: str) -> str:
    """Print the decoded tokens that carry loss for one rendered example."""
    text_tok = _text_tokenizer(tokenizer)
    # Use the trainer's data collator to get labels with -100 on masked tokens.
    tokenised = text_tok(example_text, add_special_tokens=False, return_tensors=None)
    features = [
        {
            "input_ids": tokenised["input_ids"],
            "attention_mask": tokenised["attention_mask"],
        }
    ]
    batch_out = trainer.data_collator(features)
    labels = batch_out["labels"][0].tolist()
    input_ids = batch_out["input_ids"][0].tolist()
    kept = [tid for tid, lid in zip(input_ids, labels, strict=True) if lid != -100]
    decoded = text_tok.decode(kept)
    print(f"\n=== loss-carrying tokens ({label_name}) ===")
    print(repr(decoded))
    return decoded


# ---------------------------------------------------------------------------
# Modes.


def _render_and_assert_prefix(tokenizer, sample: dict, prompts: dict, systems: dict) -> None:
    inference_prompt = render_inference_prompt(tokenizer, sample["description"], prompts, systems)
    training_text = render_training_text(
        tokenizer, sample["description"], sample["label"], prompts, systems
    )
    print("\n=== inference prompt ===\n" + inference_prompt)
    print("\n=== training text ===\n" + training_text)
    if not training_text.startswith(inference_prompt):
        raise AssertionError(
            "training text does not start with the inference prompt; chat template or "
            "add_generation_prompt flag is inconsistent"
        )
    print("\n[train] prefix check passed: inference prompt is a prefix of training text\n")


def _check_lengths_or_fail(
    tokenizer, train_rows: list[dict], dev_rows: list[dict],
    prompts: dict, systems: dict, max_seq_length: int,
) -> dict:
    print(f"[train] measuring token lengths after the {systems['max_description_chars']}-char cut")
    train_texts = _render_split(tokenizer, train_rows, prompts, systems, with_label=True)
    dev_texts = _render_split(tokenizer, dev_rows, prompts, systems, with_label=True)
    train_lens = _token_lengths(tokenizer, train_texts)
    dev_lens = _token_lengths(tokenizer, dev_texts)
    stats = {"train": _length_stats(train_lens), "dev": _length_stats(dev_lens)}
    print(json.dumps(stats, indent=2))
    overall_max = max(stats["train"]["max"], stats["dev"]["max"])
    if overall_max > max_seq_length:
        raise AssertionError(
            f"max_seq_length={max_seq_length} is too small: longest rendered example is "
            f"{overall_max} tokens. Truncation would cut the label. Raise max_seq_length "
            f"in configs/train.yaml to at least {_round_up_to_multiple(overall_max, 64)}."
        )
    print(
        f"[train] max rendered length {overall_max} <= max_seq_length {max_seq_length} "
        "(no truncation)"
    )
    return stats


def mode_profile_lengths() -> int:
    """Tokenise train+dev with the real tokenizer and print length stats."""
    train_cfg = _load_cfg(REPO_ROOT / "configs" / "train.yaml")
    prompts = load_prompts_cfg()
    systems = load_systems_cfg()
    train_rows, dev_rows = _load_data()
    max_sl = int(train_cfg.get("max_seq_length", 1024))
    _, tokenizer = _load_base(train_cfg, max_seq_length=max_sl)
    print(f"[profile] train rows: {len(train_rows)}, dev rows: {len(dev_rows)}")
    train_texts = _render_split(tokenizer, train_rows, prompts, systems, with_label=True)
    dev_texts = _render_split(tokenizer, dev_rows, prompts, systems, with_label=True)
    train_lens = _token_lengths(tokenizer, train_texts)
    dev_lens = _token_lengths(tokenizer, dev_texts)
    stats = {
        "train": _length_stats(train_lens),
        "dev": _length_stats(dev_lens),
        "overall_max": max(train_lens + dev_lens),
        "suggested_max_seq_length": _round_up_to_multiple(max(train_lens + dev_lens), 64),
    }
    print("\n=== token-length profile (after cut, with chat template) ===")
    print(json.dumps(stats, indent=2))
    out = OUTPUT_DIR / "train" / "profile.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(stats, indent=2) + "\n")
    print(f"[profile] wrote {out}")
    return 0


def mode_memory_check(n_examples: int) -> int:
    """One training step on the longest N train examples. Report peak memory."""
    train_cfg = _load_cfg(REPO_ROOT / "configs" / "train.yaml")
    prompts = load_prompts_cfg()
    systems = load_systems_cfg()
    train_rows, _ = _load_data()
    max_sl = int(train_cfg["max_seq_length"])
    model, tokenizer = _load_base(train_cfg, max_seq_length=max_sl)
    model = _attach_lora(model, train_cfg, seed=1, max_seq_length=max_sl)

    # Pick the longest N rendered examples.
    texts = _render_split(tokenizer, train_rows, prompts, systems, with_label=True)
    lens = _token_lengths(tokenizer, texts)
    order = sorted(range(len(texts)), key=lambda i: lens[i], reverse=True)[:n_examples]
    picked_texts = [texts[i] for i in order]
    picked_lens = [lens[i] for i in order]
    print(
        f"[memcheck] picked {len(picked_texts)} longest rows; "
        f"lengths max={max(picked_lens)}, min={min(picked_lens)}"
    )

    ds = Dataset.from_dict({"text": picked_texts, "length": picked_lens})
    args = _make_sft_config(
        train_cfg,
        seed=1,
        max_steps=1,
        num_train_epochs=None,
        output_dir=Path("/tmp/cve2cwe-memcheck"),
        run_name="memcheck",
        eval_steps=None,
        logging_steps=1,
        save_strategy="no",
        total_steps_hint=1,
    )
    args.report_to = []
    args.per_device_train_batch_size = n_examples  # single step on all picked rows
    trainer = SFTTrainer(model=model, tokenizer=tokenizer, train_dataset=ds, args=args)
    trainer = _apply_response_mask(trainer, train_cfg)
    _restore_length_column(trainer)
    torch.cuda.reset_peak_memory_stats()
    trainer.train()
    peak = torch.cuda.max_memory_allocated()
    print(
        f"[memcheck] peak GPU memory for batch of {n_examples} longest examples: "
        f"{peak / (1024**3):.2f} GiB"
    )
    return 0


def mode_probe() -> int:
    """100 steps on a random 3,200-row sample. W&B name: probe."""
    train_cfg = _load_cfg(REPO_ROOT / "configs" / "train.yaml")
    probe_cfg = train_cfg["probe"]
    prompts = load_prompts_cfg()
    systems = load_systems_cfg()
    train_rows, _ = _load_data()
    seed = int(probe_cfg["seed"])
    rng = random.Random(seed)
    idx = list(range(len(train_rows)))
    rng.shuffle(idx)
    picked = [train_rows[i] for i in idx[: int(probe_cfg["train_rows"])]]

    max_sl = int(train_cfg["max_seq_length"])
    model, tokenizer = _load_base(train_cfg, max_seq_length=max_sl)
    model = _attach_lora(model, train_cfg, seed=seed, max_seq_length=max_sl)
    _check_lengths_or_fail(tokenizer, picked, [], prompts, systems, max_sl)
    ds = _build_dataset(tokenizer, picked, prompts, systems)

    args = _make_sft_config(
        train_cfg,
        seed=seed,
        max_steps=int(probe_cfg["max_steps"]),
        num_train_epochs=None,
        output_dir=Path(probe_cfg["output_dir"]),
        run_name="probe",
        eval_steps=None,
        logging_steps=int(probe_cfg["logging_steps"]),
        save_strategy="no",
        total_steps_hint=int(probe_cfg["max_steps"]),
    )
    os.environ.setdefault("WANDB_PROJECT", train_cfg["wandb"]["project"])
    trainer = SFTTrainer(model=model, tokenizer=tokenizer, train_dataset=ds, args=args)
    trainer = _apply_response_mask(trainer, train_cfg)
    _restore_length_column(trainer)
    torch.cuda.reset_peak_memory_stats()
    t0 = time.time()
    trainer.train()
    dt = time.time() - t0
    peak = torch.cuda.max_memory_allocated()
    full_rows = len(train_rows)
    epoch_seconds = dt * full_rows / int(probe_cfg["train_rows"])
    print("\n=== probe summary ===")
    print(
        json.dumps(
            {
                "max_steps": int(probe_cfg["max_steps"]),
                "train_rows": int(probe_cfg["train_rows"]),
                "train_seconds": round(dt, 2),
                "peak_gpu_gib": round(peak / (1024**3), 2),
                "seconds_per_step": round(dt / int(probe_cfg["max_steps"]), 3),
                "estimated_epoch_seconds_full": round(epoch_seconds, 1),
                "estimated_epoch_minutes_full": round(epoch_seconds / 60.0, 1),
                "full_train_rows": full_rows,
            },
            indent=2,
        )
    )
    return 0


def _save_epoch_adapter(model, tokenizer, output_dir: Path, epoch: int) -> Path:
    adapter_dir = output_dir / f"epoch{epoch}"
    model.save_pretrained(str(adapter_dir))
    tokenizer.save_pretrained(str(adapter_dir))
    return adapter_dir


class _EpochSaver(TrainerCallback):
    def __init__(self, model_ref, tokenizer_ref, output_dir: Path) -> None:
        self.model = model_ref
        self.tokenizer = tokenizer_ref
        self.output_dir = output_dir
        self.saved: list[str] = []

    def on_epoch_end(self, args, state, control, **kwargs):
        epoch = int(state.epoch) if state.epoch is not None else len(self.saved) + 1
        path = _save_epoch_adapter(self.model, self.tokenizer, self.output_dir, epoch)
        self.saved.append(str(path))
        print(f"[train] saved epoch{epoch} adapter to {path}")


def mode_seed(seed: int) -> int:
    """Full training run for one seed. Writes run.json at start and end."""
    train_cfg = _load_cfg(REPO_ROOT / "configs" / "train.yaml")
    prompts = load_prompts_cfg()
    systems = load_systems_cfg()
    start_utc = _utc_now_iso()
    t0 = time.time()

    git_commit = _git_commit()
    git_dirty = _git_dirty()

    checkpoints_root = Path(os.environ.get("CVE2CWE_CHECKPOINTS", "/workspace/checkpoints"))
    seed_dir = checkpoints_root / f"seed{seed}"
    seed_dir.mkdir(parents=True, exist_ok=True)

    run_out_dir = OUTPUT_DIR / "train" / f"seed{seed}"
    run_out_dir.mkdir(parents=True, exist_ok=True)
    run_json_path = run_out_dir / "run.json"

    # Initial run.json (partial) — written before any work so it exists even
    # if training crashes.
    initial = {
        "stage": "train",
        "mode": "full",
        "seed": seed,
        "started_utc": start_utc,
        "git_commit": git_commit,
        "git_dirty": git_dirty,
        "package_versions": _package_versions(),
        "full_config": train_cfg,
        "systems": systems,
        "prompts": prompts,
        "status": "running",
    }
    run_json_path.write_text(json.dumps(initial, indent=2) + "\n")
    print(f"[train] wrote initial {run_json_path}")

    train_rows, dev_rows = _load_data()
    max_sl = int(train_cfg["max_seq_length"])

    model, tokenizer = _load_base(train_cfg, max_seq_length=max_sl)
    model = _attach_lora(model, train_cfg, seed=seed, max_seq_length=max_sl)

    # Prefix assertion on one sample.
    _render_and_assert_prefix(tokenizer, train_rows[0], prompts, systems)

    # Length check: no truncation allowed.
    lengths_stats = _check_lengths_or_fail(
        tokenizer, train_rows, dev_rows, prompts, systems, max_sl
    )

    # Adapter placement: 0 LoRA modules in vision tower.
    vision_lora = _count_vision_lora_modules(model)
    trainable, total = _trainable_param_counts(model)
    print(
        f"[train] trainable={trainable:,} of {total:,} "
        f"({100*trainable/total:.3f}%); vision-tower LoRA modules={vision_lora}"
    )
    if vision_lora != 0:
        raise AssertionError(
            f"adapter placement is not language-model-only: {vision_lora} LoRA modules "
            "found inside the vision tower"
        )

    # Datasets.
    train_ds = _build_dataset(tokenizer, train_rows, prompts, systems)
    dev_sample_cfg = train_cfg["dev_eval"]
    dev_sample_rows = _dev_sample(
        dev_rows,
        n=int(dev_sample_cfg["sample_size"]),
        sample_seed=int(dev_sample_cfg["sample_seed"]),
    )
    dev_ds = _build_dataset(tokenizer, dev_sample_rows, prompts, systems)
    print(f"[train] dev loss sample: {len(dev_sample_rows)} rows")

    num_epochs = int(train_cfg["num_train_epochs"])
    logging_steps = int(train_cfg["logging_steps"])
    eval_steps = int(dev_sample_cfg["eval_steps"])
    eff_batch_tmp = int(train_cfg["batch"]["per_device_train_batch_size"]) * int(
        train_cfg["batch"]["gradient_accumulation_steps"]
    )
    steps_per_epoch = (len(train_rows) + eff_batch_tmp - 1) // eff_batch_tmp
    total_steps = steps_per_epoch * num_epochs

    args = _make_sft_config(
        train_cfg,
        seed=seed,
        max_steps=None,
        num_train_epochs=num_epochs,
        output_dir=seed_dir,
        run_name=f"seed{seed}",
        eval_steps=eval_steps,
        logging_steps=logging_steps,
        save_strategy="no",  # we save per-epoch via the callback below
        total_steps_hint=total_steps,
    )
    os.environ.setdefault("WANDB_PROJECT", train_cfg["wandb"]["project"])

    train_probe = _TrainLossProbe()
    dev_probe = _DevLossProbe()
    epoch_saver = _EpochSaver(model_ref=None, tokenizer_ref=tokenizer, output_dir=seed_dir)

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_ds,
        eval_dataset=dev_ds,
        args=args,
        callbacks=[train_probe, dev_probe, epoch_saver],
    )
    trainer = _apply_response_mask(trainer, train_cfg)
    _restore_length_column(trainer)
    epoch_saver.model = trainer.model  # update after unsloth may wrap

    # Loss mask printouts for one train and one dev example.
    sample_train_text = train_ds[0]["text"]
    sample_dev_text = dev_ds[0]["text"]
    _print_loss_carrying_tokens("train[0]", tokenizer, trainer, sample_train_text)
    _print_loss_carrying_tokens("dev[0]", tokenizer, trainer, sample_dev_text)

    torch.cuda.reset_peak_memory_stats()
    t_train = time.time()
    trainer.train()
    train_seconds = time.time() - t_train
    peak_gpu_bytes = torch.cuda.max_memory_allocated()

    # Tokens seen (upper-bound estimate: mean input tokens × eff batch × step count).
    eff_batch = int(train_cfg["batch"]["per_device_train_batch_size"]) * int(
        train_cfg["batch"]["gradient_accumulation_steps"]
    )
    mean_tokens = lengths_stats["train"]["total"] / lengths_stats["train"]["count"]
    steps = max(trainer.state.global_step, 1)
    tokens_seen = mean_tokens * eff_batch * steps
    tokens_per_second = tokens_seen / max(train_seconds, 1e-9)

    # Save the final adapter (in addition to per-epoch saves).
    model.save_pretrained(str(seed_dir / "final"))
    tokenizer.save_pretrained(str(seed_dir / "final"))

    # Completed run.json.
    completed = dict(initial)
    completed.update(
        {
            "status": "ok",
            "finished_utc": _utc_now_iso(),
            "wall_seconds": round(time.time() - t0, 2),
            "training_seconds": round(train_seconds, 2),
            "tokens_per_second": round(tokens_per_second, 2),
            "peak_gpu_memory_bytes": int(peak_gpu_bytes),
            "peak_gpu_memory_gib": round(peak_gpu_bytes / (1024**3), 2),
            "final_train_loss": train_probe.last,
            "first_train_loss": train_probe.first,
            "dev_losses": dev_probe.losses,
            "lengths": lengths_stats,
            "effective_batch": eff_batch,
            "steps_completed": steps,
            "epoch_adapter_dirs": epoch_saver.saved,
            "final_adapter_dir": str(seed_dir / "final"),
            "wandb": _wandb_info(train_cfg["wandb"]["project"], f"seed{seed}"),
        }
    )
    run_json_path.write_text(json.dumps(completed, indent=2) + "\n")
    print(f"[train] completed {run_json_path}")
    return 0


# ---------------------------------------------------------------------------
# Entry.


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile-lengths", action="store_true")
    ap.add_argument("--memory-check", action="store_true")
    ap.add_argument("--memory-check-n", type=int, default=32)
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args(argv)

    modes = sum(bool(x) for x in [args.profile_lengths, args.memory_check, args.probe, args.seed])
    if modes != 1:
        print(
            "train: pick exactly one of --profile-lengths / --memory-check / --probe / --seed N",
            file=sys.stderr,
        )
        return 2

    if args.profile_lengths:
        return mode_profile_lengths()
    if args.memory_check:
        return mode_memory_check(n_examples=int(args.memory_check_n))
    if args.probe:
        return mode_probe()
    return mode_seed(seed=int(args.seed))


if __name__ == "__main__":
    raise SystemExit(main())
