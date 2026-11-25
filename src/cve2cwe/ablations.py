"""Ablation overrides for configs/train.yaml.

An override file may change one part of the shipped recipe. Every other key
stays as train.yaml wrote it. The sampler is pure Python so tests can run
it without Unsloth.
"""

from __future__ import annotations

import copy
import hashlib
import random
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ABLATION_DIR = REPO_ROOT / "configs" / "ablations"

# Order is the README table order. ctrl is the same-machine reference.
ABLATION_NAMES = (
    "ctrl",
    "frac05",
    "frac10",
    "frac30",
    "frac10-e6",
    "r4",
    "r64",
    "qlora4bit",
)

# Keys an override may set. what_changed is README text, not a training key.
_OVERRIDE_KEYS = {
    "run_tag",
    "train_fraction",
    "fraction_seed",
    "num_train_epochs",
    "load_in_4bit",
    "load_in_16bit",
    "lora",
    "what_changed",
}
def record_final_dev_loss(losses: list[dict], step: int, loss: float) -> None:
    """Append the dev loss at the final step unless that step is already stored.

    A short run can finish before the first eval_steps checkpoint, which
    leaves dev_losses empty. The extra evaluation fills that gap.
    """
    step = int(step)
    if any(int(row["step"]) == step for row in losses):
        return
    losses.append({"step": step, "loss": float(loss)})


def sample_train_fraction(rows: list, fraction: float, seed: int) -> list:
    """Seeded subset. The count is round(fraction x rows). Same seed, same rows.

    Rows come back in their original order. The training seed still shuffles
    batches later, so this seed only chooses which records are in the subset.
    """
    n = len(rows)
    if n == 0:
        raise SystemExit("ablation: no train rows to sample")
    k = round(float(fraction) * n)
    if k < 1 or k > n:
        raise SystemExit(f"ablation: train_fraction {fraction} selects {k} of {n} rows")
    rng = random.Random(int(seed))
    order = list(range(n))
    rng.shuffle(order)
    chosen = sorted(order[:k])
    return [rows[i] for i in chosen]


def ablation_path(name: str) -> Path:
    path = ABLATION_DIR / f"{name}.yaml"
    if not path.is_file():
        raise SystemExit(f"ablation: no override file {path}")
    return path


def load_override(path: Path) -> dict:
    with path.open() as handle:
        doc = yaml.safe_load(handle)
    if not isinstance(doc, dict):
        raise SystemExit(f"ablation: {path} is not a mapping")
    return doc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def apply_override(base: dict, override: dict, path: Path) -> tuple[dict, dict]:
    """Return the merged training config and the override record for run.json."""
    unknown = sorted(set(override) - _OVERRIDE_KEYS)
    if unknown:
        raise SystemExit(f"ablation: {path.name} has unknown keys: {', '.join(unknown)}")
    if "run_tag" not in override or str(override["run_tag"]).strip() == "":
        raise SystemExit(f"ablation: {path.name} must set run_tag")
    if str(override["run_tag"]).strip() != path.stem:
        raise SystemExit(f"ablation: {path.name} run_tag must match the filename")
    what = override.get("what_changed")
    if not isinstance(what, str) or not what.strip():
        raise SystemExit(f"ablation: {path.name} must set what_changed")

    merged = copy.deepcopy(base)
    merged["run_tag"] = str(override["run_tag"]).strip()

    if "num_train_epochs" in override:
        epochs = override["num_train_epochs"]
        if isinstance(epochs, bool) or not isinstance(epochs, int) or epochs < 1:
            raise SystemExit(f"ablation: {path.name} num_train_epochs must be a positive integer")
        merged["num_train_epochs"] = epochs

    if "load_in_4bit" in override or "load_in_16bit" in override:
        if "load_in_4bit" not in override or "load_in_16bit" not in override:
            raise SystemExit(
                f"ablation: {path.name} must set load_in_4bit and load_in_16bit together"
            )
        bit4 = override["load_in_4bit"]
        bit16 = override["load_in_16bit"]
        if not isinstance(bit4, bool) or not isinstance(bit16, bool) or bit4 == bit16:
            raise SystemExit(
                f"ablation: {path.name} needs one of load_in_4bit and load_in_16bit true"
            )
        merged["load_in_4bit"] = bit4
        merged["load_in_16bit"] = bit16

    if "lora" in override:
        lora = override["lora"]
        if not isinstance(lora, dict):
            raise SystemExit(f"ablation: {path.name} lora must be a mapping")
        extra = sorted(set(lora) - {"r", "alpha"})
        if extra or "r" not in lora or "alpha" not in lora:
            raise SystemExit(f"ablation: {path.name} lora may set only r and alpha")
        for key in ("r", "alpha"):
            value = lora[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise SystemExit(f"ablation: {path.name} lora {key} must be a positive integer")
            merged["lora"][key] = value

    has_fraction = "train_fraction" in override
    has_seed = "fraction_seed" in override
    if has_fraction != has_seed:
        raise SystemExit(f"ablation: {path.name} needs train_fraction and fraction_seed together")
    if has_fraction:
        fraction = float(override["train_fraction"])
        seed = override["fraction_seed"]
        if not 0 < fraction <= 1:
            raise SystemExit(f"ablation: {path.name} train_fraction must be in (0, 1]")
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise SystemExit(f"ablation: {path.name} fraction_seed must be an integer")
        merged["train_fraction"] = fraction
        merged["fraction_seed"] = seed

    record = {
        "path": path.relative_to(REPO_ROOT).as_posix(),
        "sha256": _sha256(path),
        "what_changed": what.strip(),
    }
    return merged, record


def load_train_config(override: Path | None) -> tuple[dict, dict | None]:
    """Load configs/train.yaml, then apply an ablation file when one is given."""
    base_path = REPO_ROOT / "configs" / "train.yaml"
    with base_path.open() as handle:
        base = yaml.safe_load(handle)
    if override is None:
        return base, None
    path = override if override.is_file() else (REPO_ROOT / override)
    path = path.resolve()
    if path.parent != ABLATION_DIR.resolve() or path.suffix != ".yaml":
        raise SystemExit(f"ablation: --override must be a yaml file in {ABLATION_DIR}")
    return apply_override(base, load_override(path), path)
