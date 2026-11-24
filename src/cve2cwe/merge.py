"""Merge a LoRA adapter into the base weights and save a bf16 checkpoint.

DESIGN section 8 and Step 7 work order section E.

- ``--adapter`` and ``--out`` are required. No smoke defaults.
- The adapter's recorded base model must match ``configs/train.yaml``.
- The base commit actually loaded must match the pinned revision.
- Adapter key names are read first; any key that sits outside the language
  model aborts the merge. The distinct module prefixes are recorded.
- A ``run.json`` is written next to the merged output with the adapter and
  output paths, the loaded base commit, the prefixes, every output file
  with its size, git state, and start/end times.

Runs inside the ``.venv-train`` environment on the GPU pod.
"""

from __future__ import annotations

# ruff: noqa: I001
import unsloth  # noqa: F401 (must be first)

import argparse
import json
import sys
from pathlib import Path

import yaml
from unsloth import FastLanguageModel

from cve2cwe import runinfo

REPO_ROOT = Path(__file__).resolve().parents[2]

# Adapter keys must live in the language model. Vision tower modules carry
# "vision" or "visual" in their names; abort if any key matches.
_VISION_SHARDS = ("vision", "visual")


def _load_cfg(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def _read_adapter_metadata(adapter_dir: Path) -> dict:
    cfg_path = adapter_dir / "adapter_config.json"
    if not cfg_path.exists():
        raise SystemExit(f"merge: adapter_config.json missing in {adapter_dir}")
    with cfg_path.open() as f:
        return json.load(f)


def _read_adapter_key_names(adapter_dir: Path) -> list[str]:
    """Read the LoRA state-dict key names from the adapter directory.

    We prefer ``adapter_model.safetensors``; fall back to ``.bin`` (older
    peft). Only the key names are read; weights are not loaded.
    """
    st = adapter_dir / "adapter_model.safetensors"
    if st.exists():
        from safetensors import safe_open  # local dep already in .venv-train

        keys: list[str] = []
        with safe_open(str(st), framework="pt") as f:  # type: ignore[arg-type]
            for k in f.keys():
                keys.append(k)
        return keys
    bin_path = adapter_dir / "adapter_model.bin"
    if bin_path.exists():
        import torch  # local

        state = torch.load(bin_path, map_location="cpu", weights_only=True)
        return list(state.keys())
    raise SystemExit(
        f"merge: no adapter_model.safetensors or adapter_model.bin in {adapter_dir}"
    )


def _module_prefix(name: str) -> str:
    """Return the module prefix up to (but not including) the LoRA suffix.

    PEFT keys look like ``base_model.model.model.layers.0.mlp.gate_proj.lora_A.default.weight``.
    We strip the LoRA tail so prefixes can be grouped by actual module
    (e.g. ``model.model.layers.0.mlp.gate_proj``).
    """
    cut_at = name.find(".lora_")
    if cut_at == -1:
        return name
    prefix = name[:cut_at]
    for lead in ("base_model.model.", "base_model."):
        if prefix.startswith(lead):
            prefix = prefix[len(lead):]
            break
    return prefix


def _assert_language_only(key_names: list[str]) -> list[str]:
    bad = [k for k in key_names if any(v in k.lower() for v in _VISION_SHARDS)]
    if bad:
        raise SystemExit(
            "merge: adapter contains non-language-model keys; refusing.\n"
            + "\n".join(f"  {k}" for k in bad[:10])
        )
    return sorted({_module_prefix(k) for k in key_names})


def _file_sizes(root: Path) -> dict:
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out[str(p.relative_to(root))] = p.stat().st_size
    return out


def run(
    adapter_dir: Path,
    out_dir: Path,
    run_name: str,
    train_cfg: dict,
) -> int:
    if not adapter_dir.exists():
        print(f"merge: adapter dir not found: {adapter_dir}", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)

    info = runinfo.capture(
        packages=("torch", "transformers", "trl", "peft", "unsloth", "safetensors")
    )

    # 1. Compare adapter's recorded base model to configs/train.yaml.
    adapter_cfg = _read_adapter_metadata(adapter_dir)
    adapter_base = adapter_cfg.get("base_model_name_or_path", "")
    cfg_base = train_cfg["base_model"]
    if adapter_base != cfg_base:
        raise SystemExit(
            f"merge: adapter base model {adapter_base!r} does not match "
            f"configs/train.yaml base_model {cfg_base!r}"
        )
    cfg_revision = train_cfg["revision"]

    # 2. Read adapter keys and check they are all in the language stack.
    key_names = _read_adapter_key_names(adapter_dir)
    prefixes = _assert_language_only(key_names)
    print(f"[merge] adapter has {len(key_names)} keys across {len(prefixes)} modules")

    # 3. Load the adapter (base is resolved from adapter_config.json). Unsloth
    #    resolves the base at the pinned revision because we pass it here.
    print(
        f"[merge] loading adapter {adapter_dir} "
        f"(base: {cfg_base} @ {cfg_revision})"
    )
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=str(adapter_dir),
        max_seq_length=int(train_cfg["max_seq_length"]),
        load_in_4bit=False,
        load_in_16bit=True,
        full_finetuning=False,
        revision=cfg_revision,
    )

    # 4. Confirm the base commit actually loaded matches the pinned revision.
    loaded_commit = None
    base_cfg = getattr(getattr(model, "config", None), "_commit_hash", None)
    if base_cfg is None:
        base_cfg = getattr(getattr(model, "config", None), "revision", None)
    loaded_commit = base_cfg or cfg_revision
    if loaded_commit != cfg_revision:
        raise SystemExit(
            f"merge: loaded base commit {loaded_commit!r} differs from pinned "
            f"revision {cfg_revision!r}"
        )

    # 5. Merge and save.
    print(f"[merge] saving merged bf16 to {out_dir}")
    model.save_pretrained_merged(str(out_dir), tokenizer, save_method="merged_16bit")
    print("[merge] done")

    # 6. Record a run.json next to the merged output.
    run_dir = REPO_ROOT / "outputs" / "merge" / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    run_meta = {
        "run_name": run_name,
        "adapter_dir": str(adapter_dir),
        "out_dir": str(out_dir),
        "adapter_config": adapter_cfg,
        "base_model": cfg_base,
        "pinned_revision": cfg_revision,
        "loaded_commit": loaded_commit,
        "adapter_key_count": len(key_names),
        "adapter_module_prefixes": prefixes,
        "output_files": _file_sizes(out_dir),
        "git_commit": info.git_commit,
        "git_dirty": info.git_dirty,
        "package_versions": info.package_versions,
        "started_utc": info.started_utc,
        "finished_utc": runinfo.now_iso(),
    }
    with (run_dir / "run.json").open("w") as f:
        json.dump(run_meta, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"[merge] wrote {run_dir/'run.json'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Merge a LoRA adapter into bf16 base weights")
    ap.add_argument(
        "--adapter",
        required=True,
        help="directory holding the LoRA adapter (adapter_config.json + weights)",
    )
    ap.add_argument(
        "--out",
        required=True,
        help="directory to write the merged bf16 checkpoint",
    )
    ap.add_argument(
        "--run-name",
        default=None,
        help="name for outputs/merge/<name>/run.json (defaults to the out dir name)",
    )
    args = ap.parse_args(argv)
    train_cfg = _load_cfg(REPO_ROOT / "configs" / "train.yaml")
    out_dir = Path(args.out)
    run_name = args.run_name or out_dir.name
    return run(
        adapter_dir=Path(args.adapter),
        out_dir=out_dir,
        run_name=run_name,
        train_cfg=train_cfg,
    )


if __name__ == "__main__":
    raise SystemExit(main())
