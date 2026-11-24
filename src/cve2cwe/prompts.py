"""Shared prompt construction.

DESIGN section 3: every system uses the first 2,000 characters of the CVE
description. One function cuts and builds the chat messages, so training and
inference see the same input. Both src/cve2cwe/train.py and
src/cve2cwe/llm_eval.py call `build_messages` here; they must not re-roll
their own prompt rendering.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_systems_cfg(path: Path | None = None) -> dict:
    path = path or (REPO_ROOT / "configs" / "systems.yaml")
    with path.open() as f:
        return yaml.safe_load(f)


def load_prompts_cfg(path: Path | None = None) -> dict:
    path = path or (REPO_ROOT / "configs" / "prompts.yaml")
    with path.open() as f:
        return yaml.safe_load(f)


def cut_description(description: str, max_chars: int) -> str:
    """Apply the N-character input cut (DESIGN section 3).

    Returns the first ``max_chars`` characters of ``description``. The cut is
    on characters, not bytes or tokens, to match the design rule exactly.
    """
    if max_chars <= 0:
        return ""
    return description[:max_chars]


def build_messages(
    description: str,
    prompts: dict,
    systems: dict,
    label: str | None = None,
) -> list[dict]:
    """Return chat messages for one record.

    The description is first cut to ``systems["max_description_chars"]``,
    then formatted into the candidate user template. If ``label`` is given,
    the assistant turn is appended (training). If not, only system + user is
    returned (inference).
    """
    max_chars = int(systems["max_description_chars"])
    desc = cut_description(description, max_chars)
    system = prompts["candidate"]["system"].rstrip()
    user = prompts["candidate"]["user_template"].format(description=desc).rstrip()
    msgs: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    if label is not None:
        msgs.append({"role": "assistant", "content": label})
    return msgs


def _apply_chat_template_no_think(tokenizer, msgs: list[dict], **kwargs) -> str:
    """Apply the chat template with reasoning disabled.

    Qwen3 and Qwen3.5 templates accept ``enable_thinking=False``; older
    templates do not, in which case we fall back to the default call.
    """
    try:
        return tokenizer.apply_chat_template(msgs, enable_thinking=False, **kwargs)
    except TypeError:
        return tokenizer.apply_chat_template(msgs, **kwargs)


def render_inference_prompt(
    tokenizer, description: str, prompts: dict, systems: dict
) -> str:
    msgs = build_messages(description, prompts, systems)
    return _apply_chat_template_no_think(
        tokenizer, msgs, tokenize=False, add_generation_prompt=True
    )


def render_training_text(
    tokenizer, description: str, label: str, prompts: dict, systems: dict
) -> str:
    msgs = build_messages(description, prompts, systems, label=label)
    return _apply_chat_template_no_think(
        tokenizer, msgs, tokenize=False, add_generation_prompt=False
    )
