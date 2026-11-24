"""Shared prompt construction.

DESIGN section 3: every system uses the first ``max_description_chars``
characters of the CVE description. The cut and the chat-message build are
done here, once, so training, baseline LLMs, candidate inference and
frontier LLMs all see the same input.

DESIGN section 6 (Step 7): one builder for every LLM system.
``build_messages(system_name, description, examples=None, *, prompts,
systems, label=None)`` returns the chat messages for one record. The
``candidate`` prompt is byte-identical to what train.py and the shipped
checkpoint saw at training time; a golden test pins that string.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]

# System names recognised by build_messages. Everything else raises.
_KNOWN_SYSTEMS = ("candidate", "zero_shot", "few_shot", "retrieval")


def load_systems_cfg(path: Path | None = None) -> dict:
    path = path or (REPO_ROOT / "configs" / "systems.yaml")
    with path.open() as f:
        return yaml.safe_load(f)


def load_prompts_cfg(path: Path | None = None) -> dict:
    path = path or (REPO_ROOT / "configs" / "prompts.yaml")
    with path.open() as f:
        return yaml.safe_load(f)


def load_labels(path: Path | None = None) -> list[dict]:
    """Return labels.json entries in file order."""
    path = path or (REPO_ROOT / "data" / "processed" / "labels.json")
    with path.open() as f:
        return json.load(f)


def cut_description(description: str, max_chars: int) -> str:
    """Apply the N-character input cut (DESIGN section 3).

    Returns the first ``max_chars`` characters of ``description``. The cut is
    on characters, not bytes or tokens, to match the design rule exactly.
    """
    if max_chars <= 0:
        return ""
    return description[:max_chars]


def _user_text(description: str, prompts: dict, systems: dict) -> str:
    """Render the user turn text for one description.

    Uses ``prompts["candidate"]["user_template"]``; baseline systems reuse
    the same template per the Step 7 work order. The description is cut
    first so every system (candidate, baselines, Claude) sees the same
    input length.
    """
    max_chars = int(systems["max_description_chars"])
    desc = cut_description(description, max_chars)
    template = prompts["candidate"]["user_template"]
    return template.format(description=desc).rstrip()


def build_baseline_system_text(prompts: dict, labels: list[dict] | None = None) -> str:
    """Return the baseline system prompt: header + blank line + label list.

    Label list is one line per label from labels.json, in the file's order,
    formatted as ``"CWE-79: <name>"``.
    """
    labels = labels if labels is not None else load_labels()
    header = prompts["baseline"]["system_header"].rstrip()
    lines = [f"{lab['id']}: {lab['name']}" for lab in labels]
    return header + "\n\n" + "\n".join(lines)


def build_messages(
    system_name: str,
    description: str,
    examples: list[dict] | None = None,
    *,
    prompts: dict,
    systems: dict,
    labels: list[dict] | None = None,
    label: str | None = None,
) -> list[dict]:
    """Chat messages for one record under ``system_name``.

    ``examples`` is a list of dicts with ``description`` and ``label`` keys,
    used only by ``few_shot`` and ``retrieval``. Example descriptions are
    inserted verbatim (they are expected to be pre-cut by the caller to the
    system's per-example limit; this keeps the cut rule in one place).

    ``label`` appends an assistant turn and is only used for training the
    candidate.
    """
    if system_name not in _KNOWN_SYSTEMS:
        raise ValueError(
            f"unknown system_name: {system_name!r}; expected one of {_KNOWN_SYSTEMS}"
        )
    if system_name == "candidate":
        system_text = prompts["candidate"]["system"].rstrip()
    else:
        system_text = build_baseline_system_text(prompts, labels)

    msgs: list[dict[str, Any]] = [{"role": "system", "content": system_text}]

    if system_name in ("few_shot", "retrieval"):
        for ex in examples or []:
            msgs.append(
                {"role": "user", "content": _user_text(ex["description"], prompts, systems)}
            )
            msgs.append({"role": "assistant", "content": ex["label"]})

    msgs.append({"role": "user", "content": _user_text(description, prompts, systems)})

    if label is not None:
        if system_name != "candidate":
            raise ValueError("label is only recorded for the candidate system")
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
    """Candidate inference prompt. train.py calls this during its own
    end-to-end sanity print; llm_eval uses the chat template on the server
    side with the same messages."""
    msgs = build_messages(
        "candidate", description, prompts=prompts, systems=systems
    )
    return _apply_chat_template_no_think(
        tokenizer, msgs, tokenize=False, add_generation_prompt=True
    )


def render_training_text(
    tokenizer, description: str, label: str, prompts: dict, systems: dict
) -> str:
    """Candidate training text. train.py uses this to build the dataset."""
    msgs = build_messages(
        "candidate", description, prompts=prompts, systems=systems, label=label
    )
    return _apply_chat_template_no_think(
        tokenizer, msgs, tokenize=False, add_generation_prompt=False
    )


__all__ = [
    "REPO_ROOT",
    "load_systems_cfg",
    "load_prompts_cfg",
    "load_labels",
    "cut_description",
    "build_baseline_system_text",
    "build_messages",
    "render_inference_prompt",
    "render_training_text",
]
