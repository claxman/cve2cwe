#!/usr/bin/env bash
# Serve a merged bf16 checkpoint with vLLM. Section 8 of docs/DESIGN.md.
# Runs on the GPU pod inside the .venv-serve environment.
#
# Usage:
#   scripts/serve.sh <model_dir> [port]
# Defaults:
#   port=8000
#
# Env vars:
#   VLLM_LOG   path for stdout/stderr (default /workspace/logs/vllm.log)
#   HF_HOME    hugging face cache (default /workspace/hf_cache)
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: scripts/serve.sh <model_dir> [port]" >&2
    exit 2
fi
MODEL="$1"
PORT="${2:-8000}"

if [ ! -d "$MODEL" ] && [[ "$MODEL" != *"/"*"/"* ]]; then
    # Allow HF repo id like Qwen/Qwen3.5-4B too; just not a local path that is
    # missing.
    echo "serve.sh: model dir not found: $MODEL" >&2
    exit 2
fi

export HF_HOME="${HF_HOME:-/workspace/hf_cache}"
VENV="${VLLM_VENV:-/workspace/.venv-serve}"
LOG="${VLLM_LOG:-/workspace/logs/vllm.log}"
mkdir -p "$(dirname "$LOG")"

# shellcheck disable=SC1091
source "$VENV/bin/activate"

# Thinking is disabled through the chat template at call time; the server
# accepts `extra_body={"chat_template_kwargs": {"enable_thinking": false}}`.
# Temperature 0, max 8 new tokens, logprobs are set on the client side.
echo "[serve] starting vllm on :$PORT serving $MODEL" | tee -a "$LOG"
exec vllm serve "$MODEL" \
    --host 0.0.0.0 \
    --port "$PORT" \
    --dtype bfloat16 \
    --max-model-len 4096 \
    --max-num-seqs 32 2>&1 | tee -a "$LOG"
