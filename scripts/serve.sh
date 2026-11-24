#!/usr/bin/env bash
# Serve an LLM with vLLM. DESIGN section 8 and Step 7 work order section C8.
# Runs on the GPU pod inside the .venv-serve environment.
#
# Defaults are read from configs/serve.yaml so the invocation stays short.
# Any --flag passed on the command line overrides the config.
#
# Usage:
#   scripts/serve.sh <model_path_or_hub_id> [options]
#
# Options:
#   --revision REV              pinned base revision (model is loaded at REV)
#   --port PORT                 TCP port (default from configs/serve.yaml)
#   --max-model-len N           server context length (default 8192)
#   --gpu-memory-utilization F  fraction (default 0.90)
#   --served-model-name NAME    name the client sends (default: the model id)
#   --max-num-seqs N            override configs/serve.yaml max_num_seqs
#
# Env vars:
#   VLLM_LOG   path for stdout/stderr (default /workspace/logs/vllm.log)
#   HF_HOME    hugging face cache (default /workspace/hf_cache)
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: scripts/serve.sh <model> [--revision ...] [--port ...] \\" >&2
    echo "       [--max-model-len ...] [--gpu-memory-utilization ...] [--served-model-name ...]" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CFG="$ROOT/configs/serve.yaml"

# Read defaults from configs/serve.yaml. Keep the parser small: one grep per
# key. Any value overridden by --flag below wins.
_yaml_get() {
    local key="$1"
    awk -v k="$key" 'BEGIN{FS=":[[:space:]]*"} $1==k {sub(/[[:space:]]*#.*$/,"",$2); gsub(/^"|"$/,"",$2); print $2; exit}' "$CFG"
}

MODEL="$1"; shift

PORT="$(_yaml_get port)"
MAX_MODEL_LEN="$(_yaml_get max_model_len)"
GPU_MEM_UTIL="$(_yaml_get gpu_memory_utilization)"
MAX_NUM_SEQS="$(_yaml_get max_num_seqs)"
HOST="$(_yaml_get host)"
REVISION=""
SERVED_NAME=""
ENFORCE_EAGER=0
NO_PREFIX_CACHING=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --revision)              REVISION="$2"; shift 2 ;;
        --port)                  PORT="$2"; shift 2 ;;
        --max-model-len)         MAX_MODEL_LEN="$2"; shift 2 ;;
        --gpu-memory-utilization) GPU_MEM_UTIL="$2"; shift 2 ;;
        --served-model-name)     SERVED_NAME="$2"; shift 2 ;;
        --max-num-seqs)          MAX_NUM_SEQS="$2"; shift 2 ;;
        # Determinism flags (pass-through to vllm).
        --enforce-eager)          ENFORCE_EAGER=1; shift ;;
        --no-enable-prefix-caching) NO_PREFIX_CACHING=1; shift ;;
        *) echo "serve.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done

: "${PORT:?port missing (configs/serve.yaml)}"
: "${MAX_MODEL_LEN:?max_model_len missing (configs/serve.yaml)}"
: "${GPU_MEM_UTIL:?gpu_memory_utilization missing (configs/serve.yaml)}"
: "${HOST:?host missing (configs/serve.yaml)}"
SERVED_NAME="${SERVED_NAME:-$MODEL}"

if [ ! -d "$MODEL" ] && [[ "$MODEL" != *"/"*"/"* ]] && [[ "$MODEL" != */* ]]; then
    echo "serve.sh: model path not found and not a hub id: $MODEL" >&2
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
CMD=(vllm serve "$MODEL"
    --host "$HOST"
    --port "$PORT"
    --dtype bfloat16
    --max-model-len "$MAX_MODEL_LEN"
    --gpu-memory-utilization "$GPU_MEM_UTIL"
    --max-num-seqs "$MAX_NUM_SEQS"
    --served-model-name "$SERVED_NAME"
)
if [ -n "$REVISION" ]; then
    CMD+=(--revision "$REVISION")
fi
if [ "$ENFORCE_EAGER" = "1" ]; then
    CMD+=(--enforce-eager)
fi
if [ "$NO_PREFIX_CACHING" = "1" ]; then
    CMD+=(--no-enable-prefix-caching)
fi

echo "[serve] starting: ${CMD[*]}" | tee -a "$LOG"
exec "${CMD[@]}" 2>&1 | tee -a "$LOG"
