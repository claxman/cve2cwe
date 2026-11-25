#!/usr/bin/env bash
# Pod-side launcher for the ablation runs. Called by
# scripts/pod.sh train-ablations <name> [name...]. Freezes a snapshot of
# the live repo into /workspace/run-<hash>/, then trains each override on
# seed 1 inside one detached tmux session. Stops on the first failure.
set -euo pipefail

HASH="${1:?usage: pod_train_ablations.sh <short-git-hash> <ablation> [ablation...]}"
shift
if [ "$#" -lt 1 ]; then
    echo "usage: pod_train_ablations.sh <short-git-hash> <ablation> [ablation...]" >&2
    exit 2
fi

LIVE=/workspace/cve2cwe
FROZEN=/workspace/run-$HASH
LOG_DIR=/workspace/logs
SESSION="cve2cwe-ablate-$HASH"

# Refuse to start while any other cve2cwe-* tmux session exists, because
# this script re-points the train venv's editable cve2cwe install at a new
# frozen tree and would corrupt a running run from the previous launch.
EXISTING=$(tmux ls 2>/dev/null | awk -F: '/^cve2cwe-/ {print $1}' || true)
if [ -n "$EXISTING" ]; then
    echo "pod_train_ablations: refusing to start; tmux session(s) still running:" >&2
    echo "$EXISTING" >&2
    exit 2
fi

mkdir -p "$LOG_DIR"

if [ ! -d "$FROZEN" ]; then
    mkdir -p "$FROZEN"
    rsync -a \
        --exclude '.venv*' \
        --exclude 'data/raw/' \
        --exclude 'checkpoints/' \
        --exclude 'wandb/' \
        --exclude 'outputs/' \
        --exclude '__pycache__/' \
        --exclude '.pytest_cache/' \
        --exclude '.ruff_cache/' \
        --exclude 'unsloth_compiled_cache/' \
        "$LIVE/" "$FROZEN/"
    # Reset the frozen tree to HEAD. The live tree's outputs/ and results/
    # are excluded from the Mac's push, so their pod-side copies drift from
    # the committed versions; checking out from .git restores every tracked
    # file so the clean check below passes.
    (cd "$FROZEN" && git checkout --quiet -- .)
    echo "pod_train_ablations: froze $LIVE -> $FROZEN"
else
    echo "pod_train_ablations: reusing existing $FROZEN"
fi

dirty=$(git -C "$FROZEN" status --porcelain)
if [ -n "$dirty" ]; then
    echo "pod_train_ablations: frozen tree $FROZEN is dirty after reset; aborting:" >&2
    echo "$dirty" >&2
    exit 2
fi

NAMES=()
for NAME in "$@"; do
    if [[ ! "$NAME" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
        echo "pod_train_ablations: bad override name: $NAME" >&2
        exit 2
    fi
    if [ ! -f "$FROZEN/configs/ablations/$NAME.yaml" ]; then
        echo "pod_train_ablations: missing $FROZEN/configs/ablations/$NAME.yaml" >&2
        exit 2
    fi
    NAMES+=("$NAME")
done

# shellcheck disable=SC1091
source /workspace/.venv-train/bin/activate
cd "$FROZEN"
uv pip install -e . --no-deps -q

RUNNER=$LOG_DIR/run_ablations_${HASH}.sh
{
    echo "#!/usr/bin/env bash"
    echo "set -o pipefail"
    echo "cd $FROZEN"
    echo "source /workspace/.venv-train/bin/activate"
    echo "export HF_HOME=/workspace/hf_cache"
    echo "export WANDB_PROJECT=cve2cwe"
    echo "export CVE2CWE_OUTPUT_DIR=/workspace/cve2cwe/outputs"
    echo "export CVE2CWE_CHECKPOINTS=/workspace/checkpoints"
    echo "if [ -f $LIVE/.env ]; then"
    echo "    set -a"
    echo "    . $LIVE/.env"
    echo "    set +a"
    echo "fi"
    for NAME in "${NAMES[@]}"; do
        cat <<SCRIPT
LOG=$LOG_DIR/ablation-${NAME}.log
echo "=== ${NAME} start \$(date -u +%FT%TZ) ===" | tee -a \$LOG
python -m cve2cwe train --seed 1 --override configs/ablations/${NAME}.yaml 2>&1 | tee -a \$LOG
rc=\${PIPESTATUS[0]}
echo "=== ${NAME} exit=\$rc ===" | tee -a \$LOG
if [ "\$rc" -ne 0 ]; then
    echo "stop on failure at ${NAME}" | tee -a \$LOG
    exit \$rc
fi
SCRIPT
    done
    echo "echo \"=== all ablations done \$(date -u +%FT%TZ) ===\" | tee -a $LOG_DIR/ablation-all.log"
} >"$RUNNER"
chmod +x "$RUNNER"

tmux new-session -d -s "$SESSION" -c "$FROZEN" "bash $RUNNER"
echo "pod_train_ablations: tmux session '$SESSION' detached. Attach with:"
echo "  tmux attach -t $SESSION"
echo "  tail -f $LOG_DIR/ablation-${NAMES[0]}.log"
