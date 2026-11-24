#!/usr/bin/env bash
# Pod-side launcher for the three training seeds. Called by
# scripts/pod.sh train-seeds <short-commit>. Freezes a snapshot of the live
# repo into /workspace/run-<hash>/ so later pushes cannot change the code
# under seeds 2 and 3, then runs seeds 1, 2, 3 sequentially inside one
# detached tmux session. Stops on the first failure.
set -euo pipefail

HASH="${1:?usage: pod_train_seeds.sh <short-git-hash>}"
LIVE=/workspace/cve2cwe
FROZEN=/workspace/run-$HASH
LOG_DIR=/workspace/logs
SESSION="cve2cwe-$HASH"

# Refuse to start while any other cve2cwe-* tmux session exists, because
# this script re-points the train venv's editable cve2cwe install at a new
# frozen tree and would corrupt a running run from the previous launch.
EXISTING=$(tmux ls 2>/dev/null | awk -F: '/^cve2cwe-/ {print $1}' || true)
if [ -n "$EXISTING" ]; then
    echo "pod_train_seeds: refusing to start; tmux session(s) still running:" >&2
    echo "$EXISTING" >&2
    exit 2
fi

mkdir -p "$LOG_DIR"

# Freeze the live tree (which was just pushed from the Mac) into a
# hash-stamped directory. If the directory already exists for this hash,
# we trust it; a new hash means a new commit means a fresh snapshot.
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
    echo "pod_train_seeds: froze $LIVE -> $FROZEN"
else
    echo "pod_train_seeds: reusing existing $FROZEN"
fi

# Confirm the frozen tree is clean before launching anything. porcelain
# catches untracked source files too; .gitignore keeps the unsloth build
# cache out of this check.
dirty=$(git -C "$FROZEN" status --porcelain)
if [ -n "$dirty" ]; then
    echo "pod_train_seeds: frozen tree $FROZEN is dirty after reset; aborting:" >&2
    echo "$dirty" >&2
    exit 2
fi

# Read the run tag from the frozen config so log, checkpoint and outputs
# names match train.py's run_name. Empty tag -> no prefix.
TAG=$(python3 -c "import yaml,sys; c=yaml.safe_load(open('$FROZEN/configs/train.yaml')); t=c.get('run_tag') or ''; sys.stdout.write(str(t).strip())" || true)
if [ -n "$TAG" ]; then
    NAME_PREFIX="${TAG}-"
    ALL_LOG=$LOG_DIR/${TAG}-all.log
else
    NAME_PREFIX=""
    ALL_LOG=$LOG_DIR/all.log
fi
RUNNER=$LOG_DIR/run_seeds_${NAME_PREFIX}${HASH}.sh

# Re-install the editable package so `python -m cve2cwe` resolves to the
# frozen tree, not the live one. This is the single pip/uv call the user
# allows while a train loop is live.
# shellcheck disable=SC1091
source /workspace/.venv-train/bin/activate
cd "$FROZEN"
uv pip install -e . --no-deps -q

# Compose the runner as a file, so tmux does not have to carry nested
# quotes. The runner is what actually starts training inside tmux.
cat >"$RUNNER" <<SCRIPT
#!/usr/bin/env bash
set -o pipefail
cd $FROZEN
source /workspace/.venv-train/bin/activate
export HF_HOME=/workspace/hf_cache
export WANDB_PROJECT=cve2cwe
# Outputs go to the live repo dir so scripts/pod.sh pull (which syncs
# /workspace/cve2cwe/outputs/) can round-trip them to the Mac.
export CVE2CWE_OUTPUT_DIR=/workspace/cve2cwe/outputs
export CVE2CWE_CHECKPOINTS=/workspace/checkpoints
if [ -f $LIVE/.env ]; then
    set -a
    . $LIVE/.env
    set +a
fi
for SEED in 1 2 3; do
    LOG=$LOG_DIR/${NAME_PREFIX}seed\${SEED}.log
    echo "=== ${NAME_PREFIX}seed\${SEED} start \$(date -u +%FT%TZ) ===" | tee -a \$LOG
    python -m cve2cwe train --seed \$SEED 2>&1 | tee -a \$LOG
    rc=\${PIPESTATUS[0]}
    echo "=== ${NAME_PREFIX}seed\${SEED} exit=\$rc ===" | tee -a \$LOG
    if [ "\$rc" -ne 0 ]; then
        echo "stop on failure at ${NAME_PREFIX}seed\${SEED}" | tee -a \$LOG
        exit \$rc
    fi
done
echo "=== all seeds done \$(date -u +%FT%TZ) ===" | tee -a $ALL_LOG
SCRIPT
chmod +x "$RUNNER"

tmux new-session -d -s "$SESSION" -c "$FROZEN" "bash $RUNNER"
echo "pod_train_seeds: tmux session '$SESSION' detached. Attach with:"
echo "  tmux attach -t $SESSION"
echo "  tail -f $LOG_DIR/${NAME_PREFIX}seed1.log"
