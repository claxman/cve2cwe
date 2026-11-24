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
RUNNER=$LOG_DIR/run_seeds_${HASH}.sh

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
        "$LIVE/" "$FROZEN/"
    echo "pod_train_seeds: froze $LIVE -> $FROZEN"
else
    echo "pod_train_seeds: reusing existing $FROZEN"
fi

# Re-install the editable package so `python -m cve2cwe` resolves to the
# frozen tree, not the live one.
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
    echo "=== seed\${SEED} start \$(date -u +%FT%TZ) ===" | tee -a $LOG_DIR/seed\${SEED}.log
    python -m cve2cwe train --seed \$SEED 2>&1 | tee -a $LOG_DIR/seed\${SEED}.log
    rc=\${PIPESTATUS[0]}
    echo "=== seed\${SEED} exit=\$rc ===" | tee -a $LOG_DIR/seed\${SEED}.log
    if [ "\$rc" -ne 0 ]; then
        echo "stop on failure at seed\${SEED}" | tee -a $LOG_DIR/seed\${SEED}.log
        exit \$rc
    fi
done
echo "=== all seeds done \$(date -u +%FT%TZ) ===" | tee -a $LOG_DIR/all.log
SCRIPT
chmod +x "$RUNNER"

# Fail fast if a stale session from a previous run is still live.
if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "pod_train_seeds: tmux session $SESSION already exists (attach with 'tmux attach -t $SESSION')" >&2
    exit 2
fi

tmux new-session -d -s "$SESSION" -c "$FROZEN" "bash $RUNNER"
echo "pod_train_seeds: tmux session '$SESSION' detached. Attach with:"
echo "  tmux attach -t $SESSION"
echo "  tail -f $LOG_DIR/seed1.log"
