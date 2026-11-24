#!/usr/bin/env bash
# Drive the GPU pod from this machine. One source of truth is the code here.
# Reads the pod address from .pod (gitignored). Use `uv pip install` on the
# pod; the venvs are created by `uv venv` and do not ship their own pip.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
POD_FILE="$ROOT/.pod"
if [ ! -f "$POD_FILE" ]; then
    echo "pod.sh: $POD_FILE is missing. Create it from the work order." >&2
    exit 2
fi
# shellcheck disable=SC1090
. "$POD_FILE"

: "${SSH_HOST:?SSH_HOST not set in .pod}"
: "${SSH_PORT:?SSH_PORT not set in .pod}"
: "${SSH_USER:?SSH_USER not set in .pod}"
: "${SSH_KEY:?SSH_KEY not set in .pod}"
: "${REPO_REMOTE:?REPO_REMOTE not set in .pod}"

# Expand ~ in SSH_KEY.
SSH_KEY_EXPANDED="${SSH_KEY/#\~/$HOME}"

SSH_CMD=(ssh -p "$SSH_PORT" -i "$SSH_KEY_EXPANDED" -o StrictHostKeyChecking=accept-new "${SSH_USER}@${SSH_HOST}")
RSYNC_SSH="ssh -p $SSH_PORT -i $SSH_KEY_EXPANDED -o StrictHostKeyChecking=accept-new"

usage() {
    cat <<'EOF'
Usage:
  scripts/pod.sh push              Sync this repo to the pod (keeps .git; skips .venv*, data/raw, checkpoints, wandb).
  scripts/pod.sh run  <cmd ...>    Run a command on the pod inside the repo.
  scripts/pod.sh pull              Sync outputs/, results/ and requirements/*.txt back here.
  scripts/pod.sh ssh               Open an interactive shell on the pod.
  scripts/pod.sh train-seeds       Freeze the committed tree into /workspace/run-<short hash>/ and
                                   launch seeds 1,2,3 sequentially in a detached tmux session
                                   (stops on first failure).
EOF
}

cmd="${1-}"
shift || true

case "$cmd" in
    push)
        "${SSH_CMD[@]}" "mkdir -p '$REPO_REMOTE'"
        # outputs/ and results/ are produced on the pod; exclude them from the
        # mirror so --delete does not wipe pod-side artefacts.
        rsync -rltz --delete --no-owner --no-group --no-perms \
            -e "$RSYNC_SSH" \
            --exclude '.venv*' \
            --exclude 'data/raw/' \
            --exclude 'checkpoints/' \
            --exclude 'wandb/' \
            --exclude 'outputs/' \
            --exclude 'results/' \
            --exclude '__pycache__/' \
            --exclude '.pytest_cache/' \
            --exclude '.ruff_cache/' \
            --exclude '.DS_Store' \
            --exclude '*.egg-info/' \
            "$ROOT/" "${SSH_USER}@${SSH_HOST}:${REPO_REMOTE}/"
        ;;
    pull)
        rsync -rltz --no-owner --no-group --no-perms -e "$RSYNC_SSH" \
            "${SSH_USER}@${SSH_HOST}:${REPO_REMOTE}/outputs/" "$ROOT/outputs/" 2>/dev/null || true
        rsync -rltz --no-owner --no-group --no-perms -e "$RSYNC_SSH" \
            "${SSH_USER}@${SSH_HOST}:${REPO_REMOTE}/results/" "$ROOT/results/" 2>/dev/null || true
        rsync -rltz --no-owner --no-group --no-perms -e "$RSYNC_SSH" \
            --include='*.txt' --exclude='*' \
            "${SSH_USER}@${SSH_HOST}:${REPO_REMOTE}/requirements/" "$ROOT/requirements/" 2>/dev/null || true
        ;;
    run)
        if [ "$#" -eq 0 ]; then
            echo "pod.sh run: needs a command" >&2
            exit 2
        fi
        # Join args preserving spaces.
        remote=""
        for a in "$@"; do
            remote+=$(printf ' %q' "$a")
        done
        "${SSH_CMD[@]}" "cd '$REPO_REMOTE' && bash -lc${remote}"
        ;;
    ssh)
        "${SSH_CMD[@]}"
        ;;
    train-seeds)
        # Must run from a clean committed tree so the pod's frozen copy
        # corresponds to a published commit. Fail fast otherwise.
        if ! git -C "$ROOT" diff-index --quiet HEAD --; then
            echo "pod.sh: working tree is dirty. Commit before launching training." >&2
            exit 2
        fi
        HASH=$(git -C "$ROOT" rev-parse --short HEAD)
        echo "pod.sh: launching training for commit $HASH"
        "${SSH_CMD[@]}" "bash /workspace/cve2cwe/scripts/pod_train_seeds.sh '$HASH'"
        ;;
    -h|--help|help|"")
        usage
        ;;
    *)
        echo "pod.sh: unknown subcommand: $cmd" >&2
        usage
        exit 2
        ;;
esac
