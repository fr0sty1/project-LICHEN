#!/bin/bash
# Launch parallel opencode workers for beads processing
# Usage: ./scripts/launch-beads-workers.sh [num_workers]
#
# IMPORTANT: Workers accumulate uncommitted changes. Run periodically:
#   ./scripts/sync-beads-workers.sh   # commits in all worktrees, merges to main
#
# Or kill + cleanup:
#   pkill -f 'opencode.*worker'
#   ./scripts/sync-beads-workers.sh

set -e

NUM_WORKERS=${1:-5}
REPO_ROOT=$(git rev-parse --show-toplevel)
PROMPT_FILE="$REPO_ROOT/scripts/beads-worker-prompt.txt"
WORKTREE_BASE="/Volumes/Attic/Desktop/Projects/lichen-workers"

echo "=== Beads Worker Launcher ==="
echo "Workers: $NUM_WORKERS"
echo "Repo: $REPO_ROOT"
echo ""

# Check prerequisites
command -v opencode >/dev/null 2>&1 || { echo "opencode not found"; exit 1; }
command -v bd >/dev/null 2>&1 || { echo "bd (beads) not found"; exit 1; }

# Show current bead status
echo "=== Current Beads Status ==="
bd list --json 2>/dev/null | jq -r 'group_by(.status) | .[] | "\(.[0].status): \(length)"'
echo ""

# Create worktrees and launch workers
echo "=== Launching Workers ==="
mkdir -p "$WORKTREE_BASE"

for i in $(seq 1 $NUM_WORKERS); do
    WORKTREE="$WORKTREE_BASE/worker$i"
    BRANCH="beads-worker-$i"

    # Create worktree if it doesn't exist
    if [ ! -d "$WORKTREE" ]; then
        echo "Creating worktree: $WORKTREE"
        git worktree add "$WORKTREE" -b "$BRANCH" HEAD 2>/dev/null || \
        git worktree add "$WORKTREE" "$BRANCH" 2>/dev/null || \
        { echo "Failed to create worktree $i"; continue; }
    fi

    # Launch opencode in background with auto-approve
    echo "Launching worker $i in $WORKTREE"
    (
        cd "$WORKTREE"
        export BEADS_AGENT_ACTOR="opencode-worker-$i"
        opencode run --auto --dir "$WORKTREE" "$(cat "$PROMPT_FILE")" 2>&1 | tee "$WORKTREE/worker.log"
    ) &

    # Small delay to stagger startup
    sleep 2
done

echo ""
echo "=== $NUM_WORKERS workers launched ==="
echo "Logs: $WORKTREE_BASE/worker*/worker.log"
echo ""
echo "Monitor with: tail -f $WORKTREE_BASE/worker*/worker.log"
echo "Stop all: pkill -f 'opencode.*beads-worker'"
echo ""
echo "Press Ctrl+C to detach (workers continue in background)"

# Wait for all background jobs
wait
