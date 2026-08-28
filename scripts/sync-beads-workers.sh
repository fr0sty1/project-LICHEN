#!/bin/bash
# Sync all beads worker worktrees: commit locally, merge code to main
# Usage: ./scripts/sync-beads-workers.sh
#
# Safe to run while workers are active (they work on separate branches)

set -e

REPO_ROOT=$(git rev-parse --show-toplevel)
WORKTREE_BASE="/Volumes/Attic/Desktop/Projects/lichen-workers"

echo "=== Syncing Beads Workers ==="

# Commit in each worktree
for worktree in "$WORKTREE_BASE"/worker*/; do
    [ -d "$worktree" ] || continue
    name=$(basename "$worktree")

    cd "$worktree"

    # Check for changes
    if [ -z "$(git status --porcelain)" ]; then
        echo "$name: clean"
        continue
    fi

    # Count changes
    beads_count=$(git status --porcelain | grep -c '\.beads/' || true)
    code_count=$(git status --porcelain | grep -v '\.beads/' | grep -v '^??' | wc -l | tr -d ' ')

    echo "$name: $beads_count beads files, $code_count code files"

    # Stage and commit
    git add .beads/ 2>/dev/null || true
    git add -u  # stage modified tracked files

    if [ -n "$(git diff --cached --name-only)" ]; then
        git commit -m "chore(beads): $name sync - ${beads_count} beads, ${code_count} code changes"
        echo "$name: committed"
    fi
done

# Back to main repo
cd "$REPO_ROOT"

echo ""
echo "=== Merging code changes to main ==="

# Merge any worker branches with code changes
for i in 1 2 3 4 5; do
    branch="beads-worker-$i"

    # Check if branch exists and has commits ahead of main
    if ! git rev-parse --verify "$branch" >/dev/null 2>&1; then
        continue
    fi

    ahead=$(git rev-list main.."$branch" --count 2>/dev/null || echo 0)
    if [ "$ahead" -eq 0 ]; then
        continue
    fi

    echo "Merging $branch ($ahead commits ahead)..."

    if git merge "$branch" --no-edit 2>/dev/null; then
        echo "  merged successfully"
    else
        echo "  CONFLICT - resolve manually"
        git merge --abort 2>/dev/null || true
    fi
done

# Commit any remaining beads changes in main
if [ -n "$(git status --porcelain .beads/)" ]; then
    git add .beads/
    git commit -m "chore(beads): sync from workers"
    echo "Main: committed beads sync"
fi

echo ""
echo "=== Sync complete ==="
git status --short | head -10
