#!/bin/bash
# Launch Claude Squad with opencode for beads processing
# This gives you an interactive TUI to manage multiple opencode instances

REPO_ROOT=$(git rev-parse --show-toplevel)
PROMPT_FILE="$REPO_ROOT/scripts/beads-worker-prompt.txt"

echo "=== Claude Squad + OpenCode ==="
echo ""
echo "Starting Claude Squad with opencode as the agent..."
echo ""
echo "In the TUI:"
echo "  n     - New instance (creates worktree + launches opencode)"
echo "  Enter - Attach to selected instance"
echo "  d     - Detach from instance"
echo "  x     - Kill instance"
echo "  q     - Quit (instances keep running)"
echo ""
echo "Each instance will run this prompt:"
echo "---"
head -10 "$PROMPT_FILE"
echo "..."
echo "---"
echo ""

# Launch Claude Squad with opencode (--auto for no permission prompts)
cd "$REPO_ROOT"
claude-squad -p "opencode --auto \"$(cat "$PROMPT_FILE")\""
