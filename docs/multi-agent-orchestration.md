# Multi-Agent Orchestration on EC2

## TL;DR (30 seconds)

Run 10+ AI coding agents in parallel on an EC2 instance to burn through a large backlog of issues. Each agent runs in its own git worktree to avoid conflicts. A shepherd script keeps them fed with work. A sync loop pushes to GitHub every 15 minutes.

**Cost:** ~$0.40/issue (x.ai Grok) + ~$0.50/hr (EC2 c8g.4xlarge)  
**Speed:** ~15 issues/hour with 7 workers  
**Setup time:** ~30 minutes

---

## Overview (5 minutes)

### The Problem

You have hundreds of issues (beads) to work through. A single AI agent working linearly would take weeks. You want to parallelize.

### The Solution

1. **EC2 instance** with enough CPU/RAM for multiple processes
2. **Multiple git worktrees** so agents don't conflict on file writes
3. **tmux session** with one window per agent
4. **opencode** (or similar coding agent) in each window
5. **Shepherd script** that detects idle agents and prompts them
6. **Sync script** that pushes to GitHub periodically

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  EC2 Instance (c8g.4xlarge: 16 vCPU, 32GB RAM)              │
│                                                             │
│  tmux session "lichen"                                      │
│  ├── window 0: opencode (worker)     ─┐                     │
│  ├── window 1: opencode (worker2)     │ 7 workers           │
│  ├── window 2: opencode (worker3)     │ doing issues        │
│  ├── window 3: opencode (worker4)     │ + 3x self-review    │
│  ├── window 4: opencode (worker5)     │ before closing      │
│  ├── window 5: opencode (worker6)     │                     │
│  ├── window 6: opencode (worker7)    ─┘                     │
│  ├── window 7: opencode (reviewer)   ← external 3x review   │
│  ├── window 8: opencode (ccp-beader) ← breaks down specs    │
│  ├── window 9: shepherd script       ← keeps workers fed    │
│  └── window 10: sync loop            ← pushes to GitHub     │
│                                                             │
│  /mnt/lichen-zephyr/work/                                   │
│  ├── project-LICHEN/           (main worktree)              │
│  ├── project-LICHEN-worker2/   (worktree on worker2 branch) │
│  ├── project-LICHEN-worker3/   (worktree on worker3 branch) │
│  └── ...                                                    │
└─────────────────────────────────────────────────────────────┘
          │
          │ git push (every 15 min)
          ▼
┌─────────────────────┐
│  GitHub Repository  │
└─────────────────────┘
```

### Key Scripts

| Script | Purpose |
|--------|---------|
| `opencode-shepherd.sh` | Polls tmux windows, prompts idle agents with work |
| `sync loop` | Pushes to GitHub every 15 minutes |
| `xai-balance.sh` | Checks x.ai billing/spend |

### Quality Enforcement: Two-Layer Code Review

Code review happens at **two levels** — both are mandatory:

1. **Self-review by the worker** (3x before closing any bead)
2. **External review by a dedicated reviewer agent** (catches what self-review misses)

This is defense-in-depth. Self-review catches obvious issues while context is fresh. External review catches blind spots, style drift, and "it works on my machine" assumptions.

#### Layer 1: Worker Self-Review (3x)

**The rule (baked into AGENTS.md and shepherd prompts):**
```
MANDATORY: After every logical chunk of code, run /codereview 3 times.
File all findings as beads (tagged codereview).
Do not close the bead until reviews done.
```

Workers review their own code before marking a bead complete. Three passes because:
- Single review catches ~60% of issues
- Two independent reviews catch ~85%
- Three catches ~95% (diminishing returns after that)
- Independent = each pass starts fresh, no "I agree with pass 1"

#### Layer 2: Dedicated Reviewer Agent

A separate `reviewer` agent reviews ALL commits systematically, independent of which worker wrote them. This catches:

- Issues the original worker was blind to (same context = same blind spots)
- Cross-worker inconsistencies (worker A does it one way, worker B another)
- Style drift across the codebase
- Security issues that require stepping back from implementation focus

The reviewer also runs 3x passes per commit — so total review coverage is 6x (3 self + 3 external).

```bash
tmux new-window -t lichen -n reviewer -c /path/to/project
tmux send-keys -t lichen:reviewer 'export XAI_API_KEY="..." && opencode' Enter

# Give it review-only work
tmux send-keys -t lichen:reviewer 'For each commit since yesterday:
1. git show <sha> to see the diff
2. Run /codereview 3 times on the changes
3. File any findings as beads with tag=codereview
4. Move to next commit
Do not fix anything - just review and file findings.' Enter
```

**Review findings become beads:**

```bash
# Reviewer creates beads like:
bd create --title="Potential null deref in parse_frame()" \
  --description="Line 142: buffer could be NULL if allocation fails" \
  --type=bug --labels=codereview --parent=<original-issue>
```

**Checking review coverage:**

```bash
# Count review beads created today
bd list --labels=codereview --since=today | wc -l

# Check a specific commit was reviewed
git log --oneline -1 <sha>
bd search "codereview <sha or title keywords>"
```

---

## Detailed Setup (20 minutes)

### Prerequisites

- AWS account with EC2 access
- SSH key configured for EC2
- x.ai API key (or other LLM provider)
- GitHub SSH access from EC2
- `bd` (beads) issue tracker installed

### Step 1: Launch EC2 Instance

```bash
# Use a beefy ARM instance for cost efficiency
# c8g.4xlarge: 16 vCPU, 32GB RAM, ~$0.50/hr

aws ec2 run-instances \
  --image-id ami-0764d1b512e22671f \  # Your AMI with tools pre-installed
  --instance-type c8g.4xlarge \
  --key-name your-key \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Project,Value=LICHEN}]'
```

Or use an existing stopped instance:
```bash
aws ec2 start-instances --instance-ids i-0d14dd9fb53dae004
# Get new public IP (no EIP):
aws ec2 describe-instances --instance-ids i-0d14dd9fb53dae004 \
  --query 'Reservations[].Instances[].PublicIpAddress' --output text
```

### Step 2: Connect and Set Up tmux

```bash
ssh ec2-user@<ip>

# Start tmux session
tmux new-session -s lichen -c /path/to/project

# The session persists across SSH disconnects
```

### Step 3: Create Worktrees

Each worker needs its own worktree to avoid git conflicts:

```bash
cd /path/to/project

# Create branches and worktrees for each worker
for i in 2 3 4 5 6 7; do
  git branch worker$i-batch HEAD 2>/dev/null || true
  git worktree add ../project-worker$i worker$i-batch
done
```

### Step 4: Start Workers

For each worker, create a tmux window and start opencode:

```bash
# Create windows
tmux new-window -t lichen -n worker2 -c /path/to/project-worker2
tmux new-window -t lichen -n worker3 -c /path/to/project-worker3
# ... etc

# Start opencode in each (with API key)
tmux send-keys -t lichen:worker2 'export XAI_API_KEY="..." && opencode' Enter
```

### Step 5: Deploy Shepherd Script

The shepherd keeps workers fed by detecting idle state and sending prompts:

```bash
cat > /path/to/opencode-shepherd.sh << 'EOF'
#!/bin/bash
set -u

SESSION="${SESSION:-lichen}"
POLL_INTERVAL="${POLL_INTERVAL:-90}"
BD_PATH="${BD_PATH:-/path/to/bd}"
WORK_DIR="${WORK_DIR:-/path/to/project}"
LOG="/path/to/shepherd.log"

WORK_PROMPT='Pick 5 beads from bd ready and work them in parallel.
MANDATORY: After every logical chunk of code, run /codereview 3 times.
File all findings as beads tagged codereview.
If you discover new work or bead is too big: bd create --parent=<id>
If blocked on human decision: bd update <id> --notes "HUMAN: question"
Keep working until bd ready is empty.'

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG"; }

tmux has-session -t "$SESSION" 2>/dev/null || { log "ERROR: no session"; exit 1; }
log "Shepherd started"

while true; do
    # Get all worker windows (exclude shepherd, sync, etc.)
    windows=$(tmux list-windows -t "$SESSION" -F '#{window_name}' | grep -Ev 'shepherd|sync')
    
    # Check if there's work to do
    ready_count=$(cd "$WORK_DIR" && "$BD_PATH" ready 2>/dev/null | grep -c "^○") || ready_count=0
    [ "$ready_count" -eq 0 ] && { log "Backlog empty"; sleep "$POLL_INTERVAL"; continue; }

    for window in $windows; do
        pane=$(tmux capture-pane -t "$SESSION:$window" -p 2>/dev/null) || continue
        
        # Detect spinners (agent is busy)
        spinners=$(printf '%s' "$pane" | grep -c '[⠇⠧⠦⠼⠴⠸⠹⠙⠋⠏]' | tr -d '\n') || spinners=0
        
        # Detect opencode UI
        opencode=$(printf '%s' "$pane" | grep -c 'Build · Grok' | tr -d '\n') || opencode=0
        
        [ "$spinners" -gt 0 ] && continue  # Busy, skip
        
        if [ "$opencode" -gt 0 ]; then
            log "[$window] Idle ($ready_count ready). Prompting."
            tmux send-keys -t "$SESSION:$window" "$WORK_PROMPT" Enter
            sleep 2
        fi
    done
    sleep "$POLL_INTERVAL"
done
EOF

chmod +x /path/to/opencode-shepherd.sh

# Run in its own tmux window
tmux new-window -t lichen -n shepherd
tmux send-keys -t lichen:shepherd '/path/to/opencode-shepherd.sh' Enter
```

### Step 6: Deploy Sync Loop

Push to GitHub periodically so work isn't lost:

```bash
tmux new-window -t lichen -n sync
tmux send-keys -t lichen:sync 'while true; do
  sleep 900  # 15 minutes
  cd /path/to/project
  git push origin main 2>&1 | tee -a /path/to/sync.log
done' Enter
```

### Step 7: Configure Git for SSH

Ensure all worktrees use SSH (not HTTPS):

```bash
git config --global url.'git@github.com:'.insteadOf 'https://github.com/'
```

---

## Operations

### Monitor Workers

```bash
# Quick status check
for w in 0 worker2 worker3 worker4 worker5 worker6 worker7; do
  spinners=$(tmux capture-pane -t lichen:$w -p | grep -c '[⠇⠧⠦⠼⠴⠸⠹⠙⠋⠏]')
  echo "$w: $spinners active"
done
```

### Check Progress

```bash
# Beads status
bd stats

# Today's closes
git log --oneline --since='today' | grep -c 'bd: close'

# Net change (closes minus creates)
created=$(git log --oneline --since='today' | grep -c 'bd: create')
closed=$(git log --oneline --since='today' | grep -c 'bd: close')
echo "Created: $created, Closed: $closed, Net: $((closed - created))"
```

### Check x.ai Spend

```bash
MGMT_KEY="your-management-key"
TEAM_ID="your-team-id"

curl -s -H "Authorization: Bearer $MGMT_KEY" \
  "https://management-api.x.ai/v1/billing/teams/$TEAM_ID/prepaid/balance" | \
  jq '{topped_up: (.total.val | tonumber / -100), purchases: .changes | length}'
```

### Kick Idle Workers

```bash
for w in 0 worker2 worker3 worker4 worker5 worker6 worker7; do
  tmux send-keys -t lichen:$w 'Pick 5 beads from bd ready and work them. Go.' Enter
done
```

### Add More Workers

```bash
# Create worktree
git branch worker8-batch HEAD
git worktree add ../project-worker8 worker8-batch

# Create window and start
tmux new-window -t lichen -n worker8 -c /path/to/project-worker8
tmux send-keys -t lichen:worker8 'export XAI_API_KEY="..." && opencode' Enter

# Give it work
tmux send-keys -t lichen:worker8 'Pick 5 beads and work them. Go.' Enter
```

### Check Review Coverage

```bash
# Review beads created today
bd list --labels=codereview --since=today

# Commits vs review beads (rough parity check)
code_commits=$(git log --oneline --since='today' | grep -cv '^[a-f0-9]* bd:')
review_beads=$(bd list --labels=codereview --since=today 2>/dev/null | wc -l)
echo "Code commits: $code_commits, Review findings: $review_beads"

# Find unreviewed commits (commits with no matching review bead)
# Manual check: look for commits not mentioned in any codereview bead
git log --oneline --since='yesterday' | grep -v 'bd:'
```

### Pull Work to Local

```bash
# Add EC2 as remote
git remote add ec2 ec2-user@<ip>:/path/to/project

# Fetch and merge
git fetch ec2 main
git merge ec2/main
```

### Stop Everything

```bash
# Stop instance (keeps EBS)
aws ec2 stop-instances --instance-ids i-0d14dd9fb53dae004

# Or just detach from tmux (workers keep running)
# Ctrl-b d
```

---

## Cost Estimates

| Resource | Rate | Usage | Cost |
|----------|------|-------|------|
| EC2 c8g.4xlarge | $0.50/hr | 48 hrs | $24 |
| x.ai Grok 4.20 | ~$0.40/issue | 625 issues | $250 |
| **Total** | | | **~$275** |

### Optimizations

- Use spot instances for ~60% EC2 savings
- Use Grok 4.1 Fast ($0.20/1M input) for simpler tasks
- Batch similar issues to reduce context overhead
- Run overnight when rates are lower (if applicable)

---

## Troubleshooting

### Workers Stop Working

**Symptom:** No spinners, workers sitting at prompt  
**Cause:** Shepherd not prompting, or workers finished batch  
**Fix:** Check shepherd log, manually kick workers

### Git Push Fails

**Symptom:** "could not read Username" error  
**Cause:** Using HTTPS instead of SSH  
**Fix:** `git config --global url.'git@github.com:'.insteadOf 'https://github.com/'`

### Shepherd Errors

**Symptom:** "integer expression expected" in shepherd log  
**Cause:** grep returning multi-line output  
**Fix:** Use `| tr -d '\n'` after grep -c

### Worker Crashes to Bash

**Symptom:** Window shows bash prompt instead of opencode  
**Cause:** opencode exited or crashed  
**Fix:** Shepherd should auto-restart, or manually: `opencode` Enter

### Duplicate Work

**Symptom:** Multiple workers claiming same issue  
**Cause:** Race condition on bd claims  
**Fix:** Assign exclusive issue ranges to workers, or accept some waste

### Reviews Not Happening

**Symptom:** Code commits without corresponding codereview beads  
**Cause:** Workers skipping /codereview or not filing findings  
**Fix:** Check AGENTS.md has the 3x review rule; update shepherd prompt to emphasize mandatory review; spawn dedicated reviewer worker

### Review Findings Piling Up

**Symptom:** Hundreds of codereview beads, net bead count increasing  
**Cause:** Reviews finding more issues than workers are closing  
**Fix:** This is good — it means reviews are working. Allocate more workers to fixing codereview-tagged beads. Consider: `bd ready --labels=codereview` to prioritize review findings

---

## Variations

### Different LLM Providers

Replace `XAI_API_KEY` with appropriate key:
- Anthropic: `ANTHROPIC_API_KEY`
- OpenAI: `OPENAI_API_KEY`

Update opencode config (`~/.config/opencode/opencode.json`):
```json
{
  "model": "anthropic/claude-sonnet-4",
  "permission": "allow"
}
```

### Different Coding Agents

The pattern works with any agent that:
1. Runs in a terminal
2. Shows visible "busy" indicators
3. Accepts text prompts

Adjust shepherd's busy-detection regex for your agent.

### Different Issue Trackers

Replace `bd` commands with your tracker:
- GitHub Issues: `gh issue list`, `gh issue close`
- Linear: `linear issue list`
- Jira: `jira issue list`

---

## Files Reference

| Path | Purpose |
|------|---------|
| `/mnt/lichen-zephyr/work/project-LICHEN` | Main worktree |
| `/mnt/lichen-zephyr/work/project-LICHEN-worker*` | Worker worktrees |
| `/mnt/lichen-zephyr/opencode-shepherd.sh` | Shepherd script |
| `/mnt/lichen-zephyr/shepherd.log` | Shepherd log |
| `/mnt/lichen-zephyr/sync.log` | Git sync log |
| `/mnt/lichen-zephyr/local-bin/bd` | Beads CLI |
| `~/.config/opencode/opencode.json` | Opencode config |

---

## Credits

This pattern emerged from a July 2026 session recovering lost work from agent token-runout stalls. The core insight: parallelize at the process level (multiple tmux windows), isolate at the git level (worktrees), and supervise with a simple bash loop (shepherd).

No novel infrastructure required — just tmux, git, and a billing API to watch.
