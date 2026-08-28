# Spinbead Design

Batch bead processor with deduped codereview and adversarial verification.

## Architecture

```
PHASE 1 - INVENTORY (one agent, returns structured data):
  - `bd ready -n 200` -> extract all bead IDs, priorities, dependencies
  - Build a DAG: which beads mention/block which files
  - Return: {beads: [{id, priority, files_touched}], file_to_beads: {}}

PHASE 2 - WAVES (iterate until empty):
  - Take all P0 beads with no unresolved dependencies -> Wave 1
  - Execute Wave 1 in parallel: each agent fixes ONE bead, returns {bead_id, files_modified[], closed: bool}
  - Collect all files_modified across Wave 1 into a SET
  - DO NOT codereview yet - batch it

  - Take all P1 beads unblocked by Wave 1 -> Wave 2
  - Repeat until P0-P3 exhausted

PHASE 3 - BATCH CODEREVIEW (after all waves):
  - Dedupe the files_modified set
  - For each unique file, ONE agent does 3-perspective review (correctness/security/edge)
  - Findings -> new beads in beads tracker, NOT recursive agents
  - Return: {new_bead_ids[]}

PHASE 4 - CONVERGE:
  - If new_bead_ids is empty -> DONE
  - Else: re-run PHASE 2-3 on new_bead_ids only

RULES:
  - Agents are LEAF WORKERS: fix one bead, return result, die
  - NO agent spawns agents - orchestrator spawns all agents
  - File reads are CACHED: if agent A read foo.rs, agent B gets it from cache
  - Modified files tracked CENTRALLY, not per-agent
  - Codereview happens ONCE per file per round, not per-bead
```

This eliminates:
- Recursive agent spawning (flat waves)
- Redundant file reads (central cache)
- Duplicate codereviews (batched, deduped)
- Context amnesia (orchestrator maintains state)

## Implementation

`scripts/spinbead.py` - standalone Python script using litellm.

```bash
# Process all ready beads
./scripts/spinbead.py

# Limit waves
./scripts/spinbead.py --max-waves 3

# Dry run (show plan, no claims)
./scripts/spinbead.py --dry-run

# Override model/concurrency
./scripts/spinbead.py --model claude-sonnet -c 4
```

Environment variables:
- `LITELLM_URL` - litellm endpoint (default: http://heft:4000/v1)
- `LITELLM_KEY` - API key (default: sk-litellm-local)
- `LITELLM_MODEL` - model name (default: ox-alpha)
- `SPINBEAD_CONCURRENCY` - parallel agents (default: 8)
- `SPINBEAD_WAVE_CAP` - max beads per wave (default: 20)
- `SPINBEAD_ACTOR` - claim identity (default: spinbead)

## Adversarial Verification

Phase 3 includes adversarial verification of findings before filing beads:

1. Initial review produces findings with confidence levels
2. Only HIGH confidence P0-P2 findings proceed
3. Each finding is challenged by a verifier agent that tries to REFUTE it
4. Verdicts: CONFIRMED (file bead), REFUTED (discard), UNCERTAIN (flag for human)
5. P0 security issues skip verification (too important to risk false negative)

Expected: 50-80% reduction in false positive beads.
