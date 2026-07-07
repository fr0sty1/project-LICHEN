<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:b380caf6 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues are stored as flat JSON files in `.beads/issues/`, tracked by git. Sync is via standard git operations.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits or git pushes unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->


## Build & Test

```bash
# Python prototype
cd python
pip install -e ".[dev]"
pytest
ruff check src/ tests/

# Simulator
lichen-sim --node-port 4444 --api-port 4445
```

## Architecture Overview

See `AGENTS.md` for full technical details. Quick reference:

```
Application:  CoAP / MQTT-SN / Raw UDP
Security:     OSCORE (E2E) + Schnorr link signatures (48B)
Transport:    UDP (compressed via SCHC)
Network:      IPv6 (link-local + ULA/GUA)
Routing:      RPL (BR traffic) + Announce (peers) + LOADng (fallback)
Adaptation:   SCHC (RFC 8724) — NOT 6LoWPAN
Link:         LICHEN frame format with replay protection
Physical:     LoRa SF10/125kHz/CR4-5
```

## Behavioral Guidelines

Guidelines to reduce common LLM coding mistakes. Bias toward caution over speed.

### 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

- State assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them—don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it—don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

### 5. Security Comments

Use `SECURITY:` prefix for comments highlighting security-critical code paths (e.g., MIC verification, authentication requirements, cryptographic limitations).

### 6. Test Integrity

**Never modify tests to make them pass.**

- Never hardcode expected values or mock results to contrive a pass.
- Never weaken, skip, or delete tests.
- A passing suite achieved by changing tests (not code) is not a pass.
- Fix the code. If unfixable within scope, escalate.
- Tests must have independent oracles: known test vectors, cross-validation, or reference implementations. A test that uses code-under-test as its own oracle proves nothing.

### 7. EC2 Instance Safety

**Only terminate instances you created in the current session.**

- Track every instance ID you launch (from `aws ec2 run-instances` output)
- Before terminating ANY instance, verify its ID is one you created
- Never terminate instances found via `describe-instances` unless you have the launch record
- If multiple instances are running, check tags or launch time before assuming ownership
- When in doubt, ask before terminating

This applies to all cloud resources: volumes, security groups, queues, etc. If you didn't create it in this session, don't delete it.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation.
