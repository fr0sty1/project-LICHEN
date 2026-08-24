# Using Gastown for LICHEN Development

## Why Gastown Fits This Project

LICHEN has the exact problems Gastown was designed to solve:

**Multi-implementation discipline.** LICHEN isn't dual-impl—it's a five-headed beast:

| Layer | Location | Role |
|-------|----------|------|
| Python prototype | `python/src/lichen/` | Reference implementation, test oracle |
| Rust crate | `crates/oscore/` | Portable core, feature-flagged (Schnorr48/Ed25519) |
| Rust LICHEN | `rust/lichen-oscore/` | LICHEN-specific wrapper |
| C/Zephyr | `lichen/subsys/lichen/` | Embedded target, production firmware |
| HALs | `lichen/subsys/lichen/hal/` | nRF52, RP2040, POSIX, etc. |
| Simulator | `lichen-sim` | Multi-node test harness |

A protocol change (like today's KDF fix) touches Python oracle, Rust crate, C implementation, and test vectors. HAL changes ripple across every board target. The simulator must track all of it.

Right now, you manually verify each layer. Gastown's Polecats can work all five in parallel, with the Refinery catching drift before merge.

**Context exhaustion.** The EDHOC audit today required multiple workflow runs because each agent hit context limits. Gastown's Beads system preserves state across sessions—an agent can pick up exactly where the last one stopped.

**Agent laziness.** You've seen it: agents that stop at the first obstacle, ask permission for obvious next steps, or "summarize what they found" instead of fixing it. Gastown's GUPP principle ("If there is work on your hook, YOU MUST RUN IT") combined with automatic nudges forces forward progress.

**Handoff friction.** Every session starts with "where were we?" Beads eliminate this—work state lives in Git, not ephemeral conversation history.

## Setup for LICHEN

You're already using Beads (`bd`). Gastown builds on top of it.

```bash
# Install Gastown (Go binary)
brew install gastown

# Initialize in project root
cd /Volumes/Attic/Desktop/Projects/project-LICHEN
gt init --beads-dir .beads

# Configure workers in gastown.toml
gt config set mayor.model claude-opus-4-5
gt config set polecat.count 4
gt config set refinery.review-preset strict
```

The key config choices:
- **Mayor**: Use Opus for orchestration—it needs to understand the full system
- **Polecats**: 4-6 for LICHEN's scope; they're ephemeral and cheap
- **Refinery preset**: `strict` enforces the C header/impl sync rule and Schnorr48/Ed25519 parity

Link your existing CLAUDE.md:
```bash
gt config set guidelines.file CLAUDE.md
```

## Daily Workflow

**Morning startup:**
```bash
gt status              # See what's queued
gt mayor               # Start the Mayor in a tmux pane
```

The Mayor reads open Beads and assigns work to Polecats. You don't micromanage individual agents—you manage the work queue.

**Filing work:**
```bash
# Instead of typing requests into Claude Code:
gt sling --epic "EDHOC KDF compliance" --formula lichen-protocol \
    "Fix KDF info structure to RFC 9528 Section 4.1.2"
```

The `lichen-protocol` formula encodes the multi-impl discipline:
```toml
# formulas/lichen-protocol.toml
[phases]
# Phase 1: Update Python oracle (source of truth for test vectors)
oracle = { workers = 1, target = "python/src/lichen/" }

# Phase 2: Parallel impl updates informed by oracle
implement = { workers = 3, parallel = true, depends_on = "oracle" }
implement.rust = { target = "crates/oscore/", feature_flags = ["edhoc", "edhoc-schnorr48"] }
implement.c = { target = "lichen/subsys/lichen/", lint = "scripts/lint-c.sh" }
implement.rust_lichen = { target = "rust/lichen-oscore/" }

# Phase 3: Cross-validate all impls against oracle vectors
validate = { workers = 1, depends_on = "implement" }

# Phase 4: Simulator integration test
sim_test = { workers = 1, depends_on = "validate", command = "lichen-sim --test" }

[rules]
python_is_oracle = true  # Python vectors are authoritative
rust_both_features = true  # Must compile with edhoc AND edhoc-schnorr48
c_header_impl_sync = true  # Header changes require impl changes
hal_changes_require_all_targets = true  # HAL change → build all boards
```

For HAL-specific work:
```toml
# formulas/lichen-hal.toml
[phases]
implement = { workers = 1 }
build_matrix = { workers = 4, parallel = true, depends_on = "implement" }
build_matrix.nrf52 = { target = "boards/nrf52dk" }
build_matrix.rp2040 = { target = "boards/rp2040" }
build_matrix.posix = { target = "boards/native_sim" }
build_matrix.qemu = { target = "boards/qemu_cortex_m3" }

[rules]
stub_all_hals = true  # New HAL function → stub in all targets
```

**Watching progress:**
```bash
gt watch                # Live view of all workers
gt logs polecat-3       # Debug a specific worker
```

**Handling stuck agents:**
The Witness detects stuck Polecats automatically. If a Polecat hasn't progressed in 5 minutes, Witness either nudges it or kills and respawns it. You don't chase lazy agents—the system does.

## Mapping Current Pain Points to Gastown Features

| Current Problem | Gastown Solution |
|-----------------|------------------|
| "Agent stopped after finding the bug instead of fixing it" | GUPP + Mayor re-slings incomplete work |
| "Workflow ran but left half the tests broken" | Refinery gates merge on test pass |
| "Had to re-explain context after compaction" | Beads persist full context in Git |
| "Agent made a change but didn't update the header" | `c_header_impl_sync` rule triggers check |
| "Spent an hour triaging the audit instead of fixing" | Mayor does triage; you approve the plan |
| "Schnorr48 change broke Ed25519 path silently" | `rust_both_features` rule builds both |
| "Fixed Rust but forgot Python oracle" | `python_is_oracle` rule requires oracle update first |
| "C change compiled on nRF but broke RP2040" | `lichen-hal` formula builds all targets |
| "HAL stub missing on POSIX target" | `stub_all_hals` rule checks all HAL impls |
| "Simulator out of sync with protocol changes" | `sim_test` phase runs after all impls |

## The Crew Pattern for Design Work

For design sessions (not pure implementation), use Crew workers instead of Polecats:

```bash
gt crew spawn --name "lichen-arch" --sticky
```

Crew workers are "pets not cattle"—they persist across sessions and accumulate project context. Use them for:
- Protocol design decisions (OSCORE persistence model, tunnel vs. native routing)
- Security audits where you want the same agent to see all findings
- Cross-impl architecture (how Python oracle informs Rust/C structure)
- HAL abstraction design (what's portable vs. target-specific)

**Simulator Crew**: The simulator is complex enough to warrant its own persistent agent:
```bash
gt crew spawn --name "sim-crew" --context "lichen-sim architecture, node topology, test harnesses"
```

This agent accumulates knowledge about:
- Multi-node test scenarios
- CoAP/DTN/SCHC integration paths
- How to reproduce edge cases across all implementations

## Cost Reality Check

Gastown is hungry. Yegge suggests budgeting $100-200/month in Claude API costs beyond a Max subscription. For LICHEN's five-impl complexity:
- 6 Polecats (Python + Rust + C + HAL + Sim + cross-validate) ≈ $120-180/month
- Mayor + Refinery overhead ≈ $40-60/month
- Persistent Crew (arch + sim) ≈ $30-50/month
- **Total: ~$200-300/month**

The ROI calculation: today's KDF fix touched 4 implementations and required 3 workflow runs plus manual fixes. With Gastown, that's one `gt sling` command, parallel Polecats, and a Refinery gate. Time saved per protocol change: 2-4 hours. At 4+ protocol changes per month, Gastown pays for itself.

## Migration Path

1. **Week 1**: Keep using Claude Code directly. File all tasks as Beads (`bd create`). You're already doing this.

2. **Week 2**: Install Gastown. Create the `lichen-protocol` and `lichen-hal` formulas. Run Mayor in dry-run mode to see how it decomposes work.

3. **Week 3**: Let Polecats handle single-impl work (Rust-only fixes, C-only lint cleanup). Verify they don't break cross-impl invariants.

4. **Week 4**: Enable multi-impl formulas. One Polecat per implementation, parallel execution, Refinery validates cross-impl consistency.

5. **Week 5**: Add HAL build matrix. Every HAL change triggers builds on all targets. Catch "works on nRF, breaks on RP2040" before merge.

6. **Week 6**: Integrate simulator. `sim_test` phase runs multi-node scenarios after all implementations pass.

7. **Ongoing**: Tune formulas. Encode lessons learned:
   - "C signature change requires header update" → `c_header_impl_sync`
   - "Schnorr48 must not break Ed25519 path" → `rust_both_features`
   - "Python oracle is authoritative for test vectors" → `python_is_oracle`
   - "HAL change requires stubs everywhere" → `stub_all_hals`

## The Core Mindset Shift

You stop being a developer-with-an-AI-assistant and become a factory operator. You don't write code or even review diffs line-by-line for routine work. You:
- Define formulas that encode LICHEN's multi-impl invariants
- Approve work plans the Mayor proposes
- Intervene when the Witness flags cross-impl drift
- Do design work with persistent Crew agents
- Watch the build matrix, not individual files

The agents do the implementation across all five layers. The system enforces they finish it, across all of them, before anything merges.

**For LICHEN specifically:**
- Python oracle changes first → then parallel Rust/C → then simulator
- HAL changes build all boards before merge
- Security-critical paths (EDHOC, OSCORE) get Crew review, not just Polecat implementation
- Beads track cross-impl dependencies so context survives compaction

## Fire-and-Forget Mode

You want to sling work and walk away until it's time to flash hardware. This requires:

**1. Fully automated quality gates (no human approval loops)**

```toml
# gastown.toml
[refinery]
auto_merge = true  # Merge without human approval if gates pass
review_preset = "lichen-strict"

[gates]
python_tests = "cd python && pytest"
rust_tests = "cargo test --features edhoc-schnorr48 && cargo test --features edhoc"
c_build = "west build -b native_sim"
c_lint = "./scripts/lint-c.sh"
sim_smoke = "lichen-sim --smoke-test"
hal_matrix = "scripts/build-all-targets.sh"

[gates.required]
all = true  # Every gate must pass; no exceptions
```

**2. Autonomous triage (Mayor decides, doesn't ask)**

```toml
[mayor]
autonomous = true
escalate_only = ["security", "spec_ambiguity", "hardware_required"]
```

The Mayor decomposes epics into Polecat work without asking. Only three things surface to you:
- Security findings (P0/P1 from audits)
- Spec ambiguity (RFC says X, Python does Y, which is right?)
- Hardware-required (can't test this in simulator)

**3. Continuous work loop**

```bash
# Start the factory and walk away
gt daemon --continuous

# Check in once a day
gt status --summary
gt log --merged --since yesterday
```

The Deacon keeps everything running. Polecats pull from the bead queue, do work, submit to Refinery. Refinery merges if gates pass. You come back to a changelog, not a to-do list.

**4. Hardware-blocking queue**

Work that needs real hardware goes to a separate queue:
```bash
gt sling --queue hardware --board nrf52dk \
    "Validate LoRa timing on actual radio"
```

This accumulates until you have hardware time. Then:
```bash
gt drain hardware --board nrf52dk
```

Polecats execute the hardware queue while you're at the bench.

**5. The "wake me up" contract**

```toml
[alerts]
channel = "slack"  # or email, or SMS for P0
p0_security = "immediate"
spec_ambiguity = "daily_digest"
hardware_blocked = "weekly_digest"
gate_failure_streak = 3  # Alert after 3 consecutive failures
```

You get pinged for things that actually need you. Everything else just happens.

**What this looks like in practice:**

Monday morning:
```bash
gt sling --epic "RFC 9528 full compliance" --formula lichen-protocol
```

Walk away. Do other work. Check in Friday:
```bash
$ gt status --summary
Epic "RFC 9528 full compliance": 47/52 beads merged
  - 5 beads blocked: hardware_required (LoRa timing validation)
  - 0 P0/P1 escalations
  - Gate pass rate: 94% (3 failures, all retried successfully)
  
$ gt log --merged --since monday | head -20
[merged] fix(edhoc): KDF info structure RFC 9528 compliance
[merged] fix(python): update oracle to match RFC 9528 KDF
[merged] fix(c): port KDF changes to Zephyr implementation
[merged] test(sim): add cross-impl KDF validation scenario
...
```

47 beads merged across 5 implementations. No human touched them after Monday. Friday you flash hardware and run the 5 blocked tests.

**The prerequisite:** Your test suite must be comprehensive enough that "all gates pass" actually means "this works." If tests are weak, fire-and-forget ships broken code.

## Spec-Driven Test Generation

The core problem: tests written alongside implementation share its bugs. Today's audit found `ZeroizeOnDrop` tests passing because both test and impl were wrong the same way.

The fix: tests must come from specs, not from code.

**LICHEN's spec sources:**

| Protocol | Spec | Test Vectors |
|----------|------|--------------|
| EDHOC | RFC 9528, RFC 9529 | Annex E (trace vectors) |
| OSCORE | RFC 8613 | Appendix C (request/response vectors) |
| SCHC | RFC 8724 | Section 7 (compression examples) |
| CoAP | RFC 7252 | Various examples throughout |
| Schnorr48 | LICHEN spec | `spec/schnorr48-vectors.md` (you define these) |

**Gastown formula for spec-to-test:**

```toml
# formulas/spec-to-test.toml
[phases]
# Phase 1: Extract test vectors from RFC
extract = { workers = 1, crew = "spec-reader" }
extract.prompt = """
Read {spec_url}. Extract ALL test vectors, trace examples, and 
normative MUST/SHOULD requirements. Output as JSON:
{
  "vectors": [{"name": "...", "inputs": {...}, "expected": {...}}],
  "requirements": [{"section": "4.1.2", "text": "...", "testable": true}]
}
"""

# Phase 2: Generate test code for each impl
generate = { workers = 3, parallel = true, depends_on = "extract" }
generate.python = { target = "python/tests/", template = "pytest" }
generate.rust = { target = "crates/oscore/src/edhoc/tests.rs", template = "rust_test" }
generate.c = { target = "lichen/tests/", template = "ztest" }

# Phase 3: Verify tests fail before impl (TDD sanity check)
red = { workers = 1, depends_on = "generate", expect_fail = true }

# Phase 4: Cross-validate that all impls produce identical output
cross_validate = { workers = 1, depends_on = "generate" }
cross_validate.command = "scripts/cross-impl-vectors.sh"
```

**The "spec-reader" Crew agent:**

```bash
gt crew spawn --name "spec-reader" --sticky --context """
You are a protocol specification reader. Your job:
1. Read RFCs and extract every testable statement
2. Convert prose requirements into concrete test cases
3. Extract all example values, trace vectors, bit patterns
4. Flag ambiguities where the spec is unclear

You do NOT look at implementation code. You derive tests purely from spec.
Output JSON that test generators consume.
"""
```

**Workflow:**

```bash
# Generate EDHOC tests from RFC 9528
gt sling --formula spec-to-test \
    --var spec_url="https://www.rfc-editor.org/rfc/rfc9528.html" \
    --var spec_name="EDHOC"

# Generate OSCORE tests from RFC 8613  
gt sling --formula spec-to-test \
    --var spec_url="https://www.rfc-editor.org/rfc/rfc8613.html" \
    --var spec_name="OSCORE"
```

**What this produces:**

```
python/tests/test_rfc9528_vectors.py    # 47 test cases from Annex E
python/tests/test_rfc9528_requirements.py  # 23 tests from MUST statements
crates/oscore/src/edhoc/rfc9528_vectors.rs  # Same 47 vectors, Rust
lichen/tests/edhoc/test_rfc9528.c       # Same 47 vectors, C/Ztest
```

All three test files test the same vectors. If any impl diverges from spec, it fails independently of the others.

**The cross-impl validator:**

```bash
# scripts/cross-impl-vectors.sh
#!/bin/bash
# Run same inputs through all impls, diff outputs

for vector in vectors/*.json; do
    py_out=$(python -m lichen.test_runner "$vector")
    rs_out=$(cargo run --example vector_runner -- "$vector")
    c_out=$(./build/vector_runner "$vector")
    
    if [[ "$py_out" != "$rs_out" ]] || [[ "$py_out" != "$c_out" ]]; then
        echo "DIVERGENCE: $vector"
        diff <(echo "$py_out") <(echo "$rs_out")
        exit 1
    fi
done
```

**For LICHEN-specific protocols (Schnorr48, frame format):**

You write the spec first (`spec/schnorr48.md`), then:
```bash
gt sling --formula spec-to-test \
    --var spec_url="file://spec/schnorr48.md" \
    --var spec_name="Schnorr48"
```

The spec-reader Crew extracts test vectors from YOUR spec doc, not from implementation.

**The discipline:**

1. Spec exists before code
2. Tests are generated from spec, not written by hand
3. All impls run same vectors
4. Impl bugs fail tests; test bugs are caught by cross-impl divergence
5. Spec ambiguity surfaces as "spec-reader couldn't determine expected output" → escalates to you

This breaks the circular dependency. Tests come from spec. Impls are validated against tests. You only touch code when something actually fails.

Once gates are trustworthy, you're operating a factory, not babysitting agents.

---

*"If there is work on your hook, YOU MUST RUN IT."* — GUPP
