# LICHEN Grind Session: Non-Hardware Completion

## Context
You are continuing work on LICHEN, a LoRa IPv6 mesh networking stack with three co-equal implementations (Rust, Python, Zephyr C). Run `bd prime` for full context. Read `AGENTS.md` for architecture.

## Session Goal
Complete ALL non-hardware beads. Hardware beads (Heltec, ThinkNode, T-Deck, T1000-E, RAK, LilyGO, physical flash/test) are OUT OF SCOPE.

## Phase 1: Inventory

```bash
bd list --status open --json | jq '[.[] | select(.type != "epic") | select(.description | test("flash|hardware|physical|Heltec|ThinkNode|T-Deck|T1000|RAK|LilyGO"; "i") | not)] | length'
```

List what remains. Categorize into:
- **Code bugs** (file:line references)
- **Implementations** (LCI handlers, drivers, transports)
- **Compliance** (policy violations)
- **Tests/Vectors** (missing coverage)
- **Docs** (missing documentation)

## Phase 2: Code Review Sweep

ultracode run /codereview on each module cluster, 3 passes per cluster with different focus:

**Pass 1 - Correctness:** Logic errors, edge cases, error handling
**Pass 2 - Security:** Injection, overflow, auth bypass, crypto misuse  
**Pass 3 - Robustness:** Races, resource leaks, panic paths

Clusters to review:
- `rust/lichen-coap/` (CoAP client/server)
- `rust/lichen-gateway/` (TUN, APRS-IS, SLIP, TAK)
- `python/src/lichen/interface/` (KISS, Meshtastic, TAK bridges)
- `python/src/lichen/coap/` (resources, client)
- `lichen/subsys/lichen/coap/` (C CoAP)
- `lichen/subsys/lichen/routing/` (C routing)
- `lichen/drivers/` (LoRa drivers)

For EACH finding, IMMEDIATELY file a bead:
```bash
bd create task "[REVIEW] <title>" --priority P<1-4> --description "<file>:<line> - <what's wrong and failure scenario>"
```

## Phase 3: Fix All Filed Beads

ultracode launch fix agents for every open bead that isn't hardware-blocked:

```bash
bd list --status open --json | jq -r '.[] | select(.type != "epic") | select(.description | test("flash|hardware|physical|Heltec|ThinkNode|T-Deck|T1000|RAK|LilyGO"; "i") | not) | "\(.id)|\(.title)"'
```

Each fix agent:
1. Reads the bead and relevant files
2. Makes the fix
3. Runs relevant tests if possible
4. Closes: `bd close <id> --resolution "Fixed: <summary>"`
5. Files sub-beads for discovered related work

## Phase 4: EC2 Build Validation

Stand up the arm64 EC2 instance for Zephyr builds:

```bash
./scripts/ec2-claude.sh start
# Wait for SSH ready
./scripts/ec2-claude.sh ssh "cd /workspace && west build -b native_sim lichen/apps/gateway"
./scripts/ec2-claude.sh ssh "cd /workspace && west twister -T lichen/tests/ --platform native_sim"
```

Run full Zephyr test suite. Any failures become beads.

## Phase 5: Implementation Beads

Fix these categories (check `bd list` for current IDs):

**LCI Handlers:**
- /keys resource handlers
- /msg resource handlers  
- /config resource handlers
- /status resource handlers
- SLIP transport binding
- BLE IPSP transport binding

**Drivers:**
- LR1110 Zephyr driver (if not hardware-blocked)
- GNSS stub completion

**Transports:**
- KISS Zephyr implementation
- Native LCI integration tests

## Phase 6: Compliance Sweep

For each policy in `spec/`:
1. Grep implementations for compliance
2. File beads for violations
3. Fix violations

Key policies:
- `02-physical-link.md` §4.4 (replay protection)
- `06-security.md` §8.6 (TOFU), §8.7 (OSCORE)
- `appendix-bufferbloat.md` (queue bounds)
- `appendix-c-safety.md` (compiler flags, sanitizers)

## Phase 7: Test Vector Parity

Ensure all three implementations pass identical test vectors:
- `spec/test-vectors/frame.json`
- `spec/test-vectors/schnorr48.json`
- `test/vectors/oscore.json`
- `test/vectors/rpl_messages.json`

Add missing vector loaders. File beads for failures.

## Phase 8: Final Validation

```bash
# Python
cd python && pytest && ruff check src/ tests/

# Rust  
cd rust && cargo test --workspace && cargo clippy --workspace

# Zephyr (on EC2)
./scripts/ec2-claude.sh ssh "cd /workspace && west twister -T lichen/tests/"
```

Any failures become beads. Fix them.

## Constraints

- **NO hardware beads** - skip anything requiring physical devices
- **NO spec changes** - fix code to match spec, not vice versa
- **File beads immediately** - don't batch findings
- **Close beads when done** - `bd close <id> --resolution "..."`
- **Commit regularly** - logical chunks, conventional commits
- **Push when stable** - after each major phase

## Success Criteria

```bash
bd list --status open --json | jq '[.[] | select(.description | test("flash|hardware|physical|Heltec|ThinkNode|T-Deck|T1000|RAK|LilyGO"; "i") | not)] | length'
```

Target: **0** non-hardware beads remaining.
