# Resume Point: Post-Convergence Cleanup

**Date:** 2026-08-25
**Status:** Ready for new work

## CURRENT PROJECT PHASE

**Spec, vectors, Python, Rust only.** We are NOT doing C/Zephyr or real hardware yet.

- Skip any beads tagged `zephyr`, `c`, `blocked:hardware`, or `ec2`
- Do not attempt C builds, Zephyr work, or hardware integration
- Focus: spec writing, test vector generation, Python prototype, Rust implementation

## THIS BOX (macOS) CANNOT DO

Even when we start C/Zephyr work, this machine cannot run it:
- **No hardware work** — no LoRa radios, no bench devices, no port access
- **No Zephyr / C builds** — no `west build`, twister, Renode, or `lichen/subsys/**`
- Zephyr/C/hardware tasks go to EC2 Zephyr workstation or filed as beads

## Recent Completed Work

Major checkpoint committed: `4c5c4af6cc cross-impl spec convergence, vector expansion, SCHC/gateway fixes`
- 530 files changed, 116k lines net
- SCHC compression LSB fixes (UDP ports, Yggdrasil addresses) — all vectors pass
- RPL root signature vector helpers hardened
- Trust store load validation and key rotation binding
- DAO TOCTOU regression tests
- CoAP lifecycle and auth behaviors restored

Rust SCHC tests: **all passing** (`cargo test -p lichen-schc`)

## Current Blockers

None. Python deps fixed via `cd python && uv sync --extra dev` (2026-08-25).

## Beads Status

No issues currently claimed. Run `bd ready` to find work.

## Priority Work Available

Non-epic P1 ready issues:
- `l1qw.15.5.3` — Zephyr: Node Handoff implementation (EC2 only)

Recently closed (2026-08-25): `l1qw.6.10.1.4.3` (Sliding Window vectors) and
`l1qw.6.10.2.2.3` (Epoch Increment vectors) verified complete; Rust now also
cross-validates `epoch_rollover.json` (`test_epoch_rollover_vectors` in
rust/lichen-link/tests/shared_vectors.rs, needs `--features schnorr,std`).

## Quick Start

```bash
# Check what's ready
bd ready | head -20

# Claim an issue
bd update <id> --claim

# Run Rust tests
cd rust && cargo test

# Run Python tests (after fixing deps)
cd python && pip install -e ".[dev]" && pytest
```
