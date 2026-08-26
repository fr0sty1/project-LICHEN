# Resume Point: Vector Convergence Sweep Complete

**Date:** 2026-08-25 (evening)
**Status:** Ready for new work

## UPDATE (late evening, same day)

Range Testing epic (l1qw.10.20) complete except Zephyr/review-blocked children:
- `10.20.4` vectors: test/vectors/rangetest.json (24 vectors, hand-derived RFC 8428
  oracle) + pytest consumer; fixed render_get non-dict-body strictness gap.
- `10.20.2` Rust: lichen-client/src/rangetest.rs codecs + rangetest_vectors.rs,
  byte-exact vs vectors; Rust emits f64-width floats to match cbor2 reference;
  normalized total_rtt_ms to always-float (was int when zero hops).
- Orphan audit under `f4z7`: gcp_iid_comparison + lr_fhss_capability wired
  (pytest consumers); 9 triage child beads filed for orphans needing features
  first. a0gf (CCP-15) shipped interference_score oracle; backoff_jitter_ms
  column flagged HUMAN (no derivable oracle — see a0gf comment).
- Follow-on feature-build children CLOSED with standalone oracle modules:
  wr0b tx_queue.py (47 tests, reserve=peek+mark reconciles cross-file
  conflict; ForwardingBuffer/Router/icmpv6 remainder split to z3k8),
  walc coap/access.py LCI authz matrix (32 tests), xt5y rpl/evidence.py
  B2.5 gate (16 tests), heog broadcast_limit.py budgets+windows+idle expiry
  (22 tests; yellow-zone RNG semantics flagged HUMAN on heog — the vector
  file contradicts itself: count=100 'probabilistic' vs count=199 'relay').
  171-test combined sweep green.

## CURRENT PROJECT PHASE

**Spec, vectors, Python, Rust only.** We are NOT doing C/Zephyr or real hardware yet.

- Skip any beads tagged `zephyr`, `c`, `blocked:hardware`, or `ec2`
- Do not attempt C builds, Zephyr work, or hardware integration

## THIS BOX (macOS) CANNOT DO

- **No hardware work** — no LoRa radios, no bench devices, no port access
- **No Zephyr / C builds** — no `west build`, twister, Renode, or `lichen/subsys/**`

## What Happened This Session (2026-08-25)

Massive vector-convergence sweep. Roughly **90 "Vectors:" beads closed with verified
evidence** across 4 parallel fanout waves. Key structural wins:

1. **Python deps fixed**: `cd python && uv sync --extra dev` (jinja2/defusedxml/lora_medium).
2. **14 orphaned vector files wired to pytest consumers** driving the real lichen
   implementation (CoAP messages/options/tokens/observe/RD, SLIP, SOS CBOR, neighbors,
   transport, ICMPv6, SRH, forwarding, announce relay, CCP4 plans).
3. **New vector families shipped**: DIS + DAO-ACK in rpl_messages.json; lci_config,
   lci_radio_config, lci_identity, core_link_format, lci_status, lci_routing_table,
   lci_raw_diag, position_cache, position_observe; SCHC rules 2-4 negatives;
   yggdrasil_address.json expanded to 14 cases (python+rust consumers);
   senml_location +7 error vectors; waypoint +3 rejects.
4. **Rust cross-validation added**: epoch_rollover.json now driven through Rust
   (`test_epoch_rollover_vectors` in rust/lichen-link/tests/shared_vectors.rs,
   needs `--features schnorr,std`). yggdrasil corpus consumer in rust/lichen-core.
5. **Epic f4z7** tracks the wiring work; most children done.

## Current Blockers / Known Failures (all pre-existing, filed)

- `385o` — test_lci_auth expects 4.04 for unauth location POST, resource returns 4.05. Product decision needed.
- `ewlm` — 3 sim/radio test failures, proven pre-existing at HEAD.
- Real divergences filed: `s9e2` (SCHC py/rust decompress), `cegf` (ccp4 JSON stale vs oracle), `9agc` (SLIP/SOS/neighbors leniency), `laol` (CCP-12 dual formula hazard mod n-1 vs mod n), **`a6qg` (P1: /sos performs NO signature verification — spec 18.3 violation; SOS/confessions burst+Retry-After gaps; group OSCORE distribution unimplemented)**, Go-Yggdrasil docstring falsity bead.

## Test State

- Python: full suite green except pre-existing failures above (~2050+ tests across vectors/consumers/coap/ipv6/crypto/timing)
- Rust: lichen-link (needs `--features schnorr,std` for shared_vectors), lichen-rpl 141, lichen-core yggdrasil 11, lichen-schc all-features green

## Priority Work Available (next natural steps)

1. **10 still-orphaned vector files need consumers**:
   `sync_hop.json`, `ccp16-desync.json`, `ccp16-hop.json`, `ccp9_rendezvous.json`,
   `announce_signed_data.json`, `sos_signature.json`, `sos_rate_limiting.json`,
   `group_oscore_key.json`, `confessions_rate.json`, `receipt_cbor.json`
   (each unblocks specific annotated GAP beads)
2. Missing families: check-in/roll-call (10.19.x), range-test (10.20/10.10.x),
   canned messages, monotonic-time invariant, ASN derivation, holdover expiry,
   multi-channel timing, rendezvous timeout/guard scenarios
3. `l1qw.15.5.3` — Zephyr Node Handoff (EC2 only)

## Quick Start

```bash
bd ready | head -20
cd python && uv sync --extra dev && uv run --extra dev pytest tests/test_vectors.py -q
cd rust && cargo test -p lichen-link --features "schnorr,std" --test shared_vectors
```
