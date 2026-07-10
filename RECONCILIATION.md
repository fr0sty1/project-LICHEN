# Tracker Reconciliation — 2026-06-13

A code-grounded audit of the beads tracker against the actual repository state.
Goal: make issue status reflect reality — close work that is genuinely done,
reopen issues that were closed without a working deliverable, and confirm the
rest are honestly open.

**Scope audited:** all 88 open issues + the 61 closed issues (full pass).
**Method:** each issue's claimed deliverable checked against the code under
`python/src/lichen` and `python/tests` (and module absence for unbuilt
subsystems). Two independent audit passes were run and cross-checked.

## Headline finding

The drift is **concentrated**, and runs mostly in the *closed → should-be-open*
direction. The **simulator infrastructure** is real and well-tested, but the
**LICHEN protocol stack it exists to validate is absent or broken**, so Phase 0
is *not* actually complete and very little should be closed.

| Subsystem | State | Evidence |
|---|---|---|
| Simulator (`sim/`) | **Built + tested** | 12 modules, ~3,600 LOC; medium, propagation, chaos, wire protocol, REST API; passing test suite |
| Radio abstraction (`radio/`) | **Built + tested** | `Radio(Protocol)` + `SimRadio` over TCP, full tests |
| Project setup | **Done** | `pyproject.toml`, package layout, pytest, type hints |
| Link layer (`link/`) | **Empty stub** | only an empty `__init__.py` (tracked by `sfk`) |
| SCHC (`schc/`) | **Corrupt / non-functional** | `rules.py` is a 10 KB single-line list-of-strings literal defining nothing; `__init__.py` empty |
| IPv6 / RPL / LOADng / routing / security / CoAP | **Absent** | no such modules exist |
| Rust workspace / Zephyr / clients / border router | **Absent** | not started |

## Actions taken (this branch)

### Closed — genuinely done (2)
| ID | Title | Why |
|---|---|---|
| `chh` | Create Python project structure | `python/` with `pyproject.toml`, `src/lichen/`, `tests/`, pytest, type hints all present |
| `p4w` | Implement Radio abstraction trait | `radio/base.py` defines `Radio(Protocol)`; `SimRadio` implements it with full tests. Hardware backends (sx126x/sx127x) and `cad()` are out of scope for the Python prototype and belong to the embedded phases (`42x`/`ihv`/`vgk`) |

### Reopened — closed without a working deliverable (3)
| ID | Title | Why the close was false |
|---|---|---|
| `5d7` | Implement SCHC compression in Python | Close reason claimed it was "completed"; `schc/rules.py` is a corrupt non-functional blob, `__init__.py` empty. Commit `7707845` ("Complete SCHC…") only added a 1-line blob |
| `4r8` | Implement metrics collection system in Simulation class | Close reason claimed "comprehensive metrics tracking"; `simulation.py` contains **zero** metrics code |
| `6l2` | Implement metrics collection for simulation harness | Closed for producing a "plan" only — no code was added |

## Reviewed and intentionally left as-is
- **`c0b` (Evaluate libschc)** — left **closed**. This is an *evaluation* task; its
  deliverable is a recommendation, which the close reason provides. The missing
  *implementation* is tracked by `5d7` (reopened) and `8bm` (open), so reopening
  `c0b` would be wrong scoping.
- **Tech-debt issues on existing sim code** (`zwz`, `irc`, `9ee`, `e0e`, `nde`,
  `tb6`, `cy1`, `cot`, `sfk`, …) — left **open**; they correctly describe real
  problems in code that exists.
- **Phases 1–4, security, CoAP, Rust, Zephyr, clients, border router** — left
  **open**; legitimately unbuilt future work (no modules exist).
- **Phase 0 epic `7xg`** — left **open**. Exit criteria check: multi-node sim
  runs (radio-only ✓ / protocol-stack ✗), SCHC validated ✗, RPL DODAG forms ✗,
  CoAP end-to-end ✗. Not complete.

## Net effect
- Open issues: 88 → 89 (−2 closed, +3 reopened).
- The tracker now reflects that Phase 0's *simulator* is done but its *protocol
  validation* has not started, and that SCHC/metrics remain to be built.
