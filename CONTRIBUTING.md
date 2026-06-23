# Contributing to LICHEN

LICHEN is an open-source LoRa IPv6 mesh protocol stack. Contributions are welcome at every layer — from the Python simulator to future Rust/C embedded implementations.

## Development environment

```bash
git clone https://github.com/fr0sty1/project-LICHEN
cd project-LICHEN/python
pip install -e ".[dev]"
```

Requires Python 3.11+. The `[dev]` extras install pytest, ruff, mypy, and httpx.

## Running the tests

```bash
cd python
pytest                          # all tests (1100+)
pytest tests/sim/               # simulator tests only
pytest --timeout=30             # with per-test timeout
```

Tests are fully deterministic; no external services are needed.

## Code style

We use **ruff** for linting and formatting:

```bash
ruff check src/ tests/          # lint
ruff check --fix src/ tests/    # auto-fix safe violations
```

Configuration lives in `python/pyproject.toml` (`[tool.ruff]`). Rule set: E, F, I, N, W, UP, B, C4, SIM. Line length is 100.

Type-checking with **mypy** (strict):

```bash
mypy src/lichen/
```

CI runs both on every PR.

## Architectural guidelines

- **No external state.** Simulation classes are deterministic; pass a `seed` for reproducibility.
- **Protocol layers are independent.** IPv6, SCHC, RPL, CoAP, and the link layer each live in their own package and can be tested in isolation.
- **No magic numbers.** Protocol constants belong in `python/src/lichen/constants.py` and the root `constants.toml`.
- **Type-annotated.** All new functions need full type annotations. `mypy --strict` must pass.

See `AGENTS.md` for the full protocol stack description and `spec/` for the protocol specification.

## Submitting changes

1. Fork the repository and create a branch from `main`.
2. Write tests for new behaviour. Tests must not be modified to pass — fix the code.
3. Run `ruff check` and `pytest` locally before opening a PR.
4. Keep PRs focused. A bug fix does not need adjacent refactoring.
5. Reference the relevant `bd` issue ID in the PR title (e.g. `feat: add DAO relay (abc)`).

## Issue tracking

We use **beads** (`bd`) for issue tracking. See `bd ready` for available work. New contributors can start with P3/P4 issues — search for issues with no blockers.

## Crypto-gated work

Several features (Schnorr link signatures, OSCORE, multi-hop with auth) require test vectors from the maintainer before implementation. These are marked as blocked in the issue tracker. Don't implement them speculatively.

## Questions?

Open a GitHub Discussion or comment on the relevant issue.
