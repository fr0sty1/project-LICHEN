# Contributing to LICHEN

LICHEN is an open-source LoRa IPv6 mesh protocol stack. Contributions are welcome at every layer — from the Python simulator to future Rust/C embedded implementations.

## Development environment

### Python prototype

```bash
git clone https://github.com/fr0sty1/project-LICHEN
cd project-LICHEN/python
pip install -e ".[dev]"
```

Requires Python 3.11+. The `[dev]` extras install pytest, ruff, mypy, and httpx.

### Rust implementation

```bash
# Install Rust toolchain (https://rustup.rs)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

cd rust
cargo build           # build all crates
cargo test            # run all tests
cargo clippy          # lint
cargo fmt --check     # format check
```

The workspace uses `resolver = "2"`. Core crates (`lichen-core`, `lichen-link`, `lichen-schc`) are `no_std`. Gateway and simulator crates require `std`.

### Zephyr embedded targets

Install prerequisites:
- [west](https://docs.zephyrproject.org/latest/develop/west/install.html): `pip install west`
- [Zephyr SDK](https://docs.zephyrproject.org/latest/develop/toolchains/zephyr_sdk.html) ≥ 0.16
  - `arm-zephyr-eabi` — for nRF52840 (RAK4631) and STM32WL (Nucleo-WL55JC) targets
  - `xtensa-espressif_esp32s3_zephyr-elf` — for ESP32-S3 targets

Initialise the workspace (run from `project-LICHEN/`):
```bash
rm -rf .west          # if retrying after a failed west update
west init -l lichen/
west update           # clones Zephyr v3.7.0 into zephyr/ alongside lichen/
west zephyr-export
pip install -r zephyr/scripts/requirements.txt
```

Build:
```bash
west build -b rak4631_nrf52840 lichen/apps/puck    # nRF52840 puck
west build -b native_sim       lichen/apps/gateway  # simulation target
```

See `lichen/README.md` for the full board matrix.

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

### Protocol vs ABC

The codebase uses two patterns for abstract types — use whichever fits:

- **`typing.Protocol`** — structural subtyping ("duck typing"). Implementors need not inherit from the Protocol class. Use this when you want to define a capability that multiple unrelated classes can satisfy without coupling them to a base class. Example: `radio/base.py` — `SimRadio` satisfies `Radio` without inheriting it.

- **`abc.ABC`** — nominal subtyping. Implementors must explicitly inherit. Use this when all implementations belong to a known closed hierarchy and you want `isinstance` checks to work. Example: `sim/chaos.py` — all `ChaosRule` subclasses are registered types that the engine dispatches over.

Both are correct; the choice depends on whether the type is open (Protocol) or closed (ABC).

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
