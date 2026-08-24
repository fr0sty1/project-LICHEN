# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Independent authenticated state anchors for rollback-sensitive files."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class AnchoredState:
    """Trusted revision and digest retained outside the protected files."""

    revision: int
    digest: bytes

    def __post_init__(self) -> None:
        if type(self.revision) is not int or not 1 <= self.revision <= (1 << 64) - 1:
            raise ValueError("anchor revision must be a nonzero u64")
        if type(self.digest) is not bytes or len(self.digest) != 32:
            raise ValueError("anchor digest must be exact 32-byte bytes")


class StateRevisionAnchor(Protocol):
    """Compare-and-advance storage independent of the protected directory."""

    def read(self, key: bytes) -> AnchoredState | None: ...

    def advance(
        self,
        key: bytes,
        expected: AnchoredState | None,
        state: AnchoredState,
    ) -> None: ...


def read_anchor(
    anchor: StateRevisionAnchor,
    key: bytes,
    error_type: type[Exception],
) -> AnchoredState | None:
    """Read and runtime-validate one external anchor record."""
    try:
        value = anchor.read(key)
    except BaseException as exc:
        raise error_type("independent rollback anchor read failed") from exc
    if value is not None and type(value) is not AnchoredState:
        raise error_type("independent rollback anchor returned invalid state")
    return value


def advance_anchor(
    anchor: StateRevisionAnchor,
    key: bytes,
    expected: AnchoredState | None,
    state: AnchoredState,
    error_type: type[Exception],
) -> None:
    """Advance and verify one external anchor record."""
    try:
        anchor.advance(key, expected, state)
    except BaseException as exc:
        raise error_type("independent rollback anchor update failed") from exc
    if read_anchor(anchor, key, error_type) != state:
        raise error_type("independent rollback anchor did not advance")


__all__ = [
    "AnchoredState",
    "StateRevisionAnchor",
    "advance_anchor",
    "read_anchor",
]
