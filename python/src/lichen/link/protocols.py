# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Link layer protocol interfaces and error types.

This module defines the abstract protocols and exceptions used by the
link layer for persistence and security clock operations.
"""

from __future__ import annotations

from typing import Protocol


class PersistenceRevisionAnchor(Protocol):
    """Independent monotonic revision capability for rollback detection."""

    def read(self, local_pubkey: bytes) -> int | None:
        """Return the durable revision, or None only before explicit bootstrap."""

    def advance(self, local_pubkey: bytes, expected: int | None, revision: int) -> None:
        """Atomically advance from ``expected`` to ``revision`` or raise."""


class _PeerCandidate(Protocol):
    pubkey: object


class LinkPersistenceError(RuntimeError):
    """Terminal LinkLayer storage failure; retrying this instance is unsafe."""


class LinkSecurityClockError(RuntimeError):
    """Terminal receipt-clock failure; authenticated ingress cannot continue."""
