# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LOADng local-evidence gate (spec appendix-loadng.md B2.5).

Local evidence for a destination means a non-expired gradient-table
entry exists, populated by an authenticated source (Announce, RREP,
RPL, or DATA). The LOADng initiator emits RREQ only when this gate
reports no evidence.

Expiry boundary per ``test/vectors/local_evidence.json``:
an entry with ``expires <= now`` is expired ("expires exactly at
lookup time" yields no evidence).

This module is the conformance oracle for the evidence gate; the main
``GradientTable`` in ``lichen.rpl.routing`` integrates these semantics.
"""

from __future__ import annotations

from dataclasses import dataclass

AUTHENTICATED_SOURCES = frozenset({"announce", "rrep", "rpl", "data"})


@dataclass(frozen=True)
class GradientEntry:
    """One reachability record as stored by the gradient table."""

    destination: str
    next_hop: str
    hop_count: int
    seq_num: int
    source: str
    expires: int


class EvidenceTable:
    """Minimal gradient table exposing only the B2.5 evidence gate."""

    def __init__(self) -> None:
        self._entries: dict[str, GradientEntry] = {}

    def add(self, entry: GradientEntry) -> None:
        self._entries[entry.destination] = entry

    def has_evidence(self, destination: str, now: int) -> bool:
        """True iff an unexpired entry exists for ``destination``."""
        entry = self._entries.get(destination)
        if entry is None:
            return False
        return now < entry.expires
