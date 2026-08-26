# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Public address classification table for the routing decision gate."""

from __future__ import annotations

from enum import StrEnum
from ipaddress import AddressValueError, IPv6Address

from lichen.rpl.evidence import (
    MAX_LOCAL_EVIDENCE_PEERS,
    EvidenceTable,
    GradientEntry,
)


class AddressClassification(StrEnum):
    """Stable routing classification names from spec section 7.2."""

    DIRECT_NEIGHBOR = "direct_neighbor"
    LOCAL_MESH = "local_mesh"
    IDENTITY_PRESERVING_GLOBAL = "identity_preserving_global"
    OFF_MESH = "off_mesh"


class AddressClassificationError(ValueError):
    """An address cannot participate in the classification table."""


def _parse_ipv6(address: str | IPv6Address) -> IPv6Address:
    if not isinstance(address, (str, IPv6Address)):
        raise AddressClassificationError("address must be an IPv6 string or IPv6Address")
    try:
        return IPv6Address(address)
    except (AddressValueError, ValueError) as exc:
        raise AddressClassificationError(f"invalid IPv6 address: {address!r}") from exc


def _is_primary(address: IPv6Address) -> bool:
    return address.packed[0] == 0x02


class AddressClassificationTable:
    """Classify destinations using authenticated, expiring local evidence.

    Precedence is link-local direct, primary-with-evidence local, primary
    without evidence global-profile, then other/unknown off-mesh.
    """

    def __init__(self, max_peers: int = MAX_LOCAL_EVIDENCE_PEERS) -> None:
        self._evidence = EvidenceTable(max_peers=max_peers)

    @property
    def max_peers(self) -> int:
        """Maximum number of live primary-address observations."""
        return self._evidence.max_peers

    def __len__(self) -> int:
        return len(self._evidence)

    def update_authenticated(
        self,
        address: str | IPv6Address,
        now_s: int,
        *,
        source: str,
    ) -> GradientEntry:
        """Refresh authenticated evidence for one canonical primary address."""
        parsed = _parse_ipv6(address)
        if not _is_primary(parsed):
            raise AddressClassificationError(
                "local evidence updates require a primary 0200::/8 address"
            )
        return self._evidence.refresh(str(parsed), now_s, source=source)

    def classify(self, address: str | IPv6Address, now_s: int) -> AddressClassification:
        """Return the routing class at one monotonic timestamp."""
        parsed = _parse_ipv6(address)
        if parsed.is_link_local:
            # Advance and enforce the shared clock even though evidence is not
            # consulted for the highest-precedence direct-neighbor class.
            self._evidence.has_evidence(str(parsed), now_s)
            return AddressClassification.DIRECT_NEIGHBOR
        if _is_primary(parsed):
            if self._evidence.has_evidence(str(parsed), now_s):
                return AddressClassification.LOCAL_MESH
            return AddressClassification.IDENTITY_PRESERVING_GLOBAL
        self._evidence.has_evidence(str(parsed), now_s)
        return AddressClassification.OFF_MESH

    def has_local_evidence(self, address: str | IPv6Address, now_s: int) -> bool:
        """Return live evidence for a canonical primary address only."""
        parsed = _parse_ipv6(address)
        if not _is_primary(parsed):
            self._evidence.has_evidence(str(parsed), now_s)
            return False
        return self._evidence.has_evidence(str(parsed), now_s)

    def prune(self, now_s: int) -> int:
        """Remove all expired classifications."""
        return self._evidence.prune(now_s)
