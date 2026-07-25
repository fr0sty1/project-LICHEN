# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Observable presence resource for mesh node tracking."""

from __future__ import annotations

import math
from typing import Any

import cbor2
from aiocoap import CONTENT, Message, resource

from lichen.coap.resources.base import CBOR


class PresenceResource(resource.ObservableResource):
    """Observable ``/presence`` — CBOR list of recently-heard mesh nodes.

    Each entry is a plain dict serialised to CBOR::

        {"id": "<hex-eui64>", "rank": 256, "t": 1700000000.0}

    An optional ``"rssi"`` key (integer dBm) is included when the caller
    provides it.  Entries are keyed internally by the hex EUI-64 string so
    a later :meth:`seen` call for the same node overwrites the old entry.

    Example::

        presence = PresenceResource()
        site = build_site(info, presence_resource=presence)
        # When a beacon arrives from a neighbour:
        presence.seen(bytes.fromhex("0102030405060708"), rank=256, t=1700000000.0)
    """

    def __init__(self) -> None:
        super().__init__()
        self._peers: dict[str, dict[str, Any]] = {}

    def seen(
        self,
        eui64: bytes,
        rank: int,
        t: float,
        rssi: int | None = None,
    ) -> None:
        """Record or refresh a peer's presence and notify observers.

        Args:
            eui64: 8-byte EUI-64 identifier of the peer.
            rank:  RPL rank of the peer node.
            t:     Unix timestamp of the observation (>= 0).
            rssi:  Received signal strength in dBm, or ``None`` if unknown.
        """
        if (
            isinstance(t, bool)
            or not isinstance(t, (int, float))
            or (isinstance(t, float) and not math.isfinite(t))
            or t < 0
        ):
            raise ValueError("timestamp must be non-negative finite number")
        entry: dict[str, Any] = {"id": eui64.hex(), "rank": rank, "t": t}
        if rssi is not None:
            entry["rssi"] = rssi
        self._peers[eui64.hex()] = entry
        self.updated_state()

    def evict(self, eui64: bytes) -> None:
        """Remove a peer from the presence table and notify observers.

        No-op if the peer is not in the table.
        """
        if self._peers.pop(eui64.hex(), None) is not None:
            self.updated_state()

    def purge_older_than(self, cutoff_t: float) -> int:
        """Remove entries with ``t < cutoff_t`` and notify if any were removed.

        cutoff_t must be non-negative.

        Returns the number of entries evicted.
        """
        if (
            isinstance(cutoff_t, bool)
            or not isinstance(cutoff_t, (int, float))
            or (isinstance(cutoff_t, float) and not math.isfinite(cutoff_t))
            or cutoff_t < 0
        ):
            raise ValueError("cutoff timestamp must be non-negative finite number")
        peers = dict(self._peers)
        stale = [k for k, v in peers.items() if v["t"] < cutoff_t]
        for k in stale:
            self._peers.pop(k, None)
        if stale:
            self.updated_state()
        return len(stale)

    async def render_get(self, request: Message) -> Message:
        msg = Message(code=CONTENT, payload=cbor2.dumps(list(self._peers.values())))
        msg.opt.content_format = CBOR
        return msg
