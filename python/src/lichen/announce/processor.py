# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Announce message processing (spec section 9.3).
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from ipaddress import IPv6Address

from lichen.announce.coords import decode_congestion, decode_coords
from lichen.announce.messages import (
    MAX_ANNOUNCE_HOPS,
    AnnounceMessage,
)
from lichen.crypto.identity import PeerIdentity, _pubkey_to_iid
from lichen.crypto.schnorr48 import verify
from lichen.gradient import (
    GRADIENT_TIMEOUT_MS,
    MAX_ENTRIES,
    GradientEntry,
    GradientSource,
    GradientTable,
)

logger = logging.getLogger(__name__)

SEQ_BITS = 16
SEQ_HALF = 1 << (SEQ_BITS - 1)


def seq_gt(a: int, b: int) -> bool:
    diff = (a - b) & 0xFFFF
    return a != b and diff < SEQ_HALF


ANNOUNCE_INTERVAL_MS = 300_000
ANNOUNCE_JITTER_MS = 30_000


class AnnounceRejectReason(Enum):
    INVALID_SIGNATURE = auto()
    IID_MISMATCH = auto()
    STALE_SEQNUM = auto()
    HOP_LIMIT_EXCEEDED = auto()
    MALFORMED = auto()


@dataclass
class AnnounceResult:
    accepted: bool
    should_relay: bool
    reject_reason: AnnounceRejectReason | None = None
    peer: PeerIdentity | None = None
    congestion: int | None = None


@dataclass
class AnnounceProcessor:
    gradient_table: GradientTable
    address_builder: Callable[[bytes], IPv6Address]
    _seen: OrderedDict[bytes, int] = field(default_factory=OrderedDict, repr=False)
    _pinned_keys: OrderedDict[bytes, bytes] = field(
        default_factory=OrderedDict, repr=False
    )

    def process(
        self,
        announce: AnnounceMessage,
        from_neighbor: IPv6Address,
        now_ms: int,
    ) -> AnnounceResult:
        expected_iid = _pubkey_to_iid(announce.pubkey)
        if announce.originator_iid != expected_iid:
            logger.warning(
                "announce IID mismatch: claimed %s, pubkey derives %s",
                announce.originator_iid.hex(),
                expected_iid.hex(),
            )
            return AnnounceResult(
                accepted=False,
                should_relay=False,
                reject_reason=AnnounceRejectReason.IID_MISMATCH,
            )

        iid = announce.originator_iid

        signable = announce.signed_data()
        if not verify(announce.pubkey, signable, announce.signature):
            logger.warning(
                "announce signature invalid: originator=%s",
                announce.originator_iid.hex(),
            )
            return AnnounceResult(
                accepted=False,
                should_relay=False,
                reject_reason=AnnounceRejectReason.INVALID_SIGNATURE,
            )

        existing_seq = self._seen.get(iid)
        if existing_seq is not None and not seq_gt(announce.seq_num, existing_seq):
            logger.debug(
                "announce stale: originator=%s seq=%d <= seen=%d",
                iid.hex(),
                announce.seq_num,
                existing_seq,
            )
            return AnnounceResult(
                accepted=False,
                should_relay=False,
                reject_reason=AnnounceRejectReason.STALE_SEQNUM,
            )

        if announce.hop_count > MAX_ANNOUNCE_HOPS:
            logger.warning(
                "announce hop limit exceeded: originator=%s hops=%d",
                iid.hex(),
                announce.hop_count,
            )
            return AnnounceResult(
                accepted=False,
                should_relay=False,
                reject_reason=AnnounceRejectReason.HOP_LIMIT_EXCEEDED,
            )

        destination = self.address_builder(iid)
        coords = decode_coords(announce.app_data)
        congestion = decode_congestion(announce.app_data)
        entry = GradientEntry(
            destination=destination,
            next_hop=from_neighbor,
            hop_count=announce.hop_count,
            seq_num=announce.seq_num,
            source=GradientSource.ANNOUNCE,
            expires=now_ms + GRADIENT_TIMEOUT_MS,
            coords=coords,
        )
        self.gradient_table.update(entry, now=now_ms)

        self._pinned_keys[iid] = announce.pubkey
        self._pinned_keys.move_to_end(iid)
        while len(self._pinned_keys) > MAX_ENTRIES:
            self._pinned_keys.popitem(last=False)

        self._seen[iid] = announce.seq_num
        self._seen.move_to_end(iid)
        while len(self._seen) > MAX_ENTRIES:
            self._seen.popitem(last=False)

        logger.debug(
            "announce accepted: originator=%s seq=%d hops=%d via=%s",
            iid.hex(),
            announce.seq_num,
            announce.hop_count,
            from_neighbor,
        )

        should_relay = announce.should_relay()

        peer = PeerIdentity(pubkey=announce.pubkey, iid=iid)
        return AnnounceResult(
            accepted=True,
            should_relay=should_relay,
            peer=peer,
            congestion=congestion,
        )

    def get_relay_message(self, announce: AnnounceMessage) -> AnnounceMessage | None:
        if not announce.should_relay():
            return None
        return announce.with_incremented_hop_count()

    def pinned_pubkey_for(self, iid: bytes) -> bytes | None:
        return self._pinned_keys.get(iid)

    def known_originators(self) -> list[bytes]:
        return list(self._seen.keys())
