# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Announce message processing (spec section 9.3)."""

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
    PIN_TABLE_FULL = auto()
    KEY_MISMATCH = auto()  # TOFU: pubkey differs from pinned key


@dataclass
class AnnounceResult:
    accepted: bool
    should_relay: bool
    reject_reason: AnnounceRejectReason | None = None
    peer: PeerIdentity | None = None
    congestion: int | None = None
    rx_channel: int | None = None


@dataclass
class AnnounceProcessor:
    gradient_table: GradientTable
    address_builder: Callable[[bytes], IPv6Address]
    _seen: OrderedDict[bytes, int] = field(default_factory=OrderedDict, repr=False)
    _pinned_keys: OrderedDict[bytes, bytes] = field(default_factory=OrderedDict, repr=False)
    _pending_reconciliation: set[bytes] = field(default_factory=set, repr=False)
    state_committer: Callable[[bytes, bytes, int], None] | None = field(default=None, repr=False)

    def process(
        self,
        announce: AnnounceMessage,
        from_neighbor: IPv6Address,
        now_ms: int,
    ) -> AnnounceResult:
        # Catch ValueError from _pubkey_to_iid if pubkey is malformed (wrong length)
        # or TypeError if pubkey is completely wrong type (None, int, etc).
        # AnnounceMessage validates at construction, but handle gracefully
        # in case of bypassed validation (corrupted deserialization, etc).
        try:
            expected_iid = _pubkey_to_iid(announce.pubkey)
        except (ValueError, TypeError):
            # Safe repr for logging - pubkey may be wrong type (None, int, etc)
            try:
                pubkey_info = f"length {len(announce.pubkey)}"
            except TypeError:
                pubkey_info = f"type {type(announce.pubkey).__name__}"
            logger.warning(
                "announce pubkey malformed: %s != 32 bytes",
                pubkey_info,
            )
            return AnnounceResult(
                accepted=False,
                should_relay=False,
                reject_reason=AnnounceRejectReason.MALFORMED,
            )
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
        reconciling = existing_seq == announce.seq_num and iid in self._pending_reconciliation
        if (
            existing_seq is not None
            and not seq_gt(announce.seq_num, existing_seq)
            and not reconciling
        ):
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

        # Complete TOFU admission before constructing or mutating routing
        # state. A rejected colliding key, or a first-seen key when the pin
        # table is full, must have no effect on the gradient table.
        existing_pubkey = self._pinned_keys.get(iid)
        if existing_pubkey is not None and existing_pubkey != announce.pubkey:
            logger.warning(
                "announce key mismatch: originator=%s pinned_key=%s new_key=%s",
                iid.hex(),
                existing_pubkey.hex()[:16] + "...",
                announce.pubkey.hex()[:16] + "...",
            )
            return AnnounceResult(
                accepted=False,
                should_relay=False,
                reject_reason=AnnounceRejectReason.KEY_MISMATCH,
            )

        if existing_pubkey is None and len(self._pinned_keys) >= MAX_ENTRIES:
            logger.warning(
                "announce pin table full: originator=%s max=%d",
                iid.hex(),
                MAX_ENTRIES,
            )
            return AnnounceResult(
                accepted=False,
                should_relay=False,
                reject_reason=AnnounceRejectReason.PIN_TABLE_FULL,
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

        # Persistence is part of admission, not a best-effort afterthought.
        # A failure is terminal to the receive loop and occurs before any
        # routable or in-memory trust state is exposed.
        if self.state_committer is not None:
            self.state_committer(iid, announce.pubkey, announce.seq_num)
            # The durable floor now exists even if the local route update
            # raises. Retain a one-shot equal-sequence reconciliation permit.
            self._pending_reconciliation.add(iid)
        self.gradient_table.update(entry, now=now_ms)
        self._pending_reconciliation.discard(iid)

        # Commit the already-admitted pin only after gradient construction and
        # update succeed, preserving retryability on local routing failures.
        self._pinned_keys[iid] = announce.pubkey
        self._pinned_keys.move_to_end(iid)

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
            rx_channel=announce.rx_channel,
        )

    def get_relay_message(self, announce: AnnounceMessage) -> AnnounceMessage | None:
        if not announce.should_relay():
            return None
        return announce.with_incremented_hop_count()

    def pinned_pubkey_for(self, iid: bytes) -> bytes | None:
        return self._pinned_keys.get(iid)

    def known_originators(self) -> list[bytes]:
        return list(self._seen.keys())

    def _restore_reconciliation_permit(self, iid: bytes, pubkey: bytes, sequence: int) -> None:
        """Restore one exact permit after a post-commit Node admission failure."""
        if self._seen.get(iid) != sequence or self._pinned_keys.get(iid) != pubkey:
            raise RuntimeError("announce reconciliation state does not match durable admission")
        self._pending_reconciliation.add(iid)
