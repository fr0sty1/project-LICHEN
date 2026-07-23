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
    """Why an announce was rejected (for logging/debugging)."""

    INVALID_SIGNATURE = auto()
    IID_MISMATCH = auto()       # IID doesn't match pubkey hash
    STALE_SEQNUM = auto()       # seq_num <= existing
    HOP_LIMIT_EXCEEDED = auto()
    MALFORMED = auto()
    KEY_CHANGE_DETECTED = auto()  # IID known, pubkey differs from pinned


@dataclass
class AnnounceResult:
    """Result of processing an announce message.

    Why a result object: Callers need to know what happened for logging,
    metrics, and deciding whether to relay. A simple bool loses information.

    Attributes:
        accepted: Whether the announce was accepted and gradient updated.
        should_relay: Whether this announce should be broadcast.
            Why separate from accepted: We accept (update gradient) but might
            not relay (hop limit reached, or duplicate from better path).
        reject_reason: Why the announce was rejected, if not accepted.
        peer: The sender's identity if signature verified.
        congestion: Queue depth from announce app_data (spec 11.4), or None.
    """

    accepted: bool
    should_relay: bool
    reject_reason: AnnounceRejectReason | None = None
    peer: PeerIdentity | None = None
    congestion: int | None = None


@dataclass
class AnnounceProcessor:
    """Processes incoming announce messages (spec 9.3).

    Why a class: Needs state across invocations:
    - gradient_table: Where to install/update routes
    - seen_announces: Per-originator seq_num for duplicate detection
    - address_builder: How to convert IID to full IPv6 (prefix is context)

    Attributes:
        gradient_table: Unified routing table (spec section 11).
        address_builder: Callback to build IPv6 address from IID.
            Why a callback: The prefix (ULA or GUA) is network context.
            The processor doesn't know/care about prefix assignment.
        _seen: Per-originator highest seq_num seen (LRU-bounded).
            Why OrderedDict: Bounded to MAX_ENTRIES to prevent unbounded growth.
            IID is the key, seq_num is the value.
        _pinned_keys: IID → pinned pubkey (TOFU trust anchors, LRU-bounded).
            Why separate from _seen: An IID's seq_num resets on reboot;
            the pinned pubkey must NOT change (that would be a key change).
    """

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
        """Process an incoming announce message (spec 9.3 pseudocode).

        Why from_neighbor: This is who we received it from, which becomes the
        next_hop in our gradient. Not the originator (they may be many hops away).

        Why now_ms: Timestamp for gradient expiration. Caller-supplied for
        testability under simulation.

        Args:
            announce: The parsed announce message.
            from_neighbor: Link-local address of the neighbor who sent this.
            now_ms: Current time in milliseconds.

        Returns:
            AnnounceResult indicating what happened.
        """
        # Step 1: Verify IID matches pubkey hash
        # Why first: This is a cheap check before expensive crypto.
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

        # Step 2: Verify signature
        # Why: Proves the announce was created by the holder of this pubkey.
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

        # Step 3: Key pinning — TOFU anchor + change detection.
        # Why: Even though IID = hash(pubkey) makes silent substitution
        # cryptographically infeasible, we maintain an explicit pin table as
        # defence-in-depth. A pin mismatch means either hash collision or a
        # bug in key derivation — both warrant a hard reject.
        iid = announce.originator_iid
        pinned_pubkey = self._pinned_keys.get(iid)
        if pinned_pubkey is not None and pinned_pubkey != announce.pubkey:
            logger.error(
                "KEY CHANGE DETECTED for IID %s: pinned=%s got=%s — rejecting",
                iid.hex(),
                pinned_pubkey.hex()[:16],
                announce.pubkey.hex()[:16],
            )
            return AnnounceResult(
                accepted=False,
                should_relay=False,
                reject_reason=AnnounceRejectReason.KEY_CHANGE_DETECTED,
            )

        # Step 4: Check for stale/duplicate (RFC 1982 serial arithmetic)
        # Why: Prevents processing old announces that were delayed in the network.
        # Why seq_gt: 16-bit seq_num wraps. Simple comparison fails after 65535→0.
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

        # Step 5: Update gradient table BEFORE updating _seen/_pinned_keys.
        # Why this order: If gradient_table.update() or address_builder() fails,
        # we must NOT mark this announce as "seen" — otherwise future retransmissions
        # will be rejected as STALE_SEQNUM but we have no route to the originator.
        # By updating the gradient first, failure leaves state unchanged.
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

        # Step 6: Pin pubkey (TOFU first-contact) and update seen cache.
        # Only reached if gradient update succeeded.
        # Use LRU eviction to bound memory: move to end, then evict oldest if over limit.
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

        # Step 7: Decide relay
        # Why: Propagate announces through the mesh, up to hop limit.
        should_relay = announce.should_relay()

        peer = PeerIdentity(pubkey=announce.pubkey, iid=iid)
        return AnnounceResult(
            accepted=True,
            should_relay=should_relay,
            peer=peer,
            congestion=congestion,
        )

    def get_relay_message(self, announce: AnnounceMessage) -> AnnounceMessage | None:
        """Get the message to relay, with incremented hop count.

        Why separate method: process() returns a result, not a modified message.
        Caller calls this if should_relay is True.

        Returns:
            Modified announce with hop_count + 1, or None if hop limit exceeded.
        """
        if not announce.should_relay():
            return None
        return announce.with_incremented_hop_count()

    def reset_seen(self, iid: bytes) -> None:
        """Forget the seq_num for an originator (e.g., on key rotation).

        Why: If a node rotates keys, their seq_num may reset. Forgetting
        allows accepting announces from their new identity.
        """
        self._seen.pop(iid, None)

    def unpin(self, iid: bytes) -> None:
        """Remove the key pin for an IID (use only for intentional key rotation).

        Why: Administrators who rotate a node's key must unpin the old binding
        or all future announces from the new key will be rejected as key changes.
        This is an intentional administrative action — not automatic.
        """
        self._pinned_keys.pop(iid, None)

    def pinned_pubkey_for(self, iid: bytes) -> bytes | None:
        """Return the pinned pubkey for an IID, or None if not yet seen."""
        return self._pinned_keys.get(iid)

    def known_originators(self) -> list[bytes]:
        """Return IIDs of all originators we've seen announces from.

        Why: For debugging/monitoring. Not for production routing logic.
        """
        return list(self._seen.keys())
