"""Announce message processing (spec section 9.3).

Processes incoming announces: verifies signatures, detects duplicates,
updates gradients, decides whether to relay.

Why separate from messages.py: Messages are pure codecs. Processing involves
state (gradient table, seen announces, peer database) and crypto operations.
Separation keeps the codec testable without crypto dependencies.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from ipaddress import IPv6Address
from typing import Callable

from lichen.announce.coords import decode_congestion, decode_coords
from lichen.announce.messages import (
    AnnounceMessage,
    MAX_ANNOUNCE_HOPS,
)
from lichen.crypto.identity import PeerIdentity, _pubkey_to_iid
from lichen.crypto.schnorr48 import verify
from lichen.gradient import GradientEntry, GradientSource, GradientTable

logger = logging.getLogger(__name__)

# Why 300_000: Spec section 9.4. 300 seconds between announces.
ANNOUNCE_INTERVAL_MS = 300_000

# Why 30_000: Spec section 9.4. Random jitter 0-30 seconds prevents collision.
ANNOUNCE_JITTER_MS = 30_000

# Why 600_000: Spec section 9.4. 2x announce interval. Gradient expires if
# no announce received within this window.
GRADIENT_TIMEOUT_MS = 600_000


class AnnounceRejectReason(Enum):
    """Why an announce was rejected (for logging/debugging)."""

    INVALID_SIGNATURE = auto()
    IID_MISMATCH = auto()  # IID doesn't match pubkey hash
    STALE_SEQNUM = auto()  # seq_num <= existing
    HOP_LIMIT_EXCEEDED = auto()
    MALFORMED = auto()


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
        _seen: Per-originator highest seq_num seen.
            Why dict[bytes, int]: IID is the key, seq_num is the value.
    """

    gradient_table: GradientTable
    address_builder: Callable[[bytes], IPv6Address]
    _seen: dict[bytes, int] = field(default_factory=dict, repr=False)

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

        # Step 3: Check for stale/duplicate
        # Why: Prevents processing old announces that were delayed in the network.
        iid = announce.originator_iid
        existing_seq = self._seen.get(iid)
        if existing_seq is not None and announce.seq_num <= existing_seq:
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

        # Accept: update seen and gradient
        self._seen[iid] = announce.seq_num

        # Step 4: Update gradient table
        # Why build full IPv6: Gradient table uses full addresses for lookup.
        destination = self.address_builder(iid)
        coords = decode_coords(announce.app_data)  # None if not present
        congestion = decode_congestion(announce.app_data)  # None if not present
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

        logger.debug(
            "announce accepted: originator=%s seq=%d hops=%d via=%s",
            iid.hex(),
            announce.seq_num,
            announce.hop_count,
            from_neighbor,
        )

        # Step 5: Decide relay
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

    def known_originators(self) -> list[bytes]:
        """Return IIDs of all originators we've seen announces from.

        Why: For debugging/monitoring. Not for production routing logic.
        """
        return list(self._seen.keys())
