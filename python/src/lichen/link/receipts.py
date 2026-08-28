# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Verified receipt storage for LICHEN link layer.

This module manages verified frame receipts that bind authenticated RxFrame
facades to their internal snapshots. Receipts allow callers to consume
authenticated frames for specific trust purposes (SCHC ACKs, DIO parsing, etc.)
while preventing reuse.

The ReceiptStore is extracted from LinkLayer to isolate receipt lifecycle
management (storage, expiration, consumption) from the broader link layer
concerns.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from typing import TYPE_CHECKING

from .frames import RxFrame, _VerifiedReceipt

if TYPE_CHECKING:
    pass

# Maximum receipts stored per peer before oldest are evicted.
MAX_VERIFIED_RECEIPTS_PER_PEER = 16

# Maximum total receipts across all peers.
# Import MAX_ENTRIES inline to avoid circular import at module load.
MAX_VERIFIED_RECEIPTS = 64 * MAX_VERIFIED_RECEIPTS_PER_PEER  # 1024

# Receipt expiration time in seconds.
VERIFIED_RECEIPT_TTL_SECONDS = 60.0

# Valid purposes for receipt consumption.
VERIFIED_RECEIPT_PURPOSES = frozenset(
    {
        "schc-ack",
        "schc-data",
        "schc-fragment",
        "dio-time",
        "dio-schc-version",
        "dio-authenticated",
        "link-rekey",
    }
)


class ReceiptStore:
    """Manages verified frame receipts for a LinkLayer.

    A ReceiptStore holds receipts that bind RxFrame facade objects to their
    authenticated snapshots. Each receipt is keyed by the facade's object id,
    ensuring that only the exact facade issued by LinkLayer.receive() can
    consume the receipt.

    Receipts expire after VERIFIED_RECEIPT_TTL_SECONDS and are purged lazily
    on store/take operations. Per-peer and global limits prevent unbounded
    memory growth.

    This class is NOT thread-safe. The caller (LinkLayer) must hold its
    security lock when calling these methods.

    Attributes:
        time_source: Callable returning current monotonic time in seconds.
    """

    def __init__(self, time_source: Callable[[], float]) -> None:
        """Initialize an empty receipt store.

        Args:
            time_source: Callable that returns the current monotonic time
                in seconds. Called on purge operations when no explicit
                time is provided.
        """
        self._time_source = time_source
        self._receipts: OrderedDict[int, _VerifiedReceipt] = OrderedDict()

    def __len__(self) -> int:
        """Return the number of stored receipts."""
        return len(self._receipts)

    def purge(self, now: float | None = None) -> None:
        """Remove expired receipts.

        Args:
            now: Current monotonic time. If None, obtained from time_source.
        """
        current = self._time_source() if now is None else now
        expired = [
            receipt_id
            for receipt_id, receipt in self._receipts.items()
            if current >= receipt.expires_at
        ]
        for receipt_id in expired:
            self._receipts.pop(receipt_id, None)

    def store(
        self,
        facade: RxFrame,
        snapshot: RxFrame,
        *,
        sender_was_pinned: bool,
    ) -> None:
        """Store a verified receipt for a received frame.

        Purges expired receipts, enforces per-peer and global limits by
        evicting oldest entries, then stores the new receipt.

        Args:
            facade: The RxFrame object returned to the caller.
            snapshot: The authenticated RxFrame snapshot (may be same object).
            sender_was_pinned: Whether the sender's key was already pinned
                at time of verification.
        """
        received_time = snapshot.received_monotonic
        self.purge(received_time)

        # Enforce per-peer limit by evicting oldest from same sender.
        same_peer = [
            receipt_id
            for receipt_id, receipt in self._receipts.items()
            if receipt.snapshot.sender_pubkey == snapshot.sender_pubkey
        ]
        while len(same_peer) >= MAX_VERIFIED_RECEIPTS_PER_PEER:
            self._receipts.pop(same_peer.pop(0), None)

        # Store the new receipt.
        self._receipts[id(facade)] = _VerifiedReceipt(
            facade=facade,
            snapshot=snapshot,
            expires_at=received_time + VERIFIED_RECEIPT_TTL_SECONDS,
            sender_was_pinned=sender_was_pinned,
        )
        self._receipts.move_to_end(id(facade))

        # Enforce global limit.
        while len(self._receipts) > MAX_VERIFIED_RECEIPTS:
            self._receipts.popitem(last=False)

    def take(self, received: RxFrame, purpose: str) -> _VerifiedReceipt:
        """Take and remove a verified receipt entry.

        Validates the purpose, purges expired receipts, then removes and
        returns the receipt if the facade matches exactly.

        Args:
            received: The RxFrame facade to look up.
            purpose: The trust purpose for this consumption.

        Returns:
            The _VerifiedReceipt entry containing facade, snapshot, and metadata.

        Raises:
            ValueError: If purpose is not in VERIFIED_RECEIPT_PURPOSES or
                if no unconsumed receipt exists for the given frame.
        """
        if purpose not in VERIFIED_RECEIPT_PURPOSES:
            raise ValueError(f"unsupported verified-frame receipt purpose: {purpose!r}")
        self.purge()
        registered = self._receipts.pop(id(received), None)
        if registered is None or registered.facade is not received:
            raise ValueError("frame lacks this LinkLayer's unconsumed verified receipt")
        return registered

    def consume(self, received: RxFrame, purpose: str) -> RxFrame:
        """Consume a verified receipt and return the authenticated snapshot.

        This is the primary public interface for receipt consumption. It
        validates the frame, removes the receipt, and returns the snapshot
        that callers can trust for the specified purpose.

        Args:
            received: The RxFrame facade to consume.
            purpose: The trust purpose (e.g., "schc-ack", "dio-time").

        Returns:
            The authenticated RxFrame snapshot.

        Raises:
            ValueError: If purpose is invalid or no receipt exists.
        """
        return self.take(received, purpose).snapshot
