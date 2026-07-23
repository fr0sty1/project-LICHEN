# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Link-layer replay protection (spec section 4.4).

Replay protection orders the 8-bit epoch as a finite value and uses a sliding
window only for the 16-bit sequence number within that epoch. A higher epoch
starts a fresh sequence window; a lower epoch is always stale. Epoch 255 is
terminal, so advancing from ``(255, 65535)`` to ``(0, 0)`` requires a new key
and replay state.

Each receiver keeps, per sender, the highest counter seen plus a sliding
bitmap window so that out-of-order-but-recent frames are still accepted exactly
once. This implements the spec's acceptance rules:

    Epoch  > LastEpoch                          -> accept
    Epoch == LastEpoch, SeqNum > LastSeqNum     -> accept
    Epoch == LastEpoch, SeqNum within window    -> accept iff not already seen
    Epoch  < LastEpoch                          -> reject (replay)
    Epoch == LastEpoch, SeqNum <= window floor  -> reject (replay)

Sequence numbers do not wrap within an epoch. Ordinary sequence exhaustion is
handled by advancing to the next epoch, up to the finite epoch limit.

The 24-bit logical counter (epoch<<16 | seqnum) uses half-space arithmetic in
some comparison paths (see seqnum.signed_diff, CoAP observe, gradient timers).
The boundary at diff=0x800000 treats frames exactly 8,388,608 positions 'ahead'
as old/replay. This is intentional and conservative: frames more than half the
counter space away could be either very old OR very far ahead, so reject. The
WRAPAROUND_WARNING_THRESHOLD at 0xFF0000 ensures re-keying happens before the
ambiguous zone. This is defense in depth; epoch logic and spec prohibition on
full wrap make the edge case unreachable in normal operation.
"""

from __future__ import annotations

import warnings
from collections import OrderedDict

WINDOW_SIZE = 32  # out-of-order tolerance, in counter positions (spec 4.4)

# SECURITY: Warn when the finite counter approaches its terminal value. At this
# threshold (~64K frames remaining), the receiver should expect re-keying.
WRAPAROUND_WARNING_THRESHOLD = 0xFF0000


def logical_counter(epoch: int, seqnum: int) -> int:
    """Combine an 8-bit epoch and 16-bit seqnum into the 24-bit counter."""
    if not 0 <= epoch <= 0xFF:
        raise ValueError(f"epoch out of range: {epoch}")
    if not 0 <= seqnum <= 0xFFFF:
        raise ValueError(f"seqnum out of range: {seqnum}")
    return (epoch << 16) | seqnum


class ReplayWindow:
    """Anti-replay sliding window over the logical counter, for a single sender.

    The window tracks the highest accepted counter and a same-epoch sequence
    bitmap where bit ``i`` means ``highest_seqnum - i`` has been seen.
    """

    def __init__(self, window_size: int = WINDOW_SIZE) -> None:
        if window_size != WINDOW_SIZE:
            raise ValueError(f"window_size must be {WINDOW_SIZE}, got {window_size}")
        self._window_size = window_size
        self._highest = -1  # no frame accepted yet
        self._bitmap = 0
        self._wraparound_warned = False

    @property
    def highest(self) -> int:
        """Highest logical counter accepted so far, or -1 if none."""
        return self._highest

    def check_and_update(self, epoch: int, seqnum: int) -> bool:
        """Validate a frame's (epoch, seqnum) and record it if fresh.

        Returns:
            True if the frame is fresh (accepted); False if it is a replay or
            falls below the window floor. State is only updated on acceptance.
        """
        counter = logical_counter(epoch, seqnum)

        # First frame from this sender.
        if self._highest < 0:
            self._highest = counter
            self._bitmap = 1
            # SECURITY: Warn if the first frame is already near exhaustion.
            if counter >= WRAPAROUND_WARNING_THRESHOLD:
                self._wraparound_warned = True
                warnings.warn(
                    f"Replay counter {counter:#x} approaching 24-bit limit (0xFFFFFF). "
                    "Re-key this link before counter exhaustion.",
                    UserWarning,
                    stacklevel=2,
                )
            return True

        highest_epoch = self._highest >> 16
        if epoch < highest_epoch:
            return False

        if epoch > highest_epoch:
            self._highest = counter
            self._bitmap = 1
            if not self._wraparound_warned and counter >= WRAPAROUND_WARNING_THRESHOLD:
                self._wraparound_warned = True
                warnings.warn(
                    f"Replay counter {counter:#x} approaching 24-bit limit (0xFFFFFF). "
                    "Re-key this link before counter exhaustion.",
                    UserWarning,
                    stacklevel=2,
                )
            return True

        highest_seqnum = self._highest & 0xFFFF
        if seqnum > highest_seqnum:
            shift = seqnum - highest_seqnum
            if shift >= self._window_size:
                self._bitmap = 1
            else:
                self._bitmap = ((self._bitmap << shift) | 1) & (
                    (1 << self._window_size) - 1
                )
            self._highest = counter
            # SECURITY: Warn once when approaching the terminal counter value.
            if not self._wraparound_warned and counter >= WRAPAROUND_WARNING_THRESHOLD:
                self._wraparound_warned = True
                warnings.warn(
                    f"Replay counter {counter:#x} approaching 24-bit limit (0xFFFFFF). "
                    "Re-key this link before counter exhaustion.",
                    UserWarning,
                    stacklevel=2,
                )
            return True

        # Within or below the same-epoch window.
        offset = highest_seqnum - seqnum
        if offset >= self._window_size:
            return False  # below the window floor: too old
        mask = 1 << offset
        if self._bitmap & mask:
            return False  # already seen: replay
        self._bitmap |= mask
        return True


class ReplayProtector:
    """Per-sender replay protection.

    Maintains an independent :class:`ReplayWindow` for each sender identity, so
    senders never interfere with one another.
    """

    def __init__(self, window_size: int = WINDOW_SIZE, max_peers: int = 32) -> None:
        if window_size != WINDOW_SIZE:
            raise ValueError(f"window_size must be {WINDOW_SIZE}, got {window_size}")
        if max_peers < 1:
            raise ValueError(f"max_peers must be positive, got {max_peers}")
        self._window_size = window_size
        self._max_peers = max_peers
        self._windows: OrderedDict[bytes | str | int, ReplayWindow] = OrderedDict()

    def check_and_update(
        self, sender: bytes | str | int, epoch: int, seqnum: int
    ) -> bool:
        """Validate and record a frame from ``sender``.

        Returns:
            True if fresh (accepted), False if a replay / below the window.
        """
        if sender in self._windows:
            self._windows.move_to_end(sender)
            window = self._windows[sender]
        else:
            if len(self._windows) >= self._max_peers:
                self._windows.popitem(last=False)
            window = ReplayWindow(self._window_size)
            self._windows[sender] = window
            self._windows.move_to_end(sender)
        return window.check_and_update(epoch, seqnum)

    def reset(self, sender: bytes | str | int) -> None:
        """Forget all state for a sender (e.g. on re-keying)."""
        self._windows.pop(sender, None)
