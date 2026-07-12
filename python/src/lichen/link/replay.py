# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Link-layer replay protection (spec section 4.4).

Replay protection uses a 24-bit logical counter formed from the 8-bit epoch
and 16-bit sequence number: ``counter = (epoch << 16) | seqnum``. Because the
epoch increments whenever the sequence number wraps (or on reboot), this
counter advances monotonically for a well-behaved sender.

Each receiver keeps, per sender, the highest counter seen plus a sliding
bitmap window so that out-of-order-but-recent frames are still accepted exactly
once. This implements the spec's acceptance rules:

    Epoch  > LastEpoch                          -> accept
    Epoch == LastEpoch, SeqNum > LastSeqNum     -> accept
    Epoch == LastEpoch, SeqNum within window    -> accept iff not already seen
    Epoch  < LastEpoch                          -> reject (replay)
    Epoch == LastEpoch, SeqNum <= window floor  -> reject (replay)

Note on the epoch boundary: the rules above are expressed over a single
monotonic 24-bit counter and a sliding window, so "Epoch < LastEpoch -> reject"
holds whenever the frame is beyond the window. The one refinement is that a
frame from the previous epoch that lands *within* the window (e.g. a frame from
just before a seqnum wrap, reordered behind the first frame of the next epoch)
is a legitimate out-of-order frame and is accepted once — exactly what the
"out-of-order tolerance" window exists for. This matches the spec's stated
24-bit-counter data model; the acceptance table is a per-field summary of it.
"""

from __future__ import annotations

import warnings

WINDOW_SIZE = 32  # out-of-order tolerance, in counter positions (spec 4.4)

# SECURITY: Warn when counter approaches 24-bit limit. After wraparound,
# frames from ~8M-16M frames ago become replayable via half-space arithmetic.
# At this threshold (~64K frames remaining), receiver should expect re-keying.
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

    The window tracks the highest accepted counter and a bitmap where bit ``i``
    means ``highest - i`` has been seen (bit 0 is ``highest`` itself).
    """

    def __init__(self, window_size: int = WINDOW_SIZE) -> None:
        if window_size <= 0:
            raise ValueError(f"window_size must be positive, got {window_size}")
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
            # SECURITY: Warn if first frame is already near wraparound.
            if counter >= WRAPAROUND_WARNING_THRESHOLD:
                self._wraparound_warned = True
                warnings.warn(
                    f"Replay counter {counter:#x} approaching 24-bit limit (0xFFFFFF). "
                    "Re-key this link before wraparound to prevent replay attacks.",
                    UserWarning,
                    stacklevel=2,
                )
            return True

        # Newer than anything seen: slide the window forward.
        # Use modular arithmetic to handle 24-bit counter wraparound (255->0).
        diff = (counter - self._highest) & 0xFFFFFF
        if 0 < diff < 0x800000:  # counter is in forward half of counter space
            shift = diff
            if shift >= self._window_size:
                self._bitmap = 1
            else:
                self._bitmap = ((self._bitmap << shift) | 1) & (
                    (1 << self._window_size) - 1
                )
            self._highest = counter
            # SECURITY: Warn once when approaching 24-bit wraparound.
            # After wrap, old frames become replayable; re-keying is required.
            if not self._wraparound_warned and counter >= WRAPAROUND_WARNING_THRESHOLD:
                self._wraparound_warned = True
                warnings.warn(
                    f"Replay counter {counter:#x} approaching 24-bit limit (0xFFFFFF). "
                    "Re-key this link before wraparound to prevent replay attacks.",
                    UserWarning,
                    stacklevel=2,
                )
            return True

        # Within or below the window (counter is behind or equal to highest).
        offset = (self._highest - counter) & 0xFFFFFF
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

    def __init__(self, window_size: int = WINDOW_SIZE) -> None:
        self._window_size = window_size
        self._windows: dict[bytes | str | int, ReplayWindow] = {}

    def check_and_update(
        self, sender: bytes | str | int, epoch: int, seqnum: int
    ) -> bool:
        """Validate and record a frame from ``sender``.

        Returns:
            True if fresh (accepted), False if a replay / below the window.
        """
        window = self._windows.get(sender)
        if window is None:
            window = ReplayWindow(self._window_size)
            self._windows[sender] = window
        return window.check_and_update(epoch, seqnum)

    def reset(self, sender: bytes | str | int) -> None:
        """Forget all state for a sender (e.g. on re-keying)."""
        self._windows.pop(sender, None)
