# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SCHC reassembly state machine — ACK-on-Error receiver (RFC 8724 section 8).

Pairs with :class:`lichen.schc.fragment.FragmentSender`. :class:`FragmentReceiver`
collects fragments for one datagram, emits an ACK (positional bitmap) at each
window boundary and after the All-1 fragment, and reassembles once every tile is
present and the CRC32 MIC verifies. Missing tiles produce a NACK bitmap that the
sender turns into retransmissions; the MIC is the final correctness guard.

:class:`ReassemblyManager` holds a bounded number of concurrent receivers keyed
by sender, evicting the oldest on overflow (the wire fragment header carries no
DTag, so datagrams are distinguished by transport key, not in-band tag).

Times are caller-supplied integer milliseconds; nothing reads a wall clock.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Hashable
from dataclasses import dataclass

from lichen.schc.fragment import MAX_WINDOW_SIZE, Ack, Fragment, FragmentError, compute_mic

DEFAULT_MAX_CONTEXTS = 4


@dataclass
class ReceiverResult:
    ack: Ack | None = None
    reassembled: bytes | None = None
    mic_ok: bool | None = None
    evicted: bool = False


class FragmentReceiver:
    """Reassembles a single datagram from ACK-on-Error fragments.

    Regular tiles are stored by their global index (window * window_size +
    position, position = window_size - 1 - FCN). The All-1 tile (the datagram's
    last tile) is stored separately so its unknown in-window position can never
    collide with a regular slot; completeness is checked by requiring the
    regular tiles to form a contiguous run from index 0, with the CRC32 MIC as
    the final correctness guard.
    """

    def __init__(self, window_size: int) -> None:
        if not isinstance(window_size, int) or not 1 <= window_size <= MAX_WINDOW_SIZE:
            raise FragmentError(f"window_size must be integer 1..{MAX_WINDOW_SIZE}")
        self.window_size = window_size
        self._tiles: dict[int, bytes] = {}
        self._current_window = 0
        self._completed_windows: set[int] = set()
        self._all1_seen = False
        self._all1_window = 0
        self._all1_payload = b""
        self._mic: bytes | None = None
        self._rule_id = 0
        self.reassembled: bytes | None = None
        self.done = False

    def _abs_window(self, frag: Fragment) -> int:
        """Map the 1-bit wire window to the monotonic absolute window number.

        SCHC ACK-on-Error uses a single W bit on the wire that alternates 0/1
        as windows advance. Internally, _current_window is a monotonically
        increasing counter (0, 1, 2, ...).

        To handle late retransmissions, out-of-order delivery, and duplicates
        correctly we scan backwards through older same-parity windows:
        1. Incomplete older window with gap at this position -> fill it
        2. Tile already present with exact payload match -> stale duplicate
           (completed or incomplete window); receive() will ignore
        3. Otherwise map to current window (same parity) or next window.
        """
        if not frag.is_all_1:
            pos = self.window_size - 1 - frag.fcn

            # Determine most-recent same-parity previous window to scan from.
            if frag.window == self._current_window % 2:
                start_window = self._current_window - 2 if self._current_window >= 2 else -1
            else:
                start_window = self._current_window - 1 if self._current_window >= 1 else -1

            older = start_window
            while older >= 0:
                older_idx = older * self.window_size + pos
                if older not in self._completed_windows:
                    if older_idx in self._tiles:
                        if self._tiles[older_idx] == frag.payload:
                            # Duplicate retransmit/reorder for already-filled
                            # slot in incomplete window; treat as stale.
                            return older
                        # payload mismatch on filled slot: likely corruption or
                        # mapping error; do not use this window, continue scan
                    else:
                        # Gap in incomplete older window: retransmission to fill.
                        return older
                elif older_idx in self._tiles and self._tiles[older_idx] == frag.payload:
                    # Completed window with exact payload match: stale duplicate.
                    return older
                older -= 2

        # No matching older window found for retransmit/duplicate.
        if frag.window == self._current_window % 2:
            return self._current_window
        return self._current_window + 1

    def _window_full(self, abs_window: int) -> bool:
        base = abs_window * self.window_size
        return all(base + p in self._tiles for p in range(self.window_size))

    def _window_bitmap(self, abs_window: int) -> tuple[bool, ...]:
        base = abs_window * self.window_size
        return tuple(base + p in self._tiles for p in range(self.window_size))

    def _window_bitmap_with_all1(self, abs_window: int, all1_pos: int) -> tuple[bool, ...]:
        """Compute bitmap including the All-1 position.

        Only call after MIC verification confirms the All-1's position.
        """
        base = abs_window * self.window_size
        bitmap = [base + p in self._tiles for p in range(self.window_size)]
        if 0 <= all1_pos < self.window_size:
            bitmap[all1_pos] = True
        return tuple(bitmap)

    def receive(self, frag: Fragment) -> ReceiverResult:
        if self.done:
            return ReceiverResult()
        if self._rule_id == 0:
            self._rule_id = frag.rule_id
        elif self._rule_id != frag.rule_id:
            return ReceiverResult()
        # Reject fragments with FCN >= window_size (except ALL_1 which has special FCN)
        if not frag.is_all_1 and frag.fcn >= self.window_size:
            return ReceiverResult()
        abs_window = self._abs_window(frag)

        # SECURITY: Reject stale retransmissions from completed windows to
        # prevent delayed duplicates from corrupting current window data.
        if abs_window in self._completed_windows:
            return ReceiverResult()

        # Never regress _current_window; only advance or stay the same.
        if abs_window > self._current_window:
            self._current_window = abs_window

        if frag.is_all_1:
            self._all1_seen = True
            self._all1_window = abs_window
            self._all1_payload = frag.payload
            self._mic = frag.mic
            return self._finalize()

        pos = self.window_size - 1 - frag.fcn
        idx = abs_window * self.window_size + pos
        # SECURITY: Don't overwrite existing tiles. A corrupted retransmission
        # from an older window (with different payload) could bypass the payload
        # comparison in _abs_window() and be mapped to the current window. By
        # refusing to overwrite, we prevent it from corrupting already-received
        # data. If the existing tile is itself corrupt, MIC will fail and we'll
        # NACK for retransmission.
        if idx not in self._tiles:
            self._tiles[idx] = frag.payload

        if self._all1_seen:
            return self._finalize()

        if frag.is_all_0 or self._window_full(abs_window):
            ack = Ack(
                self._rule_id, abs_window % 2, self._window_bitmap(abs_window),
                complete=False,
            )
            if self._window_full(abs_window):
                self._completed_windows.add(abs_window)
                self._current_window = abs_window + 1
            return ReceiverResult(ack=ack)
        return ReceiverResult()

    def _finalize(self) -> ReceiverResult:
        regular_indices = sorted(self._tiles)
        contiguous = regular_indices == list(range(len(regular_indices)))
        if not contiguous:
            # Find first missing tile and NACK its window (may be earlier than all1_window)
            present = set(regular_indices)
            first_missing = 0
            while first_missing in present:
                first_missing += 1
            gap_window = first_missing // self.window_size
            bitmap = self._window_bitmap(gap_window)
            nack = Ack(self._rule_id, gap_window % 2, bitmap, complete=False)
            return ReceiverResult(ack=nack)

        data = b"".join(self._tiles[i] for i in regular_indices) + self._all1_payload
        if compute_mic(data) == self._mic:
            # MIC passed: All-1's position is confirmed at len(regular_indices).
            # Include it in the bitmap for accurate reporting.
            base = self._all1_window * self.window_size
            all1_pos = len(regular_indices) - base
            bitmap = self._window_bitmap_with_all1(self._all1_window, all1_pos)
            self.reassembled = data
            self.done = True
            return ReceiverResult(
                ack=Ack(self._rule_id, self._all1_window % 2, bitmap, complete=True),
                reassembled=data,
                mic_ok=True,
            )
        # MIC mismatch: NACK the final window (a tile there may be missing or corrupt).
        # Don't include All-1 position here since we can't be certain about it without
        # MIC verification - there could be missing tiles we don't know about.
        bitmap = self._window_bitmap(self._all1_window)
        nack = Ack(self._rule_id, self._all1_window % 2, bitmap, complete=False)
        return ReceiverResult(ack=nack, mic_ok=False)


class ReassemblyManager:
    """Bounded set of concurrent reassembly contexts keyed by sender."""

    def __init__(
        self, window_size: int, max_contexts: int = DEFAULT_MAX_CONTEXTS
    ) -> None:
        if not isinstance(window_size, int) or not 1 <= window_size <= MAX_WINDOW_SIZE:
            raise FragmentError(f"window_size must be integer 1..{MAX_WINDOW_SIZE}")
        if max_contexts <= 0:
            raise ValueError("max_contexts must be positive")
        self.window_size = window_size
        self.max_contexts = max_contexts
        self._contexts: OrderedDict[Hashable, FragmentReceiver] = OrderedDict()

    def receive(self, key: Hashable, frag: Fragment) -> ReceiverResult:
        receiver = self._contexts.get(key)
        evicted = False
        if receiver is None:
            receiver = FragmentReceiver(self.window_size)
            self._contexts[key] = receiver
            while len(self._contexts) > self.max_contexts:
                self._contexts.popitem(last=False)
                evicted = True
        self._contexts.move_to_end(key)
        result = receiver.receive(frag)
        if evicted:
            result.evicted = True
        if result.reassembled is not None:
            self._contexts.pop(key, None)
        return result

    def drop(self, key: Hashable) -> None:
        """Discard a reassembly context (e.g. on timeout)."""
        self._contexts.pop(key, None)

    def __len__(self) -> int:
        return len(self._contexts)
