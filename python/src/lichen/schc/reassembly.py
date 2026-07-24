# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Bounded LICHEN SCHC ACK-on-Error reassembly."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Hashable
from dataclasses import dataclass

from lichen.schc.fragment import (
    ALL_1,
    DEFAULT_RECEIVER_LIMIT,
    MAX_ACK_REQUESTS,
    RULE_IDS,
    TILE_SIZE,
    WINDOW_SIZE,
    Ack,
    Fragment,
    FragmentError,
    ack_request,
    compute_mic,
    receiver_abort,
    sender_abort,
)

DEFAULT_MAX_CONTEXTS = 4


@dataclass
class ReceiverResult:
    ack: Ack | None = None
    response: bytes | None = None
    reassembled: bytes | None = None
    mic_ok: bool | None = None
    evicted: bool = False
    aborted: bool = False


class FragmentReceiver:
    """One fixed-profile reassembly context.

    Regular tiles are stored by their global index (window * window_size +
    position, position = window_size - 1 - FCN). The All-1 tile (the datagram's
    last tile) is stored separately so its unknown in-window position can never
    collide with a regular slot; completeness is checked by requiring the
    regular tiles to form a contiguous run from index 0, with the CRC32 MIC as
    the final correctness guard.
    """

    def __init__(
        self,
        window_size: int = WINDOW_SIZE,
        max_size: int = DEFAULT_RECEIVER_LIMIT,
    ) -> None:
        if not 1 <= window_size <= ALL_1:
            raise FragmentError(f"window_size must be integer 1..{ALL_1}")
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        self.window_size = window_size
        self.max_size = max_size
        self._tiles: dict[tuple[int, int], bytes] = {}
        self._current_window = 0
        self._completed_windows: set[int] = set()
        self._all1_seen = False
        self._all1_window = 0
        self._all1_payload = b""
        self._mic: bytes | None = None
        self._all1: Fragment | None = None
        self._rule_id = 0
        self.reassembled: bytes | None = None
        self.done = False
        self.attempts = 0

    def _release(self) -> None:
        self._tiles.clear()
        self._all1 = None
        self._all1_seen = False
        self.done = True

    def _abort(self, rule_id: int) -> ReceiverResult:
        self._release()
        return ReceiverResult(response=receiver_abort(rule_id), aborted=True)

    def expire(self) -> bytes | None:
        if self.done or self._rule_id == 0:
            return None
        rule_id = self._rule_id
        self._release()
        return receiver_abort(rule_id)

    def _abs_window(self, frag: Fragment) -> int:
        """Map the 1-bit wire window to the monotonic absolute window number.

        To handle late retransmissions, out-of-order delivery, and duplicates
        correctly we scan backwards through older same-parity windows:
        1. Incomplete older window with gap at this position -> fill it
        2. Tile already present with exact payload match -> stale duplicate
           (completed or incomplete window); receive() will ignore
        3. Otherwise map to current window (same parity) or next window.
        """
        if not frag.is_all_1:
            # Determine most-recent same-parity previous window to scan from.
            if frag.window == self._current_window % 2:
                start_window = self._current_window - 2 if self._current_window >= 2 else -1
            else:
                start_window = self._current_window - 1 if self._current_window >= 1 else -1

            older = start_window
            while older >= 0:
                older_key = (older, frag.fcn)
                if older not in self._completed_windows:
                    if older_key in self._tiles:
                        if self._tiles[older_key] == frag.payload:
                            # Duplicate retransmit/reorder for already-filled
                            # slot in incomplete window; treat as stale.
                            return older
                        # payload mismatch on filled slot: likely corruption or
                        # mapping error; do not use this window, continue scan
                    else:
                        # Gap in incomplete older window: retransmission to fill.
                        return older
                elif older_key in self._tiles and self._tiles[older_key] == frag.payload:
                    # Completed window with exact payload match: stale duplicate.
                    return older
                older -= 2

        # No matching older window found for retransmit/duplicate.
        if frag.window == self._current_window % 2:
            return self._current_window
        return self._current_window + 1

    def _bitmap(self, window: int) -> tuple[bool, ...]:
        bits = [False] * WINDOW_SIZE
        for (tile_window, fcn), _ in self._tiles.items():
            if tile_window == window:
                bits[62 - fcn] = True
        if self._all1 is not None and self._all1.window == window:
            bits[-1] = True
        return tuple(bits)

    def _respond(
        self,
        ack: Ack,
        *,
        packet: bytes | None = None,
        mic_ok: bool | None = None,
    ) -> ReceiverResult:
        if self.attempts >= MAX_ACK_REQUESTS:
            return self._abort(ack.rule_id)
        self.attempts += 1
        response = ack.to_bytes()
        result = ReceiverResult(
            ack=ack, response=response, reassembled=packet, mic_ok=mic_ok
        )
        if ack.complete:
            self._release()
        return result

    def _lowest_incomplete_window(self) -> int:
        assert self._all1 is not None
        if self._all1.window == 1 and any((0, fcn) not in self._tiles for fcn in range(63)):
            return 0
        return self._all1.window

    def _finalize(self) -> ReceiverResult:
        assert self._all1 is not None
        window = self._lowest_incomplete_window()
        if window != self._all1.window:
            return self._respond(Ack(self._all1.rule_id, window, self._bitmap(window)))
        regular = sorted(
            ((w * WINDOW_SIZE + 62 - fcn, tile) for (w, fcn), tile in self._tiles.items()),
            key=lambda item: item[0],
        )
        if len(regular) != len(self._tiles):
            return self._respond(Ack(self._all1.rule_id, window, self._bitmap(window)))
        data = b"".join(tile for _, tile in regular) + self._all1.payload
        if compute_mic(data) != self._all1.mic:
            return self._respond(
                Ack(
                    self._all1.rule_id,
                    self._all1.window,
                    self._bitmap(self._all1.window),
                ),
                mic_ok=False,
            )
        self.reassembled = data
        self.done = True
        return self._respond(
            Ack(self._all1.rule_id, self._all1.window, complete=True),
            packet=data,
            mic_ok=True,
        )

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
        if not frag.is_all_1 and len(frag.payload) != TILE_SIZE:
            return self._abort(frag.rule_id)
        abs_window = self._abs_window(frag)

        # SECURITY: Reject stale retransmissions from completed windows to
        # prevent delayed duplicates from corrupting current window data.
        if abs_window in self._completed_windows:
            return ReceiverResult()

        # Never regress _current_window; only advance or stay the same.
        if abs_window > self._current_window:
            self._current_window = abs_window

        if frag.is_all_1:
            if self._all1 is not None and self._all1 != frag:
                return self._abort(frag.rule_id)
            if any(window > frag.window for window, _ in self._tiles) or (
                (frag.window, 0) in self._tiles
            ):
                return self._abort(frag.rule_id)
            if (
                self._all1 is None
                and sum(map(len, self._tiles.values())) + len(frag.payload) > self.max_size
            ):
                return self._abort(frag.rule_id)
            self._all1 = frag
            return self._finalize()
        if self._all1 is not None and (
            frag.window > self._all1.window or (frag.window == self._all1.window and frag.fcn == 0)
        ):
            return self._abort(frag.rule_id)
        key = (frag.window, frag.fcn)
        existing = self._tiles.get(key)
        if existing is not None:
            if existing != frag.payload:
                return self._abort(frag.rule_id)
            return ReceiverResult()
        retained = 0 if self._all1 is None else len(self._all1.payload)
        if sum(map(len, self._tiles.values())) + retained + len(frag.payload) > self.max_size:
            return self._abort(frag.rule_id)
        self._tiles[key] = frag.payload
        return ReceiverResult()

    def receive_bytes(self, data: bytes) -> ReceiverResult:
        if len(data) < 2:
            raise FragmentError("fragmentation message too short")
        rule_id = data[0]
        if rule_id not in RULE_IDS:
            raise FragmentError(f"unsupported fragmentation rule: {rule_id:#x}")
        if data == sender_abort(rule_id):
            self._release()
            return ReceiverResult(aborted=True)
        if data == receiver_abort(rule_id):
            self._release()
            return ReceiverResult(aborted=True)
        window = data[1] >> 7
        if data == ack_request(rule_id, window):
            if self._rule_id == 0:
                self._rule_id = rule_id
            elif self._rule_id != rule_id:
                return self._abort(self._rule_id)
            if self._all1 is not None:
                return self._finalize()
            window = 0
            if self._tiles and all((0, fcn) in self._tiles for fcn in range(63)):
                window = 1
            return self._respond(Ack(rule_id, window, self._bitmap(window)))
        try:
            return self.receive(Fragment.from_bytes(data, window_size=self.window_size))
        except FragmentError:
            return self._abort(rule_id)


class ReassemblyManager:
    """Bounded contexts keyed by ``(caller key, fragmentation Rule ID)``."""

    def __init__(
        self,
        max_contexts: int = DEFAULT_MAX_CONTEXTS,
        max_size: int = DEFAULT_RECEIVER_LIMIT,
    ) -> None:
        if max_contexts <= 0:
            raise ValueError("max_contexts must be positive")
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        self.max_contexts = max_contexts
        self.max_size = max_size
        self._contexts: OrderedDict[tuple[Hashable, int], FragmentReceiver] = OrderedDict()

    def _receiver(self, key: Hashable, rule_id: int) -> FragmentReceiver | None:
        context_key = (key, rule_id)
        receiver = self._contexts.get(context_key)
        if receiver is None and len(self._contexts) < self.max_contexts:
            receiver = FragmentReceiver(max_size=self.max_size)
            self._contexts[context_key] = receiver
        return receiver

    def receive(self, key: Hashable, frag: Fragment) -> ReceiverResult:
        if frag.rule_id not in RULE_IDS:
            raise FragmentError(f"unsupported fragmentation rule: {frag.rule_id:#x}")
        receiver = self._receiver(key, frag.rule_id)
        if receiver is None:
            return ReceiverResult(response=receiver_abort(frag.rule_id), aborted=True)
        result = receiver.receive(frag)
        if result.reassembled is not None or result.aborted:
            self._contexts.pop((key, frag.rule_id), None)
        return result

    def receive_bytes(self, key: Hashable, data: bytes) -> ReceiverResult:
        if not data:
            raise FragmentError("fragmentation message too short")
        rule_id = data[0]
        if rule_id not in RULE_IDS:
            raise FragmentError(f"unsupported fragmentation rule: {rule_id:#x}")
        context_key = (key, rule_id)
        if len(data) < 2:
            self._contexts.pop(context_key, None)
            return ReceiverResult(response=receiver_abort(rule_id), aborted=True)
        if data in (sender_abort(rule_id), receiver_abort(rule_id)):
            receiver = self._contexts.pop(context_key, None)
            if receiver is not None:
                receiver.receive_bytes(data)
            return ReceiverResult(aborted=True)
        window = data[1] >> 7
        is_ack_request = data == ack_request(rule_id, window)
        if not is_ack_request:
            try:
                fragment = Fragment.from_bytes(data, window_size=WINDOW_SIZE)
            except FragmentError:
                self._contexts.pop(context_key, None)
                return ReceiverResult(response=receiver_abort(rule_id), aborted=True)
        receiver = self._receiver(key, rule_id)
        if receiver is None:
            return ReceiverResult(response=receiver_abort(rule_id), aborted=True)
        result = receiver.receive_bytes(data) if is_ack_request else receiver.receive(fragment)
        if receiver.done:
            self._contexts.pop((key, rule_id), None)
        return result

    def drop(self, key: Hashable, rule_id: int | None = None) -> None:
        if rule_id is not None:
            self._contexts.pop((key, rule_id), None)
            return
        for context_key in [context_key for context_key in self._contexts if context_key[0] == key]:
            self._contexts.pop(context_key)

    def expire(self, key: Hashable, rule_id: int) -> bytes | None:
        receiver = self._contexts.pop((key, rule_id), None)
        return None if receiver is None else receiver.expire()

    def __len__(self) -> int:
        return len(self._contexts)
