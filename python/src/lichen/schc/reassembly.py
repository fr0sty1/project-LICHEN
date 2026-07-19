# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Bounded LICHEN SCHC ACK-on-Error reassembly."""

from __future__ import annotations

from collections.abc import Hashable
from dataclasses import dataclass

from lichen.schc.fragment import (
    DEFAULT_RECEIVER_LIMIT,
    MAX_ACK_REQUESTS,
    MAX_PACKET_SIZE,
    RULE_IDS,
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
    """Outcome of one receiver input."""

    ack: Ack | None = None
    response: bytes | None = None
    reassembled: bytes | None = None
    mic_ok: bool | None = None
    aborted: bool = False


class FragmentReceiver:
    """One fixed-profile reassembly context."""

    def __init__(self, max_size: int = DEFAULT_RECEIVER_LIMIT) -> None:
        if not 1 <= max_size <= MAX_PACKET_SIZE:
            raise ValueError("max_size out of range")
        self.max_size = max_size
        self._tiles: dict[tuple[int, int], bytes] = {}
        self._all1: Fragment | None = None
        self._rule_id: int | None = None
        self.attempts = 0
        self.done = False

    def _release(self) -> None:
        self._tiles.clear()
        self._all1 = None
        self.done = True

    def _abort(self, rule_id: int) -> ReceiverResult:
        self._release()
        return ReceiverResult(response=receiver_abort(rule_id), aborted=True)

    def _bitmap(self, window: int) -> tuple[bool, ...]:
        bits = [False] * WINDOW_SIZE
        for tile_window, fcn in self._tiles:
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
        result = ReceiverResult(ack=ack, response=response, reassembled=packet, mic_ok=mic_ok)
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
        ordinals = [ordinal for ordinal, _ in regular]
        if ordinals and ordinals != list(range(ordinals[-1] + 1)):
            gap = next(i for i in range(ordinals[-1] + 1) if i not in ordinals)
            gap_window = gap // WINDOW_SIZE
            return self._respond(Ack(self._all1.rule_id, gap_window, self._bitmap(gap_window)))
        packet = b"".join(tile for _, tile in regular) + self._all1.payload
        if len(packet) > self.max_size:
            return self._abort(self._all1.rule_id)
        if compute_mic(packet) == self._all1.mic:
            return self._respond(
                Ack(self._all1.rule_id, self._all1.window, complete=True),
                packet=packet,
                mic_ok=True,
            )
        return self._respond(
            Ack(self._all1.rule_id, self._all1.window, self._bitmap(self._all1.window)),
            mic_ok=False,
        )

    def receive(self, frag: Fragment) -> ReceiverResult:
        if self.done:
            return ReceiverResult()
        try:
            Fragment.from_bytes(frag.to_bytes())
        except FragmentError:
            if frag.rule_id not in RULE_IDS:
                raise
            return self._abort(frag.rule_id)
        if self._rule_id is None:
            self._rule_id = frag.rule_id
        elif frag.rule_id != self._rule_id:
            return self._abort(self._rule_id)
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
            if self._rule_id is None:
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
            return self.receive(Fragment.from_bytes(data))
        except FragmentError:
            return self._abort(rule_id)

    def expire(self) -> bytes | None:
        if self.done or self._rule_id is None:
            return None
        rule_id = self._rule_id
        self._release()
        return receiver_abort(rule_id)


class ReassemblyManager:
    """Bounded contexts keyed by ``(caller key, fragmentation Rule ID)``."""

    def __init__(
        self,
        max_contexts: int = DEFAULT_MAX_CONTEXTS,
        max_size: int = DEFAULT_RECEIVER_LIMIT,
    ) -> None:
        if max_contexts <= 0:
            raise ValueError("max_contexts must be positive")
        if not 1 <= max_size <= MAX_PACKET_SIZE:
            raise ValueError("max_size out of range")
        self.max_contexts = max_contexts
        self.max_size = max_size
        self._contexts: dict[tuple[Hashable, int], FragmentReceiver] = {}

    def _receiver(self, key: Hashable, rule_id: int) -> FragmentReceiver | None:
        context_key = (key, rule_id)
        receiver = self._contexts.get(context_key)
        if receiver is None and len(self._contexts) < self.max_contexts:
            receiver = FragmentReceiver(self.max_size)
            self._contexts[context_key] = receiver
        return receiver

    def receive(self, key: Hashable, frag: Fragment) -> ReceiverResult:
        try:
            Fragment.from_bytes(frag.to_bytes())
        except FragmentError:
            if frag.rule_id not in RULE_IDS:
                raise
            self._contexts.pop((key, frag.rule_id), None)
            return ReceiverResult(response=receiver_abort(frag.rule_id), aborted=True)
        receiver = self._receiver(key, frag.rule_id)
        if receiver is None:
            return ReceiverResult(response=receiver_abort(frag.rule_id), aborted=True)
        result = receiver.receive(frag)
        if receiver.done:
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
                fragment = Fragment.from_bytes(data)
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
