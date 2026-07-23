# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Hashable
from dataclasses import dataclass

from lichen.schc.fragment import Ack, Fragment, compute_mic

DEFAULT_MAX_CONTEXTS = 4


@dataclass
class ReceiverResult:
    ack: Ack | None = None
    reassembled: bytes | None = None
    mic_ok: bool | None = None


class FragmentReceiver:
    def __init__(self, window_size: int) -> None:
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
        if not frag.is_all_1:
            pos = self.window_size - 1 - frag.fcn
            if frag.window == self._current_window % 2:
                start_window = self._current_window - 2 if self._current_window >= 2 else -1
            else:
                start_window = self._current_window - 1 if self._current_window >= 1 else -1
            older = start_window
            while older >= 0:
                older_idx = older * self.window_size + pos
                if older not in self._completed_windows:
                    if older_idx not in self._tiles:
                        return older
                elif older_idx in self._tiles and self._tiles[older_idx] == frag.payload:
                    return older
                older -= 2
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
        base = abs_window * self.window_size
        bitmap = [base + p in self._tiles for p in range(self.window_size)]
        if 0 <= all1_pos < self.window_size:
            bitmap[all1_pos] = True
        return tuple(bitmap)

    def receive(self, frag: Fragment) -> ReceiverResult:
        if self.done:
            return ReceiverResult()
        if not frag.is_all_1 and frag.fcn >= self.window_size:
            return ReceiverResult()
        self._rule_id = frag.rule_id
        abs_window = self._abs_window(frag)
        if abs_window in self._completed_windows:
            return ReceiverResult()
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
        bitmap = self._window_bitmap(self._all1_window)
        nack = Ack(self._rule_id, self._all1_window % 2, bitmap, complete=False)
        return ReceiverResult(ack=nack, mic_ok=False)


class ReassemblyManager:
    def __init__(
        self, window_size: int, max_contexts: int = DEFAULT_MAX_CONTEXTS
    ) -> None:
        if max_contexts <= 0:
            raise ValueError("max_contexts must be positive")
        self.window_size = window_size
        self.max_contexts = max_contexts
        self._contexts: OrderedDict[Hashable, FragmentReceiver] = OrderedDict()

    def receive(self, key: Hashable, frag: Fragment) -> ReceiverResult:
        receiver = self._contexts.get(key)
        if receiver is None:
            receiver = FragmentReceiver(self.window_size)
            self._contexts[key] = receiver
            while len(self._contexts) > self.max_contexts:
                self._contexts.popitem(last=False)
        self._contexts.move_to_end(key)
        result = receiver.receive(frag)
        if result.reassembled is not None:
            self._contexts.pop(key, None)
        return result

    def drop(self, key: Hashable) -> None:
        self._contexts.pop(key, None)

    def __len__(self) -> int:
        return len(self._contexts)
