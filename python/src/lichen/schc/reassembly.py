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

from lichen.schc.fragment import Ack, Fragment, compute_mic

DEFAULT_MAX_CONTEXTS = 4


@dataclass
class ReceiverResult:
    """Outcome of feeding one fragment to a receiver."""

    ack: Ack | None = None
    reassembled: bytes | None = None
    mic_ok: bool | None = None


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
        self.window_size = window_size
        self._tiles: dict[int, bytes] = {}  # regular tiles: global index -> bytes
        self._current_window = 0
        self._all1_seen = False
        self._all1_window = 0
        self._all1_payload = b""
        self._mic: bytes | None = None
        self._rule_id = 0
        self.reassembled: bytes | None = None
        self.done = False

    def _abs_window(self, frag: Fragment) -> int:
        if frag.window == self._current_window % 2:
            return self._current_window
        return self._current_window + 1  # advanced to the next window

    def _window_full(self, abs_window: int) -> bool:
        base = abs_window * self.window_size
        return all(base + p in self._tiles for p in range(self.window_size))

    def _window_bitmap(self, abs_window: int) -> tuple[bool, ...]:
        base = abs_window * self.window_size
        return tuple(base + p in self._tiles for p in range(self.window_size))

    def receive(self, frag: Fragment) -> ReceiverResult:
        if self.done:
            return ReceiverResult()
        self._rule_id = frag.rule_id
        abs_window = self._abs_window(frag)
        self._current_window = abs_window

        if frag.is_all_1:
            self._all1_seen = True
            self._all1_window = abs_window
            self._all1_payload = frag.payload
            self._mic = frag.mic
            return self._finalize()

        pos = self.window_size - 1 - frag.fcn
        self._tiles[abs_window * self.window_size + pos] = frag.payload

        if self._all1_seen:
            return self._finalize()

        if frag.is_all_0 or self._window_full(abs_window):
            ack = Ack(
                self._rule_id, abs_window % 2, self._window_bitmap(abs_window),
                complete=False,
            )
            if self._window_full(abs_window):
                self._current_window = abs_window + 1
            return ReceiverResult(ack=ack)
        return ReceiverResult()

    def _finalize(self) -> ReceiverResult:
        bitmap = self._window_bitmap(self._all1_window)
        nack = Ack(self._rule_id, self._all1_window % 2, bitmap, complete=False)

        regular_indices = sorted(self._tiles)
        contiguous = regular_indices == list(range(len(regular_indices)))
        if not contiguous:
            return ReceiverResult(ack=nack)

        data = b"".join(self._tiles[i] for i in regular_indices) + self._all1_payload
        if compute_mic(data) == self._mic:
            self.reassembled = data
            self.done = True
            return ReceiverResult(
                ack=Ack(self._rule_id, self._all1_window % 2, bitmap, complete=True),
                reassembled=data,
                mic_ok=True,
            )
        # A tail regular tile is missing; request the whole final window.
        return ReceiverResult(ack=nack, mic_ok=False)


class ReassemblyManager:
    """Bounded set of concurrent reassembly contexts keyed by sender."""

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
                self._contexts.popitem(last=False)  # evict oldest
        self._contexts.move_to_end(key)
        result = receiver.receive(frag)
        if result.reassembled is not None:
            self._contexts.pop(key, None)  # clear on completion
        return result

    def drop(self, key: Hashable) -> None:
        """Discard a reassembly context (e.g. on timeout)."""
        self._contexts.pop(key, None)

    def __len__(self) -> int:
        return len(self._contexts)
