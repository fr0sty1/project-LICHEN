# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Bounded LICHEN SCHC ACK-on-Error reassembly."""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable, Hashable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from lichen.crypto.identity import PeerIdentity
from lichen.gradient import MAX_ENTRIES
from lichen.ipv6.addr import iid_to_eui64
from lichen.link.frame import AddrMode
from lichen.link.replay import logical_counter
from lichen.schc.fragment import (
    ALL_1,
    DEFAULT_RECEIVER_LIMIT,
    MAX_ACK_REQUESTS,
    MAX_PACKET_SIZE,
    RULE_IDS,
    TILE_SIZE,
    WINDOW_SIZE,
    Ack,
    Fragment,
    FragmentError,
    _ValidatedSchcClock,
    ack_request,
    compute_mic,
    receiver_abort,
    sender_abort,
)

if TYPE_CHECKING:
    from lichen.link.link_layer import RxFrame

DEFAULT_MAX_CONTEXTS = 4
DEFAULT_MAX_CONTEXTS_PER_SIGNER = 2
AUTHENTICATED_HOLD_DOWN_SECONDS = 60.0
MAX_AUTHENTICATED_REJECTIONS = MAX_ENTRIES * len(RULE_IDS)


def _validate_max_size(max_size: object) -> int:
    """Validate the common fixed-profile reassembly size boundary."""
    if type(max_size) is not int or max_size <= 0:
        raise ValueError("max_size must be a positive integer")
    if max_size > MAX_PACKET_SIZE:
        raise ValueError(
            f"max_size exceeds profile capacity ({max_size} > {MAX_PACKET_SIZE})"
        )
    return max_size


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
        max_size: int = DEFAULT_RECEIVER_LIMIT,
        window_size: int = WINDOW_SIZE,
    ) -> None:
        if type(window_size) is not int or not 1 <= window_size <= ALL_1:
            raise FragmentError(f"window_size must be integer 1..{ALL_1}")
        self.window_size = window_size
        self.max_size = _validate_max_size(max_size)
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
        if type(max_contexts) is not int or max_contexts <= 0:
            raise ValueError("max_contexts must be a positive integer")
        self.max_contexts = max_contexts
        self.max_size = _validate_max_size(max_size)
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


@dataclass
class _AuthenticatedReceiverContext:
    receiver: FragmentReceiver
    generation: object
    admission_floor: int
    high_water: int
    expires_at: float


@dataclass(frozen=True)
class _AuthenticatedReceiverTombstone:
    generation: object
    high_water: int
    expires_at: float
    response: bytes | None
    status: str


class _AuthenticatedReassemblyManager:
    """Link-owned bounded receiver state keyed only by authenticated identities."""

    def __init__(
        self,
        local_identity: bytes,
        *,
        security_lock: threading.RLock,
        max_contexts: int = DEFAULT_MAX_CONTEXTS,
        max_contexts_per_signer: int = DEFAULT_MAX_CONTEXTS_PER_SIGNER,
        max_size: int = DEFAULT_RECEIVER_LIMIT,
        clock: object | None = None,
    ) -> None:
        if type(local_identity) is not bytes or len(local_identity) != 32:
            raise ValueError("local_identity must be a 32-byte signer public key")
        if type(max_contexts) is not int or max_contexts < 1:
            raise ValueError("max_contexts must be positive")
        if type(max_contexts_per_signer) is not int or max_contexts_per_signer < 1:
            raise ValueError("max_contexts_per_signer must be positive")
        if max_contexts_per_signer > max_contexts:
            raise ValueError("per-signer context limit cannot exceed global limit")
        from lichen.timing.time_sync import SYSTEM_MONOTONIC_CLOCK, MonotonicClock

        if clock is not None and type(clock) is not MonotonicClock:
            raise ValueError("clock must be an exact MonotonicClock or None")
        clock_capability = clock or SYSTEM_MONOTONIC_CLOCK
        validated_max_size = _validate_max_size(max_size)
        self._local_identity = local_identity
        self._local_eui64 = iid_to_eui64(PeerIdentity.from_pubkey(local_identity).iid)
        self._lock = security_lock
        self._max_contexts = max_contexts
        self._max_contexts_per_signer = max_contexts_per_signer
        self._max_size = validated_max_size
        self._clock_capability = clock_capability
        self._validated_clock = _ValidatedSchcClock(clock_capability)
        self._contexts: dict[tuple[bytes, bytes, object, int], _AuthenticatedReceiverContext] = {}
        self._tombstones: dict[
            tuple[bytes, bytes, object, int], _AuthenticatedReceiverTombstone
        ] = {}
        self._rejections: OrderedDict[
            tuple[bytes, bytes, object, int], _AuthenticatedReceiverTombstone
        ] = OrderedDict()
        # Generation-scoped floors outlive terminal response caching.  This is
        # bounded by the authenticated signer/rule capacity and prevents an old
        # T=0 opener from becoming a replacement session after hold-down.
        self._floors: dict[tuple[bytes, bytes, object, int], int] = {}
        self._pending_expiry_controls: OrderedDict[tuple[bytes, bytes, object, int], bytes] = (
            OrderedDict()
        )

    def _fail_clock_unlocked(self) -> None:
        """Disable all timer-owned state after a terminal clock failure."""
        self._contexts.clear()
        self._tombstones.clear()
        self._rejections.clear()
        self._floors.clear()
        self._pending_expiry_controls.clear()

    def _now_unlocked(self) -> float:
        try:
            return self._validated_clock()
        except FragmentError:
            self._fail_clock_unlocked()
            raise

    def _key(
        self, signer: bytes, generation: object, rule_id: int
    ) -> tuple[bytes, bytes, object, int]:
        if type(signer) is not bytes or len(signer) != 32:
            raise FragmentError("authenticated fragment signer must be 32 bytes")
        if rule_id not in RULE_IDS:
            raise FragmentError("unsupported authenticated fragmentation rule")
        return self._local_identity, signer, generation, rule_id

    @staticmethod
    def _is_session_opener(data: bytes) -> bool:
        """Only the first regular tile can open a T=0 transfer.

        A one-tile packet fits without fragmentation in this profile, so All-1
        is never a valid opener.  Requiring W=0/FCN=62 gives the receiver a
        stable counter admission floor before any later tile is accepted.
        """
        try:
            fragment = Fragment.from_bytes(data, window_size=WINDOW_SIZE)
        except FragmentError:
            return False
        return not fragment.is_all_1 and fragment.window == 0 and fragment.fcn == 62

    def _local_target(self, received: RxFrame) -> bool:
        frame = received.frame
        return frame.addr_mode is AddrMode.EXTENDED and frame.dst_addr == self._local_eui64

    def _expire_unlocked(self) -> None:
        now = self._now_unlocked()
        for key, context in list(self._contexts.items()):
            if now >= context.expires_at:
                self._contexts.pop(key)
                abort = receiver_abort(key[3])
                self._tombstones[key] = _AuthenticatedReceiverTombstone(
                    generation=context.generation,
                    high_water=context.high_water,
                    expires_at=now + AUTHENTICATED_HOLD_DOWN_SECONDS,
                    response=abort,
                    status="expired",
                )
                self._pending_expiry_controls[key] = abort
        for key, tombstone in list(self._tombstones.items()):
            if now >= tombstone.expires_at:
                self._floors[key] = max(self._floors.get(key, -1), tombstone.high_water)
                self._tombstones.pop(key)
        for key, tombstone in list(self._rejections.items()):
            if now >= tombstone.expires_at:
                self._floors[key] = max(self._floors.get(key, -1), tombstone.high_water)
                self._rejections.pop(key)

    @staticmethod
    def _is_terminal_request(data: bytes) -> bool:
        if len(data) < 2:
            return False
        rule_id = data[0]
        if rule_id not in RULE_IDS:
            return False
        window = data[1] >> 7
        if data == ack_request(rule_id, window):
            return True
        try:
            return Fragment.from_bytes(data, window_size=WINDOW_SIZE).is_all_1
        except FragmentError:
            return False

    def receive(
        self,
        received: RxFrame,
        data: bytes,
        generation: object,
        *,
        validate_packet: Callable[[bytes], bytes],
    ) -> tuple[ReceiverResult, bytes | None]:
        """Apply one exact link snapshot; unauthenticated callers cannot invoke it."""
        if not self._local_target(received) or not data or data[0] not in RULE_IDS:
            return ReceiverResult(), None
        signer = received.sender_pubkey
        rule_id = data[0]
        if received.key_generation is not generation:
            return ReceiverResult(), None
        key = self._key(signer, generation, rule_id)
        counter = logical_counter(received.epoch, received.seqnum)
        with self._lock:
            self._expire_unlocked()
            for stale_key in [
                candidate
                for candidate in (
                    *self._contexts,
                    *self._tombstones,
                    *self._rejections,
                    *self._floors,
                )
                if candidate[1] == signer and candidate[2] is not generation
            ]:
                self._contexts.pop(stale_key, None)
                self._tombstones.pop(stale_key, None)
                self._rejections.pop(stale_key, None)
                self._floors.pop(stale_key, None)
                self._pending_expiry_controls.pop(stale_key, None)
            window = data[1] >> 7 if len(data) >= 2 else 0
            is_receiver_control = data in (
                sender_abort(rule_id),
                receiver_abort(rule_id),
                ack_request(rule_id, window),
            )
            if not is_receiver_control:
                try:
                    Ack.from_bytes(data)
                except FragmentError:
                    pass
                else:
                    # ACKs are sender-facing controls.  They must never be
                    # interpreted as fragments or mutate inbound reassembly,
                    # even during a simultaneous receive flow from this peer.
                    return ReceiverResult(), None
            rejection = self._rejections.get(key)
            if rejection is not None:
                if rejection.generation is generation and counter > rejection.high_water:
                    self._rejections[key] = _AuthenticatedReceiverTombstone(
                        generation=generation,
                        high_water=counter,
                        expires_at=rejection.expires_at,
                        response=rejection.response,
                        status="rejected",
                    )
                return ReceiverResult(), None
            tombstone = self._tombstones.get(key)
            if tombstone is not None:
                if tombstone.generation is not generation or counter <= tombstone.high_water:
                    return ReceiverResult(), None
                self._tombstones[key] = _AuthenticatedReceiverTombstone(
                    generation=tombstone.generation,
                    high_water=counter,
                    expires_at=tombstone.expires_at,
                    response=tombstone.response,
                    status=tombstone.status,
                )
                if tombstone.status == "rejected":
                    return ReceiverResult(), None
                if self._is_terminal_request(data):
                    return ReceiverResult(response=tombstone.response), None
                return ReceiverResult(), None
            context = self._contexts.get(key)
            opened = False
            if context is None:
                if is_receiver_control:
                    return ReceiverResult(), None
                floor = self._floors.get(key, -1)
                if counter <= floor:
                    return ReceiverResult(), None
                # A newer authenticated packet takes ownership of this T=0
                # tuple.  Retire both the superseded durable floor and any
                # undrained Receiver-Abort for the expired predecessor before
                # admitting replacement state with no wire session ID.
                self._floors.pop(key, None)
                self._pending_expiry_controls.pop(key, None)
                try:
                    Fragment.from_bytes(data, window_size=WINDOW_SIZE)
                except FragmentError:
                    if len(self._rejections) >= MAX_AUTHENTICATED_REJECTIONS:
                        self._floors[key] = max(floor, counter)
                        return ReceiverResult(), None
                    self._rejections[key] = _AuthenticatedReceiverTombstone(
                        generation=generation,
                        high_water=max(floor, counter),
                        expires_at=self._now_unlocked() + AUTHENTICATED_HOLD_DOWN_SECONDS,
                        response=receiver_abort(rule_id),
                        status="rejected",
                    )
                    return ReceiverResult(response=receiver_abort(rule_id), aborted=True), None
                if not self._is_session_opener(data):
                    # A delayed non-opener cannot create a replacement T=0
                    # context.  Advance the generation floor so it cannot be
                    # admitted by a later reorder either.
                    self._floors[key] = max(floor, counter)
                    return ReceiverResult(), None
                signer_count = sum(
                    1
                    for item in (*self._contexts, *self._tombstones, *self._rejections)
                    if item[1] == signer
                )
                if (
                    len(self._contexts) + len(self._tombstones) >= self._max_contexts
                    or signer_count >= self._max_contexts_per_signer
                ):
                    if len(self._rejections) >= MAX_AUTHENTICATED_REJECTIONS:
                        self._floors[key] = max(floor, counter)
                        return ReceiverResult(), None
                    self._rejections[key] = _AuthenticatedReceiverTombstone(
                        generation=generation,
                        high_water=max(floor, counter),
                        expires_at=self._now_unlocked() + AUTHENTICATED_HOLD_DOWN_SECONDS,
                        response=receiver_abort(rule_id),
                        status="rejected",
                    )
                    return ReceiverResult(response=receiver_abort(rule_id), aborted=True), None
                context = _AuthenticatedReceiverContext(
                    receiver=FragmentReceiver(max_size=self._max_size),
                    generation=generation,
                    admission_floor=counter,
                    high_water=max(floor, counter - 1),
                    expires_at=self._now_unlocked() + AUTHENTICATED_HOLD_DOWN_SECONDS,
                )
                self._contexts[key] = context
                opened = True
            if not opened and (counter <= context.admission_floor or counter <= context.high_water):
                return ReceiverResult(), None
            result = context.receiver.receive_bytes(data)
            context.high_water = counter
            context.expires_at = self._now_unlocked() + AUTHENTICATED_HOLD_DOWN_SECONDS
            decoded: bytes | None = None
            if result.reassembled is not None:
                try:
                    decoded = validate_packet(result.reassembled)
                except (TypeError, ValueError, FragmentError):
                    result = ReceiverResult(response=receiver_abort(rule_id), aborted=True)
            if result.reassembled is not None or result.aborted:
                self._contexts.pop(key, None)
                self._tombstones[key] = _AuthenticatedReceiverTombstone(
                    generation=generation,
                    high_water=max(context.high_water, counter),
                    expires_at=self._now_unlocked() + AUTHENTICATED_HOLD_DOWN_SECONDS,
                    response=result.response,
                    status="succeeded" if decoded is not None else "aborted",
                )
            return result, decoded

    def replacement_occupied(self, signer: bytes) -> bool:
        with self._lock:
            self._expire_unlocked()
            return any(
                key[1] == signer
                for key in (*self._contexts, *self._tombstones, *self._rejections, *self._floors)
            )

    def peer_eviction_blocked(self, signer: bytes) -> bool:
        """Return whether retiring this peer would interrupt a live hold-down.

        A durable reassembly floor is not an eviction blocker: LinkLayer keeps
        the peer's conservative replay floor while atomically retiring the
        generation-scoped SCHC floor.  Active contexts and cached terminal or
        rejection responses remain protected until their hold-down expires.
        """
        with self._lock:
            self._expire_unlocked()
            return any(
                key[1] == signer for key in (*self._contexts, *self._tombstones, *self._rejections)
            )

    def expire_due(self) -> list[tuple[bytes, bytes, bytes]]:
        """Return each exact expired peer/destination/Receiver-Abort once."""
        with self._lock:
            self._expire_unlocked()
            outputs = [
                (
                    key[1],
                    iid_to_eui64(PeerIdentity.from_pubkey(key[1]).iid),
                    control,
                )
                for key, control in self._pending_expiry_controls.items()
            ]
            self._pending_expiry_controls.clear()
            return outputs

    def rotate_remote(self, old_signer: bytes, new_signer: bytes) -> None:
        with self._lock:
            for key in [
                key
                for key in (*self._contexts, *self._tombstones, *self._rejections, *self._floors)
                if key[1] in (old_signer, new_signer)
            ]:
                self._contexts.pop(key, None)
                self._tombstones.pop(key, None)
                self._rejections.pop(key, None)
                self._floors.pop(key, None)
                self._pending_expiry_controls.pop(key, None)

    def invalidate_remote_policy(self, signer: bytes) -> None:
        """Drop all inbound state when the authenticated Rule version changes."""
        with self._lock:
            for key in [
                key
                for key in (*self._contexts, *self._tombstones, *self._rejections, *self._floors)
                if key[1] == signer
            ]:
                self._contexts.pop(key, None)
                self._tombstones.pop(key, None)
                self._rejections.pop(key, None)
                self._floors.pop(key, None)
                self._pending_expiry_controls.pop(key, None)

    def export_persistence_state(self) -> list[dict[str, object]]:
        """Persist active ambiguity and terminal responses as hold-down rows."""
        with self._lock:
            self._expire_unlocked()
            rows: list[dict[str, object]] = []
            for key, context in self._contexts.items():
                rows.append(
                    {
                        "remote": key[1].hex(),
                        "rule_id": key[3],
                        "high_water": context.high_water,
                        "status": "active",
                        "response": None,
                    }
                )
            for key, tombstone in self._tombstones.items():
                rows.append(
                    {
                        "remote": key[1].hex(),
                        "rule_id": key[3],
                        "high_water": tombstone.high_water,
                        "status": tombstone.status,
                        "response": (
                            None if tombstone.response is None else tombstone.response.hex()
                        ),
                    }
                )
            for key, rejection in self._rejections.items():
                rows.append(
                    {
                        "remote": key[1].hex(),
                        "rule_id": key[3],
                        "high_water": rejection.high_water,
                        "status": "rejected",
                        "response": receiver_abort(key[3]).hex(),
                    }
                )
            for key, high_water in self._floors.items():
                rows.append(
                    {
                        "remote": key[1].hex(),
                        "rule_id": key[3],
                        "high_water": high_water,
                        "status": "floor",
                        "response": None,
                    }
                )
            return rows

    def restore_persistence_state(
        self,
        raw: object,
        generations: dict[bytes, object],
        replay_highest: Callable[[bytes], int],
    ) -> None:
        """Restore every persisted tuple as a conservative receiver tombstone."""
        if type(raw) is not list or len(raw) > (
            self._max_contexts + MAX_AUTHENTICATED_REJECTIONS + MAX_ENTRIES * len(RULE_IDS)
        ):
            raise FragmentError("invalid persisted SCHC reassembly state")
        restored_tombstones: dict[
            tuple[bytes, bytes, object, int], _AuthenticatedReceiverTombstone
        ] = {}
        restored_rejections: OrderedDict[
            tuple[bytes, bytes, object, int], _AuthenticatedReceiverTombstone
        ] = OrderedDict()
        restored_floors: dict[tuple[bytes, bytes, object, int], int] = {}
        now = self._now_unlocked()
        for item in raw:
            if type(item) is not dict or set(item) != {
                "remote",
                "rule_id",
                "high_water",
                "status",
                "response",
            }:
                raise FragmentError("invalid persisted SCHC reassembly record")
            remote_hex = item["remote"]
            rule_id = item["rule_id"]
            high_water = item["high_water"]
            status = item["status"]
            response_hex = item["response"]
            if (
                type(remote_hex) is not str
                or type(rule_id) is not int
                or rule_id not in RULE_IDS
                or type(high_water) is not int
                or not -1 <= high_water <= 0xFF_FFFF
                or type(status) is not str
                or status
                not in {
                    "active",
                    "succeeded",
                    "aborted",
                    "expired",
                    "restarted",
                    "rejected",
                    "floor",
                }
                or (response_hex is not None and type(response_hex) is not str)
            ):
                raise FragmentError("invalid persisted SCHC reassembly record")
            try:
                remote = bytes.fromhex(remote_hex)
                response = None if response_hex is None else bytes.fromhex(response_hex)
            except ValueError as exc:
                raise FragmentError("invalid persisted SCHC reassembly bytes") from exc
            valid_response = response is None
            if response is not None and response:
                if status == "succeeded":
                    window = response[1] >> 7 if len(response) >= 2 else 0
                    valid_response = response == Ack(rule_id, window, complete=True).to_bytes()
                elif status in {"aborted", "expired", "rejected"}:
                    valid_response = response == receiver_abort(rule_id)
            generation = generations.get(remote)
            if generation is None:
                raise FragmentError("inconsistent persisted SCHC reassembly record")
            key = self._key(remote, generation, rule_id)
            if (
                key in restored_tombstones
                or key in restored_rejections
                or key in restored_floors
                or high_water > replay_highest(remote)
                or not valid_response
                or (status in {"active", "restarted", "floor"} and response is not None)
            ):
                raise FragmentError("inconsistent persisted SCHC reassembly record")
            if status == "floor":
                restored_floors[key] = high_water
                continue
            restored = _AuthenticatedReceiverTombstone(
                generation=generation,
                high_water=high_water,
                expires_at=now + AUTHENTICATED_HOLD_DOWN_SECONDS,
                response=response,
                status="restarted" if status == "active" else str(status),
            )
            if status == "rejected":
                restored_rejections[key] = restored
            else:
                restored_tombstones[key] = restored
        if (
            len(restored_tombstones) > self._max_contexts
            or len(restored_rejections) > MAX_AUTHENTICATED_REJECTIONS
        ):
            raise FragmentError("persisted SCHC reassembly capacity exceeded")
        with self._lock:
            self._contexts.clear()
            self._tombstones = restored_tombstones
            self._rejections = restored_rejections
            self._floors = restored_floors
            self._pending_expiry_controls.clear()

    def fail_closed(self) -> None:
        with self._lock:
            self._contexts.clear()
            self._tombstones.clear()
            self._rejections.clear()
            self._floors.clear()
            self._pending_expiry_controls.clear()
