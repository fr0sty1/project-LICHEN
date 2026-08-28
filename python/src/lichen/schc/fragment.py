# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

import math
import threading
import weakref
import zlib
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from lichen.constants import (
    SCHC_FRAGMENT_M,
    SCHC_FRAGMENT_N,
    SCHC_FRAGMENT_T,
    SCHC_RETRANSMISSION_TIMEOUT_S,
)

if TYPE_CHECKING:
    from lichen.link.link_layer import RxFrame

    from .session_manager import SchcSessionManager

N_FCN_BITS = SCHC_FRAGMENT_N
ALL_1 = (1 << N_FCN_BITS) - 1
MAX_WINDOW_SIZE = ALL_1
WINDOW_SIZE = MAX_WINDOW_SIZE
DEFAULT_WINDOW_SIZE = WINDOW_SIZE
MIC_LENGTH = 4
RULE_IDS = (0x78, 0x79)
FRAGMENT_RULE_ID_BITS = 8
FRAGMENT_ENVELOPE_MTU = 185
FRAGMENT_HEADER_BITS = (
    FRAGMENT_RULE_ID_BITS + SCHC_FRAGMENT_T + SCHC_FRAGMENT_M + SCHC_FRAGMENT_N
)
TILE_SIZE = (FRAGMENT_ENVELOPE_MTU * 8 - FRAGMENT_HEADER_BITS - MIC_LENGTH * 8) // 8
_PROFILE_WINDOW_COUNT = 1 << SCHC_FRAGMENT_M
MAX_PACKET_SIZE = _PROFILE_WINDOW_COUNT * WINDOW_SIZE * TILE_SIZE
MAX_SCHC_PACKET = 1281
DEFAULT_RECEIVER_LIMIT = MAX_SCHC_PACKET
MAX_ACK_REQUESTS = 4
MAX_LINK_REPLAY_COUNTER = 0xFF_FFFF
SIGNER_PUBLIC_KEY_LENGTH = 32
SESSION_HOLD_DOWN_SECONDS = 60.0
MAX_SENDER_SESSION_RECORDS = 64
MAX_PREPARED_SENDERS = 64
MAX_PENDING_ACK_RECEIPTS = 16
# Reserve every active sender enough one-use wire capabilities for its complete
# two-window initial output and every permitted repair attempt.  Keeping this
# budget per session prevents one peer's retransmissions from evicting another
# peer's unsent authority.
MAX_ISSUED_FRAGMENT_WIRES_PER_SESSION = _PROFILE_WINDOW_COUNT * WINDOW_SIZE * MAX_ACK_REQUESTS
MAX_ISSUED_FRAGMENT_WIRES = MAX_SENDER_SESSION_RECORDS * MAX_ISSUED_FRAGMENT_WIRES_PER_SESSION
SESSION_IDLE_TIMEOUT_SECONDS = 60.0
RETRANSMISSION_TIMEOUT_SECONDS = float(SCHC_RETRANSMISSION_TIMEOUT_S)
PREPARED_SENDER_TTL_SECONDS = 60.0

_W_SHIFT = 6
_FCN_MASK = 0x3F
_MAX_FRAGMENT_WIRE_SIZE = TILE_SIZE + MIC_LENGTH + 2


def fragmentation_rule_for_sender(
    sender_identity: bytes,
    receiver_identity: bytes,
) -> int:
    """Derive the directional Rule ID from canonical full signer identities."""
    for name, identity in (
        ("sender_identity", sender_identity),
        ("receiver_identity", receiver_identity),
    ):
        if type(identity) is not bytes or len(identity) != SIGNER_PUBLIC_KEY_LENGTH:
            raise FragmentError(f"{name} must be a 32-byte signer public key")
    if sender_identity == receiver_identity:
        raise FragmentError("fragmentation endpoints must have distinct signer identities")
    return 0x78 if sender_identity < receiver_identity else 0x79


def fragmentation_message_is_response(
    data: bytes,
    *,
    sender_identity: bytes,
    receiver_identity: bytes,
) -> bool:
    """Classify reverse-direction controls using authenticated endpoint roles.

    ACK REQ is byte-identical to one canonical compressed negative ACK.  The
    Rule ID resolves that ambiguity: a sender's own directional rule denotes
    ACK REQ, while the opposite endpoint's rule denotes an ACK response.
    """
    if type(data) is not bytes or len(data) < 2 or data[0] not in RULE_IDS:
        return False
    rule_id = data[0]
    window = data[1] >> 7
    if data == receiver_abort(rule_id):
        return True
    if data == sender_abort(rule_id):
        return False
    if data == ack_request(rule_id, window):
        return rule_id == fragmentation_rule_for_sender(receiver_identity, sender_identity)
    try:
        Ack.from_bytes(data)
    except FragmentError:
        return False
    return True


_ISSUED_MANAGER_LOCK = threading.RLock()
_ISSUED_MANAGERS: dict[
    int,
    tuple[
        weakref.ReferenceType[FragmentSender],
        weakref.ReferenceType[SchcSessionManager],
    ],
] = {}


def _register_issued_sender(
    sender: FragmentSender,
    manager: SchcSessionManager,
) -> weakref.ReferenceType[FragmentSender]:
    sender_id = id(sender)
    manager_reference = weakref.ref(manager)

    def cleanup(reference: weakref.ReferenceType[FragmentSender]) -> None:
        owning_manager = manager_reference()
        if owning_manager is not None:
            owning_manager._discard_abandoned_prepared(sender_id, reference)
        with _ISSUED_MANAGER_LOCK:
            current = _ISSUED_MANAGERS.get(sender_id)
            if current is not None and current[0] is reference:
                _ISSUED_MANAGERS.pop(sender_id, None)

    reference = weakref.ref(sender, cleanup)
    with _ISSUED_MANAGER_LOCK:
        _ISSUED_MANAGERS[sender_id] = (reference, manager_reference)
    return reference


def _issued_manager(sender: FragmentSender) -> SchcSessionManager | None:
    with _ISSUED_MANAGER_LOCK:
        current = _ISSUED_MANAGERS.get(id(sender))
        if current is None or current[0]() is not sender:
            return None
        return current[1]()


class FragmentError(Exception):
    pass


_U64_MAX = (1 << 64) - 1


def _tile_size_input(name: str, value: int) -> int:
    if type(value) is not int or not 0 <= value <= _U64_MAX:
        raise FragmentError(f"{name} must be an unsigned 64-bit integer")
    return value


def fragment_payload_capacity(
    mtu_bytes: int,
    *,
    rule_id_bits: int,
    dtag_bits: int,
    window_bits: int,
    fcn_bits: int,
    rcs_bits: int = 0,
) -> int:
    """Return the number of whole payload bytes fitting one SCHC fragment.

    The calculation is bit-exact: the Rule ID, DTag, window, FCN, and optional
    RCS consume bits before trailing padding is added to the fragment. Inputs
    use the same unsigned 64-bit domain as the Rust implementation so vector
    results and overflow failures are portable across implementations.
    """
    mtu_bytes = _tile_size_input("mtu_bytes", mtu_bytes)
    if mtu_bytes == 0:
        raise FragmentError("mtu_bytes must be positive")
    widths = (
        ("rule_id_bits", rule_id_bits),
        ("dtag_bits", dtag_bits),
        ("window_bits", window_bits),
        ("fcn_bits", fcn_bits),
        ("rcs_bits", rcs_bits),
    )
    overhead_bits = 0
    for name, value in widths:
        width = _tile_size_input(name, value)
        if overhead_bits > _U64_MAX - width:
            raise FragmentError("fragment overhead arithmetic overflow")
        overhead_bits += width
    if mtu_bytes > _U64_MAX // 8:
        raise FragmentError("MTU arithmetic overflow")
    available_bits = mtu_bytes * 8
    if available_bits < overhead_bits + 8:
        raise FragmentError("fragment cannot carry one whole payload byte")
    return (available_bits - overhead_bits) // 8


def tile_size_for_mtu(
    mtu_bytes: int,
    *,
    rule_id_bits: int,
    dtag_bits: int,
    window_bits: int,
    fcn_bits: int,
    rcs_bits: int,
) -> int:
    """Return a tile size that fits both regular/All-0 and All-1 fragments."""
    regular = fragment_payload_capacity(
        mtu_bytes,
        rule_id_bits=rule_id_bits,
        dtag_bits=dtag_bits,
        window_bits=window_bits,
        fcn_bits=fcn_bits,
    )
    terminal = fragment_payload_capacity(
        mtu_bytes,
        rule_id_bits=rule_id_bits,
        dtag_bits=dtag_bits,
        window_bits=window_bits,
        fcn_bits=fcn_bits,
        rcs_bits=rcs_bits,
    )
    return min(regular, terminal)


class _ValidatedSchcClock:
    """Fail-stop monotonic clock guard shared by SCHC session owners."""

    def __init__(self, callback: Callable[[], float]) -> None:
        self._callback = callback
        self._lock = threading.RLock()
        self._active = False
        self._failed = False
        self._high_water = -1.0

    def __call__(self) -> float:
        with self._lock:
            if self._failed:
                raise FragmentError("SCHC monotonic clock is permanently disabled")
            if self._active:
                self._failed = True
                raise FragmentError("SCHC monotonic clock reentered")
            self._active = True
            try:
                try:
                    value = self._callback()
                except Exception as exc:
                    self._failed = True
                    raise FragmentError("SCHC monotonic clock callback failed") from exc
            finally:
                self._active = False
            if self._failed:
                raise FragmentError("SCHC monotonic clock is permanently disabled")
            if type(value) not in (int, float):
                self._failed = True
                raise FragmentError("SCHC monotonic clock must return an integer or float")
            try:
                current = float(value)
            except (OverflowError, ValueError) as exc:
                self._failed = True
                raise FragmentError("SCHC monotonic clock value is not representable") from exc
            if not math.isfinite(current) or current < 0:
                self._failed = True
                raise FragmentError("SCHC monotonic clock must be finite and non-negative")
            if current < self._high_water:
                self._failed = True
                raise FragmentError("SCHC monotonic clock regressed")
            self._high_water = current
            return current


class _IssuedFragmentWire(bytes):
    """Opaque bytes whose one-use send authority remains manager-owned."""


def compute_mic(payload: bytes) -> bytes:
    """CRC-32/ISO-HDLC (RFC 8724 §8.1) over payload || 0x00. Matches Rust impl."""
    return zlib.crc32(payload + b"\0").to_bytes(MIC_LENGTH, "big")


def _check_rule(rule_id: int) -> None:
    if type(rule_id) is not int or rule_id not in RULE_IDS:
        raise FragmentError(f"unsupported fragmentation rule: {rule_id!r}")


def _check_window(window: int, *, field: str = "window") -> None:
    if type(window) is not int or window not in (0, 1):
        raise FragmentError(f"{field} out of range")


def ack_request(rule_id: int, window: int) -> bytes:
    _check_rule(rule_id)
    _check_window(window, field="ACK REQ window")
    return bytes([rule_id, window << 7])


def sender_abort(rule_id: int) -> bytes:
    _check_rule(rule_id)
    return bytes([rule_id, 0xFE])


def receiver_abort(rule_id: int) -> bytes:
    _check_rule(rule_id)
    return bytes([rule_id, 0xFF, 0xFF])


@dataclass(frozen=True)
class Fragment:
    rule_id: int
    window: int
    fcn: int
    payload: bytes
    mic: bytes = b""

    @property
    def is_all_1(self) -> bool:
        return self.fcn == ALL_1

    @property
    def is_all_0(self) -> bool:
        return self.fcn == 0

    def to_bytes(self) -> bytes:
        _check_rule(self.rule_id)
        if type(self.payload) is not bytes or type(self.mic) is not bytes:
            raise FragmentError("fragment payload and RCS must be bytes")
        if (
            type(self.window) is not int
            or self.window not in (0, 1)
            or type(self.fcn) is not int
            or not 0 <= self.fcn <= ALL_1
        ):
            raise FragmentError("window or FCN out of range")
        if self.is_all_1:
            if len(self.mic) != MIC_LENGTH:
                raise FragmentError("All-1 requires a four-byte RCS")
            if not 1 <= len(self.payload) <= TILE_SIZE:
                raise FragmentError(f"All-1 final tile must contain 1..{TILE_SIZE} bytes")
            content = self.mic + self.payload
        else:
            if len(self.payload) < 1 or len(self.payload) > TILE_SIZE:
                raise FragmentError(f"Regular Fragment tile must contain 1..{TILE_SIZE} bytes")
            if self.window == 1 and self.is_all_0:
                raise FragmentError("the final tile must be carried in All-1")
            if self.mic:
                raise FragmentError("Regular Fragment cannot carry an RCS")
            content = self.payload
        body = (
            ((self.window << 6) | self.fcn) << (8 * len(content)) | int.from_bytes(content, "big")
        ) << 1
        return bytes([self.rule_id]) + body.to_bytes(len(content) + 1, "big")

    @classmethod
    def from_bytes(cls, data: bytes, *, window_size: int | None = None) -> Fragment:
        if type(data) is not bytes:
            raise FragmentError("fragment must be bytes")
        if len(data) < 2:
            raise FragmentError("fragment too short")
        if len(data) > _MAX_FRAGMENT_WIRE_SIZE:
            raise FragmentError("fragment exceeds fixed-profile maximum wire length")
        _check_rule(data[0])
        if data[-1] & 1:
            raise FragmentError("non-zero end padding")
        value = int.from_bytes(data[1:], "big") >> 1
        content_len = len(data) - 2
        header = value >> (8 * content_len)
        window, fcn = header >> 6, header & 0x3F
        content = (value & ((1 << (8 * content_len)) - 1)).to_bytes(content_len, "big")
        if window_size is not None:
            if type(window_size) is not int or not 1 <= window_size <= ALL_1:
                raise FragmentError(f"window_size must be integer 1..{ALL_1}")
            if fcn != ALL_1 and fcn >= window_size:
                raise FragmentError(
                    f"FCN={fcn} invalid for window_size={window_size} "
                    f"(regular FCN must be < window_size or ALL_1)"
                )
        if fcn == ALL_1:
            if not 5 <= content_len <= MIC_LENGTH + TILE_SIZE:
                raise FragmentError("All-1 requires an RCS and non-empty final tile")
            return cls(data[0], window, fcn, content[MIC_LENGTH:], content[:MIC_LENGTH])
        if len(data) != TILE_SIZE + 2:
            raise FragmentError(f"Regular Fragment tile must contain {TILE_SIZE} bytes")
        if window == 1 and fcn == 0:
            raise FragmentError("the final tile must be carried in All-1")
        return cls(data[0], window, fcn, content)


@dataclass(frozen=True)
class Ack:
    rule_id: int
    window: int
    bitmap: tuple[bool, ...] = ()
    complete: bool = False

    def to_bytes(self) -> bytes:
        _check_rule(self.rule_id)
        _check_window(self.window, field="ACK window")
        if type(self.complete) is not bool:
            raise FragmentError("ACK complete flag must be bool")
        if type(self.bitmap) is not tuple or any(type(bit) is not bool for bit in self.bitmap):
            raise FragmentError("ACK bitmap must be a tuple of bool values")
        if self.complete:
            if self.bitmap:
                raise FragmentError("C=1 ACK cannot carry a bitmap")
            return bytes([self.rule_id, (self.window << 7) | 0x40])
        if len(self.bitmap) != WINDOW_SIZE:
            raise FragmentError("C=0 ACK requires a 63-bit bitmap")
        # Bit layout: W(1) | C=0(1) | bitmap(up to 63) | padding(to byte-align)
        # Trailing 1-bits are implicit and can be elided to save bytes.
        # When trailing 1s exist, keep only the prefix + enough restored 1s
        # to reach a byte boundary (C=0 occupies 2 bits, so padding targets
        # (2 + kept) % 8 == 0).
        bits = list(self.bitmap)
        trailing = 0
        for bit in reversed(bits):
            if not bit:
                break
            trailing += 1
        if trailing:
            kept = WINDOW_SIZE - trailing
            restored = (-(2 + kept)) % 8
            encoded = bits[:kept] + [True] * restored
            padding = 0
        else:
            encoded = bits
            padding = (-(2 + len(encoded))) % 8
        # Pack: W-bit first, then C=0 bit, then encoded bitmap, then padding zeros.
        value = self.window << 1
        for bit in encoded:
            value = (value << 1) | bit
        value <<= padding
        return bytes([self.rule_id]) + value.to_bytes((2 + len(encoded) + padding) // 8, "big")

    @classmethod
    def from_bytes(cls, data: bytes, *, assigned_fcns: Iterable[int] | None = None) -> Ack:
        if type(data) is not bytes:
            raise FragmentError("ACK must be bytes")
        if len(data) < 2:
            raise FragmentError("ACK too short")
        _check_rule(data[0])
        window = data[1] >> 7
        complete = bool(data[1] & 0x40)
        if complete:
            if len(data) != 2 or data[1] & 0x3F:
                raise FragmentError("malformed C=1 ACK or control")
            return cls(data[0], window, (), True)
        bit_count = len(data[1:]) * 8 - 2
        max_bytes = (2 + WINDOW_SIZE + 7) // 8
        if len(data[1:]) > max_bytes:
            raise FragmentError("ACK bitmap size exceeds SCHC maximum window size")
        raw = int.from_bytes(data[1:], "big") & ((1 << bit_count) - 1)
        if bit_count >= WINDOW_SIZE:
            padding = bit_count - WINDOW_SIZE
            if padding > 7 or raw & ((1 << padding) - 1):
                raise FragmentError("invalid ACK padding")
            raw >>= padding
            bitmap = tuple(bool(raw & (1 << (WINDOW_SIZE - 1 - i))) for i in range(WINDOW_SIZE))
        else:
            prefix = tuple(bool(raw & (1 << (bit_count - 1 - i))) for i in range(bit_count))
            bitmap = prefix + (True,) * (WINDOW_SIZE - bit_count)
        ack = cls(data[0], window, bitmap)
        if ack.to_bytes() != data:
            raise FragmentError("non-canonical compressed ACK")
        if assigned_fcns is not None:
            assigned = {62 - fcn if fcn != ALL_1 else 62 for fcn in assigned_fcns}
            if any(bit and i not in assigned for i, bit in enumerate(bitmap)):
                raise FragmentError("unassigned bitmap bit is set")
        return ack


@dataclass(frozen=True, eq=False)
class FragmentSender:
    payload: bytes
    rule_id: int = 0x78
    receiver_limit: int = DEFAULT_RECEIVER_LIMIT
    tile_size: int = TILE_SIZE
    window_size: int = WINDOW_SIZE
    _fragments: tuple[Fragment, ...] = field(init=False, repr=False)
    _manager: SchcSessionManager | None = field(default=None, init=False, repr=False)
    _remote_signer_identity: bytes | None = field(default=None, init=False, repr=False)
    _security_generation: int | None = field(default=None, init=False, repr=False)
    _attempts: int = field(default=0, init=False, repr=False)
    _status: str = field(default="ready", init=False, repr=False)

    def __post_init__(self) -> None:
        if type(self.payload) is not bytes:
            raise FragmentError("payload must be bytes")
        if not self.payload:
            raise FragmentError("empty packets cannot be fragmented")
        _check_rule(self.rule_id)
        if type(self.receiver_limit) is not int or not 1 <= self.receiver_limit <= MAX_PACKET_SIZE:
            raise FragmentError(f"receiver_limit must be an integer in 1..{MAX_PACKET_SIZE}")
        if type(self.tile_size) is not int or self.tile_size != TILE_SIZE:
            raise FragmentError(f"tile_size must be the fixed profile value {TILE_SIZE}")
        if type(self.window_size) is not int or self.window_size != WINDOW_SIZE:
            raise FragmentError(f"window_size must be the fixed profile value {WINDOW_SIZE}")
        if len(self.payload) > MAX_PACKET_SIZE:
            raise FragmentError(
                f"payload exceeds profile capacity ({len(self.payload)} > {MAX_PACKET_SIZE})"
            )
        if len(self.payload) > self.receiver_limit:
            raise FragmentError(f"payload too large ({len(self.payload)} > {self.receiver_limit})")
        object.__setattr__(self, "_fragments", tuple(self._build()))

    @property
    def attempts(self) -> int:
        """Total generated All-1/ACK-REQ requests, whether or not radio-sent."""
        manager = _issued_manager(self)
        return self._attempts if manager is None else manager.sender_attempts(self)

    @property
    def status(self) -> str:
        """Current sender state, exposed read-only."""
        manager = _issued_manager(self)
        return self._status if manager is None else manager.sender_status(self)

    @property
    def retransmission_deadline(self) -> float | None:
        """Absolute monotonic deadline for the next authenticated retry."""
        manager = _issued_manager(self)
        return None if manager is None else manager.sender_retransmission_deadline(self)

    def _bind_session(
        self,
        manager: SchcSessionManager,
        remote_signer_identity: bytes,
        generation: int,
    ) -> None:
        if self.status != "ready" or self._manager is not None:
            raise FragmentError("sender session is already bound")
        object.__setattr__(self, "_manager", manager)
        object.__setattr__(self, "_remote_signer_identity", remote_signer_identity)
        object.__setattr__(self, "_security_generation", generation)

    def _set_security_state(
        self,
        *,
        status: str | None = None,
        attempts: int | None = None,
    ) -> None:
        """Manager-only state transition primitive; caller holds its security lock."""
        if status is not None:
            object.__setattr__(self, "_status", status)
        if attempts is not None:
            object.__setattr__(self, "_attempts", attempts)

    def _build(self) -> list[Fragment]:
        tiles = [self.payload[i : i + TILE_SIZE] for i in range(0, len(self.payload), TILE_SIZE)]
        mic = compute_mic(self.payload)
        n = len(tiles)
        frags: list[Fragment] = []
        for i, tile in enumerate(tiles):
            wire_window = i // WINDOW_SIZE
            pos = i % WINDOW_SIZE
            is_last = i == n - 1
            fcn = ALL_1 if is_last else (WINDOW_SIZE - 1 - pos)
            frags.append(Fragment(self.rule_id, wire_window, fcn, tile, mic if is_last else b""))
        return frags

    def all_fragments(self) -> list[Fragment]:
        manager = _issued_manager(self)
        fragments = self._fragments if manager is None else manager.sender_fragments(self)
        return list(fragments)

    @property
    def fragment_count(self) -> int:
        return len(self.all_fragments())

    @property
    def window_count(self) -> int:
        return self.all_fragments()[-1].window + 1

    def fragments_in_window(self, abs_window: int) -> list[Fragment]:
        start = abs_window * WINDOW_SIZE
        return self.all_fragments()[start : start + WINDOW_SIZE]

    def retransmit(self, abs_window: int, bitmap: Sequence[bool]) -> list[Fragment]:
        window_frags = self.fragments_in_window(abs_window)
        if len(bitmap) > len(window_frags):
            bitmap = bitmap[: len(window_frags)]
        missing: list[Fragment] = []
        for pos, frag in enumerate(window_frags):
            if (pos >= len(bitmap) or not bitmap[pos]) and not frag.is_all_1:
                missing.append(frag)
        return missing

    def start(self) -> list[bytes]:
        manager = _issued_manager(self)
        if manager is None:
            raise FragmentError(
                "authenticated link session required; use LinkLayer.create_fragment_sender"
            )
        return manager.activate_and_start(self)

    def final_window(self) -> int:
        return self.all_fragments()[-1].window

    def handle_ack_frame(self, received: RxFrame) -> list[bytes]:
        """Process one link-verified, replay-accepted ACK frame.

        The :class:`RxFrame` owns the immutable authenticated payload and signer
        metadata. Keeping them in one verifier-produced value prevents callers
        from pairing authentication metadata from one frame with different ACK
        bytes.
        """
        from lichen.link.link_layer import RxFrame

        if type(received) is not RxFrame:
            raise FragmentError("ACK must be supplied as a verified RxFrame")
        if self.status != "active":
            return []
        manager = _issued_manager(self)
        if manager is None:
            raise FragmentError("authenticated session required for ACK processing")
        return manager.transition_ack(self, received)

    def timeout(self) -> bytes:
        manager = _issued_manager(self)
        if manager is None:
            return b""
        return manager.transition_timeout(self)

    def timeout_if_due(self) -> bytes:
        """Fire the fixed retransmission timer only at or after its deadline."""
        manager = _issued_manager(self)
        if manager is None:
            return b""
        return manager.transition_timeout_if_due(self)

    def cancel(self) -> None:
        """Release this sender or terminate its live session exactly once."""
        manager = _issued_manager(self)
        if manager is None:
            if self.status == "ready":
                self._set_security_state(status="cancelled")
            return
        manager.transition_cancel(self)
