# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN SCHC ACK-on-Error fragment codec and sender."""

from __future__ import annotations

import zlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

RULE_IDS = (0x78, 0x79)
ALL_1 = 63
WINDOW_SIZE = 63
DEFAULT_WINDOW_SIZE = WINDOW_SIZE
TILE_SIZE = 187
MIC_LENGTH = 4
MAX_TILES = 126
MAX_PACKET_SIZE = MAX_TILES * TILE_SIZE
DEFAULT_RECEIVER_LIMIT = 1281
MAX_ACK_REQUESTS = 4


class FragmentError(ValueError):
    """Raised when a SCHC fragmentation message is invalid."""


def _check_rule(rule_id: int) -> None:
    if rule_id not in RULE_IDS:
        raise FragmentError(f"unsupported fragmentation rule: {rule_id:#x}")


def compute_mic(payload: bytes) -> bytes:
    """Return the profile CRC-32/ISO-HDLC RCS."""
    return zlib.crc32(payload + b"\x00").to_bytes(MIC_LENGTH, "big")


@dataclass(frozen=True)
class Fragment:
    """One fixed-profile Regular or All-1 Fragment."""

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
        if self.window not in (0, 1) or not 0 <= self.fcn <= ALL_1:
            raise FragmentError("window or FCN out of range")
        if self.is_all_1:
            if len(self.mic) != MIC_LENGTH:
                raise FragmentError("All-1 requires a four-byte RCS")
            if not 1 <= len(self.payload) <= TILE_SIZE:
                raise FragmentError("All-1 final tile must contain 1..187 bytes")
            content = self.mic + self.payload
        else:
            if len(self.payload) != TILE_SIZE:
                raise FragmentError("Regular Fragment tile must contain 187 bytes")
            if self.window == 1 and self.is_all_0:
                raise FragmentError("the final tile must be carried in All-1")
            if self.mic:
                raise FragmentError("Regular Fragment cannot carry an RCS")
            content = self.payload
        body = (
            ((self.window << 6) | self.fcn) << (8 * len(content)) | int.from_bytes(content)
        ) << 1
        return bytes([self.rule_id]) + body.to_bytes(len(content) + 1, "big")

    @classmethod
    def from_bytes(cls, data: bytes) -> Fragment:
        if len(data) < 2:
            raise FragmentError("fragment too short")
        _check_rule(data[0])
        if data[-1] & 1:
            raise FragmentError("non-zero end padding")
        value = int.from_bytes(data[1:], "big") >> 1
        content_len = len(data) - 2
        header = value >> (8 * content_len)
        window, fcn = header >> 6, header & 0x3F
        content = (value & ((1 << (8 * content_len)) - 1)).to_bytes(content_len, "big")
        if fcn == ALL_1:
            if not 5 <= content_len <= MIC_LENGTH + TILE_SIZE:
                raise FragmentError("All-1 requires an RCS and non-empty final tile")
            return cls(data[0], window, fcn, content[MIC_LENGTH:], content[:MIC_LENGTH])
        if len(data) != TILE_SIZE + 2:
            raise FragmentError("Regular Fragment tile must contain 187 bytes")
        if window == 1 and fcn == 0:
            raise FragmentError("the final tile must be carried in All-1")
        return cls(data[0], window, fcn, content)


@dataclass(frozen=True)
class Ack:
    """A C=0 bitmap ACK or exact C=1 success ACK."""

    rule_id: int
    window: int
    bitmap: tuple[bool, ...] = ()
    complete: bool = False

    def to_bytes(self) -> bytes:
        _check_rule(self.rule_id)
        if self.window not in (0, 1):
            raise FragmentError("ACK window out of range")
        if self.complete:
            if self.bitmap:
                raise FragmentError("C=1 ACK cannot carry a bitmap")
            return bytes([self.rule_id, (self.window << 7) | 0x40])
        if len(self.bitmap) != WINDOW_SIZE:
            raise FragmentError("C=0 ACK requires a 63-bit bitmap")
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
        value = self.window << 1  # W followed by C=0
        for bit in encoded:
            value = (value << 1) | bit
        value <<= padding
        return bytes([self.rule_id]) + value.to_bytes((2 + len(encoded) + padding) // 8, "big")

    @classmethod
    def from_bytes(cls, data: bytes, *, assigned_fcns: Iterable[int] | None = None) -> Ack:
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


def ack_request(rule_id: int, window: int) -> bytes:
    _check_rule(rule_id)
    if window not in (0, 1):
        raise FragmentError("ACK REQ window out of range")
    return bytes([rule_id, window << 7])


def sender_abort(rule_id: int) -> bytes:
    _check_rule(rule_id)
    return bytes([rule_id, 0xFE])


def receiver_abort(rule_id: int) -> bytes:
    _check_rule(rule_id)
    return bytes([rule_id, 0xFF, 0xFF])


@dataclass
class FragmentSender:
    """Bounded fixed-profile sender driven by ACKs and explicit timeouts."""

    payload: bytes
    rule_id: int = 0x78
    receiver_limit: int = DEFAULT_RECEIVER_LIMIT
    _fragments: list[Fragment] = field(init=False, repr=False)
    attempts: int = field(default=0, init=False)
    status: str = field(default="ready", init=False)

    def __post_init__(self) -> None:
        _check_rule(self.rule_id)
        if not 1 <= self.receiver_limit <= MAX_PACKET_SIZE:
            raise FragmentError("receiver limit out of range")
        if not self.payload:
            raise FragmentError("empty packets cannot be fragmented")
        if len(self.payload) > self.receiver_limit:
            raise FragmentError("packet exceeds receiver reassembly limit")
        tiles = [self.payload[i : i + TILE_SIZE] for i in range(0, len(self.payload), TILE_SIZE)]
        mic = compute_mic(self.payload)
        self._fragments = []
        for ordinal, tile in enumerate(tiles):
            final = ordinal == len(tiles) - 1
            window = ordinal // WINDOW_SIZE
            fcn = ALL_1 if final else 62 - ordinal % WINDOW_SIZE
            self._fragments.append(Fragment(self.rule_id, window, fcn, tile, mic if final else b""))

    @property
    def fragment_count(self) -> int:
        return len(self._fragments)

    @property
    def window_count(self) -> int:
        return self._fragments[-1].window + 1

    @property
    def final_window(self) -> int:
        return self._fragments[-1].window

    def all_fragments(self) -> list[Fragment]:
        return list(self._fragments)

    def fragments_in_window(self, window: int) -> list[Fragment]:
        return [fragment for fragment in self._fragments if fragment.window == window]

    def retransmit(self, window: int, bitmap: Sequence[bool]) -> list[Fragment]:
        if len(bitmap) != WINDOW_SIZE:
            raise FragmentError("ACK bitmap must contain 63 bits")
        return [
            fragment
            for fragment in self.fragments_in_window(window)
            if not bitmap[62 if fragment.is_all_1 else 62 - fragment.fcn]
        ]

    def start(self) -> list[bytes]:
        if self.status != "ready":
            raise FragmentError("sender has already started")
        self.status = "active"
        self.attempts = 1
        return [fragment.to_bytes() for fragment in self._fragments]

    def _abort(self) -> list[bytes]:
        self.status = "aborted"
        self.payload = b""
        self._fragments.clear()
        return [sender_abort(self.rule_id)]

    def _request(self, message: bytes) -> list[bytes]:
        if self.attempts >= MAX_ACK_REQUESTS:
            return self._abort()
        self.attempts += 1
        return [message]

    def handle_ack(self, ack: Ack) -> list[bytes]:
        if self.status != "active" or ack.rule_id != self.rule_id:
            return []
        if ack.complete:
            if ack.window != self.final_window:
                return []
            self.status = "succeeded"
            self.payload = b""
            self._fragments.clear()
            return []
        if ack.window not in {fragment.window for fragment in self._fragments}:
            return []
        missing = self.retransmit(ack.window, ack.bitmap)
        if not missing:
            return self._abort() if ack.window == self.final_window else []
        wires = [fragment.to_bytes() for fragment in missing]
        all1 = next((fragment for fragment in missing if fragment.is_all_1), None)
        request = (
            all1.to_bytes() if all1 is not None else ack_request(self.rule_id, self.final_window)
        )
        requested = self._request(request)
        if requested and requested[0] == sender_abort(self.rule_id):
            return requested
        if all1 is None:
            wires.extend(requested)
        return wires

    def handle_ack_bytes(self, data: bytes) -> list[bytes]:
        if self.status != "active" or not data or data[0] != self.rule_id:
            return []
        if len(data) == 3 and data[1:] == b"\xff\xff":
            self.status = "aborted"
            self.payload = b""
            self._fragments.clear()
            return []
        ack = Ack.from_bytes(data)
        if not ack.complete:
            if ack.window not in {fragment.window for fragment in self._fragments}:
                return []
            assigned = [
                fragment.fcn for fragment in self._fragments if fragment.window == ack.window
            ]
            ack = Ack.from_bytes(data, assigned_fcns=assigned)
        return self.handle_ack(ack)

    def timeout(self) -> bytes:
        if self.status != "active":
            raise FragmentError("sender is not active")
        return self._request(ack_request(self.rule_id, self.final_window))[0]
