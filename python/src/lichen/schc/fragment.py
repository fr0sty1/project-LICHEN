# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

import zlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

N_FCN_BITS = 6
ALL_1 = (1 << N_FCN_BITS) - 1
MAX_WINDOW_SIZE = ALL_1
DEFAULT_WINDOW_SIZE = 7
MIC_LENGTH = 4
RULE_IDS = (0x78, 0x79)
TILE_SIZE = 187
MAX_PACKET_SIZE = 16384
DEFAULT_RECEIVER_LIMIT = 1281
MAX_ACK_REQUESTS = 4
WINDOW_SIZE = 63

_W_SHIFT = 6
_FCN_MASK = 0x3F


class FragmentError(Exception):
    pass


def compute_mic(payload: bytes) -> bytes:
    """CRC-32/ISO-HDLC (RFC 8724 §8.1) over payload || 0x00. Matches Rust impl."""
    return zlib.crc32(payload + b"\0").to_bytes(MIC_LENGTH, "big")


def _check_rule(rule_id: int) -> None:
    if rule_id not in RULE_IDS:
        raise FragmentError(f"unsupported fragmentation rule: {rule_id:#x}")


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
        if self.window not in (0, 1) or not 0 <= self.fcn <= ALL_1:
            raise FragmentError("window or FCN out of range")
        if self.is_all_1:
            if len(self.mic) != MIC_LENGTH:
                raise FragmentError("All-1 requires a four-byte RCS")
            if not 1 <= len(self.payload) <= TILE_SIZE:
                raise FragmentError("All-1 final tile must contain 1..187 bytes")
            content = self.mic + self.payload
        else:
            if len(self.payload) < 1 or len(self.payload) > TILE_SIZE:
                raise FragmentError("Regular Fragment tile must contain 1..187 bytes")
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
        if window_size is not None:
            if not 1 <= window_size <= ALL_1:
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
            raise FragmentError("Regular Fragment tile must contain 187 bytes")
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


@dataclass
class FragmentSender:
    payload: bytes
    rule_id: int = 0x78
    receiver_limit: int = DEFAULT_RECEIVER_LIMIT
    tile_size: int = TILE_SIZE
    window_size: int = WINDOW_SIZE
    _fragments: list[Fragment] = field(init=False, repr=False)
    attempts: int = field(default=0, init=False)
    status: str = field(default="ready", init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.tile_size, int) or self.tile_size <= 0:
            raise FragmentError("tile_size must be positive integer")
        if not isinstance(self.window_size, int) or not 1 <= self.window_size <= MAX_WINDOW_SIZE:
            raise FragmentError(f"window_size must be integer 1..{MAX_WINDOW_SIZE}")
        if len(self.payload) > self.receiver_limit:
            raise FragmentError(f"payload too large ({len(self.payload)} > {self.receiver_limit})")
        self._fragments = self._build()

    def _build(self) -> list[Fragment]:
        tiles = [
            self.payload[i : i + self.tile_size]
            for i in range(0, max(len(self.payload), 1), self.tile_size)
        ]
        mic = compute_mic(self.payload)
        n = len(tiles)
        frags: list[Fragment] = []
        for i, tile in enumerate(tiles):
            wire_window = (i // self.window_size) % 2
            pos = i % self.window_size
            is_last = i == n - 1
            fcn = ALL_1 if is_last else (self.window_size - 1 - pos)
            frags.append(
                Fragment(self.rule_id, wire_window, fcn, tile, mic if is_last else b"")
            )
        return frags

    def all_fragments(self) -> list[Fragment]:
        return list(self._fragments)

    @property
    def fragment_count(self) -> int:
        return len(self._fragments)

    @property
    def window_count(self) -> int:
        return self._fragments[-1].window + 1

    def fragments_in_window(self, abs_window: int) -> list[Fragment]:
        start = abs_window * self.window_size
        return self._fragments[start : start + self.window_size]

    def retransmit(
        self, abs_window: int, bitmap: Sequence[bool]
    ) -> list[Fragment]:
        window_frags = self.fragments_in_window(abs_window)
        if len(bitmap) > len(window_frags):
            bitmap = bitmap[:len(window_frags)]
        missing: list[Fragment] = []
        for pos, frag in enumerate(window_frags):
            if pos >= len(bitmap) or not bitmap[pos]:
                missing.append(frag)
        return missing

    def start(self) -> list[bytes]:
        if self.status != "ready":
            raise FragmentError("sender not in ready state")
        self.status = "active"
        self.attempts = 1
        return [self._fragments[0].to_bytes()]

    def final_window(self) -> int:
        return self._fragments[-1].window

    def handle_ack_bytes(self, data: bytes) -> list[bytes]:
        if self.status != "active" or not data or data[0] != self.rule_id:
            return []
        ack = Ack.from_bytes(data)
        if ack.complete:
            self.status = "succeeded"
            return []
        window = ack.window
        window_frags = self.fragments_in_window(window)
        missing = []
        for frag in window_frags:
            bitmap_pos = 62 if frag.is_all_1 else (62 - frag.fcn)
            bitmap_bit = bitmap_pos < len(ack.bitmap) and ack.bitmap[bitmap_pos]
            if not bitmap_bit:
                missing.append(frag)
        if self.attempts >= MAX_ACK_REQUESTS:
            return [sender_abort(self.rule_id)]
        self.attempts += 1
        result = [frag.to_bytes() for frag in missing]
        result.append(ack_request(self.rule_id, self.final_window()))
        return result

    def timeout(self) -> bytes:
        if self.status != "active":
            return b""
        if self.attempts >= MAX_ACK_REQUESTS:
            self.status = "aborted"
            return sender_abort(self.rule_id)
        self.attempts += 1
        return ack_request(self.rule_id, self.final_window())
