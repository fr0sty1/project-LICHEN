# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

import zlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

N_FCN_BITS = 6
ALL_1 = (1 << N_FCN_BITS) - 1
MAX_WINDOW_SIZE = ALL_1 - 1
DEFAULT_WINDOW_SIZE = 7
MIC_LENGTH = 4

_W_SHIFT = 6
_FCN_MASK = 0x3F


class FragmentError(Exception):
    pass


def compute_mic(payload: bytes) -> bytes:
    return zlib.crc32(payload).to_bytes(MIC_LENGTH, "big")


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
    rule_id: int
    window: int
    bitmap: tuple[bool, ...] = ()
    complete: bool = False

    def to_bytes(self) -> bytes:
        byte1 = ((self.window & 1) << _W_SHIFT) | (0x01 if self.complete else 0)
        if self.complete:
            return bytes([self.rule_id, byte1])
        bits = 0
        for received in self.bitmap:
            bits = (bits << 1) | (1 if received else 0)
        n = len(self.bitmap)
        pad = (-n) % 8
        body = (bits << pad).to_bytes((n + pad) // 8, "big") if n else b""
        return bytes([self.rule_id, byte1, n]) + body

    @classmethod
    def from_bytes(cls, data: bytes) -> Ack:
        if len(data) < 2:
            raise FragmentError("ACK too short")
        rule_id = data[0]
        window = (data[1] >> _W_SHIFT) & 1
        complete = bool(data[1] & 0x01)
        if complete:
            return cls(rule_id, window, (), complete)
        if len(data) < 3:
            raise FragmentError("ACK too short")
        n = data[2]
        if n > MAX_WINDOW_SIZE:
            raise FragmentError(f"bitmap size {n} exceeds maximum {MAX_WINDOW_SIZE}")
        body = data[3:]
        required_bytes = (n + 7) // 8
        if len(body) < required_bytes:
            raise FragmentError(
                f"ACK bitmap truncated: need {required_bytes} bytes, got {len(body)}"
            )
        bitmap = []
        for i in range(n):
            byte = body[i // 8]
            bitmap.append(bool((byte >> (7 - (i % 8))) & 1))
        return cls(rule_id, window, tuple(bitmap), complete)


@dataclass
class FragmentSender:
    payload: bytes
    rule_id: int = 0x78
    receiver_limit: int = DEFAULT_RECEIVER_LIMIT
    _fragments: list[Fragment] = field(init=False, repr=False)
    attempts: int = field(default=0, init=False)
    status: str = field(default="ready", init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.tile_size, int) or self.tile_size <= 0:
            raise FragmentError("tile_size must be positive integer")
        if not isinstance(self.window_size, int) or not 1 <= self.window_size <= MAX_WINDOW_SIZE:
            raise FragmentError(f"window_size must be integer 1..{MAX_WINDOW_SIZE}")
        if len(self.payload) > 1280:
            raise FragmentError(f"payload too large ({len(self.payload)} > 1280)")
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
