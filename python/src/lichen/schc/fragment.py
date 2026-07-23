# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

import zlib
from collections.abc import Sequence
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


@dataclass
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
        if not 0 <= self.rule_id <= 0xFF:
            raise FragmentError(f"rule_id out of range: {self.rule_id}")
        if not 0 <= self.fcn <= ALL_1:
            raise FragmentError(f"fcn out of range: {self.fcn}")
        if self.window not in (0, 1):
            raise FragmentError(f"window must be 0 or 1: {self.window}")
        header = bytes(
            [self.rule_id, ((self.window & 1) << _W_SHIFT) | (self.fcn & _FCN_MASK)]
        )
        if self.is_all_1:
            if len(self.mic) != MIC_LENGTH:
                raise FragmentError("All-1 fragment requires a 4-byte MIC")
            return header + self.mic + self.payload
        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> Fragment:
        if len(data) < 2:
            raise FragmentError("fragment too short")
        rule_id = data[0]
        window = (data[1] >> _W_SHIFT) & 1
        fcn = data[1] & _FCN_MASK
        rest = data[2:]
        if fcn == ALL_1:
            if len(rest) < MIC_LENGTH:
                raise FragmentError("All-1 fragment missing MIC")
            return cls(rule_id, window, fcn, rest[MIC_LENGTH:], rest[:MIC_LENGTH])
        return cls(rule_id, window, fcn, rest)


@dataclass
class Ack:
    rule_id: int
    window: int
    bitmap: tuple[bool, ...]
    complete: bool = False

    def to_bytes(self) -> bytes:
        byte1 = ((self.window & 1) << _W_SHIFT) | (0x01 if self.complete else 0)
        bits = 0
        for received in self.bitmap:
            bits = (bits << 1) | (1 if received else 0)
        n = len(self.bitmap)
        pad = (-n) % 8
        body = (bits << pad).to_bytes((n + pad) // 8, "big") if n else b""
        return bytes([self.rule_id, byte1, n]) + body

    @classmethod
    def from_bytes(cls, data: bytes) -> Ack:
        if len(data) < 3:
            raise FragmentError("ACK too short")
        rule_id = data[0]
        window = (data[1] >> _W_SHIFT) & 1
        complete = bool(data[1] & 0x01)
        n = data[2]
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
    rule_id: int
    tile_size: int
    window_size: int = DEFAULT_WINDOW_SIZE
    _fragments: list[Fragment] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        if self.tile_size <= 0:
            raise FragmentError("tile_size must be positive")
        if not 1 <= self.window_size <= MAX_WINDOW_SIZE:
            raise FragmentError(f"window_size must be 1..{MAX_WINDOW_SIZE}")
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
        return (self.fragment_count + self.window_size - 1) // self.window_size

    def fragments_in_window(self, abs_window: int) -> list[Fragment]:
        start = abs_window * self.window_size
        return self._fragments[start : start + self.window_size]

    def retransmit(
        self, abs_window: int, bitmap: Sequence[bool]
    ) -> list[Fragment]:
        window_frags = self.fragments_in_window(abs_window)
        missing: list[Fragment] = []
        for pos, frag in enumerate(window_frags):
            if pos >= len(bitmap) or not bitmap[pos]:
                missing.append(frag)
        return missing
