# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SCHC fragmentation — ACK-on-Error sender side (RFC 8724 section 8).

A compressed packet larger than the link MTU is split into *tiles* carried by
SCHC fragments. Each fragment header is a fragmentation Rule ID byte followed by
a byte holding the 1-bit window (W) and 6-bit fragment counter (FCN), per spec
5.6. FCN counts down within a window; the final fragment of the datagram uses
the All-1 FCN and carries a CRC32 Reassembly Check Sequence (the MIC).

This module implements the fragment wire format, the MIC, and the sender
(:class:`FragmentSender`): tiling, the per-tile window/FCN schedule, and
ACK-driven retransmission. The receiver-side reassembly state machine lives in
:mod:`lichen.schc.reassembly` (issue e2m). The sender is deterministic; the
caller drives the radio and feeds back ACK bitmaps.
"""

from __future__ import annotations

import zlib
from collections.abc import Sequence
from dataclasses import dataclass, field

N_FCN_BITS = 6
ALL_1 = (1 << N_FCN_BITS) - 1  # 63 — marks the last fragment of the datagram
MAX_WINDOW_SIZE = ALL_1 - 1  # 62 regular FCNs (62..0) per full window
DEFAULT_WINDOW_SIZE = 7
MIC_LENGTH = 4  # CRC32

_W_SHIFT = 6
_FCN_MASK = 0x3F


class FragmentError(Exception):
    """Raised when a SCHC fragment is malformed."""


def compute_mic(payload: bytes) -> bytes:
    """Reassembly Check Sequence over the full datagram (RFC 8724 default CRC32)."""
    return zlib.crc32(payload).to_bytes(MIC_LENGTH, "big")


@dataclass
class Fragment:
    """A single SCHC fragment (spec 5.6)."""

    rule_id: int
    window: int  # 1-bit window indicator (W)
    fcn: int  # 6-bit fragment counter
    payload: bytes
    mic: bytes = b""  # 4-byte CRC32, present only on the All-1 fragment

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
    """An ACK-on-Error acknowledgement: a positional receipt bitmap for a window.

    ``bitmap[p]`` is True if the p-th fragment (transmission order) of the window
    was received. ``complete`` is True when the whole datagram is reassembled.
    """

    rule_id: int
    window: int
    bitmap: tuple[bool, ...]
    complete: bool = False

    def to_bytes(self) -> bytes:
        # Byte 1: window bit in top position (bit 6), complete flag in LSB (bit 0)
        byte1 = ((self.window & 1) << _W_SHIFT) | (0x01 if self.complete else 0)
        # Pack bitmap into big-endian bytes: first fragment's bit is MSB of first byte.
        # Shift-accumulate: for each bool, shift left and OR in 1 or 0.
        # Example: bitmap (T,F,T,T,F) -> bits = 0b10110 = 22
        bits = 0
        for received in self.bitmap:
            bits = (bits << 1) | (1 if received else 0)
        n = len(self.bitmap)
        # Pad to a whole number of bytes: if n=5, pad=3, so we shift left 3
        # to align the 5 bits to the MSB of a single byte (0b10110 -> 0b10110000).
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
    """Splits a payload into SCHC fragments and handles retransmission."""

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
        """Every fragment of the datagram in transmission order."""
        return list(self._fragments)

    @property
    def fragment_count(self) -> int:
        return len(self._fragments)

    @property
    def window_count(self) -> int:
        return (self.fragment_count + self.window_size - 1) // self.window_size

    def fragments_in_window(self, abs_window: int) -> list[Fragment]:
        """Fragments belonging to absolute window ``abs_window`` (transmission order)."""
        start = abs_window * self.window_size
        return self._fragments[start : start + self.window_size]

    def retransmit(
        self, abs_window: int, bitmap: Sequence[bool]
    ) -> list[Fragment]:
        """Fragments in ``abs_window`` not acknowledged by ``bitmap`` (positional)."""
        window_frags = self.fragments_in_window(abs_window)
        if len(bitmap) > len(window_frags):
            raise FragmentError(
                f"bitmap ({len(bitmap)}) longer than window {abs_window} "
                f"({len(window_frags)} fragments)"
            )
        missing: list[Fragment] = []
        for pos, frag in enumerate(window_frags):
            if pos >= len(bitmap) or not bitmap[pos]:
                missing.append(frag)
        return missing
