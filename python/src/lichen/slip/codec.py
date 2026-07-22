# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SLIP framing codec (RFC 1055).

SLIP wraps IPv6 packets for transport over a serial UART — the link between a
local client (phone, desktop) and the gateway node.

Wire encoding::

    END     = 0xC0  — marks packet boundaries (prepended and appended)
    ESC     = 0xDB  — escape prefix
    ESC_END = 0xDC  — ESC ESC_END encodes a literal 0xC0 in the payload
    ESC_ESC = 0xDD  — ESC ESC_ESC encodes a literal 0xDB in the payload

Usage::

    # Encode one packet for transmission:
    frame = encode(ipv6_bytes)

    # Decode a stream of bytes incrementally:
    dec = StreamDecoder()
    for chunk in uart_read():
        for packet in dec.feed(chunk):
            process(packet)
"""

from __future__ import annotations

END = 0xC0
ESC = 0xDB
ESC_END = 0xDC
ESC_ESC = 0xDD


def encode(packet: bytes) -> bytes:
    """Return ``packet`` wrapped in SLIP framing.

    The result is: END + escaped(packet) + END.
    Leading END acts as a flush in case the receiver is out of sync.
    """
    out = bytearray()
    out.append(END)
    for byte in packet:
        if byte == END:
            out.append(ESC)
            out.append(ESC_END)
        elif byte == ESC:
            out.append(ESC)
            out.append(ESC_ESC)
        else:
            out.append(byte)
    out.append(END)
    return bytes(out)


def decode(frame: bytes) -> bytes:
    """Decode a single SLIP frame, stripping END bytes and un-escaping.

    ``frame`` may include leading/trailing END bytes; they are ignored.
    Raises :class:`ValueError` if the frame ends with a bare ESC byte.

    Invalid escape sequences (ESC followed by anything other than ESC_END
    or ESC_ESC) are handled per RFC 1055: the ESC is discarded and the
    following byte is passed through as data. This matches the behavior
    of :class:`StreamDecoder`.
    """
    out = bytearray()
    i = 0
    seen_data = False
    while i < len(frame):
        b = frame[i]
        if b == END:
            i += 1
            if seen_data:
                break
            continue
        seen_data = True
        if b == ESC:
            i += 1
            if i >= len(frame):
                raise ValueError("SLIP frame ends with bare ESC")
            nxt = frame[i]
            if nxt == ESC_END:
                out.append(END)
            elif nxt == ESC_ESC:
                out.append(ESC)
            else:
                out.append(nxt)
        else:
            out.append(b)
        i += 1
    return bytes(out)


class StreamDecoder:
    """Incrementally decode a SLIP byte stream.

    Feed arbitrary chunks of bytes from a UART or pipe; call :meth:`feed` and
    iterate the returned packets.  Partial packets are buffered between calls.

    A maximum buffer size prevents memory exhaustion from malicious or faulty
    peers sending continuous bytes without END delimiters.

    Error handling:
        Invalid escape sequences (ESC followed by anything other than ESC_END
        or ESC_ESC) are handled per RFC 1055: the ESC is discarded and the
        following byte is passed through as data. This matches :func:`decode`.

    Args:
        max_size: Maximum bytes to buffer before discarding a partial packet.
            Defaults to 2048, which accommodates IPv6 MTU (1280-1500) plus
            escape expansion overhead.
    """

    DEFAULT_MAX_SIZE = 2048

    def __init__(self, max_size: int | None = None) -> None:
        self._buf: bytearray = bytearray()
        self._escaped: bool = False
        self._max_size: int = max_size if max_size is not None else self.DEFAULT_MAX_SIZE
        self._overflow: bool = False  # True when discarding bytes until next END

    def feed(self, data: bytes) -> list[bytes]:
        """Process ``data`` and return all complete packets decoded so far.

        If the buffer exceeds ``max_size``, the partial packet is discarded and
        all bytes are ignored until the next END delimiter. This prevents memory
        exhaustion from malicious or faulty peers sending continuous bytes without
        END, and ensures we resync cleanly at the next packet boundary.
        """
        packets: list[bytes] = []
        for byte in data:
            # Handle overflow mode first - discard bytes until END
            if self._overflow:
                if byte == END:
                    self._overflow = False
                continue

            if len(self._buf) >= self._max_size:
                self._buf.clear()
                self._escaped = False
                if byte != END:
                    self._overflow = True
                continue

            if self._escaped:
                self._escaped = False
                if byte == ESC_END:
                    self._buf.append(END)
                elif byte == ESC_ESC:
                    self._buf.append(ESC)
                else:
                    # RFC 1055: invalid escape — ignore ESC, pass byte through as data
                    self._buf.append(byte)
            elif byte == ESC:
                self._escaped = True
            elif byte == END:
                if self._buf:
                    packets.append(bytes(self._buf))
                    self._buf = bytearray()
                # else: consecutive END bytes (idle or sync) — ignore
            else:
                self._buf.append(byte)
        return packets

    def reset(self) -> None:
        """Discard any partial packet and reset all state."""
        self._buf = bytearray()
        self._escaped = False
        self._overflow = False
