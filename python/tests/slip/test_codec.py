# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the SLIP framing codec."""

from __future__ import annotations

import pytest

from lichen.slip.codec import END, ESC, ESC_END, ESC_ESC, StreamDecoder, decode, encode


class TestEncode:
    def test_empty_packet(self) -> None:
        assert encode(b"") == bytes([END, END])

    def test_plain_payload(self) -> None:
        out = encode(b"\x60\x00\x00\x00")
        assert out == bytes([END, 0x60, 0x00, 0x00, 0x00, END])

    def test_escapes_end_byte(self) -> None:
        out = encode(bytes([END]))
        assert out == bytes([END, ESC, ESC_END, END])

    def test_escapes_esc_byte(self) -> None:
        out = encode(bytes([ESC]))
        assert out == bytes([END, ESC, ESC_ESC, END])

    def test_escapes_both_in_sequence(self) -> None:
        out = encode(bytes([END, ESC]))
        assert out == bytes([END, ESC, ESC_END, ESC, ESC_ESC, END])

    def test_realistic_ipv6_header_start(self) -> None:
        # IPv6 version nibble is 0x60; not a special SLIP byte
        ipv6 = bytes([0x60] + [0x00] * 39)
        out = encode(ipv6)
        assert out[0] == END
        assert out[-1] == END
        assert out[1:-1] == ipv6  # no escaping needed


class TestDecode:
    def test_plain_frame(self) -> None:
        frame = bytes([END, 0x01, 0x02, 0x03, END])
        assert decode(frame) == bytes([0x01, 0x02, 0x03])

    def test_strips_leading_end(self) -> None:
        assert decode(bytes([END, 0xAA, END])) == bytes([0xAA])

    def test_unescape_end(self) -> None:
        frame = bytes([END, ESC, ESC_END, END])
        assert decode(frame) == bytes([END])

    def test_unescape_esc(self) -> None:
        frame = bytes([END, ESC, ESC_ESC, END])
        assert decode(frame) == bytes([ESC])

    def test_consecutive_ends_ignored(self) -> None:
        # Multiple END bytes between frames — should produce empty result
        assert decode(bytes([END, END, END])) == b""

    def test_bare_esc_at_end_raises(self) -> None:
        with pytest.raises(ValueError, match="bare ESC"):
            decode(bytes([END, ESC]))

    def test_invalid_escape_passes_byte_through(self) -> None:
        # RFC 1055: invalid escape — ignore ESC, pass byte through as data
        # ESC 0x00 is invalid; 0x00 should be captured (ESC discarded per RFC)
        result = decode(bytes([END, ESC, 0x00, END]))
        assert result == b"\x00"

    def test_round_trip(self) -> None:
        for payload in [b"", b"\x00", b"\xc0\xdb", bytes(range(256))]:
            assert decode(encode(payload)) == payload


class TestStreamDecoder:
    def test_single_chunk(self) -> None:
        dec = StreamDecoder()
        packets = dec.feed(encode(b"hello"))
        assert packets == [b"hello"]

    def test_split_across_two_feeds(self) -> None:
        dec = StreamDecoder()
        frame = encode(b"\x01\x02\x03")
        mid = len(frame) // 2
        p1 = dec.feed(frame[:mid])
        p2 = dec.feed(frame[mid:])
        assert p1 == []
        assert p2 == [b"\x01\x02\x03"]

    def test_two_packets_in_one_feed(self) -> None:
        dec = StreamDecoder()
        data = encode(b"first") + encode(b"second")
        packets = dec.feed(data)
        assert packets == [b"first", b"second"]

    def test_escape_split_across_feeds(self) -> None:
        # ESC byte arrives in one chunk, the escape code in the next
        dec = StreamDecoder()
        # frame: END ESC ESC_END END  (encodes a single END byte)
        frame = bytes([END, ESC, ESC_END, END])
        p1 = dec.feed(frame[:2])   # END ESC — partial
        p2 = dec.feed(frame[2:])   # ESC_END END
        assert p1 == []
        assert p2 == [bytes([END])]

    def test_consecutive_ends_between_packets(self) -> None:
        dec = StreamDecoder()
        # Two consecutive ENDs between packets is valid (sync/idle marker)
        data = encode(b"a") + bytes([END]) + encode(b"b")
        packets = dec.feed(data)
        assert packets == [b"a", b"b"]

    def test_reset_discards_partial(self) -> None:
        dec = StreamDecoder()
        frame = encode(b"data")
        dec.feed(frame[:3])  # partial
        dec.reset()
        # After reset, the rest of the old frame is junk; only new complete packets
        packets = dec.feed(encode(b"fresh"))
        assert packets == [b"fresh"]

    def test_byte_by_byte(self) -> None:
        dec = StreamDecoder()
        payload = bytes([0xC0, 0xDB, 0x00, 0xFF])  # contains special bytes
        frame = encode(payload)
        packets = []
        for b in frame:
            packets.extend(dec.feed(bytes([b])))
        assert packets == [payload]

    def test_invalid_escape_passes_byte_through(self) -> None:
        # RFC 1055: invalid escape — ignore ESC, pass byte through as data
        dec = StreamDecoder()
        # Build a frame with an invalid escape manually
        bad = bytes([END, ESC, 0x00, 0x41, END])  # ESC 0x00 is invalid
        packets = dec.feed(bad)
        # Both 0x00 and 0x41 should be captured (ESC is discarded per RFC)
        assert packets == [b"\x00A"]

    def test_default_max_size(self) -> None:
        dec = StreamDecoder()
        assert dec._max_size == StreamDecoder.DEFAULT_MAX_SIZE

    def test_custom_max_size(self) -> None:
        dec = StreamDecoder(max_size=128)
        assert dec._max_size == 128

    def test_buffer_overflow_discards_partial_packet(self) -> None:
        # Use a small max_size for testing
        dec = StreamDecoder(max_size=10)
        # Feed 15 bytes without END — should discard when buffer hits 10
        # Bytes 0-9 fill buffer, byte 10 triggers overflow (clear + set overflow flag),
        # bytes 11-14 are all discarded (in overflow mode, waiting for END)
        dec.feed(bytes(range(15)))
        assert len(dec._buf) == 0
        assert dec._overflow is True

    def test_buffer_overflow_allows_next_packet(self) -> None:
        # Use a small max_size for testing
        dec = StreamDecoder(max_size=10)
        # Feed END, oversized data, END, then a valid packet
        # The leading END establishes sync, then oversized data overflows,
        # trailing END delimits the garbage, and valid packet decodes
        overflow_data = bytes([END]) + bytes(range(20)) + bytes([END])
        valid_packet = encode(b"ok")
        packets = dec.feed(overflow_data + valid_packet)
        # Garbage packets from overflow may appear, but "ok" should be last
        assert packets[-1] == b"ok"

    def test_buffer_overflow_clears_escape_state(self) -> None:
        # Use a small max_size for testing
        dec = StreamDecoder(max_size=5)
        # Set escape state then overflow
        dec.feed(bytes([ESC]))  # Escape state active
        assert dec._escaped is True
        dec.feed(bytes([1, 2, 3, 4, 5]))  # This should trigger overflow + clear
        # Escape state should be cleared along with buffer
        assert dec._escaped is False

    def test_buffer_overflow_at_end_delimiter_preserves_next_packet(self) -> None:
        # Regression test: When END byte triggers overflow check, next packet must
        # not be discarded. If max_size bytes are in buffer and next byte is END,
        # we discard the oversized packet but do NOT enter overflow mode - because
        # END already delimits the bad packet.
        dec = StreamDecoder(max_size=10)
        # Build: [10 bytes of data][END][valid packet][END]
        oversized = bytes([END]) + bytes(range(10))  # 10 bytes in buffer
        # Note: bytes(range(10)) = 0x00..0x09, none are END/ESC
        # After feeding these 11 bytes: buffer has 10 bytes, next byte (END) triggers check
        # Since it's END, we should discard buffer but NOT enter overflow mode
        data = oversized + bytes([END]) + encode(b"valid")
        packets = dec.feed(data)
        # The valid packet should be received (not discarded as overflow)
        assert b"valid" in packets
