"""Tests for APRS message format."""

import time
from unittest.mock import MagicMock

from lichen.interface.kiss.aprs import (
    AprsAck,
    AprsMessage,
    AprsMessageTracker,
    AprsPacketType,
    AprsRej,
    create_ack,
    create_message,
    get_packet_type,
    parse_aprs_packet,
)


class TestAprsMessageEncode:
    def test_simple_message(self):
        msg = AprsMessage(addressee="W1AW", text="Hello")
        encoded = msg.encode()
        assert encoded == b":W1AW     :Hello"

    def test_message_with_id(self):
        msg = AprsMessage(addressee="N0CALL", text="Test", msg_id="123")
        encoded = msg.encode()
        assert encoded == b":N0CALL   :Test{123"

    def test_addressee_padded(self):
        msg = AprsMessage(addressee="AB", text="x")
        encoded = msg.encode()
        # AB should be padded to 9 chars
        assert encoded == b":AB       :x"

    def test_addressee_truncated(self):
        msg = AprsMessage(addressee="VERYLONGCALL", text="x")
        encoded = msg.encode()
        # Should be truncated to 9 chars
        assert encoded == b":VERYLONGC:x"

    def test_addressee_uppercased(self):
        msg = AprsMessage(addressee="w1aw", text="x")
        encoded = msg.encode()
        assert encoded.startswith(b":W1AW")

    def test_unicode_text(self):
        msg = AprsMessage(addressee="TEST", text="Hello 世界")
        encoded = msg.encode()
        assert b"Hello" in encoded
        assert "世界".encode() in encoded


class TestAprsAckEncode:
    def test_ack_format(self):
        ack = AprsAck(addressee="W1AW", msg_id="42")
        encoded = ack.encode()
        assert encoded == b":W1AW     :ack42"

    def test_ack_addressee_padded(self):
        ack = AprsAck(addressee="AB", msg_id="1")
        encoded = ack.encode()
        assert encoded == b":AB       :ack1"


class TestAprsRejEncode:
    def test_rej_format(self):
        rej = AprsRej(addressee="W1AW", msg_id="99")
        encoded = rej.encode()
        assert encoded == b":W1AW     :rej99"


class TestParseAprsPacket:
    def test_parse_simple_message(self):
        data = b":W1AW     :Hello World"
        result = parse_aprs_packet(data)
        assert isinstance(result, AprsMessage)
        assert result.addressee == "W1AW"
        assert result.text == "Hello World"
        assert result.msg_id is None

    def test_parse_message_with_id(self):
        data = b":N0CALL   :Test message{12345"
        result = parse_aprs_packet(data)
        assert isinstance(result, AprsMessage)
        assert result.addressee == "N0CALL"
        assert result.text == "Test message"
        assert result.msg_id == "12345"

    def test_parse_message_short_id(self):
        data = b":TEST     :Hi{1"
        result = parse_aprs_packet(data)
        assert isinstance(result, AprsMessage)
        assert result.msg_id == "1"

    def test_parse_ack(self):
        data = b":W1AW     :ack42"
        result = parse_aprs_packet(data)
        assert isinstance(result, AprsAck)
        assert result.addressee == "W1AW"
        assert result.msg_id == "42"

    def test_parse_rej(self):
        data = b":W1AW     :rej99"
        result = parse_aprs_packet(data)
        assert isinstance(result, AprsRej)
        assert result.addressee == "W1AW"
        assert result.msg_id == "99"

    def test_parse_strips_addressee(self):
        data = b":AB       :test"
        result = parse_aprs_packet(data)
        assert isinstance(result, AprsMessage)
        assert result.addressee == "AB"  # Stripped

    def test_parse_unknown_format(self):
        data = b"not aprs format"
        result = parse_aprs_packet(data)
        assert result is None

    def test_parse_too_short(self):
        data = b":AB:x"
        result = parse_aprs_packet(data)
        assert result is None

    def test_roundtrip_message(self):
        original = AprsMessage(addressee="W1AW", text="Hello", msg_id="42")
        encoded = original.encode()
        parsed = parse_aprs_packet(encoded)
        assert isinstance(parsed, AprsMessage)
        assert parsed.addressee == original.addressee
        assert parsed.text == original.text
        assert parsed.msg_id == original.msg_id

    def test_roundtrip_ack(self):
        original = AprsAck(addressee="N0CALL", msg_id="999")
        encoded = original.encode()
        parsed = parse_aprs_packet(encoded)
        assert isinstance(parsed, AprsAck)
        assert parsed.addressee == original.addressee
        assert parsed.msg_id == original.msg_id


class TestGetPacketType:
    def test_message_type(self):
        data = b":W1AW     :Hello"
        assert get_packet_type(data) == AprsPacketType.MESSAGE

    def test_ack_type(self):
        data = b":W1AW     :ack42"
        assert get_packet_type(data) == AprsPacketType.ACK

    def test_rej_type(self):
        data = b":W1AW     :rej42"
        assert get_packet_type(data) == AprsPacketType.REJ

    def test_position_types(self):
        assert get_packet_type(b"!4903.50N/07201.75W-") == AprsPacketType.POSITION
        assert get_packet_type(b"=4903.50N/07201.75W-") == AprsPacketType.POSITION
        assert get_packet_type(b"@092345z4903.50N/07201.75W") == AprsPacketType.POSITION

    def test_unknown_type(self):
        assert get_packet_type(b"random garbage") == AprsPacketType.UNKNOWN
        assert get_packet_type(b"") == AprsPacketType.UNKNOWN


class TestAprsMessageTracker:
    def test_next_msg_id_increments(self):
        tracker = AprsMessageTracker()
        id1 = tracker.next_msg_id()
        id2 = tracker.next_msg_id()
        assert id1 != id2
        assert int(id2) == int(id1) + 1

    def test_track_message(self):
        tracker = AprsMessageTracker()
        tracker.track_message("W1AW", "Hello", "1")
        assert tracker.pending_count() == 1

    def test_handle_ack_removes_pending(self):
        tracker = AprsMessageTracker()
        tracker.track_message("W1AW", "Hello", "1")
        assert tracker.pending_count() == 1

        result = tracker.handle_ack("1")
        assert result is True
        assert tracker.pending_count() == 0

    def test_handle_ack_unknown_returns_false(self):
        tracker = AprsMessageTracker()
        result = tracker.handle_ack("999")
        assert result is False

    def test_handle_ack_callback(self):
        callback = MagicMock()
        tracker = AprsMessageTracker(on_ack=callback)
        tracker.track_message("W1AW", "Hello", "42")
        tracker.handle_ack("42")
        callback.assert_called_once_with("W1AW", "42")

    def test_handle_rej_removes_pending(self):
        tracker = AprsMessageTracker()
        tracker.track_message("W1AW", "Hello", "1")
        result = tracker.handle_rej("1")
        assert result is True
        assert tracker.pending_count() == 0

    def test_clear(self):
        tracker = AprsMessageTracker()
        tracker.track_message("A", "x", "1")
        tracker.track_message("B", "y", "2")
        assert tracker.pending_count() == 2
        tracker.clear()
        assert tracker.pending_count() == 0


class TestAprsMessageTrackerRetries:
    def test_get_retries_empty_when_fresh(self):
        tracker = AprsMessageTracker(retry_interval_s=0.01)
        tracker.track_message("W1AW", "Hello", "1")
        # Immediately after tracking, no retries needed
        retries = tracker.get_retries()
        assert retries == []

    def test_get_retries_after_interval(self):
        tracker = AprsMessageTracker(retry_interval_s=0.01, retry_count=3)
        tracker.track_message("W1AW", "Hello", "1")
        time.sleep(0.02)

        retries = tracker.get_retries()
        assert len(retries) == 1
        addressee, text, msg_id = retries[0]
        assert addressee == "W1AW"
        assert text == "Hello"
        assert msg_id == "1"

    def test_retry_count_decrements(self):
        tracker = AprsMessageTracker(retry_interval_s=0.001, retry_count=2)
        tracker.track_message("W1AW", "Test", "1")

        # First retry
        time.sleep(0.002)
        retries = tracker.get_retries()
        assert len(retries) == 1

        # Second retry
        time.sleep(0.002)
        retries = tracker.get_retries()
        assert len(retries) == 1

        # Third attempt - should timeout
        time.sleep(0.002)
        retries = tracker.get_retries()
        assert len(retries) == 0
        assert tracker.pending_count() == 0

    def test_timeout_callback(self):
        callback = MagicMock()
        tracker = AprsMessageTracker(
            retry_interval_s=0.001,
            retry_count=0,  # No retries, immediate timeout
            on_timeout=callback,
        )
        tracker.track_message("W1AW", "Timeout test", "1")
        time.sleep(0.002)
        tracker.get_retries()

        callback.assert_called_once_with("W1AW", "1", "Timeout test")


class TestHelperFunctions:
    def test_create_message(self):
        msg = create_message("W1AW", "Hello", "42")
        assert isinstance(msg, AprsMessage)
        assert msg.addressee == "W1AW"
        assert msg.text == "Hello"
        assert msg.msg_id == "42"

    def test_create_message_no_id(self):
        msg = create_message("W1AW", "Hello")
        assert msg.msg_id is None

    def test_create_ack(self):
        ack = create_ack("W1AW", "42")
        assert isinstance(ack, AprsAck)
        assert ack.addressee == "W1AW"
        assert ack.msg_id == "42"


class TestAprsMessageEdgeCases:
    def test_message_with_colon_in_text(self):
        msg = AprsMessage(addressee="TEST", text="Hello: World")
        encoded = msg.encode()
        parsed = parse_aprs_packet(encoded)
        assert isinstance(parsed, AprsMessage)
        assert parsed.text == "Hello: World"

    def test_message_with_brace_in_text(self):
        # Text containing { but followed by non-alphanumeric
        data = b":TEST     :{smile}"
        result = parse_aprs_packet(data)
        # This is ambiguous - parser may interpret smile as msg_id
        # Current implementation: {smile} would be parsed as text="{smile" with no id
        # because } is not valid in msg_id
        assert isinstance(result, AprsMessage)

    def test_long_message_id(self):
        # Max 5 chars
        msg = AprsMessage(addressee="TEST", text="Hi", msg_id="ABCDE")
        encoded = msg.encode()
        parsed = parse_aprs_packet(encoded)
        assert parsed.msg_id == "ABCDE"

    def test_alphanumeric_message_id(self):
        msg = AprsMessage(addressee="TEST", text="Hi", msg_id="Ab1C2")
        encoded = msg.encode()
        parsed = parse_aprs_packet(encoded)
        assert parsed.msg_id == "Ab1C2"
