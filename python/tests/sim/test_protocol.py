# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for LICHEN simulator wire protocol."""

from __future__ import annotations

import struct

import pytest

from lichen.sim.protocol import (
    MSG_ERR,
    MSG_OK,
    MSG_REGISTER,
    MSG_RX_ENTER,
    MSG_RX_EXIT,
    MSG_RX_PACKET,
    MSG_RX_TIMEOUT_PUSH,
    MSG_TIME,
    MSG_TIME_OK,
    MSG_TX,
    MSG_TX_DONE,
    MSG_TX_FAIL,
    ProtocolError,
    decode_err,
    decode_register,
    decode_rx_enter,
    decode_rx_packet,
    decode_time_ok,
    decode_tx,
    decode_tx_done,
    encode_err,
    encode_ok,
    encode_register,
    encode_rx_enter,
    encode_rx_exit,
    encode_rx_packet,
    encode_rx_timeout_push,
    encode_time,
    encode_time_ok,
    encode_tx,
    encode_tx_done,
    encode_tx_fail,
    get_message_payload,
    get_message_type,
)


class TestMessageTypeConstants:
    """Test that message type constants have expected values."""

    def test_ok_is_0x00(self) -> None:
        assert MSG_OK == 0x00

    def test_register_is_0x01(self) -> None:
        assert MSG_REGISTER == 0x01

    def test_tx_is_0x10(self) -> None:
        assert MSG_TX == 0x10

    def test_tx_done_is_0x11(self) -> None:
        assert MSG_TX_DONE == 0x11

    def test_tx_fail_is_0x12(self) -> None:
        assert MSG_TX_FAIL == 0x12

    def test_rx_enter_is_0x24(self) -> None:
        assert MSG_RX_ENTER == 0x24

    def test_rx_exit_is_0x26(self) -> None:
        assert MSG_RX_EXIT == 0x26

    def test_rx_packet_is_0x27(self) -> None:
        assert MSG_RX_PACKET == 0x27

    def test_rx_timeout_push_is_0x28(self) -> None:
        assert MSG_RX_TIMEOUT_PUSH == 0x28

    def test_time_is_0x30(self) -> None:
        assert MSG_TIME == 0x30

    def test_time_ok_is_0x31(self) -> None:
        assert MSG_TIME_OK == 0x31

    def test_err_is_0xff(self) -> None:
        assert MSG_ERR == 0xFF


class TestRegisterMessage:
    """Test REGISTER message encoding/decoding."""

    def test_roundtrip_basic(self) -> None:
        """Basic round-trip with simple IDs and coordinates."""
        sim_id = "sim-001"
        node_id = "node-42"
        x, y, z = 100.5, 200.25, 10.0

        encoded = encode_register(sim_id, node_id, x, y, z)
        assert get_message_type(encoded) == MSG_REGISTER

        payload = get_message_payload(encoded)
        decoded = decode_register(payload)

        assert decoded == (sim_id, node_id, x, y, z)

    def test_roundtrip_empty_ids(self) -> None:
        """Round-trip with empty ID strings."""
        encoded = encode_register("", "", 0.0, 0.0, 0.0)
        payload = get_message_payload(encoded)
        decoded = decode_register(payload)

        assert decoded == ("", "", 0.0, 0.0, 0.0)

    def test_roundtrip_max_length_ids(self) -> None:
        """Round-trip with maximum length IDs (255 bytes each)."""
        sim_id = "s" * 255
        node_id = "n" * 255

        encoded = encode_register(sim_id, node_id, 1.0, 2.0, 3.0)
        payload = get_message_payload(encoded)
        decoded = decode_register(payload)

        assert decoded[0] == sim_id
        assert decoded[1] == node_id

    def test_roundtrip_unicode_ids(self) -> None:
        """Round-trip with unicode characters in IDs."""
        sim_id = "sim-cafe"
        node_id = "node-test"

        encoded = encode_register(sim_id, node_id, 0.0, 0.0, 0.0)
        payload = get_message_payload(encoded)
        decoded = decode_register(payload)

        assert decoded[:2] == (sim_id, node_id)

    def test_roundtrip_negative_coordinates(self) -> None:
        """Round-trip with negative coordinate values."""
        x, y, z = -100.5, -200.75, -50.125

        encoded = encode_register("sim", "node", x, y, z)
        payload = get_message_payload(encoded)
        decoded = decode_register(payload)

        assert decoded[2:] == (x, y, z)

    def test_roundtrip_large_coordinates(self) -> None:
        """Round-trip with large coordinate values."""
        x, y, z = 1e10, -1e10, 1e-10

        encoded = encode_register("sim", "node", x, y, z)
        payload = get_message_payload(encoded)
        decoded = decode_register(payload)

        assert decoded[2:] == (x, y, z)

    def test_encode_sim_id_too_long(self) -> None:
        """Encoding should fail if sim_id exceeds 255 bytes."""
        with pytest.raises(ProtocolError, match="sim_id too long"):
            encode_register("s" * 256, "node", 0.0, 0.0, 0.0)

    def test_encode_node_id_too_long(self) -> None:
        """Encoding should fail if node_id exceeds 255 bytes."""
        with pytest.raises(ProtocolError, match="node_id too long"):
            encode_register("sim", "n" * 256, 0.0, 0.0, 0.0)

    def test_decode_empty_data(self) -> None:
        """Decoding should fail on empty data."""
        with pytest.raises(ProtocolError, match="too short"):
            decode_register(b"")

    def test_decode_truncated_at_sim_id(self) -> None:
        """Decoding should fail if truncated during sim_id."""
        # Length byte says 10, but only 5 bytes follow
        data = bytes([10]) + b"12345"
        with pytest.raises(ProtocolError, match="truncated at sim_id"):
            decode_register(data)

    def test_decode_truncated_at_node_id_length(self) -> None:
        """Decoding should fail if truncated before node_id length."""
        data = bytes([3]) + b"sim"  # Missing node_id length
        with pytest.raises(ProtocolError, match="truncated before node_id"):
            decode_register(data)

    def test_decode_truncated_at_coordinates(self) -> None:
        """Decoding should fail if truncated during coordinates."""
        data = bytes([3]) + b"sim" + bytes([4]) + b"node" + b"\x00" * 20
        with pytest.raises(ProtocolError, match="truncated at coordinates"):
            decode_register(data)

    def test_wire_format(self) -> None:
        """Verify exact wire format."""
        encoded = encode_register("AB", "CD", 1.0, 2.0, 3.0)

        assert encoded[0] == MSG_REGISTER
        assert encoded[1] == 2  # sim_id length
        assert encoded[2:4] == b"AB"
        assert encoded[4] == 2  # node_id length
        assert encoded[5:7] == b"CD"
        # Remaining 24 bytes are coordinates (little-endian doubles)
        x, y, z = struct.unpack("<ddd", encoded[7:31])
        assert (x, y, z) == (1.0, 2.0, 3.0)


class TestTxMessage:
    """Test TX message encoding/decoding."""

    def test_roundtrip_basic(self) -> None:
        """Basic round-trip with simple payload."""
        payload = b"Hello, World!"

        encoded = encode_tx(payload)
        assert get_message_type(encoded) == MSG_TX

        msg_payload = get_message_payload(encoded)
        decoded_payload, channel = decode_tx(msg_payload)

        assert decoded_payload == payload
        assert channel == 0

    def test_roundtrip_empty_payload(self) -> None:
        """Round-trip with empty payload."""
        encoded = encode_tx(b"")
        msg_payload = get_message_payload(encoded)
        decoded_payload, channel = decode_tx(msg_payload)

        assert decoded_payload == b""
        assert channel == 0

    def test_roundtrip_binary_payload(self) -> None:
        """Round-trip with binary data including null bytes."""
        payload = bytes(range(256))

        encoded = encode_tx(payload)
        msg_payload = get_message_payload(encoded)
        decoded_payload, channel = decode_tx(msg_payload)

        assert decoded_payload == payload
        assert channel == 0

    def test_roundtrip_max_payload(self) -> None:
        """Round-trip with maximum payload size (65535 bytes)."""
        payload = b"x" * 65535

        encoded = encode_tx(payload)
        msg_payload = get_message_payload(encoded)
        decoded_payload, channel = decode_tx(msg_payload)

        assert decoded_payload == payload
        assert channel == 0

    def test_encode_payload_too_long(self) -> None:
        """Encoding should fail if payload exceeds 65535 bytes."""
        with pytest.raises(ProtocolError, match="payload too long"):
            encode_tx(b"x" * 65536)

    def test_decode_empty_data(self) -> None:
        """Decoding should fail on data shorter than 2 bytes."""
        with pytest.raises(ProtocolError, match="too short"):
            decode_tx(b"\x00")

    def test_decode_truncated_payload(self) -> None:
        """Decoding should fail if payload is truncated."""
        # Length says 100 but only 10 bytes follow
        data = struct.pack("<H", 100) + b"0123456789"
        with pytest.raises(ProtocolError, match="truncated"):
            decode_tx(data)

    def test_wire_format(self) -> None:
        """Verify exact wire format."""
        payload = b"test"
        encoded = encode_tx(payload)

        assert encoded[0] == MSG_TX
        assert struct.unpack("<H", encoded[1:3])[0] == 4
        assert encoded[4:8] == b"test"


class TestTxDoneMessage:
    """Test TX_DONE message encoding/decoding."""

    def test_roundtrip_basic(self) -> None:
        """Basic round-trip with typical airtime."""
        airtime_us = 123456

        encoded = encode_tx_done(airtime_us)
        assert get_message_type(encoded) == MSG_TX_DONE

        payload = get_message_payload(encoded)
        decoded = decode_tx_done(payload)

        assert decoded == airtime_us

    def test_roundtrip_zero(self) -> None:
        """Round-trip with zero airtime."""
        encoded = encode_tx_done(0)
        payload = get_message_payload(encoded)
        decoded = decode_tx_done(payload)

        assert decoded == 0

    def test_roundtrip_max_value(self) -> None:
        """Round-trip with maximum uint32 value."""
        max_val = 2**32 - 1

        encoded = encode_tx_done(max_val)
        payload = get_message_payload(encoded)
        decoded = decode_tx_done(payload)

        assert decoded == max_val

    def test_decode_too_short(self) -> None:
        """Decoding should fail if data is too short."""
        with pytest.raises(ProtocolError, match="too short"):
            decode_tx_done(b"\x00\x00\x00")

    def test_wire_format(self) -> None:
        """Verify exact wire format (little-endian)."""
        encoded = encode_tx_done(0x12345678)

        assert encoded[0] == MSG_TX_DONE
        assert encoded[1:5] == b"\x78\x56\x34\x12"


class TestTxFailMessage:
    """Test TX_FAIL message encoding."""

    def test_encode(self) -> None:
        """TX_FAIL should be a single type byte."""
        encoded = encode_tx_fail()

        assert encoded == bytes([MSG_TX_FAIL])
        assert get_message_type(encoded) == MSG_TX_FAIL


class TestRxEnterMessage:
    """Test RX_ENTER message encoding/decoding (push-based RX)."""

    def test_roundtrip_basic(self) -> None:
        """Basic round-trip with typical timeout."""
        timeout_us = 5_000_000  # 5 seconds

        encoded = encode_rx_enter(timeout_us)
        assert get_message_type(encoded) == MSG_RX_ENTER

        payload = get_message_payload(encoded)
        decoded_timeout, channel = decode_rx_enter(payload)

        assert decoded_timeout == timeout_us
        assert channel == 0

    def test_roundtrip_zero_timeout(self) -> None:
        """Round-trip with zero timeout."""
        encoded = encode_rx_enter(0)
        payload = get_message_payload(encoded)
        decoded_timeout, channel = decode_rx_enter(payload)

        assert decoded_timeout == 0
        assert channel == 0

    def test_roundtrip_max_timeout(self) -> None:
        """Round-trip with maximum uint32 timeout."""
        max_val = 2**32 - 1

        encoded = encode_rx_enter(max_val)
        payload = get_message_payload(encoded)
        decoded_timeout, channel = decode_rx_enter(payload)

        assert decoded_timeout == max_val
        assert channel == 0

    def test_decode_too_short(self) -> None:
        """Decoding should fail if data is too short."""
        with pytest.raises(ProtocolError, match="too short"):
            decode_rx_enter(b"\x00\x00")

    def test_wire_format(self) -> None:
        """Verify exact wire format (little-endian)."""
        encoded = encode_rx_enter(0xAABBCCDD)

        assert encoded[0] == MSG_RX_ENTER
        assert encoded[1:5] == b"\xDD\xCC\xBB\xAA"

    def test_encode_rejects_negative(self) -> None:
        """Encoding should fail for negative timeout."""
        with pytest.raises(ProtocolError, match="timeout_us out of range"):
            encode_rx_enter(-1)

    def test_encode_rejects_over_uint32(self) -> None:
        """Encoding should fail for timeout exceeding uint32."""
        with pytest.raises(ProtocolError, match="timeout_us out of range"):
            encode_rx_enter(0x1_0000_0000)


class TestRxExitMessage:
    """Test RX_EXIT message encoding (push-based RX)."""

    def test_encode(self) -> None:
        """RX_EXIT should be a single type byte."""
        encoded = encode_rx_exit()

        assert encoded == bytes([MSG_RX_EXIT])
        assert get_message_type(encoded) == MSG_RX_EXIT


class TestRxPacketMessage:
    """Test RX_PACKET message encoding/decoding (push-based RX)."""

    def test_roundtrip_basic(self) -> None:
        """Basic round-trip with typical values."""
        payload = b"received data"
        rssi = -85
        snr = -55  # -5.5 dB * 10

        encoded = encode_rx_packet(payload, rssi, snr)
        assert get_message_type(encoded) == MSG_RX_PACKET

        msg_payload = get_message_payload(encoded)
        decoded = decode_rx_packet(msg_payload)

        assert decoded == (payload, rssi, snr)

    def test_roundtrip_empty_payload(self) -> None:
        """Round-trip with empty payload."""
        encoded = encode_rx_packet(b"", -100, 50)
        msg_payload = get_message_payload(encoded)
        decoded = decode_rx_packet(msg_payload)

        assert decoded == (b"", -100, 50)

    def test_roundtrip_positive_values(self) -> None:
        """Round-trip with positive RSSI/SNR values."""
        encoded = encode_rx_packet(b"x", 10, 200)
        msg_payload = get_message_payload(encoded)
        decoded = decode_rx_packet(msg_payload)

        assert decoded == (b"x", 10, 200)

    def test_roundtrip_extreme_rssi_snr(self) -> None:
        """Round-trip with int16 min/max values."""
        encoded = encode_rx_packet(b"test", -32768, 32767)
        msg_payload = get_message_payload(encoded)
        decoded = decode_rx_packet(msg_payload)

        assert decoded == (b"test", -32768, 32767)

    def test_encode_payload_too_long(self) -> None:
        """Encoding should fail if payload exceeds 65535 bytes."""
        with pytest.raises(ProtocolError, match="payload too long"):
            encode_rx_packet(b"x" * 65536, -50, 100)

    def test_decode_too_short(self) -> None:
        """Decoding should fail if data is too short."""
        with pytest.raises(ProtocolError, match="too short"):
            decode_rx_packet(b"\x00")

    def test_decode_truncated(self) -> None:
        """Decoding should fail if truncated after payload."""
        # Length says 4, payload present, but RSSI/SNR missing
        data = struct.pack("<H", 4) + b"test" + b"\x00"
        with pytest.raises(ProtocolError, match="truncated"):
            decode_rx_packet(data)

    def test_wire_format(self) -> None:
        """Verify exact wire format."""
        payload = b"AB"
        rssi = -100
        snr = 75

        encoded = encode_rx_packet(payload, rssi, snr)

        assert encoded[0] == MSG_RX_PACKET
        assert struct.unpack("<H", encoded[1:3])[0] == 2  # payload length
        assert encoded[3:5] == b"AB"
        assert struct.unpack("<h", encoded[5:7])[0] == -100  # RSSI
        assert struct.unpack("<h", encoded[7:9])[0] == 75  # SNR

    def test_encode_rejects_out_of_range_rssi(self) -> None:
        """Encoding should fail if RSSI is out of int16 range."""
        with pytest.raises(ProtocolError, match="rssi out of range"):
            encode_rx_packet(b"", -32769, 0)
        with pytest.raises(ProtocolError, match="rssi out of range"):
            encode_rx_packet(b"", 32768, 0)

    def test_encode_rejects_out_of_range_snr(self) -> None:
        """Encoding should fail if SNR is out of int16 range."""
        with pytest.raises(ProtocolError, match="snr out of range"):
            encode_rx_packet(b"", 0, 40000)


class TestRxTimeoutPushMessage:
    """Test RX_TIMEOUT_PUSH message encoding (push-based RX)."""

    def test_encode(self) -> None:
        """RX_TIMEOUT_PUSH should be a single type byte."""
        encoded = encode_rx_timeout_push()

        assert encoded == bytes([MSG_RX_TIMEOUT_PUSH])
        assert get_message_type(encoded) == MSG_RX_TIMEOUT_PUSH


class TestTimeMessage:
    """Test TIME message encoding."""

    def test_encode(self) -> None:
        """TIME should be a single type byte."""
        encoded = encode_time()

        assert encoded == bytes([MSG_TIME])
        assert get_message_type(encoded) == MSG_TIME


class TestTimeOkMessage:
    """Test TIME_OK message encoding/decoding."""

    def test_roundtrip_basic(self) -> None:
        """Basic round-trip with typical time value."""
        time_us = 1_000_000_000  # 1 second

        encoded = encode_time_ok(time_us)
        assert get_message_type(encoded) == MSG_TIME_OK

        payload = get_message_payload(encoded)
        decoded = decode_time_ok(payload)

        assert decoded == time_us

    def test_roundtrip_zero(self) -> None:
        """Round-trip with zero time."""
        encoded = encode_time_ok(0)
        payload = get_message_payload(encoded)
        decoded = decode_time_ok(payload)

        assert decoded == 0

    def test_roundtrip_max_value(self) -> None:
        """Round-trip with maximum uint64 value."""
        max_val = 2**64 - 1

        encoded = encode_time_ok(max_val)
        payload = get_message_payload(encoded)
        decoded = decode_time_ok(payload)

        assert decoded == max_val

    def test_roundtrip_large_time(self) -> None:
        """Round-trip with large time value (years in microseconds)."""
        # 100 years in microseconds
        time_us = 100 * 365 * 24 * 60 * 60 * 1_000_000

        encoded = encode_time_ok(time_us)
        payload = get_message_payload(encoded)
        decoded = decode_time_ok(payload)

        assert decoded == time_us

    def test_decode_too_short(self) -> None:
        """Decoding should fail if data is too short."""
        with pytest.raises(ProtocolError, match="too short"):
            decode_time_ok(b"\x00" * 7)

    def test_wire_format(self) -> None:
        """Verify exact wire format (little-endian uint64)."""
        encoded = encode_time_ok(0x0102030405060708)

        assert encoded[0] == MSG_TIME_OK
        assert encoded[1:9] == b"\x08\x07\x06\x05\x04\x03\x02\x01"


class TestOkMessage:
    """Test OK message encoding."""

    def test_encode(self) -> None:
        """OK should be a single type byte."""
        encoded = encode_ok()

        assert encoded == bytes([MSG_OK])
        assert get_message_type(encoded) == MSG_OK


class TestErrMessage:
    """Test ERR message encoding/decoding."""

    def test_roundtrip_basic(self) -> None:
        """Basic round-trip with typical error."""
        code = 42
        msg = "Something went wrong"

        encoded = encode_err(code, msg)
        assert get_message_type(encoded) == MSG_ERR

        payload = get_message_payload(encoded)
        decoded = decode_err(payload)

        assert decoded == (code, msg)

    def test_roundtrip_empty_message(self) -> None:
        """Round-trip with empty error message."""
        encoded = encode_err(1, "")
        payload = get_message_payload(encoded)
        decoded = decode_err(payload)

        assert decoded == (1, "")

    def test_roundtrip_max_code(self) -> None:
        """Round-trip with maximum error code (255)."""
        encoded = encode_err(255, "max code")
        payload = get_message_payload(encoded)
        decoded = decode_err(payload)

        assert decoded == (255, "max code")

    def test_roundtrip_max_length_message(self) -> None:
        """Round-trip with maximum message length (255 bytes)."""
        msg = "e" * 255

        encoded = encode_err(0, msg)
        payload = get_message_payload(encoded)
        decoded = decode_err(payload)

        assert decoded == (0, msg)

    def test_roundtrip_unicode_message(self) -> None:
        """Round-trip with unicode characters in message."""
        msg = "Error: invalid input"

        encoded = encode_err(99, msg)
        payload = get_message_payload(encoded)
        decoded = decode_err(payload)

        assert decoded == (99, msg)

    def test_encode_message_too_long(self) -> None:
        """Encoding should fail if message exceeds 255 bytes."""
        with pytest.raises(ProtocolError, match="error message too long"):
            encode_err(1, "e" * 256)

    def test_decode_too_short(self) -> None:
        """Decoding should fail if data is too short."""
        with pytest.raises(ProtocolError, match="too short"):
            decode_err(b"\x00")

    def test_decode_truncated(self) -> None:
        """Decoding should fail if message is truncated."""
        # Code=1, length=10, but only 5 bytes follow
        data = bytes([1, 10]) + b"12345"
        with pytest.raises(ProtocolError, match="truncated"):
            decode_err(data)

    def test_wire_format(self) -> None:
        """Verify exact wire format."""
        encoded = encode_err(0xAB, "hi")

        assert encoded[0] == MSG_ERR
        assert encoded[1] == 0xAB  # error code
        assert encoded[2] == 2  # message length
        assert encoded[3:5] == b"hi"


class TestMessageHelpers:
    """Test get_message_type and get_message_payload helpers."""

    def test_get_type_from_various_messages(self) -> None:
        """get_message_type should work on all message types."""
        assert get_message_type(encode_ok()) == MSG_OK
        assert get_message_type(encode_register("s", "n", 0, 0, 0)) == MSG_REGISTER
        assert get_message_type(encode_tx(b"x")) == MSG_TX
        assert get_message_type(encode_tx_done(100)) == MSG_TX_DONE
        assert get_message_type(encode_tx_fail()) == MSG_TX_FAIL
        assert get_message_type(encode_rx_enter(5000)) == MSG_RX_ENTER
        assert get_message_type(encode_rx_exit()) == MSG_RX_EXIT
        assert get_message_type(encode_rx_packet(b"x", -50, 10)) == MSG_RX_PACKET
        assert get_message_type(encode_rx_timeout_push()) == MSG_RX_TIMEOUT_PUSH
        assert get_message_type(encode_time()) == MSG_TIME
        assert get_message_type(encode_time_ok(123)) == MSG_TIME_OK
        assert get_message_type(encode_err(1, "oops")) == MSG_ERR

    def test_get_type_empty_data(self) -> None:
        """get_message_type should fail on empty data."""
        with pytest.raises(ProtocolError, match="Empty message"):
            get_message_type(b"")

    def test_get_payload_empty_data(self) -> None:
        """get_message_payload should fail on empty data."""
        with pytest.raises(ProtocolError, match="Empty message"):
            get_message_payload(b"")

    def test_get_payload_single_byte(self) -> None:
        """get_message_payload on single-byte message returns empty."""
        assert get_message_payload(encode_ok()) == b""
        assert get_message_payload(encode_time()) == b""

    def test_get_payload_multi_byte(self) -> None:
        """get_message_payload strips the type byte."""
        encoded = encode_tx_done(0x12345678)
        payload = get_message_payload(encoded)

        # Should be just the uint32 airtime
        assert len(payload) == 4
        assert struct.unpack("<I", payload)[0] == 0x12345678


class TestLittleEndianness:
    """Verify that all multi-byte fields use little-endian byte order."""

    def test_register_coordinates(self) -> None:
        """REGISTER coordinates should be little-endian doubles."""
        encoded = encode_register("", "", 1.0, 2.0, 3.0)
        # Skip: type(1) + sim_id_len(1) + node_id_len(1) = 3 bytes
        coords_start = 3
        x, y, z = struct.unpack("<ddd", encoded[coords_start : coords_start + 24])
        assert (x, y, z) == (1.0, 2.0, 3.0)

    def test_tx_length(self) -> None:
        """TX payload length should be little-endian uint16."""
        encoded = encode_tx(b"x" * 0x1234)
        length = struct.unpack("<H", encoded[1:3])[0]
        assert length == 0x1234

    def test_tx_done_airtime(self) -> None:
        """TX_DONE airtime should be little-endian uint32."""
        encoded = encode_tx_done(0xDEADBEEF)
        airtime = struct.unpack("<I", encoded[1:5])[0]
        assert airtime == 0xDEADBEEF

    def test_rx_timeout(self) -> None:
        """RX_ENTER timeout should be little-endian uint32."""
        encoded = encode_rx_enter(0xCAFEBABE)
        timeout = struct.unpack("<I", encoded[1:5])[0]
        assert timeout == 0xCAFEBABE

    def test_rx_ok_rssi_snr(self) -> None:
        """RX_PACKET RSSI and SNR should be little-endian int16."""
        encoded = encode_rx_packet(b"", -1234, 5678)
        # Skip: type(1) + length(2) + payload(0) = 3 bytes
        rssi, snr = struct.unpack("<hh", encoded[3:7])
        assert rssi == -1234
        assert snr == 5678

    def test_time_ok_time(self) -> None:
        """TIME_OK time should be little-endian uint64."""
        encoded = encode_time_ok(0xFEDCBA9876543210)
        time_val = struct.unpack("<Q", encoded[1:9])[0]
        assert time_val == 0xFEDCBA9876543210


class TestEncoderRangeValidation:
    """Fixed-width integer fields must be range-checked, raising ProtocolError."""

    def test_tx_done_accepts_uint32_bounds(self) -> None:
        """airtime_us at the uint32 boundaries encodes successfully."""
        assert decode_tx_done(encode_tx_done(0)[1:]) == 0
        assert decode_tx_done(encode_tx_done(0xFFFFFFFF)[1:]) == 0xFFFFFFFF

    def test_tx_done_rejects_negative(self) -> None:
        with pytest.raises(ProtocolError, match="airtime_us out of range"):
            encode_tx_done(-1)

    def test_tx_done_rejects_over_uint32(self) -> None:
        with pytest.raises(ProtocolError, match="airtime_us out of range"):
            encode_tx_done(0x1_0000_0000)

    def test_rx_enter_rejects_out_of_range_timeout(self) -> None:
        with pytest.raises(ProtocolError, match="timeout_us out of range"):
            encode_rx_enter(-1)
        with pytest.raises(ProtocolError, match="timeout_us out of range"):
            encode_rx_enter(0x1_0000_0000)

    def test_rx_packet_accepts_int16_bounds(self) -> None:
        """rssi/snr at the int16 boundaries encode successfully."""
        payload, rssi, snr = decode_rx_packet(encode_rx_packet(b"x", -32768, 32767)[1:])
        assert (payload, rssi, snr) == (b"x", -32768, 32767)

    def test_rx_packet_rejects_out_of_range_rssi(self) -> None:
        with pytest.raises(ProtocolError, match="rssi out of range"):
            encode_rx_packet(b"", -32769, 0)
        with pytest.raises(ProtocolError, match="rssi out of range"):
            encode_rx_packet(b"", 32768, 0)

    def test_rx_packet_rejects_out_of_range_snr(self) -> None:
        with pytest.raises(ProtocolError, match="snr out of range"):
            encode_rx_packet(b"", 0, 40000)

    def test_err_rejects_out_of_range_code(self) -> None:
        with pytest.raises(ProtocolError, match="code out of range"):
            encode_err(256, "boom")
        with pytest.raises(ProtocolError, match="code out of range"):
            encode_err(-1, "boom")
