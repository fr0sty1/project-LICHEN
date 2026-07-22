# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for manual protobuf encoding/decoding."""

import pytest

from lichen.interface.meshtastic.proto import (
    Data,
    DeviceMetadata,
    FromRadio,
    MeshPacket,
    MyNodeInfo,
    NodeInfo,
    PacketPriority,
    ProtoError,
    QueueStatus,
    Routing,
    RoutingError,
    ToRadio,
    _decode_varint,
    _encode_varint,
    _varint_to_int32,
)


class TestVarint:
    """Test varint encoding/decoding."""

    def test_encode_zero(self):
        assert _encode_varint(0) == b"\x00"

    def test_encode_small(self):
        assert _encode_varint(1) == b"\x01"
        assert _encode_varint(127) == b"\x7f"

    def test_encode_multibyte(self):
        assert _encode_varint(128) == b"\x80\x01"
        assert _encode_varint(300) == b"\xac\x02"
        assert _encode_varint(16383) == b"\xff\x7f"

    def test_encode_large(self):
        # 2^32 - 1
        assert _encode_varint(0xFFFFFFFF) == b"\xff\xff\xff\xff\x0f"

    def test_decode_zero(self):
        val, consumed = _decode_varint(b"\x00")
        assert val == 0
        assert consumed == 1

    def test_decode_small(self):
        val, consumed = _decode_varint(b"\x01")
        assert val == 1
        assert consumed == 1

    def test_decode_multibyte(self):
        val, consumed = _decode_varint(b"\xac\x02")
        assert val == 300
        assert consumed == 2

    def test_decode_with_offset(self):
        val, consumed = _decode_varint(b"\xff\xac\x02", offset=1)
        assert val == 300
        assert consumed == 3

    def test_decode_truncated(self):
        with pytest.raises(ProtoError, match="truncated"):
            _decode_varint(b"\x80")  # Continuation bit set but no next byte

    def test_varint_to_int32_positive(self):
        assert _varint_to_int32(0) == 0
        assert _varint_to_int32(1) == 1
        assert _varint_to_int32(0x7FFFFFFF) == 0x7FFFFFFF  # Max positive int32

    def test_varint_to_int32_negative(self):
        """Test conversion of sign-extended varints to signed int32."""
        # -1 encoded as 10-byte varint gives 0xFFFFFFFFFFFFFFFF (2^64 - 1)
        assert _varint_to_int32(0xFFFFFFFFFFFFFFFF) == -1
        # -60 encoded gives 0xFFFFFFFFFFFFFFC4
        assert _varint_to_int32(0xFFFFFFFFFFFFFFC4) == -60
        # -120 (typical weak RSSI) gives 0xFFFFFFFFFFFFFF88
        assert _varint_to_int32(0xFFFFFFFFFFFFFF88) == -120


class TestData:
    """Test Data message encoding/decoding."""

    def test_empty(self):
        data = Data()
        encoded = data.to_bytes()
        assert encoded == b""
        decoded = Data.from_bytes(encoded)
        assert decoded.portnum == 0
        assert decoded.payload == b""

    def test_text_message(self):
        data = Data(portnum=1, payload=b"Hello, World!")
        encoded = data.to_bytes()
        decoded = Data.from_bytes(encoded)
        assert decoded.portnum == 1
        assert decoded.payload == b"Hello, World!"

    def test_with_request_id(self):
        data = Data(
            portnum=1,
            payload=b"test",
            want_response=True,
            dest=0x12345678,
            source=0xDEADBEEF,
            request_id=0x42424242,
        )
        encoded = data.to_bytes()
        decoded = Data.from_bytes(encoded)
        assert decoded.portnum == 1
        assert decoded.payload == b"test"
        assert decoded.want_response is True
        assert decoded.dest == 0x12345678
        assert decoded.source == 0xDEADBEEF
        assert decoded.request_id == 0x42424242


class TestRouting:
    """Test Routing message encoding/decoding."""

    def test_ack(self):
        routing = Routing(error_reason=RoutingError.NONE)
        encoded = routing.to_bytes()
        assert encoded == b""  # NONE is default, not encoded

    def test_nak_timeout(self):
        routing = Routing(error_reason=RoutingError.TIMEOUT)
        encoded = routing.to_bytes()
        decoded = Routing.from_bytes(encoded)
        assert decoded.error_reason == RoutingError.TIMEOUT

    def test_nak_no_route(self):
        routing = Routing(error_reason=RoutingError.NO_ROUTE)
        encoded = routing.to_bytes()
        decoded = Routing.from_bytes(encoded)
        assert decoded.error_reason == RoutingError.NO_ROUTE


class TestMeshPacket:
    """Test MeshPacket encoding/decoding."""

    def test_empty(self):
        pkt = MeshPacket()
        encoded = pkt.to_bytes()
        decoded = MeshPacket.from_bytes(encoded)
        assert decoded.from_ == 0
        assert decoded.to == 0
        assert decoded.decoded is None
        assert decoded.encrypted is None

    def test_with_addresses(self):
        pkt = MeshPacket(
            from_=0x12345678,
            to=0xDEADBEEF,
            channel=1,
            id=0x42424242,
            hop_limit=3,
        )
        encoded = pkt.to_bytes()
        decoded = MeshPacket.from_bytes(encoded)
        assert decoded.from_ == 0x12345678
        assert decoded.to == 0xDEADBEEF
        assert decoded.channel == 1
        assert decoded.id == 0x42424242
        assert decoded.hop_limit == 3

    def test_with_decoded_data(self):
        data = Data(portnum=1, payload=b"Hello")
        pkt = MeshPacket(
            from_=0x11111111,
            to=0x22222222,
            decoded=data,
        )
        encoded = pkt.to_bytes()
        decoded = MeshPacket.from_bytes(encoded)
        assert decoded.decoded is not None
        assert decoded.decoded.portnum == 1
        assert decoded.decoded.payload == b"Hello"

    def test_with_encrypted(self):
        pkt = MeshPacket(
            from_=0x11111111,
            to=0x22222222,
            encrypted=b"\x00\x01\x02\x03",
        )
        encoded = pkt.to_bytes()
        decoded = MeshPacket.from_bytes(encoded)
        assert decoded.encrypted == b"\x00\x01\x02\x03"
        assert decoded.decoded is None

    def test_priority(self):
        pkt = MeshPacket(priority=PacketPriority.ACK)
        encoded = pkt.to_bytes()
        decoded = MeshPacket.from_bytes(encoded)
        assert decoded.priority == PacketPriority.ACK

    def test_snr_float(self):
        pkt = MeshPacket(rx_snr=12.5)
        encoded = pkt.to_bytes()
        decoded = MeshPacket.from_bytes(encoded)
        assert abs(decoded.rx_snr - 12.5) < 0.01

    def test_rx_rssi_negative(self):
        """Test that negative RSSI values are decoded correctly.

        Protobuf int32 encodes negative values as 10-byte sign-extended
        varints. RSSI values are typically -30 to -120 dBm.
        """
        pkt = MeshPacket(rx_rssi=-60)
        encoded = pkt.to_bytes()
        decoded = MeshPacket.from_bytes(encoded)
        assert decoded.rx_rssi == -60

    def test_rx_rssi_negative_boundary(self):
        """Test RSSI at the signed int32 boundary."""
        pkt = MeshPacket(rx_rssi=-1)
        encoded = pkt.to_bytes()
        decoded = MeshPacket.from_bytes(encoded)
        assert decoded.rx_rssi == -1

    def test_rx_rssi_positive(self):
        """Test positive RSSI values still work."""
        pkt = MeshPacket(rx_rssi=10)
        encoded = pkt.to_bytes()
        decoded = MeshPacket.from_bytes(encoded)
        assert decoded.rx_rssi == 10


class TestMyNodeInfo:
    """Test MyNodeInfo encoding."""

    def test_basic(self):
        info = MyNodeInfo(
            my_node_num=0x12345678,
            reboot_count=5,
            min_app_version=30200,
        )
        encoded = info.to_bytes()
        # Verify it's valid protobuf by checking structure
        assert len(encoded) > 0
        # Should contain varint fields 1, 8, 11


class TestDeviceMetadata:
    """Test DeviceMetadata encoding."""

    def test_basic(self):
        meta = DeviceMetadata(
            firmware_version="2.5.0.lichen",
            device_state_version=1,
            has_bluetooth=True,
            hw_model=255,
        )
        encoded = meta.to_bytes()
        assert b"2.5.0.lichen" in encoded


class TestQueueStatus:
    """Test QueueStatus encoding/decoding with signed int32 res."""

    def test_basic(self):
        qs = QueueStatus(res=0, free=8, maxlen=8, mesh_packet_id=0x42)
        encoded = qs.to_bytes()
        assert len(encoded) > 0

    def test_negative_res(self):
        """Test signed int32 handling for res (e.g. error codes)."""
        qs = QueueStatus(res=-5, free=5, maxlen=10, mesh_packet_id=0x1234)
        encoded = qs.to_bytes()
        decoded = QueueStatus.from_bytes(encoded)
        assert decoded.res == -5
        assert decoded.free == 5
        assert decoded.maxlen == 10
        assert decoded.mesh_packet_id == 0x1234


class TestNodeInfo:
    """Test NodeInfo encoding."""

    def test_basic(self):
        info = NodeInfo(
            num=0x12345678,
            user=b"\x0a\x08!1234567",  # Simplified user protobuf
            last_heard=1700000000,
        )
        encoded = info.to_bytes()
        assert len(encoded) > 0


class TestToRadio:
    """Test ToRadio decoding."""

    def test_want_config_id(self):
        # Manually encode want_config_id = 69420
        # Field 3, wire type 0 (varint)
        data = b"\x18" + _encode_varint(69420)
        msg = ToRadio.from_bytes(data)
        assert msg.want_config_id == 69420
        assert msg.packet is None
        assert msg.disconnect is False

    def test_disconnect(self):
        # Field 4, wire type 0, value 1
        data = b"\x20\x01"
        msg = ToRadio.from_bytes(data)
        assert msg.disconnect is True
        assert msg.want_config_id is None

    def test_with_packet(self):
        # Build a minimal packet
        inner_pkt = MeshPacket(from_=0x11111111, to=0x22222222)
        inner_bytes = inner_pkt.to_bytes()
        # Field 1, wire type 2 (length-delimited)
        data = b"\x0a" + _encode_varint(len(inner_bytes)) + inner_bytes
        msg = ToRadio.from_bytes(data)
        assert msg.packet is not None
        assert msg.packet.from_ == 0x11111111
        assert msg.packet.to == 0x22222222


class TestFromRadio:
    """Test FromRadio encoding."""

    def test_with_packet(self):
        pkt = MeshPacket(from_=0x11111111, to=0x22222222)
        msg = FromRadio(id=1, packet=pkt)
        encoded = msg.to_bytes()
        # Should start with id field (1, varint), then packet field (2, len-delim)
        assert len(encoded) > 0
        # Verify id is present
        assert encoded[0] == 0x08  # Field 1, wire type 0

    def test_with_my_info(self):
        info = MyNodeInfo(my_node_num=0x12345678)
        msg = FromRadio(id=2, my_info=info)
        encoded = msg.to_bytes()
        assert len(encoded) > 0

    def test_config_complete_id(self):
        msg = FromRadio(id=3, config_complete_id=69420)
        encoded = msg.to_bytes()
        assert len(encoded) > 0
        # Should contain field 7 (config_complete_id)

    def test_with_queue_status(self):
        qs = QueueStatus(free=8, maxlen=8)
        msg = FromRadio(queue_status=qs)
        encoded = msg.to_bytes()
        assert len(encoded) > 0


class TestRoundTrip:
    """Test round-trip encoding/decoding."""

    def test_complex_packet(self):
        """Test a complex packet survives round-trip."""
        data = Data(
            portnum=1,
            payload=b"Hello, Meshtastic!",
            want_response=True,
            dest=0xFFFFFFFF,
            source=0x12345678,
            request_id=0x42424242,
        )
        pkt = MeshPacket(
            from_=0x12345678,
            to=0xFFFFFFFF,
            channel=0,
            decoded=data,
            id=0x11111111,
            rx_time=1700000000,
            rx_snr=10.5,
            hop_limit=3,
            want_ack=True,
            priority=PacketPriority.RELIABLE,
            via_mqtt=False,
            hop_start=3,
        )
        encoded = pkt.to_bytes()
        decoded = MeshPacket.from_bytes(encoded)

        assert decoded.from_ == pkt.from_
        assert decoded.to == pkt.to
        assert decoded.channel == pkt.channel
        assert decoded.id == pkt.id
        assert decoded.rx_time == pkt.rx_time
        assert abs(decoded.rx_snr - pkt.rx_snr) < 0.01
        assert decoded.hop_limit == pkt.hop_limit
        assert decoded.want_ack == pkt.want_ack
        assert decoded.priority == pkt.priority
        assert decoded.hop_start == pkt.hop_start
        assert decoded.decoded is not None
        assert decoded.decoded.portnum == data.portnum
        assert decoded.decoded.payload == data.payload
        assert decoded.decoded.want_response == data.want_response
        assert decoded.decoded.dest == data.dest
        assert decoded.decoded.source == data.source
        assert decoded.decoded.request_id == data.request_id
