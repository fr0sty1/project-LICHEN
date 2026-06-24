"""Tests for LICHEN Native protocol messages."""

import pytest

from lichen.interface.messages import (
    ConfigGet,
    ConfigKey,
    ConfigResult,
    ConfigSet,
    GradientEntry,
    Hello,
    LogEntry,
    LogLevel,
    LogSubscribe,
    Message,
    MessageReceived,
    MessageType,
    MeshState,
    NeighborEntry,
    NodeInfo,
    ResultCode,
    SendMessage,
    decode_message,
    encode_message,
)


class TestHello:
    def test_minimal(self):
        msg = Hello()
        d = msg.to_dict()
        assert d[0] == MessageType.HELLO
        assert d[1] == 1  # version
        assert d[2] == []  # supported
        assert d[3] == ""  # firmware

    def test_full(self):
        msg = Hello(
            version=1,
            supported=[0x01, 0x10, 0x20],
            firmware="lichen-0.1.0",
            iid=bytes(8),
            name="test-node",
            max_size=4096,
            features={1: True, 4: True},
        )
        d = msg.to_dict()
        assert d[4] == bytes(8)
        assert d[5] == "test-node"
        assert d[6] == 4096
        assert d[7] == {1: True, 4: True}

    def test_roundtrip(self):
        original = Hello(
            version=1,
            supported=[0x01, 0x20],
            firmware="test",
            iid=b"\x01\x02\x03\x04\x05\x06\x07\x08",
        )
        data = encode_message(original)
        decoded = decode_message(data)
        assert isinstance(decoded, Hello)
        assert decoded.version == original.version
        assert decoded.supported == original.supported
        assert decoded.firmware == original.firmware
        assert decoded.iid == original.iid


class TestConfig:
    def test_config_get_all(self):
        msg = ConfigGet()
        d = msg.to_dict()
        assert d[0] == MessageType.CONFIG_GET
        assert 1 not in d  # no keys = get all

    def test_config_get_specific(self):
        msg = ConfigGet(keys=[ConfigKey.TX_POWER, ConfigKey.FREQUENCY])
        d = msg.to_dict()
        assert d[1] == [1, 2]

    def test_config_set(self):
        msg = ConfigSet(values={ConfigKey.TX_POWER: 14, ConfigKey.DEVICE_NAME: "foo"})
        d = msg.to_dict()
        assert d[0] == MessageType.CONFIG_SET
        assert d[1] == {1: 14, 32: "foo"}
        assert 2 not in d  # persist defaults to True

    def test_config_set_no_persist(self):
        msg = ConfigSet(values={1: 10}, persist=False)
        d = msg.to_dict()
        assert d[2] is False

    def test_config_result_ok(self):
        msg = ConfigResult(result=ResultCode.OK, values={1: 22, 2: 915000000})
        d = msg.to_dict()
        assert d[0] == MessageType.CONFIG_RESULT
        assert d[1] == 0
        assert d[2] == {1: 22, 2: 915000000}

    def test_config_result_error(self):
        msg = ConfigResult(result=ResultCode.INVALID_PARAM, error="bad value")
        d = msg.to_dict()
        assert d[1] == 2
        assert d[3] == "bad value"


class TestMessaging:
    def test_send_message_minimal(self):
        msg = SendMessage(dest=bytes(8), payload=b"hello")
        d = msg.to_dict()
        assert d[0] == MessageType.SEND_MESSAGE
        assert d[1] == bytes(8)
        assert d[2] == b"hello"
        assert 3 not in d  # default port

    def test_send_message_full(self):
        msg = SendMessage(
            dest=bytes(16),  # IPv6
            payload=b"data",
            dest_port=1234,
            src_port=5678,
            ack=True,
            msg_id=42,
            ttl=32,
        )
        d = msg.to_dict()
        assert d[3] == 1234
        assert d[4] == 5678
        assert d[5] is True
        assert d[6] == 42
        assert d[7] == 32

    def test_message_received(self):
        msg = MessageReceived(
            src=b"\x01" * 8,
            payload=b"response",
            rssi=-85,
            snr=9,
        )
        d = msg.to_dict()
        assert d[0] == MessageType.MESSAGE_RECEIVED
        assert d[5] == -85
        assert d[6] == 9

    def test_messaging_roundtrip(self):
        original = SendMessage(dest=b"\xAA" * 8, payload=b"test", ack=True, msg_id=123)
        data = encode_message(original)
        decoded = decode_message(data)
        assert isinstance(decoded, SendMessage)
        assert decoded.dest == original.dest
        assert decoded.payload == original.payload
        assert decoded.ack is True
        assert decoded.msg_id == 123


class TestMeshState:
    def test_empty(self):
        msg = MeshState()
        d = msg.to_dict()
        assert d[0] == MessageType.MESH_STATE
        assert d[1] == []
        assert d[2] == []

    def test_with_entries(self):
        msg = MeshState(
            gradients=[
                GradientEntry(
                    dest=b"\x11" * 8,
                    next_hop=b"\x22" * 8,
                    hops=2,
                    seq=100,
                    expires_ms=25000,
                )
            ],
            neighbors=[NeighborEntry(iid=b"\x22" * 8, rssi=-72, snr=10, lqi=95)],
            seq=1,
        )
        d = msg.to_dict()
        assert len(d[1]) == 1
        assert d[1][0][3] == 2  # hops
        assert len(d[2]) == 1
        assert d[2][0][2] == -72  # rssi
        assert d[3] == 1

    def test_roundtrip(self):
        original = MeshState(
            gradients=[
                GradientEntry(
                    dest=bytes(8), next_hop=bytes(8), hops=1, seq=50, expires_ms=10000
                )
            ],
            neighbors=[NeighborEntry(iid=bytes(8), rssi=-80)],
        )
        data = encode_message(original)
        decoded = decode_message(data)
        assert isinstance(decoded, MeshState)
        assert len(decoded.gradients) == 1
        assert decoded.gradients[0].hops == 1
        assert len(decoded.neighbors) == 1
        assert decoded.neighbors[0].rssi == -80


class TestNodeInfo:
    def test_minimal(self):
        msg = NodeInfo(iid=bytes(8))
        d = msg.to_dict()
        assert d[0] == MessageType.NODE_INFO
        assert d[1] == bytes(8)

    def test_full(self):
        msg = NodeInfo(
            iid=b"\x01" * 8,
            name="sensor",
            firmware="lichen-0.1.0",
            hardware="rak4631",
            uptime_ms=3600000,
            battery={1: 78, 2: 3950},
            gps={1: 47606000, 2: -122332000},
        )
        d = msg.to_dict()
        assert d[2] == "sensor"
        assert d[6][1] == 78
        assert d[7][1] == 47606000


class TestLogging:
    def test_log_subscribe(self):
        msg = LogSubscribe(enable=True, level=LogLevel.DEBUG, modules=["radio"])
        d = msg.to_dict()
        assert d[0] == MessageType.LOG_SUBSCRIBE
        assert d[1] is True
        assert d[2] == 4
        assert d[3] == ["radio"]

    def test_log_entry(self):
        msg = LogEntry(level=LogLevel.INFO, msg="TX complete", module="radio")
        d = msg.to_dict()
        assert d[0] == MessageType.LOG_ENTRY
        assert d[1] == 3
        assert d[2] == "TX complete"
        assert d[3] == "radio"

    def test_roundtrip(self):
        original = LogEntry(level=LogLevel.WARN, msg="low battery", time_ms=1000)
        data = encode_message(original)
        decoded = decode_message(data)
        assert isinstance(decoded, LogEntry)
        assert decoded.level == LogLevel.WARN
        assert decoded.msg == "low battery"
        assert decoded.time_ms == 1000


class TestCodec:
    def test_unknown_type(self):
        import cbor2

        data = cbor2.dumps({0: 0xFF})
        with pytest.raises(ValueError, match="unknown message type"):
            decode_message(data)

    def test_missing_type(self):
        import cbor2

        data = cbor2.dumps({1: "no type field"})
        with pytest.raises(ValueError, match="missing type field"):
            decode_message(data)

    def test_invalid_cbor(self):
        with pytest.raises(Exception):
            decode_message(b"\xFF\xFF\xFF")
