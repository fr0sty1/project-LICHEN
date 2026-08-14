# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for MQTT-SN codec.

Oracles are hand-computed from OASIS MQTT-SN 1.2 specification wire formats,
independent of the code under test.
"""

from __future__ import annotations

import pytest

from lichen.mqttsn import (
    Advertise,
    Connack,
    Connect,
    Disconnect,
    GwInfo,
    MqttSnError,
    MsgType,
    Pingreq,
    Pingresp,
    Puback,
    Pubcomp,
    Publish,
    Pubrec,
    Pubrel,
    Regack,
    Register,
    ReturnCode,
    SearchGw,
    Suback,
    Subscribe,
    TopicIdType,
    Unsuback,
    Unsubscribe,
    WillMsg,
    WillMsgReq,
    WillTopic,
    WillTopicReq,
    decode,
    decode_flags,
    encode,
    encode_flags,
)


class TestFlagsEncoding:
    """Test flags byte encoding and decoding."""

    def test_encode_flags_default(self) -> None:
        assert encode_flags() == 0x00

    def test_encode_flags_all_set(self) -> None:
        flags = encode_flags(
            dup=True, qos=3, retain=True, will=True, clean_session=True, topic_id_type=3
        )
        # dup=0x80, qos=0x60, retain=0x10, will=0x08, clean=0x04, type=0x03
        assert flags == 0xFF

    def test_encode_flags_qos_levels(self) -> None:
        assert encode_flags(qos=0) == 0x00
        assert encode_flags(qos=1) == 0x20
        assert encode_flags(qos=2) == 0x40
        assert encode_flags(qos=3) == 0x60

    def test_decode_flags_roundtrip(self) -> None:
        original = {
            "dup": True,
            "qos": 2,
            "retain": True,
            "will": False,
            "clean_session": True,
            "topic_id_type": 1,
        }
        flags = encode_flags(**original)
        decoded = decode_flags(flags)
        assert decoded == original


class TestConnectRoundtrip:
    """Test CONNECT message encoding and decoding."""

    def test_minimal_connect(self) -> None:
        msg = Connect()
        data = encode(msg)
        decoded = decode(data)
        assert decoded == msg

    def test_connect_with_client_id(self) -> None:
        msg = Connect(client_id=b"sensor01", duration=60, clean_session=True)
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Connect)
        assert decoded.client_id == b"sensor01"
        assert decoded.duration == 60
        assert decoded.clean_session is True
        assert decoded.will is False

    def test_connect_with_will(self) -> None:
        msg = Connect(client_id=b"test", duration=120, will=True, clean_session=False)
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Connect)
        assert decoded.will is True
        assert decoded.clean_session is False

    def test_connect_wire_format(self) -> None:
        """Hand-computed wire format for CONNECT message.

        Length=12, MsgType=0x04, Flags=0x04 (clean_session), ProtocolId=0x01,
        Duration=0x003C (60), ClientId="test"
        """
        msg = Connect(client_id=b"test", duration=60, clean_session=True)
        data = encode(msg)
        # Length(1) + MsgType(1) + Flags(1) + ProtocolId(1) + Duration(2) + ClientId(4) = 10 bytes
        assert len(data) == 10
        assert data[0] == 10  # Length
        assert data[1] == MsgType.CONNECT
        assert data[2] == 0x04  # clean_session flag
        assert data[3] == 0x01  # Protocol ID
        assert data[4:6] == b"\x00\x3c"  # Duration 60
        assert data[6:] == b"test"

    def test_connect_rejects_long_client_id(self) -> None:
        with pytest.raises(ValueError, match="client_id must be at most 23 bytes"):
            Connect(client_id=b"x" * 24)


class TestConnackRoundtrip:
    """Test CONNACK message encoding and decoding."""

    def test_connack_accepted(self) -> None:
        msg = Connack(return_code=ReturnCode.ACCEPTED)
        data = encode(msg)
        decoded = decode(data)
        assert decoded == msg

    def test_connack_rejected(self) -> None:
        msg = Connack(return_code=ReturnCode.REJECTED_CONGESTION)
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Connack)
        assert decoded.return_code == ReturnCode.REJECTED_CONGESTION

    def test_connack_wire_format(self) -> None:
        """Hand-computed wire format: Length=3, MsgType=0x05, ReturnCode=0x00."""
        msg = Connack()
        data = encode(msg)
        assert data == bytes([3, 0x05, 0x00])


class TestPublishRoundtrip:
    """Test PUBLISH message encoding and decoding."""

    def test_publish_qos0(self) -> None:
        msg = Publish(topic_id=42, data=b"hello", qos=0)
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Publish)
        assert decoded.topic_id == 42
        assert decoded.data == b"hello"
        assert decoded.qos == 0
        assert decoded.msg_id == 0

    def test_publish_qos1(self) -> None:
        msg = Publish(topic_id=100, msg_id=1234, data=b"data", qos=1)
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Publish)
        assert decoded.topic_id == 100
        assert decoded.msg_id == 1234
        assert decoded.qos == 1

    def test_publish_with_flags(self) -> None:
        msg = Publish(
            topic_id=1,
            msg_id=2,
            data=b"x",
            qos=2,
            retain=True,
            dup=True,
            topic_id_type=TopicIdType.PREDEFINED,
        )
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Publish)
        assert decoded.retain is True
        assert decoded.dup is True
        assert decoded.qos == 2
        assert decoded.topic_id_type == TopicIdType.PREDEFINED

    def test_publish_wire_format(self) -> None:
        """Hand-computed wire format for PUBLISH.

        Length=12, MsgType=0x0C, Flags=0x20 (QoS1), TopicId=0x002A (42),
        MsgId=0x0001, Data="hello"
        """
        msg = Publish(topic_id=42, msg_id=1, data=b"hello", qos=1)
        data = encode(msg)
        # 1 + 1 + 1 + 2 + 2 + 5 = 12 bytes
        assert len(data) == 12
        assert data[0] == 12
        assert data[1] == MsgType.PUBLISH
        assert data[2] == 0x20  # QoS 1
        assert data[3:5] == b"\x00\x2a"  # TopicId 42
        assert data[5:7] == b"\x00\x01"  # MsgId 1
        assert data[7:] == b"hello"


class TestPubackRoundtrip:
    """Test PUBACK message encoding and decoding."""

    def test_puback(self) -> None:
        msg = Puback(topic_id=42, msg_id=1, return_code=ReturnCode.ACCEPTED)
        data = encode(msg)
        decoded = decode(data)
        assert decoded == msg

    def test_puback_wire_format(self) -> None:
        """Hand-computed: Length=7, MsgType=0x0D, TopicId, MsgId, ReturnCode."""
        msg = Puback(topic_id=256, msg_id=512, return_code=0)
        data = encode(msg)
        assert data == bytes([7, 0x0D, 0x01, 0x00, 0x02, 0x00, 0x00])


class TestQoS2Flow:
    """Test QoS 2 message flow (PUBREC, PUBREL, PUBCOMP)."""

    def test_pubrec(self) -> None:
        msg = Pubrec(msg_id=1000)
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Pubrec)
        assert decoded.msg_id == 1000

    def test_pubrel(self) -> None:
        msg = Pubrel(msg_id=2000)
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Pubrel)
        assert decoded.msg_id == 2000

    def test_pubcomp(self) -> None:
        msg = Pubcomp(msg_id=3000)
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Pubcomp)
        assert decoded.msg_id == 3000

    def test_qos2_wire_formats(self) -> None:
        """All QoS2 messages have fixed 4-byte format."""
        assert encode(Pubrec(msg_id=0x1234)) == bytes([4, 0x0F, 0x12, 0x34])
        assert encode(Pubrel(msg_id=0x5678)) == bytes([4, 0x10, 0x56, 0x78])
        assert encode(Pubcomp(msg_id=0xABCD)) == bytes([4, 0x0E, 0xAB, 0xCD])


class TestRegisterRoundtrip:
    """Test REGISTER/REGACK message encoding and decoding."""

    def test_register(self) -> None:
        msg = Register(topic_id=0, msg_id=1, topic_name=b"sensors/temp")
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Register)
        assert decoded.topic_name == b"sensors/temp"
        assert decoded.msg_id == 1

    def test_regack(self) -> None:
        msg = Regack(topic_id=42, msg_id=1, return_code=ReturnCode.ACCEPTED)
        data = encode(msg)
        decoded = decode(data)
        assert decoded == msg

    def test_regack_wire_format(self) -> None:
        """Hand-computed: Length=7, MsgType=0x0B, TopicId, MsgId, ReturnCode."""
        msg = Regack(topic_id=0x0001, msg_id=0x0002, return_code=0)
        data = encode(msg)
        assert data == bytes([7, 0x0B, 0x00, 0x01, 0x00, 0x02, 0x00])


class TestSubscribeRoundtrip:
    """Test SUBSCRIBE/SUBACK message encoding and decoding."""

    def test_subscribe_topic_name(self) -> None:
        msg = Subscribe(msg_id=1, topic=b"test/topic", qos=1)
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Subscribe)
        assert decoded.topic == b"test/topic"
        assert decoded.qos == 1

    def test_subscribe_predefined_topic_id(self) -> None:
        msg = Subscribe(
            msg_id=2, topic=100, qos=0, topic_id_type=TopicIdType.PREDEFINED
        )
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Subscribe)
        assert decoded.topic == 100
        assert decoded.topic_id_type == TopicIdType.PREDEFINED

    def test_suback(self) -> None:
        msg = Suback(topic_id=42, msg_id=1, return_code=ReturnCode.ACCEPTED, qos=1)
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Suback)
        assert decoded.topic_id == 42
        assert decoded.qos == 1

    def test_suback_wire_format(self) -> None:
        """Hand-computed: Length=8, MsgType=0x13, Flags, TopicId, MsgId, ReturnCode."""
        msg = Suback(topic_id=0x0001, msg_id=0x0002, return_code=0, qos=2)
        data = encode(msg)
        assert len(data) == 8
        assert data[0] == 8
        assert data[1] == MsgType.SUBACK
        assert data[2] == 0x40  # QoS 2
        assert data[3:5] == b"\x00\x01"  # TopicId
        assert data[5:7] == b"\x00\x02"  # MsgId
        assert data[7] == 0x00  # ReturnCode


class TestUnsubscribeRoundtrip:
    """Test UNSUBSCRIBE/UNSUBACK message encoding and decoding."""

    def test_unsubscribe_topic_name(self) -> None:
        msg = Unsubscribe(msg_id=1, topic=b"test/topic")
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Unsubscribe)
        assert decoded.topic == b"test/topic"

    def test_unsubscribe_topic_id(self) -> None:
        msg = Unsubscribe(msg_id=2, topic=42, topic_id_type=TopicIdType.PREDEFINED)
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Unsubscribe)
        assert decoded.topic == 42

    def test_unsuback(self) -> None:
        msg = Unsuback(msg_id=1234)
        data = encode(msg)
        decoded = decode(data)
        assert decoded == msg


class TestPingRoundtrip:
    """Test PINGREQ/PINGRESP message encoding and decoding."""

    def test_pingreq_empty(self) -> None:
        msg = Pingreq()
        data = encode(msg)
        decoded = decode(data)
        assert decoded == msg
        assert data == bytes([2, 0x16])

    def test_pingreq_with_client_id(self) -> None:
        msg = Pingreq(client_id=b"sleepy")
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Pingreq)
        assert decoded.client_id == b"sleepy"

    def test_pingresp(self) -> None:
        msg = Pingresp()
        data = encode(msg)
        decoded = decode(data)
        assert decoded == msg
        assert data == bytes([2, 0x17])


class TestDisconnectRoundtrip:
    """Test DISCONNECT message encoding and decoding."""

    def test_disconnect_normal(self) -> None:
        msg = Disconnect()
        data = encode(msg)
        decoded = decode(data)
        assert decoded == msg
        assert data == bytes([2, 0x18])

    def test_disconnect_with_duration(self) -> None:
        msg = Disconnect(duration=3600)
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Disconnect)
        assert decoded.duration == 3600

    def test_disconnect_wire_format_with_duration(self) -> None:
        """Hand-computed: Length=4, MsgType=0x18, Duration=0x0E10 (3600)."""
        msg = Disconnect(duration=3600)
        data = encode(msg)
        assert data == bytes([4, 0x18, 0x0E, 0x10])


class TestGatewayMessages:
    """Test gateway advertisement messages."""

    def test_advertise(self) -> None:
        msg = Advertise(gw_id=1, duration=900)
        data = encode(msg)
        decoded = decode(data)
        assert decoded == msg

    def test_advertise_wire_format(self) -> None:
        """Hand-computed: Length=5, MsgType=0x00, GwId=1, Duration=0x0384 (900)."""
        msg = Advertise(gw_id=1, duration=900)
        data = encode(msg)
        assert data == bytes([5, 0x00, 0x01, 0x03, 0x84])

    def test_searchgw(self) -> None:
        msg = SearchGw(radius=3)
        data = encode(msg)
        decoded = decode(data)
        assert decoded == msg
        assert data == bytes([3, 0x01, 0x03])

    def test_gwinfo_without_addr(self) -> None:
        msg = GwInfo(gw_id=5)
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, GwInfo)
        assert decoded.gw_id == 5
        assert decoded.gw_addr == b""

    def test_gwinfo_with_addr(self) -> None:
        msg = GwInfo(gw_id=10, gw_addr=b"\xc0\xa8\x01\x01")
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, GwInfo)
        assert decoded.gw_id == 10
        assert decoded.gw_addr == b"\xc0\xa8\x01\x01"


class TestWillMessages:
    """Test will message flow."""

    def test_willtopicreq(self) -> None:
        msg = WillTopicReq()
        data = encode(msg)
        decoded = decode(data)
        assert decoded == msg
        assert data == bytes([2, 0x06])

    def test_willtopic_empty(self) -> None:
        msg = WillTopic()
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, WillTopic)
        assert decoded.topic == b""

    def test_willtopic_with_data(self) -> None:
        msg = WillTopic(topic=b"last/will", qos=1, retain=True)
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, WillTopic)
        assert decoded.topic == b"last/will"
        assert decoded.qos == 1
        assert decoded.retain is True

    def test_willmsgreq(self) -> None:
        msg = WillMsgReq()
        data = encode(msg)
        decoded = decode(data)
        assert decoded == msg
        assert data == bytes([2, 0x08])

    def test_willmsg(self) -> None:
        msg = WillMsg(data=b"goodbye")
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, WillMsg)
        assert decoded.data == b"goodbye"


class TestExtendedLength:
    """Test extended 3-byte length encoding for messages > 255 bytes."""

    def test_long_publish_payload(self) -> None:
        # Create a message that requires extended length
        long_data = b"x" * 300
        msg = Publish(topic_id=1, data=long_data)
        data = encode(msg)
        # Extended length format: 0x01 + 2-byte length
        assert data[0] == 0x01
        decoded = decode(data)
        assert isinstance(decoded, Publish)
        assert decoded.data == long_data

    def test_long_topic_name(self) -> None:
        long_topic = b"a/very/long/topic/name/" + b"x" * 250
        msg = Register(topic_name=long_topic, msg_id=1)
        data = encode(msg)
        assert data[0] == 0x01  # Extended length marker
        decoded = decode(data)
        assert isinstance(decoded, Register)
        assert decoded.topic_name == long_topic


class TestErrorHandling:
    """Test error conditions in codec."""

    def test_decode_empty(self) -> None:
        with pytest.raises(MqttSnError, match="too short"):
            decode(b"")

    def test_decode_truncated(self) -> None:
        with pytest.raises(MqttSnError, match="truncated"):
            decode(bytes([10, 0x04]))  # Claims 10 bytes but only 2 provided

    def test_decode_unknown_msg_type(self) -> None:
        with pytest.raises(MqttSnError, match="unknown message type"):
            decode(bytes([2, 0xFF]))

    def test_decode_truncated_extended_length(self) -> None:
        with pytest.raises(MqttSnError, match="truncated"):
            decode(bytes([0x01, 0x00]))  # Extended length but incomplete

    def test_connect_invalid_duration(self) -> None:
        with pytest.raises(ValueError, match="duration must be 0-65535"):
            Connect(duration=-1)

    def test_publish_invalid_qos(self) -> None:
        with pytest.raises(ValueError, match="qos must be 0-3"):
            Publish(qos=4)

    def test_topic_id_range(self) -> None:
        with pytest.raises(ValueError, match="topic_id must be 0-65535"):
            Register(topic_id=70000)


class TestRoundtripAll:
    """Comprehensive roundtrip tests for all message types."""

    @pytest.mark.parametrize(
        "msg",
        [
            Advertise(gw_id=1, duration=300),
            SearchGw(radius=5),
            GwInfo(gw_id=2, gw_addr=b"\x01\x02\x03\x04"),
            Connect(client_id=b"node123", duration=120, clean_session=True),
            Connack(return_code=ReturnCode.ACCEPTED),
            WillTopicReq(),
            WillTopic(topic=b"will/topic", qos=1, retain=True),
            WillMsgReq(),
            WillMsg(data=b"last words"),
            Register(topic_id=0, msg_id=1, topic_name=b"home/sensor/temp"),
            Regack(topic_id=42, msg_id=1, return_code=ReturnCode.ACCEPTED),
            Publish(topic_id=42, msg_id=1, data=b"23.5", qos=1),
            Puback(topic_id=42, msg_id=1, return_code=ReturnCode.ACCEPTED),
            Pubrec(msg_id=100),
            Pubrel(msg_id=100),
            Pubcomp(msg_id=100),
            Subscribe(msg_id=1, topic=b"home/#", qos=1),
            Suback(topic_id=50, msg_id=1, return_code=ReturnCode.ACCEPTED, qos=1),
            Unsubscribe(msg_id=2, topic=b"home/#"),
            Unsuback(msg_id=2),
            Pingreq(),
            Pingreq(client_id=b"sleeper"),
            Pingresp(),
            Disconnect(),
            Disconnect(duration=7200),
        ],
    )
    def test_all_messages_roundtrip(self, msg: object) -> None:
        data = encode(msg)  # type: ignore[arg-type]
        decoded = decode(data)
        assert decoded == msg


class TestPredefinedTopicIds:
    """Test predefined topic ID support."""

    def test_publish_with_predefined_topic(self) -> None:
        # Predefined topic ID 1 might be mapped to a well-known topic
        msg = Publish(
            topic_id=1,
            data=b"value",
            qos=0,
            topic_id_type=TopicIdType.PREDEFINED,
        )
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Publish)
        assert decoded.topic_id_type == TopicIdType.PREDEFINED

    def test_subscribe_predefined(self) -> None:
        msg = Subscribe(
            msg_id=1,
            topic=10,  # Predefined topic ID
            qos=1,
            topic_id_type=TopicIdType.PREDEFINED,
        )
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Subscribe)
        assert decoded.topic == 10
        assert decoded.topic_id_type == TopicIdType.PREDEFINED


class TestShortTopicNames:
    """Test 2-character short topic name support."""

    def test_publish_short_topic_name(self) -> None:
        # Short topic name encoded as 2-byte value
        # "AB" = 0x4142
        msg = Publish(
            topic_id=0x4142,  # "AB" as bytes
            data=b"data",
            qos=0,
            topic_id_type=TopicIdType.SHORT_NAME,
        )
        data = encode(msg)
        decoded = decode(data)
        assert isinstance(decoded, Publish)
        assert decoded.topic_id == 0x4142
        assert decoded.topic_id_type == TopicIdType.SHORT_NAME
