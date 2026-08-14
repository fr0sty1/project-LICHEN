# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""MQTT-SN codec for encoding and decoding messages (OASIS MQTT-SN 1.2).

The MQTT-SN wire format uses a simple Length-MsgType-Data structure:
- 1-byte length (if < 256) or 3-byte length (0x01 + 2-byte big-endian)
- 1-byte message type
- Variable payload depending on message type

Typical usage::

    from lichen.mqttsn.codec import encode, decode
    from lichen.mqttsn.messages import Connect

    msg = Connect(client_id=b"sensor01", duration=60, clean_session=True)
    data = encode(msg)
    decoded = decode(data)
    assert decoded == msg
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from lichen.mqttsn.messages import (
    Advertise,
    Connack,
    Connect,
    Disconnect,
    GwInfo,
    Message,
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
    SearchGw,
    Suback,
    Subscribe,
    Unsuback,
    Unsubscribe,
    WillMsg,
    WillMsgReq,
    WillTopic,
    WillTopicReq,
    decode_flags,
    encode_flags,
)

if TYPE_CHECKING:
    pass


class MqttSnError(Exception):
    """Error during MQTT-SN encoding or decoding."""


def _encode_with_length(body: bytes) -> bytes:
    """Wrap message body with appropriate length prefix.

    For short messages (body + 1 <= 255): 1-byte length prefix
    For long messages: 3-byte prefix (0x01 + 2-byte big-endian total length)

    The length value always includes the length field itself.
    """
    # Try short format first: 1-byte length + body
    short_total = 1 + len(body)
    if short_total <= 255:
        return bytes([short_total]) + body

    # Use extended format: 0x01 + 2-byte length + body
    extended_total = 3 + len(body)
    if extended_total > 0xFFFF:
        raise MqttSnError(f"message too long: {extended_total} bytes (max 65535)")
    return b"\x01" + struct.pack(">H", extended_total) + body


def _encode_length(length: int) -> bytes:
    """Encode MQTT-SN message length field (for fixed-size messages).

    Messages <= 255 bytes use 1-byte length.
    Messages > 255 bytes use 3-byte format: 0x01 + 2-byte big-endian length.

    Note: For variable-length messages, use _encode_with_length() instead.
    """
    if length <= 0:
        raise MqttSnError("message length must be positive")
    if length <= 255:
        return bytes([length])
    if length > 0xFFFF:
        raise MqttSnError(f"message too long: {length} bytes (max 65535)")
    return b"\x01" + struct.pack(">H", length)


def _decode_length(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode MQTT-SN message length field.

    Returns (length, bytes_consumed).
    """
    if offset >= len(data):
        raise MqttSnError("truncated message: missing length")
    first = data[offset]
    if first == 0x01:
        if offset + 3 > len(data):
            raise MqttSnError("truncated message: incomplete extended length")
        length = struct.unpack(">H", data[offset + 1 : offset + 3])[0]
        return length, 3
    return first, 1


def encode(msg: Message) -> bytes:
    """Encode an MQTT-SN message to bytes."""
    if isinstance(msg, Advertise):
        return _encode_advertise(msg)
    if isinstance(msg, SearchGw):
        return _encode_searchgw(msg)
    if isinstance(msg, GwInfo):
        return _encode_gwinfo(msg)
    if isinstance(msg, Connect):
        return _encode_connect(msg)
    if isinstance(msg, Connack):
        return _encode_connack(msg)
    if isinstance(msg, WillTopicReq):
        return _encode_willtopicreq(msg)
    if isinstance(msg, WillTopic):
        return _encode_willtopic(msg)
    if isinstance(msg, WillMsgReq):
        return _encode_willmsgreq(msg)
    if isinstance(msg, WillMsg):
        return _encode_willmsg(msg)
    if isinstance(msg, Register):
        return _encode_register(msg)
    if isinstance(msg, Regack):
        return _encode_regack(msg)
    if isinstance(msg, Publish):
        return _encode_publish(msg)
    if isinstance(msg, Puback):
        return _encode_puback(msg)
    if isinstance(msg, Pubrec):
        return _encode_pubrec(msg)
    if isinstance(msg, Pubrel):
        return _encode_pubrel(msg)
    if isinstance(msg, Pubcomp):
        return _encode_pubcomp(msg)
    if isinstance(msg, Subscribe):
        return _encode_subscribe(msg)
    if isinstance(msg, Suback):
        return _encode_suback(msg)
    if isinstance(msg, Unsubscribe):
        return _encode_unsubscribe(msg)
    if isinstance(msg, Unsuback):
        return _encode_unsuback(msg)
    if isinstance(msg, Pingreq):
        return _encode_pingreq(msg)
    if isinstance(msg, Pingresp):
        return _encode_pingresp(msg)
    if isinstance(msg, Disconnect):
        return _encode_disconnect(msg)
    raise MqttSnError(f"unknown message type: {type(msg).__name__}")


def decode(data: bytes) -> Message:
    """Decode bytes to an MQTT-SN message."""
    if len(data) < 2:
        raise MqttSnError("message too short")

    length, len_size = _decode_length(data)
    if len(data) < length:
        raise MqttSnError(f"truncated message: expected {length} bytes, got {len(data)}")

    msg_type = data[len_size]
    payload = data[len_size + 1 : length]

    try:
        msg_type_enum = MsgType(msg_type)
    except ValueError:
        raise MqttSnError(f"unknown message type: 0x{msg_type:02x}") from None

    if msg_type_enum == MsgType.ADVERTISE:
        return _decode_advertise(payload)
    if msg_type_enum == MsgType.SEARCHGW:
        return _decode_searchgw(payload)
    if msg_type_enum == MsgType.GWINFO:
        return _decode_gwinfo(payload)
    if msg_type_enum == MsgType.CONNECT:
        return _decode_connect(payload)
    if msg_type_enum == MsgType.CONNACK:
        return _decode_connack(payload)
    if msg_type_enum == MsgType.WILLTOPICREQ:
        return _decode_willtopicreq(payload)
    if msg_type_enum == MsgType.WILLTOPIC:
        return _decode_willtopic(payload)
    if msg_type_enum == MsgType.WILLMSGREQ:
        return _decode_willmsgreq(payload)
    if msg_type_enum == MsgType.WILLMSG:
        return _decode_willmsg(payload)
    if msg_type_enum == MsgType.REGISTER:
        return _decode_register(payload)
    if msg_type_enum == MsgType.REGACK:
        return _decode_regack(payload)
    if msg_type_enum == MsgType.PUBLISH:
        return _decode_publish(payload)
    if msg_type_enum == MsgType.PUBACK:
        return _decode_puback(payload)
    if msg_type_enum == MsgType.PUBREC:
        return _decode_pubrec(payload)
    if msg_type_enum == MsgType.PUBREL:
        return _decode_pubrel(payload)
    if msg_type_enum == MsgType.PUBCOMP:
        return _decode_pubcomp(payload)
    if msg_type_enum == MsgType.SUBSCRIBE:
        return _decode_subscribe(payload)
    if msg_type_enum == MsgType.SUBACK:
        return _decode_suback(payload)
    if msg_type_enum == MsgType.UNSUBSCRIBE:
        return _decode_unsubscribe(payload)
    if msg_type_enum == MsgType.UNSUBACK:
        return _decode_unsuback(payload)
    if msg_type_enum == MsgType.PINGREQ:
        return _decode_pingreq(payload)
    if msg_type_enum == MsgType.PINGRESP:
        return _decode_pingresp(payload)
    if msg_type_enum == MsgType.DISCONNECT:
        return _decode_disconnect(payload)

    raise MqttSnError(f"unsupported message type: {msg_type_enum.name}")


# --- ADVERTISE ---


def _encode_advertise(msg: Advertise) -> bytes:
    # Length(1) + MsgType(1) + GwId(1) + Duration(2) = 5 bytes
    payload = bytes([msg.gw_id]) + struct.pack(">H", msg.duration)
    return bytes([5, MsgType.ADVERTISE]) + payload


def _decode_advertise(payload: bytes) -> Advertise:
    if len(payload) != 3:
        raise MqttSnError(f"ADVERTISE payload must be 3 bytes, got {len(payload)}")
    gw_id = payload[0]
    duration = struct.unpack(">H", payload[1:3])[0]
    return Advertise(gw_id=gw_id, duration=duration)


# --- SEARCHGW ---


def _encode_searchgw(msg: SearchGw) -> bytes:
    # Length(1) + MsgType(1) + Radius(1) = 3 bytes
    return bytes([3, MsgType.SEARCHGW, msg.radius])


def _decode_searchgw(payload: bytes) -> SearchGw:
    if len(payload) != 1:
        raise MqttSnError(f"SEARCHGW payload must be 1 byte, got {len(payload)}")
    return SearchGw(radius=payload[0])


# --- GWINFO ---


def _encode_gwinfo(msg: GwInfo) -> bytes:
    # MsgType(1) + GwId(1) + GwAddr(variable)
    body = bytes([MsgType.GWINFO, msg.gw_id]) + msg.gw_addr
    return _encode_with_length(body)


def _decode_gwinfo(payload: bytes) -> GwInfo:
    if len(payload) < 1:
        raise MqttSnError("GWINFO payload too short")
    gw_id = payload[0]
    gw_addr = payload[1:]
    return GwInfo(gw_id=gw_id, gw_addr=gw_addr)


# --- CONNECT ---


def _encode_connect(msg: Connect) -> bytes:
    # MsgType(1) + Flags(1) + ProtocolId(1) + Duration(2) + ClientId
    flags = encode_flags(will=msg.will, clean_session=msg.clean_session)
    protocol_id = 0x01  # MQTT-SN protocol ID
    body = bytes([MsgType.CONNECT, flags, protocol_id])
    body += struct.pack(">H", msg.duration)
    body += msg.client_id
    return _encode_with_length(body)


def _decode_connect(payload: bytes) -> Connect:
    if len(payload) < 4:
        raise MqttSnError(f"CONNECT payload too short: {len(payload)} bytes")
    flags = payload[0]
    # protocol_id = payload[1]  # Should be 0x01
    duration = struct.unpack(">H", payload[2:4])[0]
    client_id = payload[4:]
    flag_dict = decode_flags(flags)
    return Connect(
        client_id=client_id,
        duration=duration,
        clean_session=flag_dict["clean_session"],
        will=flag_dict["will"],
    )


# --- CONNACK ---


def _encode_connack(msg: Connack) -> bytes:
    # Length(1) + MsgType(1) + ReturnCode(1) = 3 bytes
    return bytes([3, MsgType.CONNACK, msg.return_code])


def _decode_connack(payload: bytes) -> Connack:
    if len(payload) != 1:
        raise MqttSnError(f"CONNACK payload must be 1 byte, got {len(payload)}")
    return Connack(return_code=payload[0])


# --- WILLTOPICREQ ---


def _encode_willtopicreq(msg: WillTopicReq) -> bytes:
    # Length(1) + MsgType(1) = 2 bytes
    return bytes([2, MsgType.WILLTOPICREQ])


def _decode_willtopicreq(payload: bytes) -> WillTopicReq:
    # No payload expected
    return WillTopicReq()


# --- WILLTOPIC ---


def _encode_willtopic(msg: WillTopic) -> bytes:
    if not msg.topic:
        # Empty will topic (delete will)
        return bytes([2, MsgType.WILLTOPIC])
    flags = encode_flags(qos=msg.qos, retain=msg.retain)
    body = bytes([MsgType.WILLTOPIC, flags]) + msg.topic
    return _encode_with_length(body)


def _decode_willtopic(payload: bytes) -> WillTopic:
    if len(payload) == 0:
        return WillTopic()
    if len(payload) < 1:
        raise MqttSnError("WILLTOPIC payload too short")
    flags = payload[0]
    topic = payload[1:]
    flag_dict = decode_flags(flags)
    return WillTopic(topic=topic, qos=flag_dict["qos"], retain=flag_dict["retain"])


# --- WILLMSGREQ ---


def _encode_willmsgreq(msg: WillMsgReq) -> bytes:
    # Length(1) + MsgType(1) = 2 bytes
    return bytes([2, MsgType.WILLMSGREQ])


def _decode_willmsgreq(payload: bytes) -> WillMsgReq:
    return WillMsgReq()


# --- WILLMSG ---


def _encode_willmsg(msg: WillMsg) -> bytes:
    body = bytes([MsgType.WILLMSG]) + msg.data
    return _encode_with_length(body)


def _decode_willmsg(payload: bytes) -> WillMsg:
    return WillMsg(data=payload)


# --- REGISTER ---


def _encode_register(msg: Register) -> bytes:
    # MsgType(1) + TopicId(2) + MsgId(2) + TopicName
    body = bytes([MsgType.REGISTER])
    body += struct.pack(">H", msg.topic_id)
    body += struct.pack(">H", msg.msg_id)
    body += msg.topic_name
    return _encode_with_length(body)


def _decode_register(payload: bytes) -> Register:
    if len(payload) < 4:
        raise MqttSnError(f"REGISTER payload too short: {len(payload)} bytes")
    topic_id = struct.unpack(">H", payload[0:2])[0]
    msg_id = struct.unpack(">H", payload[2:4])[0]
    topic_name = payload[4:]
    return Register(topic_id=topic_id, msg_id=msg_id, topic_name=topic_name)


# --- REGACK ---


def _encode_regack(msg: Regack) -> bytes:
    # Length(1) + MsgType(1) + TopicId(2) + MsgId(2) + ReturnCode(1) = 7 bytes
    body = struct.pack(">H", msg.topic_id)
    body += struct.pack(">H", msg.msg_id)
    body += bytes([msg.return_code])
    return bytes([7, MsgType.REGACK]) + body


def _decode_regack(payload: bytes) -> Regack:
    if len(payload) != 5:
        raise MqttSnError(f"REGACK payload must be 5 bytes, got {len(payload)}")
    topic_id = struct.unpack(">H", payload[0:2])[0]
    msg_id = struct.unpack(">H", payload[2:4])[0]
    return_code = payload[4]
    return Regack(topic_id=topic_id, msg_id=msg_id, return_code=return_code)


# --- PUBLISH ---


def _encode_publish(msg: Publish) -> bytes:
    # MsgType(1) + Flags(1) + TopicId(2) + MsgId(2) + Data
    flags = encode_flags(
        dup=msg.dup,
        qos=msg.qos,
        retain=msg.retain,
        topic_id_type=msg.topic_id_type,
    )
    body = bytes([MsgType.PUBLISH, flags])
    body += struct.pack(">H", msg.topic_id)
    body += struct.pack(">H", msg.msg_id)
    body += msg.data
    return _encode_with_length(body)


def _decode_publish(payload: bytes) -> Publish:
    if len(payload) < 5:
        raise MqttSnError(f"PUBLISH payload too short: {len(payload)} bytes")
    flags = payload[0]
    topic_id = struct.unpack(">H", payload[1:3])[0]
    msg_id = struct.unpack(">H", payload[3:5])[0]
    data = payload[5:]
    flag_dict = decode_flags(flags)
    return Publish(
        topic_id=topic_id,
        msg_id=msg_id,
        data=data,
        qos=flag_dict["qos"],
        retain=flag_dict["retain"],
        dup=flag_dict["dup"],
        topic_id_type=flag_dict["topic_id_type"],
    )


# --- PUBACK ---


def _encode_puback(msg: Puback) -> bytes:
    # Length(1) + MsgType(1) + TopicId(2) + MsgId(2) + ReturnCode(1) = 7 bytes
    body = struct.pack(">H", msg.topic_id)
    body += struct.pack(">H", msg.msg_id)
    body += bytes([msg.return_code])
    return bytes([7, MsgType.PUBACK]) + body


def _decode_puback(payload: bytes) -> Puback:
    if len(payload) != 5:
        raise MqttSnError(f"PUBACK payload must be 5 bytes, got {len(payload)}")
    topic_id = struct.unpack(">H", payload[0:2])[0]
    msg_id = struct.unpack(">H", payload[2:4])[0]
    return_code = payload[4]
    return Puback(topic_id=topic_id, msg_id=msg_id, return_code=return_code)


# --- PUBREC ---


def _encode_pubrec(msg: Pubrec) -> bytes:
    # Length(1) + MsgType(1) + MsgId(2) = 4 bytes
    return bytes([4, MsgType.PUBREC]) + struct.pack(">H", msg.msg_id)


def _decode_pubrec(payload: bytes) -> Pubrec:
    if len(payload) != 2:
        raise MqttSnError(f"PUBREC payload must be 2 bytes, got {len(payload)}")
    msg_id = struct.unpack(">H", payload)[0]
    return Pubrec(msg_id=msg_id)


# --- PUBREL ---


def _encode_pubrel(msg: Pubrel) -> bytes:
    # Length(1) + MsgType(1) + MsgId(2) = 4 bytes
    return bytes([4, MsgType.PUBREL]) + struct.pack(">H", msg.msg_id)


def _decode_pubrel(payload: bytes) -> Pubrel:
    if len(payload) != 2:
        raise MqttSnError(f"PUBREL payload must be 2 bytes, got {len(payload)}")
    msg_id = struct.unpack(">H", payload)[0]
    return Pubrel(msg_id=msg_id)


# --- PUBCOMP ---


def _encode_pubcomp(msg: Pubcomp) -> bytes:
    # Length(1) + MsgType(1) + MsgId(2) = 4 bytes
    return bytes([4, MsgType.PUBCOMP]) + struct.pack(">H", msg.msg_id)


def _decode_pubcomp(payload: bytes) -> Pubcomp:
    if len(payload) != 2:
        raise MqttSnError(f"PUBCOMP payload must be 2 bytes, got {len(payload)}")
    msg_id = struct.unpack(">H", payload)[0]
    return Pubcomp(msg_id=msg_id)


# --- SUBSCRIBE ---


def _encode_subscribe(msg: Subscribe) -> bytes:
    # MsgType(1) + Flags(1) + MsgId(2) + Topic/TopicId
    flags = encode_flags(
        dup=msg.dup,
        qos=msg.qos,
        topic_id_type=msg.topic_id_type,
    )
    body = bytes([MsgType.SUBSCRIBE, flags])
    body += struct.pack(">H", msg.msg_id)
    if isinstance(msg.topic, int):
        body += struct.pack(">H", msg.topic)
    else:
        body += msg.topic
    return _encode_with_length(body)


def _decode_subscribe(payload: bytes) -> Subscribe:
    if len(payload) < 3:
        raise MqttSnError(f"SUBSCRIBE payload too short: {len(payload)} bytes")
    flags = payload[0]
    msg_id = struct.unpack(">H", payload[1:3])[0]
    flag_dict = decode_flags(flags)
    topic_id_type = flag_dict["topic_id_type"]

    # If predefined or short topic ID type, topic is 2-byte integer
    if topic_id_type in (1, 2):  # PREDEFINED or SHORT_NAME
        if len(payload) < 5:
            raise MqttSnError("SUBSCRIBE with topic ID requires 5+ bytes payload")
        topic: bytes | int = struct.unpack(">H", payload[3:5])[0]
    else:
        topic = payload[3:]

    return Subscribe(
        msg_id=msg_id,
        topic=topic,
        qos=flag_dict["qos"],
        dup=flag_dict["dup"],
        topic_id_type=topic_id_type,
    )


# --- SUBACK ---


def _encode_suback(msg: Suback) -> bytes:
    # Length(1) + MsgType(1) + Flags(1) + TopicId(2) + MsgId(2) + ReturnCode(1) = 8 bytes
    flags = encode_flags(qos=msg.qos)
    body = bytes([flags])
    body += struct.pack(">H", msg.topic_id)
    body += struct.pack(">H", msg.msg_id)
    body += bytes([msg.return_code])
    return bytes([8, MsgType.SUBACK]) + body


def _decode_suback(payload: bytes) -> Suback:
    if len(payload) != 6:
        raise MqttSnError(f"SUBACK payload must be 6 bytes, got {len(payload)}")
    flags = payload[0]
    topic_id = struct.unpack(">H", payload[1:3])[0]
    msg_id = struct.unpack(">H", payload[3:5])[0]
    return_code = payload[5]
    flag_dict = decode_flags(flags)
    return Suback(
        topic_id=topic_id,
        msg_id=msg_id,
        return_code=return_code,
        qos=flag_dict["qos"],
    )


# --- UNSUBSCRIBE ---


def _encode_unsubscribe(msg: Unsubscribe) -> bytes:
    # MsgType(1) + Flags(1) + MsgId(2) + Topic/TopicId
    flags = encode_flags(topic_id_type=msg.topic_id_type)
    body = bytes([MsgType.UNSUBSCRIBE, flags])
    body += struct.pack(">H", msg.msg_id)
    if isinstance(msg.topic, int):
        body += struct.pack(">H", msg.topic)
    else:
        body += msg.topic
    return _encode_with_length(body)


def _decode_unsubscribe(payload: bytes) -> Unsubscribe:
    if len(payload) < 3:
        raise MqttSnError(f"UNSUBSCRIBE payload too short: {len(payload)} bytes")
    flags = payload[0]
    msg_id = struct.unpack(">H", payload[1:3])[0]
    flag_dict = decode_flags(flags)
    topic_id_type = flag_dict["topic_id_type"]

    if topic_id_type in (1, 2):  # PREDEFINED or SHORT_NAME
        if len(payload) < 5:
            raise MqttSnError("UNSUBSCRIBE with topic ID requires 5+ bytes payload")
        topic: bytes | int = struct.unpack(">H", payload[3:5])[0]
    else:
        topic = payload[3:]

    return Unsubscribe(
        msg_id=msg_id,
        topic=topic,
        topic_id_type=topic_id_type,
    )


# --- UNSUBACK ---


def _encode_unsuback(msg: Unsuback) -> bytes:
    # Length(1) + MsgType(1) + MsgId(2) = 4 bytes
    return bytes([4, MsgType.UNSUBACK]) + struct.pack(">H", msg.msg_id)


def _decode_unsuback(payload: bytes) -> Unsuback:
    if len(payload) != 2:
        raise MqttSnError(f"UNSUBACK payload must be 2 bytes, got {len(payload)}")
    msg_id = struct.unpack(">H", payload)[0]
    return Unsuback(msg_id=msg_id)


# --- PINGREQ ---


def _encode_pingreq(msg: Pingreq) -> bytes:
    # MsgType(1) + ClientId(optional)
    body = bytes([MsgType.PINGREQ]) + msg.client_id
    return _encode_with_length(body)


def _decode_pingreq(payload: bytes) -> Pingreq:
    return Pingreq(client_id=payload)


# --- PINGRESP ---


def _encode_pingresp(msg: Pingresp) -> bytes:
    # Length(1) + MsgType(1) = 2 bytes
    return bytes([2, MsgType.PINGRESP])


def _decode_pingresp(payload: bytes) -> Pingresp:
    return Pingresp()


# --- DISCONNECT ---


def _encode_disconnect(msg: Disconnect) -> bytes:
    if msg.duration is None:
        # Normal disconnect without duration
        return bytes([2, MsgType.DISCONNECT])
    # Disconnect with sleep duration
    return bytes([4, MsgType.DISCONNECT]) + struct.pack(">H", msg.duration)


def _decode_disconnect(payload: bytes) -> Disconnect:
    if len(payload) == 0:
        return Disconnect()
    if len(payload) == 2:
        duration = struct.unpack(">H", payload)[0]
        return Disconnect(duration=duration)
    raise MqttSnError(f"DISCONNECT payload must be 0 or 2 bytes, got {len(payload)}")
