# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""MQTT-SN message types and dataclasses (OASIS MQTT-SN 1.2).

This module defines message constants and dataclass structures for encoding
and decoding MQTT-SN protocol messages over constrained networks.

Typical usage::

    from lichen.mqttsn.messages import Connect, MsgType

    msg = Connect(
        client_id=b"sensor01",
        duration=60,
        clean_session=True,
    )
    assert msg.msg_type == MsgType.CONNECT
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class MsgType(IntEnum):
    """MQTT-SN message type codes (OASIS MQTT-SN 1.2 Table 2)."""

    ADVERTISE = 0x00
    SEARCHGW = 0x01
    GWINFO = 0x02
    # Reserved 0x03
    CONNECT = 0x04
    CONNACK = 0x05
    WILLTOPICREQ = 0x06
    WILLTOPIC = 0x07
    WILLMSGREQ = 0x08
    WILLMSG = 0x09
    REGISTER = 0x0A
    REGACK = 0x0B
    PUBLISH = 0x0C
    PUBACK = 0x0D
    PUBCOMP = 0x0E
    PUBREC = 0x0F
    PUBREL = 0x10
    # Reserved 0x11
    SUBSCRIBE = 0x12
    SUBACK = 0x13
    UNSUBSCRIBE = 0x14
    UNSUBACK = 0x15
    PINGREQ = 0x16
    PINGRESP = 0x17
    DISCONNECT = 0x18
    # Reserved 0x19
    WILLTOPICUPD = 0x1A
    WILLTOPICRESP = 0x1B
    WILLMSGUPD = 0x1C
    WILLMSGRESP = 0x1D
    # 0xFE = Encapsulated message (forwarder)


class ReturnCode(IntEnum):
    """MQTT-SN return codes (OASIS MQTT-SN 1.2 Table 5)."""

    ACCEPTED = 0x00
    REJECTED_CONGESTION = 0x01
    REJECTED_INVALID_TOPIC_ID = 0x02
    REJECTED_NOT_SUPPORTED = 0x03


class TopicIdType(IntEnum):
    """Topic ID type flags (bits 0-1 of Flags byte)."""

    NORMAL = 0b00  # Topic ID is a normal registration ID
    PREDEFINED = 0b01  # Topic ID is predefined
    SHORT_NAME = 0b10  # Topic Name is a 2-byte short name
    # 0b11 reserved


class QoS(IntEnum):
    """Quality of Service levels."""

    AT_MOST_ONCE = 0  # QoS 0 - fire and forget
    AT_LEAST_ONCE = 1  # QoS 1 - acknowledged delivery
    EXACTLY_ONCE = 2  # QoS 2 - assured delivery
    MINUS_ONE = 3  # QoS -1 - no connection required


# Flags byte bit positions
FLAG_DUP = 0x80  # bit 7: duplicate
FLAG_QOS_MASK = 0x60  # bits 6-5: QoS
FLAG_QOS_SHIFT = 5
FLAG_RETAIN = 0x10  # bit 4: retain
FLAG_WILL = 0x08  # bit 3: will
FLAG_CLEAN_SESSION = 0x04  # bit 2: clean session
FLAG_TOPIC_ID_TYPE_MASK = 0x03  # bits 1-0: topic ID type


def encode_flags(
    *,
    dup: bool = False,
    qos: int = 0,
    retain: bool = False,
    will: bool = False,
    clean_session: bool = False,
    topic_id_type: int = 0,
) -> int:
    """Encode MQTT-SN flags byte."""
    flags = 0
    if dup:
        flags |= FLAG_DUP
    flags |= (qos & 0x03) << FLAG_QOS_SHIFT
    if retain:
        flags |= FLAG_RETAIN
    if will:
        flags |= FLAG_WILL
    if clean_session:
        flags |= FLAG_CLEAN_SESSION
    flags |= topic_id_type & FLAG_TOPIC_ID_TYPE_MASK
    return flags


def decode_flags(flags: int) -> dict[str, bool | int]:
    """Decode MQTT-SN flags byte into components."""
    return {
        "dup": bool(flags & FLAG_DUP),
        "qos": (flags & FLAG_QOS_MASK) >> FLAG_QOS_SHIFT,
        "retain": bool(flags & FLAG_RETAIN),
        "will": bool(flags & FLAG_WILL),
        "clean_session": bool(flags & FLAG_CLEAN_SESSION),
        "topic_id_type": flags & FLAG_TOPIC_ID_TYPE_MASK,
    }


@dataclass(frozen=True, slots=True)
class Connect:
    """CONNECT message - client requests connection to gateway.

    Fields:
        client_id: Client identifier (1-23 bytes)
        duration: Keep-alive duration in seconds
        clean_session: Start fresh session
        will: Client has a will message
    """

    msg_type: int = MsgType.CONNECT
    client_id: bytes = b""
    duration: int = 0
    clean_session: bool = True
    will: bool = False

    def __post_init__(self) -> None:
        if len(self.client_id) > 23:
            raise ValueError("client_id must be at most 23 bytes")
        if not 0 <= self.duration <= 0xFFFF:
            raise ValueError("duration must be 0-65535")


@dataclass(frozen=True, slots=True)
class Connack:
    """CONNACK message - gateway acknowledges connection."""

    msg_type: int = MsgType.CONNACK
    return_code: int = ReturnCode.ACCEPTED


@dataclass(frozen=True, slots=True)
class WillTopicReq:
    """WILLTOPICREQ message - gateway requests will topic."""

    msg_type: int = MsgType.WILLTOPICREQ


@dataclass(frozen=True, slots=True)
class WillTopic:
    """WILLTOPIC message - client sends will topic.

    Fields:
        topic: Will topic name (or empty to delete will)
        qos: QoS level for will message
        retain: Retain flag for will message
    """

    msg_type: int = MsgType.WILLTOPIC
    topic: bytes = b""
    qos: int = 0
    retain: bool = False


@dataclass(frozen=True, slots=True)
class WillMsgReq:
    """WILLMSGREQ message - gateway requests will message."""

    msg_type: int = MsgType.WILLMSGREQ


@dataclass(frozen=True, slots=True)
class WillMsg:
    """WILLMSG message - client sends will message body."""

    msg_type: int = MsgType.WILLMSG
    data: bytes = b""


@dataclass(frozen=True, slots=True)
class Register:
    """REGISTER message - register topic name for topic ID.

    Used by client to register a topic name with gateway and receive
    a topic ID, or by gateway to inform client of a topic ID mapping.

    Fields:
        topic_id: Assigned topic ID (0 when client is registering)
        msg_id: Message ID for matching request/response
        topic_name: Topic name to register
    """

    msg_type: int = MsgType.REGISTER
    topic_id: int = 0
    msg_id: int = 0
    topic_name: bytes = b""

    def __post_init__(self) -> None:
        if not 0 <= self.topic_id <= 0xFFFF:
            raise ValueError("topic_id must be 0-65535")
        if not 0 <= self.msg_id <= 0xFFFF:
            raise ValueError("msg_id must be 0-65535")


@dataclass(frozen=True, slots=True)
class Regack:
    """REGACK message - acknowledge topic registration.

    Fields:
        topic_id: Assigned topic ID
        msg_id: Message ID matching the REGISTER
        return_code: Result of registration
    """

    msg_type: int = MsgType.REGACK
    topic_id: int = 0
    msg_id: int = 0
    return_code: int = ReturnCode.ACCEPTED

    def __post_init__(self) -> None:
        if not 0 <= self.topic_id <= 0xFFFF:
            raise ValueError("topic_id must be 0-65535")
        if not 0 <= self.msg_id <= 0xFFFF:
            raise ValueError("msg_id must be 0-65535")


@dataclass(frozen=True, slots=True)
class Publish:
    """PUBLISH message - publish data to a topic.

    Fields:
        topic_id: Topic ID (or short name as 2 bytes)
        msg_id: Message ID (only for QoS > 0)
        data: Payload data
        qos: Quality of service level
        retain: Retain this message
        dup: Duplicate delivery attempt
        topic_id_type: Type of topic_id field
    """

    msg_type: int = MsgType.PUBLISH
    topic_id: int = 0
    msg_id: int = 0
    data: bytes = b""
    qos: int = 0
    retain: bool = False
    dup: bool = False
    topic_id_type: int = TopicIdType.NORMAL

    def __post_init__(self) -> None:
        if not 0 <= self.topic_id <= 0xFFFF:
            raise ValueError("topic_id must be 0-65535")
        if not 0 <= self.msg_id <= 0xFFFF:
            raise ValueError("msg_id must be 0-65535")
        if not 0 <= self.qos <= 3:
            raise ValueError("qos must be 0-3")


@dataclass(frozen=True, slots=True)
class Puback:
    """PUBACK message - acknowledge QoS 1 publish.

    Fields:
        topic_id: Topic ID from PUBLISH
        msg_id: Message ID from PUBLISH
        return_code: Result code
    """

    msg_type: int = MsgType.PUBACK
    topic_id: int = 0
    msg_id: int = 0
    return_code: int = ReturnCode.ACCEPTED

    def __post_init__(self) -> None:
        if not 0 <= self.topic_id <= 0xFFFF:
            raise ValueError("topic_id must be 0-65535")
        if not 0 <= self.msg_id <= 0xFFFF:
            raise ValueError("msg_id must be 0-65535")


@dataclass(frozen=True, slots=True)
class Pubrec:
    """PUBREC message - first ack in QoS 2 flow."""

    msg_type: int = MsgType.PUBREC
    msg_id: int = 0

    def __post_init__(self) -> None:
        if not 0 <= self.msg_id <= 0xFFFF:
            raise ValueError("msg_id must be 0-65535")


@dataclass(frozen=True, slots=True)
class Pubrel:
    """PUBREL message - second ack in QoS 2 flow."""

    msg_type: int = MsgType.PUBREL
    msg_id: int = 0

    def __post_init__(self) -> None:
        if not 0 <= self.msg_id <= 0xFFFF:
            raise ValueError("msg_id must be 0-65535")


@dataclass(frozen=True, slots=True)
class Pubcomp:
    """PUBCOMP message - final ack in QoS 2 flow."""

    msg_type: int = MsgType.PUBCOMP
    msg_id: int = 0

    def __post_init__(self) -> None:
        if not 0 <= self.msg_id <= 0xFFFF:
            raise ValueError("msg_id must be 0-65535")


@dataclass(frozen=True, slots=True)
class Subscribe:
    """SUBSCRIBE message - subscribe to a topic.

    Fields:
        msg_id: Message ID for matching SUBACK
        topic: Topic name or topic ID depending on topic_id_type
        qos: Requested QoS level
        dup: Duplicate request
        topic_id_type: How to interpret topic field
    """

    msg_type: int = MsgType.SUBSCRIBE
    msg_id: int = 0
    topic: bytes | int = b""
    qos: int = 0
    dup: bool = False
    topic_id_type: int = TopicIdType.NORMAL

    def __post_init__(self) -> None:
        if not 0 <= self.msg_id <= 0xFFFF:
            raise ValueError("msg_id must be 0-65535")
        if isinstance(self.topic, int) and not 0 <= self.topic <= 0xFFFF:
            raise ValueError("topic ID must be 0-65535")


@dataclass(frozen=True, slots=True)
class Suback:
    """SUBACK message - acknowledge subscription.

    Fields:
        topic_id: Assigned topic ID
        msg_id: Message ID from SUBSCRIBE
        return_code: Result code
        qos: Granted QoS level
    """

    msg_type: int = MsgType.SUBACK
    topic_id: int = 0
    msg_id: int = 0
    return_code: int = ReturnCode.ACCEPTED
    qos: int = 0

    def __post_init__(self) -> None:
        if not 0 <= self.topic_id <= 0xFFFF:
            raise ValueError("topic_id must be 0-65535")
        if not 0 <= self.msg_id <= 0xFFFF:
            raise ValueError("msg_id must be 0-65535")


@dataclass(frozen=True, slots=True)
class Unsubscribe:
    """UNSUBSCRIBE message - unsubscribe from a topic.

    Fields:
        msg_id: Message ID for matching UNSUBACK
        topic: Topic name or topic ID
        topic_id_type: How to interpret topic field
    """

    msg_type: int = MsgType.UNSUBSCRIBE
    msg_id: int = 0
    topic: bytes | int = b""
    topic_id_type: int = TopicIdType.NORMAL

    def __post_init__(self) -> None:
        if not 0 <= self.msg_id <= 0xFFFF:
            raise ValueError("msg_id must be 0-65535")


@dataclass(frozen=True, slots=True)
class Unsuback:
    """UNSUBACK message - acknowledge unsubscription."""

    msg_type: int = MsgType.UNSUBACK
    msg_id: int = 0

    def __post_init__(self) -> None:
        if not 0 <= self.msg_id <= 0xFFFF:
            raise ValueError("msg_id must be 0-65535")


@dataclass(frozen=True, slots=True)
class Pingreq:
    """PINGREQ message - keep-alive ping request.

    Fields:
        client_id: Optional client ID (for sleeping clients)
    """

    msg_type: int = MsgType.PINGREQ
    client_id: bytes = b""


@dataclass(frozen=True, slots=True)
class Pingresp:
    """PINGRESP message - keep-alive ping response."""

    msg_type: int = MsgType.PINGRESP


@dataclass(frozen=True, slots=True)
class Disconnect:
    """DISCONNECT message - client or gateway disconnect.

    Fields:
        duration: Sleep duration in seconds (0 for normal disconnect)
    """

    msg_type: int = MsgType.DISCONNECT
    duration: int | None = None

    def __post_init__(self) -> None:
        if self.duration is not None and not 0 <= self.duration <= 0xFFFF:
            raise ValueError("duration must be 0-65535 or None")


@dataclass(frozen=True, slots=True)
class Advertise:
    """ADVERTISE message - gateway advertises presence.

    Fields:
        gw_id: Gateway ID
        duration: Time until next advertise in seconds
    """

    msg_type: int = MsgType.ADVERTISE
    gw_id: int = 0
    duration: int = 0

    def __post_init__(self) -> None:
        if not 0 <= self.gw_id <= 0xFF:
            raise ValueError("gw_id must be 0-255")
        if not 0 <= self.duration <= 0xFFFF:
            raise ValueError("duration must be 0-65535")


@dataclass(frozen=True, slots=True)
class SearchGw:
    """SEARCHGW message - client searches for gateway.

    Fields:
        radius: Broadcast radius
    """

    msg_type: int = MsgType.SEARCHGW
    radius: int = 0

    def __post_init__(self) -> None:
        if not 0 <= self.radius <= 0xFF:
            raise ValueError("radius must be 0-255")


@dataclass(frozen=True, slots=True)
class GwInfo:
    """GWINFO message - gateway info response.

    Fields:
        gw_id: Gateway ID
        gw_addr: Optional gateway address
    """

    msg_type: int = MsgType.GWINFO
    gw_id: int = 0
    gw_addr: bytes = b""

    def __post_init__(self) -> None:
        if not 0 <= self.gw_id <= 0xFF:
            raise ValueError("gw_id must be 0-255")


# Union type for all message types
Message = (
    Advertise
    | SearchGw
    | GwInfo
    | Connect
    | Connack
    | WillTopicReq
    | WillTopic
    | WillMsgReq
    | WillMsg
    | Register
    | Regack
    | Publish
    | Puback
    | Pubrec
    | Pubrel
    | Pubcomp
    | Subscribe
    | Suback
    | Unsubscribe
    | Unsuback
    | Pingreq
    | Pingresp
    | Disconnect
)
