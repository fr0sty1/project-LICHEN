# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""MQTT-SN protocol codec for LICHEN (OASIS MQTT-SN 1.2).

MQTT-SN is a lightweight publish/subscribe protocol optimized for sensor
networks and constrained devices. This module provides message dataclasses
and encode/decode functions for wire-format serialization.

Key differences from MQTT:
- Uses 2-byte topic IDs instead of full topic strings
- Supports predefined topic IDs for common topics
- Gateway discovery and advertisement
- Sleeping client support

Typical usage::

    from lichen.mqttsn import Connect, Publish, encode, decode

    # Create and encode a CONNECT message
    connect = Connect(client_id=b"sensor01", duration=60, clean_session=True)
    data = encode(connect)

    # Decode received data
    msg = decode(data)
    if isinstance(msg, Connect):
        print(f"Client {msg.client_id!r} connecting")
"""

from lichen.mqttsn.codec import MqttSnError, decode, encode
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
    QoS,
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
    decode_flags,
    encode_flags,
)

__all__ = [
    # Codec
    "decode",
    "encode",
    "MqttSnError",
    # Enums
    "MsgType",
    "QoS",
    "ReturnCode",
    "TopicIdType",
    # Flag helpers
    "decode_flags",
    "encode_flags",
    # Messages
    "Advertise",
    "Connack",
    "Connect",
    "Disconnect",
    "GwInfo",
    "Message",
    "Pingreq",
    "Pingresp",
    "Puback",
    "Pubcomp",
    "Publish",
    "Pubrec",
    "Pubrel",
    "Regack",
    "Register",
    "SearchGw",
    "Suback",
    "Subscribe",
    "Unsuback",
    "Unsubscribe",
    "WillMsg",
    "WillMsgReq",
    "WillTopic",
    "WillTopicReq",
]
