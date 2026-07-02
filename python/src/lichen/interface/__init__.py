"""Legacy LICHEN Native CBOR protocol interface.

Current LCI sessions use IPv6 + CoAP from spec/11-lci.md. This package keeps
the historical spec/lichen-native draft available for prototype compatibility.
"""

from lichen.interface.framing import FrameReader, FrameWriter, frame, unframe
from lichen.interface.handler import NodeHandler, bind_native
from lichen.interface.messages import (
    ConfigGet,
    ConfigResult,
    ConfigSet,
    Hello,
    LogEntry,
    LogSubscribe,
    MeshState,
    Message,
    MessageReceived,
    NodeInfo,
    SendMessage,
    decode_message,
    encode_message,
)
from lichen.interface.serial import SerialConnection, list_serial_ports, open_serial
from lichen.interface.tcp import TcpConnection, TcpServer, connect, serve

__all__ = [
    # Framing
    "FrameReader",
    "FrameWriter",
    "frame",
    "unframe",
    # Messages
    "Message",
    "Hello",
    "ConfigGet",
    "ConfigSet",
    "ConfigResult",
    "SendMessage",
    "MessageReceived",
    "MeshState",
    "NodeInfo",
    "LogEntry",
    "LogSubscribe",
    "encode_message",
    "decode_message",
    # TCP transport
    "TcpConnection",
    "TcpServer",
    "connect",
    "serve",
    # Node handler
    "NodeHandler",
    "bind_native",
    # Serial transport
    "SerialConnection",
    "open_serial",
    "list_serial_ports",
]
