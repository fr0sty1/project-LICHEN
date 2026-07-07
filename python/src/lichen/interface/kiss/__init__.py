"""KISS protocol interface for TNC app compatibility."""

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
from lichen.interface.kiss.aprs_synth import (
    AprsDataType,
    SynthResult,
    synthesize_aprs,
)
from lichen.interface.kiss.ax25 import (
    Ax25Error,
    Ax25Frame,
    ax25_decode,
    ax25_encode,
)
from lichen.interface.kiss.bridge import (
    PORT_AX25,
    PORT_RAW,
    KissBridge,
)
from lichen.interface.kiss.callsign import (
    BROADCAST_CALL,
    LICHEN_PREFIX,
    PeerLookup,
    SimplePeerLookup,
    broadcast_iid,
    callsign_to_iid,
    callsign_to_suffix,
    iid_to_callsign,
    is_broadcast_callsign,
)
from lichen.interface.kiss.framing import (
    FEND,
    FESC,
    TFEND,
    TFESC,
    KissCommand,
    KissError,
    KissFrame,
    KissReader,
    kiss_decode,
    kiss_encode,
    kiss_escape,
    kiss_unescape,
)
from lichen.interface.kiss.gatt import (
    RX_CHAR_UUID,
    SERVICE_UUID,
    TX_CHAR_UUID,
    KissGattService,
)
from lichen.interface.kiss.handler import (
    DefaultKissConfig,
    KissConfig,
    KissHandler,
)
from lichen.interface.kiss.payload_fmt import (
    format_payload,
    is_printable_text,
)
from lichen.interface.kiss.serial import (
    KissSerialConnection,
    open_kiss_serial,
)

__all__ = [
    "Ax25Error",
    "Ax25Frame",
    "ax25_decode",
    "ax25_encode",
    "FEND",
    "FESC",
    "TFEND",
    "TFESC",
    "KissCommand",
    "KissConfig",
    "KissError",
    "KissFrame",
    "KissHandler",
    "KissReader",
    "KissSerialConnection",
    "DefaultKissConfig",
    "kiss_encode",
    "kiss_decode",
    "kiss_escape",
    "kiss_unescape",
    "open_kiss_serial",
    "BROADCAST_CALL",
    "LICHEN_PREFIX",
    "PeerLookup",
    "SimplePeerLookup",
    "broadcast_iid",
    "callsign_to_iid",
    "callsign_to_suffix",
    "iid_to_callsign",
    "is_broadcast_callsign",
    "PORT_AX25",
    "PORT_RAW",
    "KissBridge",
    "SERVICE_UUID",
    "TX_CHAR_UUID",
    "RX_CHAR_UUID",
    "KissGattService",
    "AprsAck",
    "AprsMessage",
    "AprsMessageTracker",
    "AprsPacketType",
    "AprsRej",
    "create_ack",
    "create_message",
    "get_packet_type",
    "parse_aprs_packet",
    "format_payload",
    "is_printable_text",
    "AprsDataType",
    "SynthResult",
    "synthesize_aprs",
]
