# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN CoAP transmission parameters and duty cycle awareness (spec 07 §10.2.2-10.2.3).

Implements the LICHEN-specific overrides for RFC 7252 retransmission and
the duty cycle tracking mandated by spec/07-transport-app.md.

All values are the Python oracle (source of truth) for cross-language vectors.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum

import cbor2
from aiocoap import Message
from aiocoap.numbers import ContentFormat
from aiocoap.numbers.codes import SERVICE_UNAVAILABLE

from lichen.link.tx_queue import Priority

# --- Transmission parameters (spec §10.2.2) ---

LICHEN_ACK_TIMEOUT: float = 15.0  # seconds (RFC 7252 default 2s)
LICHEN_ACK_RANDOM_FACTOR: float = 2.0  # default 1.5
LICHEN_MAX_RETRANSMIT: int = 2  # default 4
LICHEN_NSTART: int = 1
LICHEN_DEFAULT_LEISURE: float = 15.0  # seconds (default 5s)
LICHEN_PROBING_RATE: float = 0.1  # bytes/second (default 1 B/s)

RFC7252_ACK_TIMEOUT: float = 2.0
RFC7252_ACK_RANDOM_FACTOR: float = 1.5
RFC7252_MAX_RETRANSMIT: int = 4
RFC7252_NSTART: int = 1
RFC7252_DEFAULT_LEISURE: float = 5.0
RFC7252_PROBING_RATE: float = 1.0


@dataclass(frozen=True, slots=True)
class CoapParams:
    """CoAP transmission parameters."""

    ack_timeout: float = LICHEN_ACK_TIMEOUT
    ack_random_factor: float = LICHEN_ACK_RANDOM_FACTOR
    max_retransmit: int = LICHEN_MAX_RETRANSMIT
    nstart: int = LICHEN_NSTART
    default_leisure: float = LICHEN_DEFAULT_LEISURE
    probing_rate: float = LICHEN_PROBING_RATE

    def retransmit_timeouts(self) -> list[float]:
        """Return retransmission timeouts for each retry (RFC 7252 §4.8).

        With LICHEN values: 15-30s, 30-60s, give up at ~90s.
        """
        base = self.ack_timeout
        timeouts: list[float] = []
        for i in range(self.max_retransmit):
            timeouts.append(base * (2**i))
        return timeouts

    def exchange_lifetime(self) -> float:
        """Approximate MAX_TRANSMIT_SPAN + MAX_LATENCY (upper bound)."""
        base = self.ack_timeout
        # MAX_TRANSMIT_SPAN = ACK_TIMEOUT * (2^(MAX_RETRANSMIT) -1) * ACK_RANDOM_FACTOR
        max_span = base * ((2**self.max_retransmit) - 1) * self.ack_random_factor
        return max_span + self.default_leisure


LICHEN_PARAMS = CoapParams()
RFC7252_PARAMS = CoapParams(
    ack_timeout=RFC7252_ACK_TIMEOUT,
    ack_random_factor=RFC7252_ACK_RANDOM_FACTOR,
    max_retransmit=RFC7252_MAX_RETRANSMIT,
    nstart=RFC7252_NSTART,
    default_leisure=RFC7252_DEFAULT_LEISURE,
    probing_rate=RFC7252_PROBING_RATE,
)

# Content-Format dispatch (spec §10.2.1)
CONTENT_FORMAT_TEXT_PLAIN: int = 0
CONTENT_FORMAT_CBOR: int = 60
CONTENT_FORMAT_SENML_JSON: int = 110
CONTENT_FORMAT_SENML_CBOR: int = 112
CONTENT_FORMAT_OCF_CBOR: int = 11542

CONTENT_FORMATS: dict[int, str] = {
    0: "text/plain",
    60: "application/cbor",
    110: "application/senml+json",
    112: "application/senml+cbor",
    11542: "application/vnd.ocf+cbor",
}

# UDP port allocation (spec §9.1)
PORT_COMPACT_COT: int = 5681
PORT_SENML: int = 5682
PORT_COAP: int = 5683
PORT_COAPS_RESERVED: int = 5684
PORT_CAYENNE: int = 5685
PORT_APRS_IS: int = 5686
PORT_NMEA: int = 5687
PORT_MQTT_SN: int = 10883

PORT_ALLOCATION: dict[int, str] = {
    5681: "Compact CoT (Raw UDP)",
    5682: "SenML CBOR (Raw UDP)",
    5683: "CoAP",
    5684: "Reserved (CoAPS/DTLS)",
    5685: "Cayenne LPP (Raw UDP)",
    5686: "APRS-IS (Raw UDP)",
    5687: "NMEA (Raw UDP)",
    10883: "MQTT-SN",
}


class CongestionLevel(StrEnum):
    """Duty cycle congestion levels (spec §10.2.3)."""

    NORMAL = "normal"
    ELEVATED = "elevated"
    CRITICAL = "critical"
    EXHAUSTED = "exhausted"


@dataclass(frozen=True, slots=True)
class CongestionState:
    """Atomic snapshot of congestion level and retry delay.

    This dataclass provides an atomic read of both congestion_level and
    retry_after_ms to avoid race conditions when these values are read
    separately in concurrent environments (r1-P3-43).
    """

    level: CongestionLevel
    retry_after_ms: int | None = None


def congestion_level(duty_used_ratio: float) -> CongestionLevel:
    """Map duty cycle ratio [0,1] to congestion level."""
    if duty_used_ratio > 0.95:
        return CongestionLevel.EXHAUSTED
    if duty_used_ratio >= 0.80:
        return CongestionLevel.CRITICAL
    if duty_used_ratio >= 0.50:
        return CongestionLevel.ELEVATED
    return CongestionLevel.NORMAL


# TxPriority is now unified with link.tx_queue.Priority.
# This alias preserves backward compatibility for existing coap imports.
TxPriority = Priority

# Application-to-priority mapping (spec §10.2.3)
# Uses semantic names from Priority enum for clarity.
APP_PRIORITY: dict[tuple[int, str], Priority] = {
    (5681, "alert"): Priority.SOS,  # CoT subtype 0x20 -> P0
    (5681, "chat"): Priority.URGENT,  # CoT subtype 0x01 -> P2
    (5681, "pli"): Priority.NORMAL,  # CoT subtype 0x02-0x05 -> P3
    (5681, "marker"): Priority.NORMAL,  # CoT subtype 0x10 -> P3
    (5682, "senml"): Priority.NORMAL,  # P3
    (5683, "con"): Priority.URGENT,  # P2
    (5683, "non"): Priority.NORMAL,  # P3
    (5685, "cayenne"): Priority.NORMAL,  # P3
    (5686, "aprs"): Priority.NORMAL,  # P3
    (5687, "nmea"): Priority.NORMAL,  # P3
    (10883, "qos1"): Priority.URGENT,  # P2
    (10883, "qos0"): Priority.NORMAL,  # P3
}


def app_priority(port: int, subtype: str) -> Priority:
    """Return TX priority for given port and application subtype."""
    key = (port, subtype)
    if key in APP_PRIORITY:
        return APP_PRIORITY[key]
    # Default: NORMAL (P3) for unknown app mappings
    return Priority.NORMAL


class CongestionError(Exception):
    """Raised when transmission is blocked due to duty cycle congestion.

    Per spec 07 section 10.2.3, congested nodes must shed traffic:
    - ELEVATED: delay non-urgent (NORMAL/BULK)
    - CRITICAL: only SOS/routing
    - EXHAUSTED: stop all TX

    Attributes:
        level: Current congestion level.
        priority: Priority of the blocked transmission.
        retry_after_ms: Estimated time until transmission may be allowed (ms).
    """

    def __init__(
        self,
        level: CongestionLevel,
        priority: Priority,
        retry_after_ms: int | None = None,
    ) -> None:
        self.level = level
        self.priority = priority
        self.retry_after_ms = retry_after_ms
        super().__init__(
            f"transmission blocked at {level.value} congestion "
            f"(priority {priority.name})"
        )


def check_congestion_allows(level: CongestionLevel, priority: Priority) -> bool:
    """Check if a transmission is allowed at the given congestion level.

    Implements spec 07 section 10.2.3:
    - NORMAL (<50%): all traffic allowed
    - ELEVATED (50-80%): delay non-urgent (NORMAL/BULK), allow SOS/ROUTING/URGENT
    - CRITICAL (80-95%): only SOS/ROUTING
    - EXHAUSTED (>95%): stop all TX

    Args:
        level: Current duty cycle congestion level.
        priority: Priority of the transmission (SOS=highest, BULK=lowest).

    Returns:
        True if transmission is allowed, False if it should be blocked.
    """
    if level == CongestionLevel.NORMAL:
        return True
    if level == CongestionLevel.ELEVATED:
        # Allow SOS, ROUTING, URGENT (values 0-2)
        return priority <= Priority.URGENT
    if level == CongestionLevel.CRITICAL:
        # Only SOS, ROUTING (values 0-1)
        return priority <= Priority.ROUTING
    # EXHAUSTED: block all
    return False


def congestion_service_unavailable(
    level: CongestionLevel,
    retry_after_s: int | float | None = None,
) -> Message:
    """Build a 5.03 Service Unavailable response per spec 07 section 10.2.3.

    When congested, respond to new requests with:
        5.03 Service Unavailable
        Max-Age: <seconds until duty cycle recovers>
        Content-Format: application/cbor
        {
          "reason": "duty_cycle",
          "retry_after": <seconds>,
          "level": "<congestion level>"
        }

    Args:
        level: Current congestion level.
        retry_after_s: Seconds until retry may succeed. Defaults to 120.
            Negative values are clamped to 0. IEEE 754 infinity and NaN
            are treated as None (use default).

    Returns:
        A CoAP Message with code 5.03 and CBOR payload.
    """
    # SECURITY: Reject IEEE 754 infinity/NaN before any comparison (r2-P2-34).
    # These special values cannot be converted to valid Max-Age (uint) and
    # would cause undefined behavior if encoded in CBOR payload.
    if retry_after_s is not None:
        try:
            if not math.isfinite(retry_after_s):
                retry_after_s = None
        except (TypeError, OverflowError):
            # Non-numeric type or overflow; treat as invalid
            retry_after_s = None
    if retry_after_s is None:
        retry_after_s = 120  # Default per spec example
    elif retry_after_s < 0:
        # SECURITY: Clamp negative values to 0 (r1-P3-42). Negative Max-Age is
        # invalid per RFC 7252 (uint) and could cause undefined behavior.
        retry_after_s = 0
    # Ensure integer for Max-Age option (RFC 7252 requires uint)
    retry_after_s = int(retry_after_s)
    payload = cbor2.dumps({
        "reason": "duty_cycle",
        "retry_after": retry_after_s,
        "level": level.value,
    })
    msg = Message(code=SERVICE_UNAVAILABLE, payload=payload)
    msg.opt.content_format = ContentFormat.CBOR
    # Always set Max-Age to match retry_after per spec 07 section 10.2.3.
    # Max-Age=0 is valid per RFC 7252 (means "immediately stale").
    msg.opt.max_age = retry_after_s
    return msg
