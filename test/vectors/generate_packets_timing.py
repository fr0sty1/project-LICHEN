#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate packets/timing vectors from numeric and independent security oracles."""

from __future__ import annotations

import argparse
import math
import struct
import sys
from enum import Enum, auto
from pathlib import Path

VECTORS_DIR = Path(__file__).resolve().parent
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from atomic_json import (  # noqa: E402
    atomic_write_json_batch,
    json_bytes,
    read_bounded_exact,
)
from reference_schnorr48 import ReferenceIdentity, sign, signature_transcript  # noqa: E402

FORMAT_VERSION = 2


def packets_formats_vectors() -> list[dict[str, object]]:
    # These are spec literals, deliberately independent of lichen.packets.
    # The consumer suite separately requires the production helpers to match.
    complete_link_frame = {
        "Length": 106,
        "LLSec": 0xA1,
        "Epoch": 0x01,
        "SeqNum": 0x0042,
        "DstAddr": 0x0001,
        "signer_eui64_len": 8,
        "payload_dispatch": 0x14,
        "payload_len": 44,
        "signature_len": 48,
        "total_on_wire": 107,
    }
    packet_summary = {
        "app_payload": 16,
        "security_e2e": 0,
        "transport_network": 27,
        "routing_overhead": 3,
        "link_security": 61,
        "total": 107,
    }
    link_security_breakdown = {
        "Length": 1,
        "LLSec": 1,
        "Epoch": 1,
        "SeqNum": 2,
        "SignerEui64": 8,
        "Signature": 48,
    }
    rpl_dio_fields = {
        "link_layer": [
            "Len",
            "LLSec",
            "Epoch",
            "SeqNum",
            "SignerEUI64",
            "Payload",
            "Sig",
        ],
        "ipv6_compressed": [
            "validated SCHC Rule 255",
            "full IPv6 header",
            "destination ff02::1a",
        ],
        "icmpv6": {"Type": 155, "Code": 1, "label": "DIO"},
        "dio_payload": [
            "RPLInstanceID",
            "Version",
            "Rank",
            "G/MOP/Prf",
            "DTSN",
            "Flags",
            "Reserved",
            "DODAGID",
        ],
        "options": ["Rule-Version 0x13/0x01/0x03 (mandatory)"],
    }

    def encode_dio_base(*, instance_id: int, version: int, rank: int) -> bytes:
        """Literal RFC 6550 DIO base plus the mandatory LICHEN option."""
        assert 0 <= instance_id <= 0xFF
        assert 0 <= version <= 0xFF
        assert 0 <= rank <= 0xFFFF
        return (
            bytes(
                (
                    instance_id,
                    version,
                    rank >> 8,
                    rank & 0xFF,
                    0x08,  # G=0, MOP=1, Prf=0
                    0x00,  # DTSN
                    0x00,  # Flags
                    0x00,  # Reserved
                )
            )
            + bytes(16)
            + bytes((0x13, 0x01, 0x03))
        )

    vectors: list[dict[str, object]] = []
    # 13.1 complete example
    vectors.append(
        {
            "name": "complete_packet_example_link_frame",
            "description": (
                "13.1 plaintext example: 16-byte app value, 43-byte SCHC packet, "
                "44-byte authenticated L2 payload, Length 106 body, 107 on-wire, "
                "LLSec 0xA1, mandatory 8-byte signer EUI-64, and 48-byte signature."
            ),
            "category": "packet_walkthrough",
            "app_payload_len": 16,
            "link_frame": complete_link_frame,
            "l2_payload_len": 44,
            "schc_packet_len": 43,
            "total_on_wire": 107,
            "body_bytes": 106,
        }
    )

    # 13.2 size summary
    vectors.append(
        {
            "name": "packet_size_summary",
            "description": (
                "13.2 exact plaintext example: app 16B + transport/network 27B + "
                "routing/addressing 3B + link security 61B = 107B."
            ),
            "category": "size_budget",
            "summary": packet_summary,
            "link_security_breakdown": link_security_breakdown,
            "link_security_overhead": 61,
            "exact_total": 107,
            "min_total_at_zero_routing": 104,
            "max_total_at_six_routing": 110,
        }
    )

    # per-mode overhead
    for mode in ("none", "short", "extended", "elided"):
        for signed in (True, False):
            destination_length = {"none": 0, "short": 2, "extended": 8, "elided": 0}[
                mode
            ]
            signer_length = 8 if signed else 0
            signature_length = 48 if signed else 0
            total = 5 + destination_length + signer_length + signature_length
            vectors.append(
                {
                    "name": f"link_overhead_{mode}_{'signed' if signed else 'unsigned'}",
                    "description": (
                        f"Link frame overhead for addr_mode={mode} signed={signed}: "
                        f"total {total}B, body {total - 1}B."
                    ),
                    "category": "link_overhead",
                    "addr_mode": mode,
                    "signed": signed,
                    "total": total,
                    "body": total - 1,
                    "dst_addr_len": destination_length,
                    "signer_eui64_len": signer_length,
                }
            )

    # RPL DIO skeleton
    vectors.append(
        {
            "name": "rpl_dio_skeleton",
            "description": (
                "13.3 RPL DIO packet fields and deterministic 27-byte DIO: "
                "24-byte RFC 6550 base plus mandatory Rule-Version 13 01 03."
            ),
            "category": "dio_format",
            "fields": rpl_dio_fields,
            "example_hex": encode_dio_base(instance_id=0, version=7, rank=256).hex(),
            "example_len": len(encode_dio_base(instance_id=0, version=7, rank=256)),
        }
    )

    # DIO encoding edge cases
    for rank in (0, 256, 0xFFFF):
        vectors.append(
            {
                "name": f"dio_rank_{rank}",
                "description": f"DIO encoding with rank={rank}.",
                "category": "dio_rank",
                "rank": rank,
                "hex": encode_dio_base(instance_id=0, version=0, rank=rank).hex(),
            }
        )

    return vectors


def packets_formats_document() -> dict[str, object]:
    """Build the independently specified packet-format vector document."""
    return {
        "format_version": FORMAT_VERSION,
        "description": (
            "Packets and Timing packet format vectors (spec 09 §13). "
            "Fixed packet-budget fields are independent spec-derived oracles."
        ),
        "vectors": packets_formats_vectors(),
    }


def packets_timing_vectors() -> list[dict[str, object]]:
    from ipaddress import IPv6Address

    # Independent spec constants/reference calculations. Regeneration never
    # imports lichen.*, so production regressions cannot rewrite the oracle.
    TRICKLE_IMIN_MS, TRICKLE_IMAX_EXACT_MS, TRICKLE_K = 4_000, 1_024_000, 10
    DAO_RETRY_DELAYS_MS = (4_000, 8_000, 16_000)
    DAO_REFRESH_S, DAO_SOFT_STATE_LIFETIME_S = 900, 1_800
    TELEMETRY_INTERVAL_MIN_S, TELEMETRY_INTERVAL_MAX_S, HEARTBEAT_INTERVAL_S = (
        300,
        3_600,
        1_800,
    )
    EU868_DUTY_CYCLE_PERCENT = 10.0
    CSMA_CAD_TIMEOUT_SYMBOLS, CSMA_BACKOFF_UNIT_MS = 3, 10
    CSMA_BACKOFF_MAX, CSMA_RETRY_LIMIT = 5, 3
    DIO_TIME_OPTION_TYPE = 0x15
    DESYNC_CONSTANTS = {
        "LISTEN_PERIOD_MIN_S": 30,
        "LISTEN_PERIOD_MAX_S": 60,
        "DELAY_PER_NODE_S": 5,
        "MAX_STARTUP_DELAY_S": 300,
    }

    def airtime_us_with_params(
        payload_len: int, *, sf: int = 10, bw_hz: int = 125_000
    ) -> int:
        numerator = 8 * payload_len - 4 * sf + 28 + 16
        payload_symbols = 0 if numerator <= 0 else math.ceil(numerator / (4 * sf)) * 5
        return int((8 + 4.25 + 8 + payload_symbols) * (2**sf / bw_hz) * 1_000_000)

    def airtime_us(payload_len: int) -> int:
        return airtime_us_with_params(payload_len)

    def cw_for_exponent(exponent: int) -> int:
        return 0 if exponent == 0 else (1 << exponent) - 1

    class _Result:
        def __init__(self, value: str) -> None:
            self.value = value

    class CsmaState:
        def __init__(self, backoff_exp: int = 0) -> None:
            self.backoff_exp, self.retries = backoff_exp, 0

        def next_backoff_slots(self, value: float) -> int:
            return (
                int(value * (cw_for_exponent(self.backoff_exp) + 1))
                if self.backoff_exp
                else 0
            )

        def on_cad_busy(self) -> _Result:
            self.retries += 1
            if self.retries > CSMA_RETRY_LIMIT:
                return _Result("retry_exhausted")
            self.backoff_exp = min(self.backoff_exp + 1, CSMA_BACKOFF_MAX)
            return _Result("cad_busy")

    def dao_retry_delay(attempt: int) -> int | None:
        if type(attempt) is not int:
            raise TypeError("attempt must be an exact integer")
        if attempt < 0:
            raise ValueError("attempt must be non-negative")
        return (
            DAO_RETRY_DELAYS_MS[attempt] if attempt < len(DAO_RETRY_DELAYS_MS) else None
        )

    def is_valid_dao_sequence(sequence: int, prev_max: int | None = None) -> bool:
        if type(sequence) is not int or not 0 < sequence <= 0xFFFFFFFFFFFFFFFF:
            return False
        if prev_max is not None and (
            type(prev_max) is not int or not 0 <= prev_max <= 0xFFFFFFFFFFFFFFFF
        ):
            return False
        return prev_max is None or sequence > prev_max

    def hash_32(data: bytes) -> int:
        value = 0x811C9DC5
        for octet in data:
            value = ((value ^ octet) * 0x01000193) & 0xFFFFFFFF
        return value

    def slot_for(eui64: bytes, sfn: int, count: int) -> int:
        return ((hash_32(eui64) + (sfn & 0xFFFFFFFF)) & 0xFFFFFFFF) % count

    def sfn_delta(current: int, previous: int) -> int:
        return (current - previous) & 0xFFFFFFFF

    def initial_startup_delay(nodes: int) -> int:
        return min(300, nodes * 5)

    class DesyncState(Enum):
        SYNCED = auto()
        DESYNCED = auto()
        RECOVERING = auto()

    class DesyncFSM:
        def __init__(self) -> None:
            self.state, self.consecutive_valid, self.missed_superframes = (
                DesyncState.SYNCED,
                0,
                0,
            )

        def on_sfn_wrap(self, time_valid: bool) -> DesyncState:
            if self.state is DesyncState.SYNCED and not time_valid:
                self.state = DesyncState.DESYNCED
            return self.state

        def on_beacon(self, valid: bool) -> DesyncState:
            if self.state is DesyncState.DESYNCED and valid:
                self.state, self.consecutive_valid, self.missed_superframes = (
                    DesyncState.RECOVERING,
                    1,
                    0,
                )
            elif self.state is DesyncState.RECOVERING and valid:
                self.consecutive_valid += 1
                self.missed_superframes = 0
                if self.consecutive_valid >= 3:
                    self.state, self.consecutive_valid = DesyncState.SYNCED, 0
            return self.state

        def on_missed_superframe(self) -> DesyncState:
            if self.state is DesyncState.RECOVERING:
                self.missed_superframes += 1
                if self.missed_superframes >= 3:
                    self.state, self.consecutive_valid, self.missed_superframes = (
                        DesyncState.DESYNCED,
                        0,
                        0,
                    )
            return self.state

    class TrickleTimer:
        def __init__(self, *, imin_ms: int, imax_doublings: int, k: int, rng) -> None:  # type: ignore[no-untyped-def]
            self.imin_ms, self.imax_doublings, self.k, self.rng = (
                imin_ms,
                imax_doublings,
                k,
                rng,
            )
            (
                self.interval,
                self.interval_start,
                self.transmit_time,
                self.interval_end,
                self.counter,
            ) = imin_ms, 0, 0, 0, 0

        def start(self, now: int) -> None:
            self.interval_start = now
            self.transmit_time = (
                now + self.interval // 2 + int(self.rng() * (self.interval // 2))
            )
            self.interval_end = now + self.interval

        def heard_consistent(self) -> None:
            self.counter += 1

        def should_transmit(self) -> bool:
            return self.counter < self.k

        def expire(self, now: int) -> None:
            self.interval = min(self.interval * 2, self.imin_ms << self.imax_doublings)
            self.interval_start = now

    class Stratum:
        NO_SYNC, NTS, GNSS_GPSD = 0, 3, 4

    class DioTimeOption:
        def __init__(self, stratum: int, timestamp: int) -> None:
            self.stratum, self.timestamp = stratum, timestamp

        def encode(self) -> bytes:
            return bytes((0x15, 6, self.stratum, 0)) + self.timestamp.to_bytes(4, "big")

    vectors: list[dict[str, object]] = []
    remote_identity = ReferenceIdentity.from_seed(bytes(range(32, 64)))
    wrong_identity = ReferenceIdentity.from_seed(bytes(reversed(range(32))))

    def dio_payload(
        time_options: int,
        *,
        instance: int = 0,
        dodag: str = "fe80::1",
        mop: int = 1,
        bad_checksum: bool = False,
        schc_dispatch: bool = True,
        next_header: int = 58,
        icmp_type: int = 155,
        icmp_code: int = 1,
    ) -> tuple[bytes, bytes]:
        options = b"\x00\xee\x01\xaa\x13\x01\x03"
        options += DioTimeOption(Stratum.GNSS_GPSD, 1700000000).encode() * time_options
        dio = (
            bytes((instance, 1, 2, 0, mop << 3, 0, 0, 0))
            + IPv6Address(dodag).packed
            + options
        )
        src = IPv6Address(IPv6Address("fe80::").packed[:8] + remote_identity.iid)
        dst = IPv6Address("ff02::1a")
        icmp_zeros = bytes((icmp_type, icmp_code, 0, 0)) + dio
        checksum_data = (
            src.packed
            + dst.packed
            + len(icmp_zeros).to_bytes(4, "big")
            + b"\x00\x00\x00\x3a"
            + icmp_zeros
        )
        if len(checksum_data) & 1:
            checksum_data += b"\x00"
        words = struct.unpack(f">{len(checksum_data) // 2}H", checksum_data)
        total = sum(words)
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        icmp = (
            bytes((icmp_type, icmp_code)) + ((~total) & 0xFFFF).to_bytes(2, "big") + dio
        )
        ipv6 = bytearray(
            b"\x60\x00\x00\x00"
            + len(icmp).to_bytes(2, "big")
            + bytes((next_header, 255))
            + src.packed
            + dst.packed
            + icmp
        )
        if bad_checksum:
            ipv6[42] ^= 1
        payload = b"\x14\xff" + bytes(ipv6)
        if not schc_dispatch:
            payload = b"\x15" + payload[1:]
        return payload, bytes(ipv6)

    def signed_wire(identity: ReferenceIdentity, payload: bytes, counter: int) -> str:
        epoch, seqnum = counter >> 16, counter & 0xFFFF
        length = 4 + 8 + len(payload) + 48
        wire_prefix = (
            bytes((length, 0xA0, epoch))
            + seqnum.to_bytes(2, "big")
            + identity.eui64
            + payload
        )
        signable = signature_transcript(wire_prefix, 0)
        signature = sign(identity, signable)
        return (wire_prefix + signature).hex()

    canonical_payload, canonical_ipv6 = dio_payload(1)
    missing_payload, missing_ipv6 = dio_payload(0)
    duplicate_payload, duplicate_ipv6 = dio_payload(2)
    bad_checksum_payload, _ = dio_payload(1, bad_checksum=True)
    wrong_dispatch_payload, _ = dio_payload(1, schc_dispatch=False)
    wrong_instance_payload, _ = dio_payload(1, instance=1)
    wrong_dodag_payload, _ = dio_payload(1, dodag="fe80::99")
    wrong_mop_payload, _ = dio_payload(1, mop=2)
    wrong_next_header_payload, _ = dio_payload(1, next_header=59)
    wrong_icmp_type_payload, _ = dio_payload(1, icmp_type=154)
    wrong_icmp_code_payload, _ = dio_payload(1, icmp_code=0)
    bare_dio_payload = canonical_ipv6[44:]
    malformed_schc_payload = b"\x14\xff\x60"
    time_wire = DioTimeOption(Stratum.GNSS_GPSD, 1700000000).encode()
    time_offset = canonical_ipv6.index(time_wire)
    signer_hex = remote_identity.pubkey.hex()
    network_cases = [
        {
            "name": "signed-canonical-authorized",
            "wire_hex": signed_wire(remote_identity, canonical_payload, 1),
            "signer_pubkey_hex": signer_hex,
            "counter": 1,
            "ipv6_hex": canonical_ipv6.hex(),
            "expected_authoritative": True,
            "rejection_stage": None,
            "rejection": None,
        },
        {
            "name": "signed-missing-time-option",
            "wire_hex": signed_wire(remote_identity, missing_payload, 2),
            "signer_pubkey_hex": signer_hex,
            "counter": 2,
            "ipv6_hex": missing_ipv6.hex(),
            "expected_authoritative": False,
            "rejection_stage": "time_verifier",
            "rejection": "dio-time-option-count",
        },
        {
            "name": "signed-duplicate-time-option",
            "wire_hex": signed_wire(remote_identity, duplicate_payload, 3),
            "signer_pubkey_hex": signer_hex,
            "counter": 3,
            "ipv6_hex": duplicate_ipv6.hex(),
            "expected_authoritative": False,
            "rejection_stage": "time_verifier",
            "rejection": "dio-time-option-count",
        },
        {
            "name": "signed-wrong-dispatch",
            "wire_hex": signed_wire(remote_identity, wrong_dispatch_payload, 4),
            "signer_pubkey_hex": signer_hex,
            "counter": 4,
            "expected_authoritative": False,
            "rejection_stage": "dio_admission",
            "rejection": "authenticated DIO must use the SCHC L2 dispatch",
        },
        {
            "name": "signed-bad-icmpv6-checksum",
            "wire_hex": signed_wire(remote_identity, bad_checksum_payload, 5),
            "signer_pubkey_hex": signer_hex,
            "counter": 5,
            "expected_authoritative": False,
            "rejection_stage": "dio_admission",
            "rejection": "authenticated SCHC payload is not a valid RPL DIO",
        },
        {
            "name": "signed-bare-dio",
            "wire_hex": signed_wire(remote_identity, bare_dio_payload, 10),
            "signer_pubkey_hex": signer_hex,
            "counter": 10,
            "expected_authoritative": False,
            "rejection_stage": "dio_admission",
            "rejection": "authenticated DIO must use the SCHC L2 dispatch",
        },
        {
            "name": "signed-malformed-schc",
            "wire_hex": signed_wire(remote_identity, malformed_schc_payload, 11),
            "signer_pubkey_hex": signer_hex,
            "counter": 11,
            "expected_authoritative": False,
            "rejection_stage": "dio_admission",
            "rejection": "IPv6 packet length must be 40..65575, got 1",
        },
        {
            "name": "signed-wrong-ipv6-next-header",
            "wire_hex": signed_wire(remote_identity, wrong_next_header_payload, 12),
            "signer_pubkey_hex": signer_hex,
            "counter": 12,
            "expected_authoritative": False,
            "rejection_stage": "dio_admission",
            "rejection": "authenticated DIO must be carried in ICMPv6",
        },
        {
            "name": "signed-wrong-icmpv6-type",
            "wire_hex": signed_wire(remote_identity, wrong_icmp_type_payload, 13),
            "signer_pubkey_hex": signer_hex,
            "counter": 13,
            "expected_authoritative": False,
            "rejection_stage": "dio_admission",
            "rejection": "authenticated SCHC payload is not a valid RPL DIO",
        },
        {
            "name": "signed-wrong-icmpv6-code",
            "wire_hex": signed_wire(remote_identity, wrong_icmp_code_payload, 14),
            "signer_pubkey_hex": signer_hex,
            "counter": 14,
            "expected_authoritative": False,
            "rejection_stage": "dio_admission",
            "rejection": "authenticated SCHC payload is not a valid RPL DIO",
        },
        {
            "name": "signed-wrong-role",
            "wire_hex": signed_wire(remote_identity, canonical_payload, 15),
            "signer_pubkey_hex": signer_hex,
            "counter": 15,
            "expected_role": "root",
            "expected_authoritative": False,
            "rejection_stage": "dio_admission",
            "rejection": "authenticated DIO role mismatch",
        },
        {
            "name": "signed-wrong-instance",
            "wire_hex": signed_wire(remote_identity, wrong_instance_payload, 6),
            "signer_pubkey_hex": signer_hex,
            "counter": 6,
            "expected_rpl_instance_id": 0,
            "expected_authoritative": False,
            "rejection_stage": "dio_admission",
            "rejection": "authenticated DIO RPLInstanceID mismatch",
        },
        {
            "name": "signed-wrong-dodag",
            "wire_hex": signed_wire(remote_identity, wrong_dodag_payload, 7),
            "signer_pubkey_hex": signer_hex,
            "counter": 7,
            "expected_dodag_id": "fe80::1",
            "expected_authoritative": False,
            "rejection_stage": "dio_admission",
            "rejection": "authenticated DIO DODAGID mismatch",
        },
        {
            "name": "signed-wrong-mop",
            "wire_hex": signed_wire(remote_identity, wrong_mop_payload, 8),
            "signer_pubkey_hex": signer_hex,
            "counter": 8,
            "expected_mop": 1,
            "expected_authoritative": False,
            "rejection_stage": "dio_admission",
            "rejection": "authenticated DIO MOP mismatch",
        },
        {
            "name": "signed-wrong-signer",
            "wire_hex": signed_wire(wrong_identity, canonical_payload, 9),
            "signer_pubkey_hex": wrong_identity.pubkey.hex(),
            "counter": 9,
            "expected_authoritative": False,
            "rejection_stage": "dio_admission",
            "rejection": "source_signer_mismatch",
        },
        {
            "name": "signed-replay",
            "wire_hex": signed_wire(remote_identity, canonical_payload, 1),
            "signer_pubkey_hex": signer_hex,
            "counter": 1,
            "expected_authoritative": False,
            "rejection_stage": "link_receive",
            "receive_count": 2,
            "rejection": "REPLAY",
        },
    ]

    # 14.1 Trickle constants
    vectors.append(
        {
            "name": "trickle_constants",
            "description": "14.1 Trickle Imin=4s, Imax=17min (exact 1_024_000ms = 4000*2^8), k=10.",
            "category": "trickle_constants",
            "Imin_ms": TRICKLE_IMIN_MS,
            "Imax_exact_ms": TRICKLE_IMAX_EXACT_MS,
            "k": TRICKLE_K,
        }
    )

    # Trickle state machine deterministic walk (rng=0.0 -> transmit at half)
    t = TrickleTimer(
        imin_ms=TRICKLE_IMIN_MS, imax_doublings=8, k=TRICKLE_K, rng=lambda: 0.0
    )
    t.start(now=0)
    vectors.append(
        {
            "name": "trickle_interval_start",
            "description": (
                "Trickle first interval: start 0, transmit at half (Imin/2) with "
                "rng=0.0, interval_end=4000."
            ),
            "category": "trickle_state",
            "interval": t.interval,
            "interval_start": t.interval_start,
            "transmit_time": t.transmit_time,
            "interval_end": t.interval_end,
        }
    )
    # heard_consistent suppression
    t.heard_consistent()
    vectors.append(
        {
            "name": "trickle_heard_consistent",
            "description": "After 1 heard consistent, counter=1, should_transmit true (k=10).",
            "category": "trickle_state",
            "counter": t.counter,
            "should_transmit": t.should_transmit(),
        }
    )
    # saturate counter to k
    for _ in range(20):
        t.heard_consistent()
    vectors.append(
        {
            "name": "trickle_suppressed_at_k",
            "description": "After >=k heard consistent, should_transmit false (suppressed).",
            "category": "trickle_state",
            "counter": t.counter,
            "should_transmit": t.should_transmit(),
        }
    )
    t2 = TrickleTimer(
        imin_ms=TRICKLE_IMIN_MS, imax_doublings=8, k=TRICKLE_K, rng=lambda: 0.5
    )
    t2.start(now=0)
    t2.expire(now=t2.interval_end)
    vectors.append(
        {
            "name": "trickle_expire_double",
            "description": "After expire, interval doubles to 8000 (capped at 1_024_000).",
            "category": "trickle_state",
            "interval_after_expire": t2.interval,
        }
    )

    # 14.2 DAO timing
    vectors.append(
        {
            "name": "dao_retry_delays",
            "description": "14.2 DAO retry exponential backoff 4,8,16s.",
            "category": "dao_timing",
            "retry_delays_ms": list(DAO_RETRY_DELAYS_MS),
            "retry_0": dao_retry_delay(0),
            "retry_1": dao_retry_delay(1),
            "retry_2": dao_retry_delay(2),
            "retry_3_none": dao_retry_delay(3),
            "refresh_s": DAO_REFRESH_S,
            "lifetime_s": DAO_SOFT_STATE_LIFETIME_S,
            "refresh_is_half_lifetime": DAO_REFRESH_S == DAO_SOFT_STATE_LIFETIME_S // 2,
        }
    )
    vectors.append(
        {
            "name": "dao_sequence_validation",
            "description": (
                "DAO Origin Sequence: starts above zero, monotonically increasing, "
                "must not wrap at 0xffffffffffffffff."
            ),
            "category": "dao_sequence",
            "seq_0_invalid": is_valid_dao_sequence(0),
            "seq_1_valid": is_valid_dao_sequence(1),
            "seq_advance_valid": is_valid_dao_sequence(2, prev_max=1),
            "seq_no_advance_invalid": is_valid_dao_sequence(1, prev_max=1),
            "seq_max_valid_terminal": is_valid_dao_sequence(0xFFFFFFFFFFFFFFFF),
        }
    )

    # 14.3 Data traffic
    vectors.append(
        {
            "name": "data_traffic_intervals",
            "description": "14.3 Periodic telemetry 5-60min, heartbeat 30min.",
            "category": "data_traffic",
            "telemetry_min_s": TELEMETRY_INTERVAL_MIN_S,
            "telemetry_max_s": TELEMETRY_INTERVAL_MAX_S,
            "heartbeat_s": HEARTBEAT_INTERVAL_S,
        }
    )

    # 14.4 Duty cycle. This oracle uses the complete explicit PHY tuple rather
    # than the historical rounded 200 ms implementation constant.
    sf9_at = airtime_us_with_params(60, sf=9, bw_hz=125_000)
    sf9_airtime_ms = sf9_at / 1000.0
    max_whole_packets = int(
        3600 * (EU868_DUTY_CYCLE_PERCENT / 100) / (sf9_at / 1_000_000)
    )
    vectors.append(
        {
            "name": "duty_cycle_eu868_10pct",
            "description": (
                "14.4 EU 868 10% duty cycle: exact SF9/125kHz CR4/5 "
                "60-byte airtime is 369.664 ms, permitting 973 whole packets/hour."
            ),
            "category": "duty_cycle",
            "duty_cycle_percent": EU868_DUTY_CYCLE_PERCENT,
            "payload_len": 60,
            "sf": 9,
            "bw_hz": 125_000,
            "coding_rate": "4/5",
            "preamble_symbols": 8,
            "explicit_header": True,
            "phy_crc": True,
            "airtime_us": sf9_at,
            "airtime_60b_ms": sf9_airtime_ms,
            "max_packets_per_hour": max_whole_packets,
            "max_via_formula": max_whole_packets,
        }
    )
    # duty cycle usage examples
    vectors.append(
        {
            "name": "duty_cycle_usage_examples",
            "description": "Duty cycle usage percent for various airtime sums in 1-hour window.",
            "category": "duty_cycle_usage",
            "usage_3600s_window_36s_airtime_pct": (36 / 3600) * 100,  # 1% at 36s
            "usage_180s_airtime_pct": (180 / 3600) * 100,  # 5%
        }
    )

    # airtime calculations (using oracle)
    for plen in (17, 22, 60, 77, 82, 88, 127):
        at_us = airtime_us(plen)
        vectors.append(
            {
                "name": f"airtime_payload_{plen}",
                "description": f"Airtime for payload {plen}B at SF10/125kHz (sim default).",
                "category": "airtime",
                "payload_len": plen,
                "airtime_us": at_us,
                "airtime_ms": at_us / 1000.0,
            }
        )
    # SF9 example via the same explicit parameter tuple as the duty-cycle vector.
    vectors.append(
        {
            "name": "airtime_sf9_60b",
            "description": "Airtime for 60B at SF9/125kHz, CR4/5, explicit header and CRC.",
            "category": "airtime_sf9",
            "payload_len": 60,
            "sf": 9,
            "bw_hz": 125_000,
            "airtime_us": sf9_at,
            "airtime_ms": sf9_at / 1000.0,
        }
    )

    # 14.5 CSMA/CA
    vectors.append(
        {
            "name": "csma_parameters",
            "description": "14.5 CSMA CAD 3 symbols, backoff 10ms, max 5 (CW 31), retry 3.",
            "category": "csma_params",
            "cad_timeout_symbols": CSMA_CAD_TIMEOUT_SYMBOLS,
            "backoff_unit_ms": CSMA_BACKOFF_UNIT_MS,
            "backoff_max": CSMA_BACKOFF_MAX,
            "retry_limit": CSMA_RETRY_LIMIT,
            "cw_values": [cw_for_exponent(e) for e in range(6)],
        }
    )
    # CSMA backoff state
    vectors.append(
        {
            "name": "csma_backoff_slots",
            "description": (
                "CSMA slots: CW=0 for exp 0, CW=31 for exp 5, deterministic rng mapping."
            ),
            "category": "csma_backoff",
            "cw_exp0": cw_for_exponent(0),
            "cw_exp5": cw_for_exponent(5),
            "slots_exp0_rng0": CsmaState(backoff_exp=0).next_backoff_slots(0.5),
            "slots_exp5_rng0": CsmaState(backoff_exp=5).next_backoff_slots(0.0),
            "slots_exp5_rng_half": CsmaState(backoff_exp=5).next_backoff_slots(0.5),
            "slots_exp5_rng_max": CsmaState(backoff_exp=5).next_backoff_slots(0.999),
        }
    )
    cs2 = CsmaState()
    results = []
    for _ in range(4):
        results.append(cs2.on_cad_busy().value)
    vectors.append(
        {
            "name": "csma_retry_exhaustion",
            "description": "CSMA retry exhaustion after 3 retries => 4th returns retry_exhausted.",
            "category": "csma_retry",
            "results": results,
        }
    )

    # 14.6 Time sync
    vectors.append(
        {
            "name": "time_sync_epoch_floor",
            "description": (
                "Independent literal decisions for verifier-issued, identity-bound, "
                "versioned provision metadata."
            ),
            "category": "time_sync",
            "cases": [
                {
                    "action": "firmware_only",
                    "build_epoch": 1700000000,
                    "expected_floor": 1700000000,
                    "status": "missing",
                },
                {
                    "action": "authenticated_provision",
                    "build_epoch": 1700000000,
                    "provision_epoch": 1800000000,
                    "record_version": 1,
                    "max_provision_lead_s": 100000000,
                    "expected_floor": 1800000000,
                    "status": "accepted",
                },
                {
                    "action": "authenticated_provision",
                    "build_epoch": 1900000000,
                    "provision_epoch": 1800000000,
                    "record_version": 1,
                    "max_provision_lead_s": 100000000,
                    "expected_floor": 1900000000,
                    "status": "before-build",
                },
                {
                    "action": "authenticated_provision",
                    "build_epoch": 1700000000,
                    "provision_epoch": 1800000001,
                    "record_version": 1,
                    "max_provision_lead_s": 100000000,
                    "expected_floor": 1700000000,
                    "status": "beyond-lead",
                },
                {
                    "action": "raw_integer",
                    "build_epoch": 1700000000,
                    "provision_epoch": 1800000000,
                    "expected_floor": 1700000000,
                    "status": "unauthenticated",
                },
            ],
        }
    )
    vectors.append(
        {
            "name": "time_sync_stratum",
            "description": (
                "Time stratum 0..4 and possible source classes; stratum does not infer provenance."
            ),
            "category": "time_stratum",
            "strata": [
                {"value": 0, "name": "NO_SYNC", "source_classes": ["Monotonic"]},
                {
                    "value": 1,
                    "name": "CONSERVATIVE_SYNC",
                    "source_classes": [
                        "Network",
                        "Local-client",
                        "Manual/static",
                        "Internal RTC",
                    ],
                },
                {"value": 2, "name": "ROUGHTIME", "source_classes": ["Network"]},
                {"value": 3, "name": "NTS", "source_classes": ["Network"]},
                {
                    "value": 4,
                    "name": "GNSS_GPSD",
                    "source_classes": ["GNSS", "Local-client"],
                },
            ],
        }
    )
    # DIO Time Option encode/decode
    # These literals are the cross-implementation contract. The assertions
    # catch oracle drift without deriving expected vector fields from it.
    assert DIO_TIME_OPTION_TYPE == 0x15
    assert DioTimeOption(Stratum.NTS, 1700000000).encode().hex() == "150603006553f100"
    assert DioTimeOption(Stratum.NO_SYNC, 0).encode().hex() == "1506000000000000"
    vectors.append(
        {
            "name": "dio_time_option",
            "description": (
                "DIO Time Option project-local provisional Type 0x15 (not "
                "IANA-assigned and no early-allocation request submitted), 8 bytes: "
                "Type(1)+Len(1)+Stratum(1)+Reserved(1)+Timestamp(4)."
            ),
            "category": "dio_time_option",
            "option_type": 21,
            "encoded_hex": "150603006553f100",
            "decoded_stratum": 3,
            "decoded_timestamp": 1700000000,
            "no_sync_encoded_hex": "1506000000000000",
        }
    )
    vectors.append(
        {
            "name": "time_adoption",
            "description": (
                "Non-authoritative scalar prefilter literals: higher stratum passes the "
                "prefilter, while lower stratum and below-floor values do not."
            ),
            "category": "time_adoption",
            "authoritative": False,
            "cases": [
                {
                    "local": 1,
                    "received": 4,
                    "timestamp": 1700000000,
                    "floor": 1700000000,
                    "expected": True,
                },
                {
                    "local": 4,
                    "received": 1,
                    "timestamp": 1700000000,
                    "floor": 1700000000,
                    "expected": False,
                },
                {
                    "local": 1,
                    "received": 4,
                    "timestamp": 1699999999,
                    "floor": 1700000000,
                    "expected": False,
                },
            ],
        }
    )
    vectors.append(
        {
            "name": "time_sync_trust_policy",
            "description": (
                "Independent literal trust, authorization, accuracy, anti-ratchet, and "
                "provisioning decisions; expected outcomes are not computed by the oracle."
            ),
            "category": "time_sync_trust",
            "dio_envelope": {
                "description": (
                    "SCHC-compressed IPv6/ICMPv6 RPL DIO with a valid pseudoheader "
                    "checksum, Pad1, unknown option, SCHC version, and Time Option."
                ),
                "link_payload_hex": canonical_payload.hex(),
                "ipv6_hex": canonical_ipv6.hex(),
                "src_ipv6": str(
                    IPv6Address(IPv6Address("fe80::").packed[:8] + remote_identity.iid)
                ),
                "dst_ipv6": "ff02::1a",
                "rpl_instance_id": 0,
                "dodag_id": "fe80::1",
                "mop": 1,
                "role": "peer",
                "option_ipv6_span": [time_offset, time_offset + len(time_wire)],
                "option_hex": time_wire.hex(),
                "duplicate_link_payload_hex": duplicate_payload.hex(),
                "origin_source": "GNSS",
                "transport_source": "Network",
            },
            "network_cases": network_cases,
            "correction_cases": [
                {
                    "name": "bounded-step-cumulative-ratchet",
                    "policy": {
                        "max_sample_age_s": 300,
                        "max_forward_step_s": 3600,
                        "max_cumulative_forward_correction_s": 3600,
                        "max_correction_rate_ppm": 0,
                    },
                    "transitions": [
                        {
                            "action": "sample",
                            "clock": 0,
                            "timestamp": 1700000000,
                            "accepted": True,
                            "rejection": None,
                        },
                        {
                            "action": "sample",
                            "clock": 1,
                            "timestamp": 1700003601,
                            "accepted": True,
                            "rejection": None,
                        },
                        {
                            "action": "sample",
                            "clock": 2,
                            "timestamp": 1700007202,
                            "accepted": False,
                            "rejection": "cumulative-forward-correction-exceeds-policy",
                        },
                    ],
                },
                {
                    "name": "anchor-survives-source-expiry",
                    "policy": {
                        "max_sample_age_s": 0,
                        "max_forward_step_s": 2000,
                        "max_cumulative_forward_correction_s": 100,
                        "max_correction_rate_ppm": 0,
                    },
                    "transitions": [
                        {
                            "action": "sample",
                            "clock": 0,
                            "timestamp": 1700000000,
                            "accepted": True,
                            "rejection": None,
                        },
                        {
                            "action": "expire",
                            "clock": 1,
                            "accepted": False,
                            "rejection": "current-source-expired",
                        },
                        {
                            "action": "sample",
                            "clock": 1,
                            "timestamp": 1700001001,
                            "accepted": False,
                            "rejection": "cumulative-forward-correction-exceeds-policy",
                        },
                    ],
                },
                {
                    "name": "anchor-survives-explicit-clear",
                    "policy": {
                        "max_sample_age_s": 300,
                        "max_forward_step_s": 2000,
                        "max_cumulative_forward_correction_s": 100,
                        "max_correction_rate_ppm": 0,
                    },
                    "transitions": [
                        {
                            "action": "sample",
                            "clock": 0,
                            "timestamp": 1700000000,
                            "accepted": True,
                            "rejection": None,
                        },
                        {
                            "action": "clear",
                            "clock": 1,
                            "accepted": False,
                            "rejection": "vector-clear",
                        },
                        {
                            "action": "sample",
                            "clock": 1,
                            "timestamp": 1700001001,
                            "accepted": False,
                            "rejection": "cumulative-forward-correction-exceeds-policy",
                        },
                    ],
                },
            ],
            "provider_cases": [
                {
                    "name": "gnss-position-valid-time-invalid",
                    "source": "GNSS",
                    "stratum": 4,
                    "source_valid": True,
                    "gnss_position_valid": True,
                    "gnss_time_valid": False,
                    "expected_authoritative": False,
                    "rejection": "gnss-time-not-valid",
                    "rejection_stage": "tracker",
                },
                {
                    "name": "rtc-uninitialized",
                    "source": "Internal RTC",
                    "stratum": 1,
                    "source_valid": True,
                    "rtc_initialized": False,
                    "expected_authoritative": False,
                    "rejection": "rtc-validity-metadata-missing",
                    "rejection_stage": "tracker",
                },
                {
                    "name": "direct-nts-authenticated",
                    "source": "Network",
                    "stratum": 3,
                    "source_valid": True,
                    "network_protocol": "NTS",
                    "network_authenticated": True,
                    "expected_authoritative": True,
                    "rejection": None,
                    "rejection_stage": None,
                },
                {
                    "name": "projected-initial-lead-plus-one",
                    "source": "GNSS",
                    "stratum": 4,
                    "raw_lead_seconds": 91,
                    "observation_delay_seconds": 10,
                    "maximum_initial_lead_seconds": 100,
                    "expected_authoritative": False,
                    "rejection": "initial-time-too-far-above-epoch-floor",
                    "rejection_stage": "tracker",
                },
                {
                    "name": "idle-source-expiry",
                    "source": "GNSS",
                    "stratum": 4,
                    "sample_age_seconds": 11,
                    "maximum_sample_age_seconds": 10,
                    "authoritative_read": True,
                    "expected_authoritative": False,
                    "rejection": "current-source-expired",
                    "rejection_stage": "authoritative_read",
                },
                {
                    "name": "rtc-accumulated-age-boundary",
                    "source": "Internal RTC",
                    "stratum": 1,
                    "rtc_initialized": True,
                    "rtc_age_seconds": 299,
                    "sample_age_seconds": 1,
                    "maximum_sample_age_seconds": 300,
                    "authoritative_read": True,
                    "expected_authoritative": True,
                    "rejection": None,
                    "rejection_stage": None,
                },
                {
                    "name": "rtc-accumulated-age-expired",
                    "source": "Internal RTC",
                    "stratum": 1,
                    "rtc_initialized": True,
                    "rtc_age_seconds": 299,
                    "sample_age_seconds": 1.001,
                    "maximum_sample_age_seconds": 300,
                    "authoritative_read": True,
                    "expected_authoritative": False,
                    "rejection": "current-rtc-state-stale",
                    "rejection_stage": "authoritative_read",
                },
                {
                    "name": "local-client-verified-gpsd",
                    "source": "Local-client",
                    "stratum": 4,
                    "source_subtype": "gpsd",
                    "source_subtype_verified": True,
                    "quality": {
                        "gpsd_mode": 3,
                        "gpsd_time_valid": True,
                        "gpsd_time_accuracy_seconds": 1,
                    },
                    "expected_authoritative": True,
                    "rejection": None,
                    "rejection_stage": None,
                },
                {
                    "name": "local-client-unverified-gpsd",
                    "source": "Local-client",
                    "stratum": 4,
                    "source_subtype": "gpsd",
                    "source_subtype_verified": False,
                    "quality": {
                        "gpsd_mode": 3,
                        "gpsd_time_valid": True,
                        "gpsd_time_accuracy_seconds": 1,
                    },
                    "expected_authoritative": False,
                    "rejection": "stratum 4 local-client time requires verified gpsd",
                    "rejection_stage": "provider",
                },
                {
                    "name": "local-client-gpsd-missing-quality",
                    "source": "Local-client",
                    "stratum": 4,
                    "source_subtype": "gpsd",
                    "source_subtype_verified": True,
                    "quality": {},
                    "expected_authoritative": False,
                    "rejection": "gpsd-fix-mode-not-valid",
                    "rejection_stage": "provider",
                },
                {
                    "name": "local-client-gpsd-time-invalid",
                    "source": "Local-client",
                    "stratum": 4,
                    "source_subtype": "gpsd",
                    "source_subtype_verified": True,
                    "quality": {
                        "gpsd_mode": 3,
                        "gpsd_time_valid": False,
                        "gpsd_time_accuracy_seconds": 1,
                    },
                    "expected_authoritative": False,
                    "rejection": "gpsd-time-not-valid",
                    "rejection_stage": "provider",
                },
            ],
            "provision_cases": [
                {
                    "name": "virgin-marker-noop-not-acknowledged",
                    "build_epoch": 1700000000,
                    "expected_floor": 1700000000,
                    "status": "virgin marker persistence was not acknowledged",
                    "action": "virgin_noop_reject",
                },
                {
                    "name": "virgin-marker-consumed-once",
                    "build_epoch": 1700000000,
                    "expected_floor": 1700000000,
                    "status": "virgin provision state is not bound to the configured admin",
                    "action": "virgin_reuse_reject",
                },
                {
                    "name": "raw-integer-cannot-raise-floor",
                    "build_epoch": 1700000000,
                    "provision_epoch": 1800000000,
                    "expected_floor": 1700000000,
                    "status": "unauthenticated",
                    "action": "raw_integer",
                },
                {
                    "name": "record-version-rollback",
                    "build_epoch": 1700000000,
                    "provision_epoch": 1800000000,
                    "record_version": 1,
                    "minimum_record_version": 2,
                    "record_board": "expected",
                    "expected_floor": 1700000000,
                    "status": "rollback",
                    "action": "install_reject",
                },
                {
                    "name": "board-identity-mismatch",
                    "build_epoch": 1700000000,
                    "provision_epoch": 1800000000,
                    "record_version": 2,
                    "record_board": "other",
                    "expected_floor": 1700000000,
                    "status": "identity-mismatch",
                    "action": "install_reject",
                },
                {
                    "name": "new-version-persists-before-acceptance",
                    "build_epoch": 1700000000,
                    "provision_epoch": 1700000100,
                    "record_version": 2,
                    "minimum_record_version": 1,
                    "record_board": "expected",
                    "expected_floor": 1700000100,
                    "status": "accepted",
                    "action": "install_accept",
                },
                {
                    "name": "clear-reboot-same-record-reactivation",
                    "build_epoch": 1700000000,
                    "provision_epoch": 1700000100,
                    "record_version": 2,
                    "record_board": "expected",
                    "expected_floor": 1700000100,
                    "status": "accepted",
                    "action": "clear_reboot_reactivate",
                },
            ],
        }
    )

    # 14.7-14.8 SFN and slot
    eui = bytes.fromhex("0011223344556677")
    vectors.append(
        {
            "name": "sfn_delta_wrap",
            "description": "SFN delta unsigned 32-bit: (0 - 0xFFFFFFFF) mod 2^32 = 1.",
            "category": "sfn_delta",
            "delta_wrap": sfn_delta(0, 0xFFFFFFFF),
            "delta_normal": sfn_delta(100, 90),
            "delta_zero": sfn_delta(42, 42),
        }
    )
    vectors.append(
        {
            "name": "sfn_slot_assignment",
            "description": "Slot = (hash_32(eui64)+sfn) mod num_slots per spec 14.7.",
            "category": "sfn_slot",
            "eui64_hex": eui.hex(),
            "hash": hash_32(eui),
            "slot_sfn0_n8": slot_for(eui, 0, 8),
            "slot_sfn1_n8": slot_for(eui, 1, 8),
            "slot_sfn0_n16": slot_for(eui, 0, 16),
        }
    )
    # density-aware startup
    vectors.append(
        {
            "name": "density_startup_delay",
            "description": "Initial delay = min(300, nodes_heard*5); LISTEN 30-60s.",
            "category": "density_startup",
            "constants": DESYNC_CONSTANTS,
            "delay_0_nodes": initial_startup_delay(0),
            "delay_10_nodes": initial_startup_delay(10),
            "delay_100_nodes": initial_startup_delay(100),  # capped at 300
        }
    )
    # Desync FSM
    fsm = DesyncFSM()
    fsm.on_sfn_wrap(time_valid=False)
    vectors.append(
        {
            "name": "desync_fsm_wrap_invalid",
            "description": "SYNCED + SFN wrap invalid time => DESYNCED.",
            "category": "desync_fsm",
            "state_after_wrap": fsm.state.name,
        }
    )
    fsm2 = DesyncFSM()
    fsm2.state = DesyncState.DESYNCED
    fsm2.on_beacon(valid=True)
    vectors.append(
        {
            "name": "desync_fsm_recovering",
            "description": "DESYNCED + valid beacon => RECOVERING (needs 3 consecutive).",
            "category": "desync_fsm",
            "state_after_valid": fsm2.state.name,
            "consecutive": fsm2.consecutive_valid,
        }
    )
    fsm3 = DesyncFSM()
    fsm3.state = DesyncState.RECOVERING
    fsm3.consecutive_valid = 2
    fsm3.on_beacon(valid=True)
    vectors.append(
        {
            "name": "desync_fsm_recovered",
            "description": "RECOVERING + 3rd consecutive valid => SYNCED.",
            "category": "desync_fsm",
            "state_after_3rd": fsm3.state.name,
        }
    )
    timeout_cases: list[dict[str, object]] = []
    for valid_count in (1, 2):
        timeout_fsm = DesyncFSM()
        timeout_fsm.state = DesyncState.DESYNCED
        for _ in range(valid_count):
            timeout_fsm.on_beacon(valid=True)
        states = [timeout_fsm.on_missed_superframe().name for _ in range(3)]
        timeout_cases.append(
            {
                "valid_count": valid_count,
                "timeout_superframes": 3,
                "states": states,
                "final_consecutive": timeout_fsm.consecutive_valid,
            }
        )
    vectors.append(
        {
            "name": "desync_fsm_recovery_timeout",
            "description": "Incomplete recovery returns to DESYNCED after 3 missed superframes.",
            "category": "desync_fsm",
            "cases": timeout_cases,
        }
    )

    # Guard and slot size are spec-derived. A slot is dimensioned for the
    # maximum permitted PHY payload at the configured data rate, not a typical
    # packet or a mutable implementation default.
    guard_ms = 50
    max_phy_payload_bytes = 255
    max_payload_airtime_us = airtime_us_with_params(
        max_phy_payload_bytes,
        sf=10,
        bw_hz=125_000,
    )
    minimum_slot_ms = (max_payload_airtime_us + 999) // 1000 + guard_ms
    vectors.append(
        {
            "name": "tdma_slot_constants",
            "description": (
                "14.8 slot minimum is ceil(maximum permitted PHY-payload airtime) "
                "+ the single normative 50 ms guard."
            ),
            "category": "tdma_constants",
            "guard_ms": guard_ms,
            "max_phy_payload_bytes": max_phy_payload_bytes,
            "sf": 10,
            "bw_hz": 125_000,
            "coding_rate": "4/5",
            "preamble_symbols": 8,
            "explicit_header": True,
            "phy_crc": True,
            "max_payload_airtime_us": max_payload_airtime_us,
            "slot_ms": minimum_slot_ms,
        }
    )

    return vectors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare canonical output byte-for-byte without writing",
    )
    arguments = parser.parse_args(argv)
    pf = packets_formats_document()
    timing_vectors = packets_timing_vectors()
    pt = {
        "format_version": FORMAT_VERSION,
        "description": (
            "Packets and Timing timing vectors (spec 09 §14 Trickle, DAO, duty "
            "cycle, airtime, CSMA, time sync, SFN, TDMA). Numeric regression "
            "fixtures use literal spec calculations and local state-machine oracles; "
            "signed trust fixtures use the independent PyNaCl Schnorr reference."
        ),
        "vectors": timing_vectors,
    }
    outputs = [
        (VECTORS_DIR / "packets-formats.json", pf),
        (VECTORS_DIR / "packets-timing.json", pt),
    ]
    if arguments.check:
        mismatches: list[str] = []
        for path, document in outputs:
            try:
                current = read_bounded_exact(path)
            except (FileNotFoundError, RuntimeError):
                mismatches.append(path.name)
            else:
                if current != json_bytes(document):
                    mismatches.append(path.name)
        if mismatches:
            print("out-of-date vector files: " + ", ".join(mismatches), file=sys.stderr)
            return 1
    else:
        atomic_write_json_batch(outputs)
    format_vectors = pf["vectors"]
    assert isinstance(format_vectors, list)
    action = "Checked" if arguments.check else "Wrote"
    print(f"{action} {len(format_vectors)} vectors in packets-formats.json")
    print(f"{action} {len(timing_vectors)} vectors in packets-timing.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
