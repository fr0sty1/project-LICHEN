# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for LOADng control message codecs (spec section 10, B2).

Byte oracles are hand-built from the spec 10.3/10.4 wire layouts:
RREQ/RREP = flags(1) hop(1) seq(2) originator(16) destination(16) [signature].
RERR = flags(1) error_code(1) unreachable(16) [signature].
"""

from __future__ import annotations

from collections.abc import Callable
from ipaddress import IPv6Address

import pytest

from lichen.ipv6.icmpv6 import Icmpv6Message
from lichen.loadng.messages import (
    RERR,
    RREP,
    RREQ,
    SIGNATURE_LENGTH,
    LoadngCode,
    LoadngError,
    LoadngMessage,
    from_icmpv6,
    to_icmpv6,
)

ORIG = IPv6Address("fd00::1")
DEST = IPv6Address("fd00::2")
BROKEN = IPv6Address("fd00::9")

# Spec 10.3/10.4/10.6 ICMPv6 body (Type is the ICMPv6 code, not in the body):
# RREQ/RREP = flags(1) hop(1) seq(2) originator(16) destination(16) [sig]
# RERR      = flags(1) error_code(1) unreachable(16) [sig]
# Address literals are RFC 4291 packed form, independent of the codec.
ORIG_WIRE = bytes.fromhex("fd000000000000000000000000000001")
DEST_WIRE = bytes.fromhex("fd000000000000000000000000000002")
BROKEN_WIRE = bytes.fromhex("fd000000000000000000000000000009")
# Spec 10.3 / draft-lichen-schnorr-00: SIG is 48 bytes. Literal hex so a
# SIGNATURE_LENGTH change cannot silently resize this fixture.
SIG_WIRE = bytes.fromhex(
    "26f70691bbde0c1e8becc00e7e7663cb6b72364b6ea208fdabef226c5b0d07ce"
    "c9c661fd69671981ca40277598ea9c01"
)
RREQ_RREP_PREFIX = 36
RERR_PREFIX = 18


def _rreq_rrep_body(
    flags: int, hop: int, seq: int, originator: bytes, destination: bytes, signature: bytes = b""
) -> bytes:
    """Build RREQ/RREP body from spec 10.3/10.4 field order (not via to_bytes)."""
    return bytes([flags, hop]) + seq.to_bytes(2, "big") + originator + destination + signature


def _rerr_body(flags: int, error_code: int, unreachable: bytes, signature: bytes = b"") -> bytes:
    """Build RERR body from spec 10.6 field order (not via to_bytes)."""
    return bytes([flags, error_code]) + unreachable + signature


def test_signature_length_is_schnorr48() -> None:
    assert SIGNATURE_LENGTH == 48
    assert len(SIG_WIRE) == 48


def test_rreq_known_vector() -> None:
    rreq = RREQ(originator=ORIG, destination=DEST, seq_num=1, hop_limit=4)
    expected = bytes([0x00, 0x04, 0x00, 0x01]) + ORIG.packed + DEST.packed
    assert rreq.to_bytes() == expected
    assert len(rreq.to_bytes()) == 36
    parsed = RREQ.from_bytes(expected)
    assert parsed.originator == ORIG
    assert parsed.destination == DEST
    assert parsed.seq_num == 1
    assert parsed.hop_limit == 4
    assert parsed.flags == 0
    assert parsed.signature == b""


def test_rreq_round_trip() -> None:
    rreq = RREQ(originator=ORIG, destination=DEST, seq_num=300, hop_limit=8, flags=0x02)
    assert RREQ.from_bytes(rreq.to_bytes()) == rreq


def test_rrep_known_vector() -> None:
    rrep = RREP(originator=ORIG, destination=DEST, seq_num=1, hop_count=3)
    expected = bytes([0x00, 0x03, 0x00, 0x01]) + ORIG.packed + DEST.packed
    assert rrep.to_bytes() == expected
    parsed = RREP.from_bytes(expected)
    assert parsed.originator == ORIG
    assert parsed.destination == DEST
    assert parsed.seq_num == 1
    assert parsed.hop_count == 3
    assert parsed.flags == 0
    assert parsed.signature == b""


def test_rrep_round_trip() -> None:
    rrep = RREP(originator=ORIG, destination=DEST, seq_num=7, hop_count=5, flags=1)
    assert RREP.from_bytes(rrep.to_bytes()) == rrep


def test_rerr_known_vector() -> None:
    rerr = RERR(unreachable=BROKEN, error_code=1)
    expected = bytes([0x00, 0x01]) + BROKEN.packed
    assert rerr.to_bytes() == expected
    assert len(rerr.to_bytes()) == 18
    parsed = RERR.from_bytes(expected)
    assert parsed.unreachable == BROKEN
    assert parsed.error_code == 1
    assert parsed.flags == 0
    assert parsed.signature == b""


def test_rerr_round_trip() -> None:
    rerr = RERR(unreachable=BROKEN, error_code=2, flags=0x80)
    assert RERR.from_bytes(rerr.to_bytes()) == rerr


def test_signature_carried_opaquely() -> None:
    rreq = RREQ(originator=ORIG, destination=DEST, seq_num=1, signature=SIG_WIRE)
    raw = rreq.to_bytes()
    assert len(raw) == 36 + 48
    parsed = RREQ.from_bytes(raw)
    assert parsed.signature == SIG_WIRE
    assert parsed == rreq


@pytest.mark.parametrize("seq_num", [-1, 0x10000])
def test_seq_num_range_validated(seq_num: int) -> None:
    # seq_num is a 2-byte field. A check of only `> 0xFFFF` would OverflowError
    # on -1 from to_bytes(2, "big") instead of LoadngError.
    with pytest.raises(LoadngError, match="seq_num"):
        RREQ(originator=ORIG, destination=DEST, seq_num=seq_num).to_bytes()
    with pytest.raises(LoadngError, match="seq_num"):
        RREP(originator=ORIG, destination=DEST, seq_num=seq_num).to_bytes()


@pytest.mark.parametrize("seq_num", [0, 0xFFFF])
def test_seq_num_bounds_encode_and_parse(seq_num: int) -> None:
    rreq_wire = _rreq_rrep_body(0x00, 4, seq_num, ORIG_WIRE, DEST_WIRE)
    assert RREQ(originator=ORIG, destination=DEST, seq_num=seq_num).to_bytes() == rreq_wire
    parsed_rreq = RREQ.from_bytes(rreq_wire)
    assert parsed_rreq.seq_num == seq_num
    assert parsed_rreq.originator == ORIG
    assert parsed_rreq.destination == DEST
    rrep_wire = _rreq_rrep_body(0x00, 0, seq_num, ORIG_WIRE, DEST_WIRE)
    assert RREP(originator=ORIG, destination=DEST, seq_num=seq_num).to_bytes() == rrep_wire
    parsed_rrep = RREP.from_bytes(rrep_wire)
    assert parsed_rrep.seq_num == seq_num
    assert parsed_rrep.originator == ORIG
    assert parsed_rrep.destination == DEST


@pytest.mark.parametrize("error_code", [-1, 256])
def test_rerr_to_bytes_rejects_error_code_out_of_range(error_code: int) -> None:
    # error_code is one wire byte. Masking with & 0xFF would encode 256 as 0
    # (Unspecified) and -1 as 255 instead of failing closed.
    with pytest.raises(LoadngError, match="error_code"):
        RERR(unreachable=BROKEN, error_code=error_code).to_bytes()


@pytest.mark.parametrize("error_code", [0, 255])
def test_rerr_error_code_bounds_encode_and_parse(error_code: int) -> None:
    wire = _rerr_body(0x00, error_code, BROKEN_WIRE)
    assert len(wire) == RERR_PREFIX
    assert RERR(unreachable=BROKEN, error_code=error_code).to_bytes() == wire
    parsed = RERR.from_bytes(wire)
    assert parsed.error_code == error_code
    assert parsed.unreachable == BROKEN
    assert parsed.flags == 0
    assert parsed.signature == b""


@pytest.mark.parametrize("flags", [-1, 256])
def test_to_bytes_rejects_flags_out_of_range(flags: int) -> None:
    # Flags is one wire byte (spec 10.3/10.4/10.6). Masking with & 0xFF would
    # drop 0x100 to 0 and wrap -1 to 255.
    with pytest.raises(LoadngError, match="flags"):
        RREQ(originator=ORIG, destination=DEST, seq_num=1, flags=flags).to_bytes()
    with pytest.raises(LoadngError, match="flags"):
        RREP(originator=ORIG, destination=DEST, seq_num=1, flags=flags).to_bytes()
    with pytest.raises(LoadngError, match="flags"):
        RERR(unreachable=BROKEN, flags=flags).to_bytes()


@pytest.mark.parametrize("flags", [0, 255])
def test_flags_bounds_encode_and_parse(flags: int) -> None:
    rreq_wire = _rreq_rrep_body(flags, 4, 1, ORIG_WIRE, DEST_WIRE)
    assert RREQ(originator=ORIG, destination=DEST, seq_num=1, flags=flags).to_bytes() == rreq_wire
    assert RREQ.from_bytes(rreq_wire).flags == flags
    rrep_wire = _rreq_rrep_body(flags, 0, 1, ORIG_WIRE, DEST_WIRE)
    assert RREP(originator=ORIG, destination=DEST, seq_num=1, flags=flags).to_bytes() == rrep_wire
    assert RREP.from_bytes(rrep_wire).flags == flags
    rerr_wire = _rerr_body(flags, 1, BROKEN_WIRE)
    assert RERR(unreachable=BROKEN, error_code=1, flags=flags).to_bytes() == rerr_wire
    assert RERR.from_bytes(rerr_wire).flags == flags


def test_rreq_hop_limit_range_validated() -> None:
    # Negative hop_limit should raise
    with pytest.raises(LoadngError):
        RREQ(originator=ORIG, destination=DEST, seq_num=1, hop_limit=-1).to_bytes()
    # hop_limit above MAX_HOP_LIMIT (15) should raise
    with pytest.raises(LoadngError):
        RREQ(originator=ORIG, destination=DEST, seq_num=1, hop_limit=16).to_bytes()
    # Edge: 0 and 15 should be valid
    RREQ(originator=ORIG, destination=DEST, seq_num=1, hop_limit=0).to_bytes()
    RREQ(originator=ORIG, destination=DEST, seq_num=1, hop_limit=15).to_bytes()


def test_rrep_hop_count_range_validated() -> None:
    # Negative hop_count should raise
    with pytest.raises(LoadngError):
        RREP(originator=ORIG, destination=DEST, seq_num=1, hop_count=-1).to_bytes()
    # hop_count above MAX_HOP_LIMIT (15) should raise
    with pytest.raises(LoadngError):
        RREP(originator=ORIG, destination=DEST, seq_num=1, hop_count=16).to_bytes()
    # Edge: 0 and 15 should be valid
    RREP(originator=ORIG, destination=DEST, seq_num=1, hop_count=0).to_bytes()
    RREP(originator=ORIG, destination=DEST, seq_num=1, hop_count=15).to_bytes()


@pytest.mark.parametrize("hop", [16, 255])
def test_rreq_from_bytes_rejects_hop_limit_over_max(hop: int) -> None:
    # Independent of to_bytes: hop_limit is a raw wire byte and cannot be
    # produced by RREQ.to_bytes, which already rejects values >15.
    wire = bytes([0x00, hop, 0x00, 0x01]) + ORIG.packed + DEST.packed
    with pytest.raises(LoadngError, match="hop_limit"):
        RREQ.from_bytes(wire)


@pytest.mark.parametrize("hop", [16, 255])
def test_rrep_from_bytes_rejects_hop_count_over_max(hop: int) -> None:
    wire = bytes([0x00, hop, 0x00, 0x01]) + ORIG.packed + DEST.packed
    with pytest.raises(LoadngError, match="hop_count"):
        RREP.from_bytes(wire)


@pytest.mark.parametrize("hop", [16, 255])
def test_rreq_from_bytes_rejects_signed_hop_limit_over_max(hop: int) -> None:
    # Signed 84-byte path must still enforce MAX_HOP_LIMIT; a "signed is
    # trusted" branch would pass unsigned hop tests and fail only here.
    wire = _rreq_rrep_body(0x00, hop, 1, ORIG_WIRE, DEST_WIRE, SIG_WIRE)
    assert len(wire) == RREQ_RREP_PREFIX + 48
    with pytest.raises(LoadngError, match="hop_limit"):
        RREQ.from_bytes(wire)


@pytest.mark.parametrize("hop", [16, 255])
def test_rrep_from_bytes_rejects_signed_hop_count_over_max(hop: int) -> None:
    wire = _rreq_rrep_body(0x00, hop, 1, ORIG_WIRE, DEST_WIRE, SIG_WIRE)
    assert len(wire) == RREQ_RREP_PREFIX + 48
    with pytest.raises(LoadngError, match="hop_count"):
        RREP.from_bytes(wire)


def test_from_bytes_accepts_hop_field_bounds() -> None:
    # 0 is in range (RREQ: do not rebroadcast; RREP: destination itself).
    for hop in (0, 15):
        rreq_wire = _rreq_rrep_body(0x00, hop, 1, ORIG_WIRE, DEST_WIRE)
        parsed_rreq = RREQ.from_bytes(rreq_wire)
        assert parsed_rreq.hop_limit == hop
        assert parsed_rreq.originator == ORIG
        assert parsed_rreq.destination == DEST
        assert parsed_rreq.seq_num == 1
        assert parsed_rreq.flags == 0
        assert parsed_rreq.signature == b""
        rrep_wire = _rreq_rrep_body(0x00, hop, 1, ORIG_WIRE, DEST_WIRE)
        parsed_rrep = RREP.from_bytes(rrep_wire)
        assert parsed_rrep.hop_count == hop
        assert parsed_rrep.originator == ORIG
        assert parsed_rrep.destination == DEST
        assert parsed_rrep.seq_num == 1
        assert parsed_rrep.flags == 0
        assert parsed_rrep.signature == b""


def test_from_bytes_rejects_truncated() -> None:
    with pytest.raises(LoadngError):
        RREQ.from_bytes(bytes(10))
    with pytest.raises(LoadngError):
        RERR.from_bytes(bytes(5))


def test_icmpv6_wrap_and_dispatch() -> None:
    for message, code in [
        (RREQ(ORIG, DEST, 1), LoadngCode.RREQ),
        (RREP(ORIG, DEST, 1), LoadngCode.RREP),
        (RERR(BROKEN), LoadngCode.RERR),
    ]:
        icmp = to_icmpv6(message)
        assert icmp.type == 158
        assert icmp.code == code
        assert from_icmpv6(icmp) == message


def test_icmpv6_wrap_and_dispatch_signed() -> None:
    # A wrapper that slices body[:36]/[:18] would drop the Schnorr tail.
    cases: list[tuple[LoadngMessage, int, int]] = [
        (
            RREQ(ORIG, DEST, 300, hop_limit=8, flags=0x02, signature=SIG_WIRE),
            LoadngCode.RREQ,
            84,
        ),
        (
            RREP(ORIG, DEST, 7, hop_count=5, flags=0x04, signature=SIG_WIRE),
            LoadngCode.RREP,
            84,
        ),
        (
            RERR(BROKEN, error_code=1, flags=0x80, signature=SIG_WIRE),
            LoadngCode.RERR,
            66,
        ),
    ]
    for message, code, body_len in cases:
        icmp = to_icmpv6(message)
        assert icmp.type == 158
        assert icmp.code == code
        assert len(icmp.body) == body_len
        assert icmp.body[-48:] == SIG_WIRE
        parsed = from_icmpv6(icmp)
        assert parsed == message
        assert parsed.signature == SIG_WIRE


def test_from_icmpv6_rejects_non_loadng() -> None:
    # Bodies would parse if the type-158 check were deleted; empty bodies
    # would still raise from from_bytes("too short") and hide that bug.
    rreq_body = _rreq_rrep_body(0x02, 8, 0x012C, ORIG_WIRE, DEST_WIRE)
    rerr_body = _rerr_body(0x80, 1, BROKEN_WIRE)
    assert len(rreq_body) == RREQ_RREP_PREFIX
    assert len(rerr_body) == RERR_PREFIX
    with pytest.raises(LoadngError, match="not a LOADng message"):
        from_icmpv6(Icmpv6Message(type=155, code=LoadngCode.RREQ, body=rreq_body))
    with pytest.raises(LoadngError, match="not a LOADng message"):
        from_icmpv6(Icmpv6Message(type=155, code=LoadngCode.RERR, body=rerr_body))


@pytest.mark.parametrize("code", [3, 4, 255])
@pytest.mark.parametrize(
    "body",
    [
        _rreq_rrep_body(0x02, 8, 0x012C, ORIG_WIRE, DEST_WIRE),
        _rerr_body(0x80, 1, BROKEN_WIRE),
    ],
)
def test_from_icmpv6_rejects_unsupported_code(code: int, body: bytes) -> None:
    # Code 3 is RACK (no dataclass); 4 and 255 are outside LoadngCode.
    # Parseable bodies so mapping RACK/unknown onto RREQ/RERR still fails.
    with pytest.raises(LoadngError, match="unsupported LOADng code"):
        from_icmpv6(Icmpv6Message(type=158, code=code, body=body))


def test_rreq_from_bytes_parses_unsigned_hex_wire() -> None:
    # Independent of to_bytes: full 36-byte unsigned RREQ from spec 10.3 hex.
    # flags/hop are not dataclass defaults (0 / INITIAL_HOP_LIMIT=4).
    wire = bytes.fromhex(
        "02"  # flags
        "08"  # hop_limit
        "012c"  # seq_num 300
        "fd000000000000000000000000000001"  # originator fd00::1
        "fd000000000000000000000000000002"  # destination fd00::2
    )
    assert len(wire) == RREQ_RREP_PREFIX
    parsed = RREQ.from_bytes(wire)
    assert parsed.flags == 0x02
    assert parsed.hop_limit == 8
    assert parsed.seq_num == 0x012C
    assert parsed.originator == ORIG
    assert parsed.destination == DEST
    assert parsed.signature == b""


def test_rrep_from_bytes_parses_unsigned_hex_wire() -> None:
    # Independent of to_bytes: full 36-byte unsigned RREP from spec 10.4 hex.
    wire = bytes.fromhex(
        "01"  # flags
        "03"  # hop_count
        "0007"  # seq_num
        "fd000000000000000000000000000001"  # originator fd00::1
        "fd000000000000000000000000000002"  # destination fd00::2
    )
    assert len(wire) == RREQ_RREP_PREFIX
    parsed = RREP.from_bytes(wire)
    assert parsed.flags == 0x01
    assert parsed.hop_count == 3
    assert parsed.seq_num == 7
    assert parsed.originator == ORIG
    assert parsed.destination == DEST
    assert parsed.signature == b""


def test_rerr_from_bytes_parses_unsigned_hex_wire() -> None:
    wire = bytes.fromhex(
        "80"  # flags
        "02"  # error_code
        "fd000000000000000000000000000009"  # unreachable fd00::9
    )
    assert len(wire) == RERR_PREFIX
    parsed = RERR.from_bytes(wire)
    assert parsed.flags == 0x80
    assert parsed.error_code == 2
    assert parsed.unreachable == BROKEN
    assert parsed.signature == b""


def test_rreq_from_bytes_parses_signed_wire() -> None:
    wire = _rreq_rrep_body(0x02, 8, 300, ORIG_WIRE, DEST_WIRE, SIG_WIRE)
    assert len(wire) == RREQ_RREP_PREFIX + 48
    parsed = RREQ.from_bytes(wire)
    assert parsed.flags == 0x02
    assert parsed.hop_limit == 8
    assert parsed.seq_num == 300
    assert parsed.originator == ORIG
    assert parsed.destination == DEST
    assert parsed.signature == SIG_WIRE


def test_rrep_from_bytes_parses_signed_wire() -> None:
    wire = _rreq_rrep_body(0x01, 5, 7, ORIG_WIRE, DEST_WIRE, SIG_WIRE)
    assert len(wire) == RREQ_RREP_PREFIX + 48
    parsed = RREP.from_bytes(wire)
    assert parsed.flags == 0x01
    assert parsed.hop_count == 5
    assert parsed.seq_num == 7
    assert parsed.originator == ORIG
    assert parsed.destination == DEST
    assert parsed.signature == SIG_WIRE


def test_rerr_from_bytes_parses_signed_wire() -> None:
    wire = _rerr_body(0x80, 2, BROKEN_WIRE, SIG_WIRE)
    assert len(wire) == RERR_PREFIX + 48
    parsed = RERR.from_bytes(wire)
    assert parsed.flags == 0x80
    assert parsed.error_code == 2
    assert parsed.unreachable == BROKEN
    assert parsed.signature == SIG_WIRE


@pytest.mark.parametrize("tail_len", [1, 32, 47, 49, 96])
@pytest.mark.parametrize(
    "parse, prefix",
    [
        (RREQ.from_bytes, _rreq_rrep_body(0x00, 4, 1, ORIG_WIRE, DEST_WIRE)),
        (RREP.from_bytes, _rreq_rrep_body(0x00, 3, 1, ORIG_WIRE, DEST_WIRE)),
        (RERR.from_bytes, _rerr_body(0x00, 1, BROKEN_WIRE)),
    ],
)
def test_from_bytes_rejects_invalid_signature_tail(
    parse: Callable[[bytes], object], prefix: bytes, tail_len: int
) -> None:
    # 1/47/49 are neither unsigned (0) nor Schnorr-48. 32 is the old truncated
    # Ed25519 MIC; 96 is a concatenated second 48-byte SIG. Prefix is assembled
    # independently so deleting the leftover-length check would fail here.
    assert len(prefix) in (RREQ_RREP_PREFIX, RERR_PREFIX)
    with pytest.raises(LoadngError, match="signature"):
        parse(prefix + bytes(tail_len))


@pytest.mark.parametrize(
    "parse, n",
    [
        (RREQ.from_bytes, RREQ_RREP_PREFIX - 1),
        (RREP.from_bytes, RREQ_RREP_PREFIX - 1),
        (RERR.from_bytes, RERR_PREFIX - 1),
    ],
)
def test_from_bytes_rejects_truncated_prefix_minus_one(
    parse: Callable[[bytes], object], n: int
) -> None:
    # prefix-1 (35 / 17) is the tight bound; bytes(10)/bytes(5) would still
    # fail a copy-pasted shorter guard.
    with pytest.raises(LoadngError):
        parse(bytes(n))


def test_from_icmpv6_parses_hand_built_bodies() -> None:
    # flags/hop are not dataclass defaults; flags are not equal to the ICMPv6
    # code (RREQ=0, RREP=1, RERR=2) so a flags-from-code bug would fail.
    rreq_body = bytes.fromhex(
        "0208012cfd000000000000000000000000000001fd000000000000000000000000000002"
    )
    rreq = from_icmpv6(Icmpv6Message(type=158, code=LoadngCode.RREQ, body=rreq_body))
    assert isinstance(rreq, RREQ)
    assert rreq.originator == ORIG
    assert rreq.destination == DEST
    assert rreq.seq_num == 0x012C
    assert rreq.hop_limit == 8
    assert rreq.flags == 0x02
    assert rreq.signature == b""

    rrep_body = _rreq_rrep_body(0x04, 5, 7, ORIG_WIRE, DEST_WIRE)
    rrep = from_icmpv6(Icmpv6Message(type=158, code=LoadngCode.RREP, body=rrep_body))
    assert isinstance(rrep, RREP)
    assert rrep.originator == ORIG
    assert rrep.destination == DEST
    assert rrep.seq_num == 7
    assert rrep.hop_count == 5
    assert rrep.flags == 0x04
    assert rrep.signature == b""

    rerr_body = _rerr_body(0x80, 1, BROKEN_WIRE)
    rerr = from_icmpv6(Icmpv6Message(type=158, code=LoadngCode.RERR, body=rerr_body))
    assert isinstance(rerr, RERR)
    assert rerr.unreachable == BROKEN
    assert rerr.error_code == 1
    assert rerr.flags == 0x80
    assert rerr.signature == b""


def test_from_icmpv6_parses_signed_bodies() -> None:
    rreq_body = _rreq_rrep_body(0x02, 8, 0x012C, ORIG_WIRE, DEST_WIRE, SIG_WIRE)
    assert len(rreq_body) == 84
    rreq = from_icmpv6(Icmpv6Message(type=158, code=LoadngCode.RREQ, body=rreq_body))
    assert isinstance(rreq, RREQ)
    assert rreq.flags == 0x02
    assert rreq.hop_limit == 8
    assert rreq.seq_num == 0x012C
    assert rreq.originator == ORIG
    assert rreq.destination == DEST
    assert rreq.signature == SIG_WIRE

    rrep_body = _rreq_rrep_body(0x04, 5, 7, ORIG_WIRE, DEST_WIRE, SIG_WIRE)
    assert len(rrep_body) == 84
    rrep = from_icmpv6(Icmpv6Message(type=158, code=LoadngCode.RREP, body=rrep_body))
    assert isinstance(rrep, RREP)
    assert rrep.flags == 0x04
    assert rrep.hop_count == 5
    assert rrep.seq_num == 7
    assert rrep.originator == ORIG
    assert rrep.destination == DEST
    assert rrep.signature == SIG_WIRE

    rerr_body = _rerr_body(0x80, 1, BROKEN_WIRE, SIG_WIRE)
    assert len(rerr_body) == 66
    rerr = from_icmpv6(Icmpv6Message(type=158, code=LoadngCode.RERR, body=rerr_body))
    assert isinstance(rerr, RERR)
    assert rerr.flags == 0x80
    assert rerr.error_code == 1
    assert rerr.unreachable == BROKEN
    assert rerr.signature == SIG_WIRE


@pytest.mark.parametrize("tail_len", [1, 32, 47, 49, 96])
@pytest.mark.parametrize(
    "code, prefix",
    [
        (LoadngCode.RREQ, _rreq_rrep_body(0x02, 8, 0x012C, ORIG_WIRE, DEST_WIRE)),
        (LoadngCode.RREP, _rreq_rrep_body(0x04, 5, 7, ORIG_WIRE, DEST_WIRE)),
        (LoadngCode.RERR, _rerr_body(0x80, 1, BROKEN_WIRE)),
    ],
)
def test_from_icmpv6_rejects_invalid_signature_tail(
    code: LoadngCode, prefix: bytes, tail_len: int
) -> None:
    # Same leftover set as from_bytes: a wrapper that caps at prefix+48
    # (RREQ/RREP 84, RERR 66) would accept 49 and 96 as a valid SIG.
    # 1/47/49 are neither unsigned (0) nor Schnorr-48. 32 is the old truncated
    # Ed25519 MIC; 96 is a concatenated second 48-byte SIG.
    with pytest.raises(LoadngError, match="signature"):
        from_icmpv6(Icmpv6Message(type=158, code=code, body=prefix + bytes(tail_len)))
