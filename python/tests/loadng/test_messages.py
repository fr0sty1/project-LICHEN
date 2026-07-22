# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for LOADng control message codecs (spec section 10, B2).

Byte oracles are hand-built from the spec 10.3/10.4 wire layouts:
RREQ/RREP = flags(1) hop(1) seq(2) originator(16) destination(16) [signature].
RERR = flags(1) error_code(1) unreachable(16) [signature].
"""

from __future__ import annotations

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
    from_icmpv6,
    to_icmpv6,
)

ORIG = IPv6Address("fd00::1")
DEST = IPv6Address("fd00::2")
BROKEN = IPv6Address("fd00::9")


def test_rreq_known_vector() -> None:
    rreq = RREQ(originator=ORIG, destination=DEST, seq_num=1, hop_limit=4)
    expected = bytes([0x00, 0x04, 0x00, 0x01]) + ORIG.packed + DEST.packed
    assert rreq.to_bytes() == expected
    assert len(rreq.to_bytes()) == 36


def test_rreq_round_trip() -> None:
    rreq = RREQ(originator=ORIG, destination=DEST, seq_num=300, hop_limit=8, flags=0x02)
    assert RREQ.from_bytes(rreq.to_bytes()) == rreq


def test_rrep_known_vector() -> None:
    rrep = RREP(originator=ORIG, destination=DEST, seq_num=1, hop_count=3)
    expected = bytes([0x00, 0x03, 0x00, 0x01]) + ORIG.packed + DEST.packed
    assert rrep.to_bytes() == expected


def test_rrep_round_trip() -> None:
    rrep = RREP(originator=ORIG, destination=DEST, seq_num=7, hop_count=5, flags=1)
    assert RREP.from_bytes(rrep.to_bytes()) == rrep


def test_rerr_known_vector() -> None:
    rerr = RERR(unreachable=BROKEN, error_code=1)
    expected = bytes([0x00, 0x01]) + BROKEN.packed
    assert rerr.to_bytes() == expected
    assert len(rerr.to_bytes()) == 18


def test_rerr_round_trip() -> None:
    rerr = RERR(unreachable=BROKEN, error_code=2, flags=0x80)
    assert RERR.from_bytes(rerr.to_bytes()) == rerr


def test_signature_carried_opaquely() -> None:
    sig = bytes(range(SIGNATURE_LENGTH))  # 48 bytes
    rreq = RREQ(originator=ORIG, destination=DEST, seq_num=1, signature=sig)
    raw = rreq.to_bytes()
    assert len(raw) == 36 + SIGNATURE_LENGTH
    parsed = RREQ.from_bytes(raw)
    assert parsed.signature == sig
    assert parsed == rreq


def test_seq_num_range_validated() -> None:
    with pytest.raises(LoadngError):
        RREQ(originator=ORIG, destination=DEST, seq_num=0x10000).to_bytes()


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


def test_from_icmpv6_rejects_non_loadng() -> None:
    with pytest.raises(LoadngError):
        from_icmpv6(Icmpv6Message(type=155, code=0, body=b""))


def test_from_icmpv6_rejects_rack_code() -> None:
    # RACK (code 3) has no dataclass yet; dispatch should reject it cleanly.
    with pytest.raises(LoadngError):
        from_icmpv6(Icmpv6Message(type=158, code=3, body=b""))
