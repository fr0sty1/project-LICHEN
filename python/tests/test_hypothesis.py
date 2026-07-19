"""Property-based tests using Hypothesis.

These tests generate random inputs to find edge cases that unit tests miss.
Run with: pytest tests/test_hypothesis.py -v --hypothesis-show-statistics
"""

from ipaddress import IPv6Address

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

# Import modules to test
from lichen.announce.messages import AnnounceMessage
from lichen.coap.schc_channel import unwrap_coap, wrap_coap
from lichen.interface.kiss.framing import FEND, KissCommand, kiss_encode
from lichen.ipv6.addr import eui64_to_iid
from lichen.ipv6.packet import PacketError
from lichen.ipv6.udp import UdpError
from lichen.link.frame import FrameError, LichenFrame
from lichen.schc.codec import compress
from lichen.schc.rules import COAP_RULE

# ============================================================================
# Link Layer Tests
# ============================================================================


@given(
    llsec=st.integers(min_value=0, max_value=255),
    epoch=st.integers(min_value=0, max_value=255),
    seqnum=st.integers(min_value=0, max_value=65535),
    payload=st.binary(min_size=0, max_size=200),
)
def test_frame_rejects_incorrect_length(llsec, epoch, seqnum, payload):
    """A frame whose declared length differs from its body is invalid."""
    body = bytes([llsec, epoch]) + seqnum.to_bytes(2, "big") + payload
    declared_length = (len(body) + 1) % 255

    with pytest.raises(FrameError, match="length field says"):
        LichenFrame.from_bytes(bytes([declared_length]) + body)


@given(
    epoch=st.integers(min_value=0, max_value=255),
    seqnum=st.integers(min_value=0, max_value=65535),
    payload=st.binary(max_size=200),
)
def test_unsigned_frame_wire_format(epoch, seqnum, payload):
    """Unsigned frames match the specified byte layout."""
    frame = LichenFrame(
        epoch=epoch,
        seqnum=seqnum,
        dst_addr=b"",
        payload=payload,
        mic=b"",
    )

    expected = (
        bytes([4 + len(payload), 0, epoch])
        + seqnum.to_bytes(2, "big")
        + payload
    )
    assert frame.to_bytes() == expected


def test_replay_accepts_epoch_transition_at_seqnum_wrap():
    """A wrapped sequence number is newer when its epoch advances."""
    from lichen.link.replay import ReplayWindow

    window = ReplayWindow()

    assert window.check_and_update(0, 0xFFFF)
    assert window.check_and_update(1, 0)
    assert not window.check_and_update(1, 0)


# ============================================================================
# SCHC Tests
# ============================================================================


@given(
    msg_type=st.integers(min_value=0, max_value=3),
    token_length=st.integers(min_value=0, max_value=8),
    code=st.integers(min_value=0, max_value=255),
    message_id=st.integers(min_value=0, max_value=65535),
)
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_schc_coap_rule_wire_format(msg_type, token_length, code, message_id):
    """SCHC CoAP residue uses the specified MSB-first field layout."""
    fields = {
        "CoAP.Version": 1,
        "CoAP.Type": msg_type,
        "CoAP.TKL": token_length,
        "CoAP.Code": code,
        "CoAP.MID": message_id,
    }

    residue = (((msg_type << 4 | token_length) << 8 | code) << 16 | message_id) << 2
    assert compress(COAP_RULE, fields) == b"\x40" + residue.to_bytes(4, "big")


def test_schc_rule_id_is_encoded_as_one_byte():
    """SCHC rule IDs use the one-byte wire representation."""
    compressed = compress(
        COAP_RULE,
        {
            "CoAP.Version": 1,
            "CoAP.Type": 0,
            "CoAP.TKL": 0,
            "CoAP.Code": 0,
            "CoAP.MID": 0,
        },
    )

    assert compressed[0] == 0x40


# ============================================================================
# CoAP Tests
# ============================================================================


@given(payload=st.binary(max_size=1024))
def test_coap_datagram_wire_format(payload):
    """CoAP datagrams use the specified IPv6 and UDP field layout."""
    src = IPv6Address("fe80::1")
    dst = IPv6Address("fe80::2")
    encoded = wrap_coap(
        src,
        dst,
        payload,
    )

    assert encoded[:4] == b"\x60\x00\x00\x00"
    assert encoded[4:8] == (8 + len(payload)).to_bytes(2, "big") + b"\x11\x40"
    assert encoded[8:24] == src.packed
    assert encoded[24:40] == dst.packed
    assert encoded[40:44] == b"\x16\x33\x16\x33"
    assert encoded[44:46] == (8 + len(payload)).to_bytes(2, "big")
    pseudo_header = (
        src.packed
        + dst.packed
        + (8 + len(payload)).to_bytes(4, "big")
        + b"\x00\x00\x00\x11"
    )
    udp = encoded[40:46] + b"\x00\x00" + payload
    checksum_input = pseudo_header + udp
    if len(checksum_input) % 2:
        checksum_input += b"\x00"
    total = sum(
        int.from_bytes(checksum_input[offset : offset + 2], "big")
        for offset in range(0, len(checksum_input), 2)
    )
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    checksum = (~total) & 0xFFFF
    assert encoded[46:48] == (checksum or 0xFFFF).to_bytes(2, "big")
    assert encoded[48:] == payload


@given(data=st.binary(min_size=0, max_size=100))
def test_coap_parse_no_panic(data):
    """CoAP parser rejects arbitrary malformed input with documented errors."""
    try:
        payload = unwrap_coap(data)
    except (PacketError, UdpError, ValueError):
        return
    assert isinstance(payload, bytes)


# ============================================================================
# IPv6 Tests
# ============================================================================


@given(eui64=st.binary(min_size=8, max_size=8))
def test_iid_derivation_deterministic(eui64):
    """IID derivation flips only the EUI-64 universal/local bit."""
    expected = bytes([eui64[0] ^ 0x02]) + eui64[1:]
    assert eui64_to_iid(eui64) == expected


# ============================================================================
# KISS Framing Tests
# ============================================================================


@given(payload=st.binary(min_size=0, max_size=500))
def test_kiss_wire_format(payload):
    """KISS encoding matches the standard byte substitutions."""
    encoded = kiss_encode(0, KissCommand.DATA, payload)
    escaped = payload.replace(b"\xdb", b"\xdb\xdd").replace(b"\xc0", b"\xdb\xdc")
    assert encoded == b"\xc0\x00" + escaped + b"\xc0"


@given(payload=st.binary(min_size=0, max_size=100))
def test_kiss_escaping(payload):
    """KISS escaping should handle special bytes correctly."""
    encoded = kiss_encode(0, KissCommand.DATA, payload)

    # No raw KISS_END (0xC0) should appear in middle of frame
    middle = encoded[1:-1]
    # 0xC0 should only appear escaped as 0xDB 0xDC
    # This is a property that should hold
    assert FEND not in middle


# ============================================================================
# Announce Tests
# ============================================================================


@given(
    seq_num=st.integers(min_value=0, max_value=65535),
    hop_count=st.integers(min_value=0, max_value=15),
    originator_iid=st.binary(min_size=8, max_size=8),
)
def test_announce_fields(seq_num, hop_count, originator_iid):
    """Announce message fields should be preserved."""
    # Build an announce
    msg = AnnounceMessage(
        seq_num=seq_num,
        hop_count=hop_count,
        originator_iid=originator_iid,
        pubkey=b"\x00" * 32,
        app_data=b"",
    )

    assert msg.seq_num == seq_num
    assert msg.hop_count == hop_count
    assert msg.originator_iid == originator_iid


# ============================================================================
# Stateful Tests
# ============================================================================


class ReplayWindowMachine(RuleBasedStateMachine):
    """Stateful test for replay window behavior."""

    def __init__(self):
        super().__init__()
        from lichen.link.replay import ReplayWindow
        self.window = ReplayWindow(window_size=32)
        self.seen = set()
        self.highest = -1

    @rule(seqnum=st.integers(min_value=0, max_value=65535))
    def receive_seqnum(self, seqnum):
        """Receive a sequence number and check replay detection."""
        expected = self.highest < 0 or seqnum > self.highest
        if not expected:
            expected = self.highest - seqnum < 32 and seqnum not in self.seen
        result = self.window.check_and_update(0, seqnum)

        assert result is expected
        if expected:
            self.seen.add(seqnum)
            self.highest = max(self.highest, seqnum)

    @invariant()
    def seen_matches_window(self):
        """Internal state should be consistent."""
        assert self.window.highest == self.highest


TestReplayWindow = ReplayWindowMachine.TestCase


# ============================================================================
# Profiles for CI
# ============================================================================


# Hypothesis profile for extended CI runs (more examples)
settings.register_profile(
    "ci-extended",
    max_examples=500,
    suppress_health_check=[HealthCheck.too_slow],
)
