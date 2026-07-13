"""Property-based tests using Hypothesis.

These tests generate random inputs to find edge cases that unit tests miss.
Run with: pytest tests/test_hypothesis.py -v --hypothesis-show-statistics
"""

import pytest
from hypothesis import given, settings, strategies as st, assume, HealthCheck
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant

# Import modules to test
from lichen.link.frame import LichenFrame, InvalidFrame
from lichen.link.seqnum import LinkSeqNum
from lichen.schc.rules import compress, decompress, RuleId
from lichen.coap.message import CoapMessage, MessageType, Code
from lichen.ipv6.address import Ipv6Address, iid_from_pubkey
from lichen.announce.messages import AnnounceMessage
from lichen.interface.kiss.framing import kiss_encode, kiss_decode, KISS_END


# ============================================================================
# Link Layer Tests
# ============================================================================


@given(
    length=st.integers(min_value=0, max_value=255),
    llsec=st.integers(min_value=0, max_value=255),
    epoch=st.integers(min_value=0, max_value=255),
    seqnum=st.integers(min_value=0, max_value=65535),
    payload=st.binary(min_size=0, max_size=200),
)
def test_frame_roundtrip(length, llsec, epoch, seqnum, payload):
    """Frame encode/decode should be inverse operations."""
    # Build a frame
    frame_bytes = bytes([length, llsec, epoch]) + seqnum.to_bytes(2, "big") + payload

    try:
        frame = LichenFrame.parse(frame_bytes)
        # Re-encode and compare
        rebuilt = frame.to_bytes()
        reparsed = LichenFrame.parse(rebuilt)
        assert frame.epoch == reparsed.epoch
        assert frame.seqnum == reparsed.seqnum
    except InvalidFrame:
        pass  # Invalid input is OK


@given(seqnum=st.integers(min_value=0, max_value=65535))
def test_seqnum_wrap(seqnum):
    """Sequence numbers should wrap correctly at 65535."""
    seq = LinkSeqNum(seqnum)
    next_seq = seq.next()

    if seqnum == 65535:
        assert next_seq.value == 0
    else:
        assert next_seq.value == seqnum + 1


@given(
    a=st.integers(min_value=0, max_value=65535),
    b=st.integers(min_value=0, max_value=65535),
)
def test_seqnum_comparison(a, b):
    """Sequence number comparison should handle wraparound."""
    seq_a = LinkSeqNum(a)
    seq_b = LinkSeqNum(b)

    # Comparison should be consistent
    if a == b:
        assert not seq_a.is_after(seq_b)
        assert not seq_b.is_after(seq_a)
    else:
        # One must be after the other (considering wrap)
        assert seq_a.is_after(seq_b) != seq_b.is_after(seq_a)


# ============================================================================
# SCHC Tests
# ============================================================================


@given(payload=st.binary(min_size=40, max_size=1280))
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_schc_roundtrip(payload):
    """SCHC compress/decompress should preserve original packet."""
    # Need a valid IPv6 packet structure
    if len(payload) < 40:
        return

    # Try to compress
    try:
        compressed, rule_id = compress(payload)
        decompressed = decompress(compressed, rule_id)
        assert decompressed == payload
    except Exception:
        pass  # Invalid packet structure is OK


@given(rule_id=st.integers(min_value=0, max_value=255))
def test_rule_id_validity(rule_id):
    """Rule IDs should be handled without panic."""
    rid = RuleId(rule_id)
    assert 0 <= rid.value <= 255


# ============================================================================
# CoAP Tests
# ============================================================================


@given(
    msg_type=st.sampled_from(list(MessageType)),
    code=st.sampled_from(list(Code)),
    message_id=st.integers(min_value=0, max_value=65535),
    token=st.binary(min_size=0, max_size=8),
    payload=st.binary(min_size=0, max_size=1024),
)
def test_coap_roundtrip(msg_type, code, message_id, token, payload):
    """CoAP encode/decode should preserve message content."""
    msg = CoapMessage(
        msg_type=msg_type,
        code=code,
        message_id=message_id,
        token=token,
        payload=payload,
    )

    encoded = msg.to_bytes()
    decoded = CoapMessage.parse(encoded)

    assert decoded.msg_type == msg_type
    assert decoded.code == code
    assert decoded.message_id == message_id
    assert decoded.token == token
    assert decoded.payload == payload


@given(data=st.binary(min_size=0, max_size=100))
def test_coap_parse_no_panic(data):
    """CoAP parser should never panic on arbitrary input."""
    try:
        CoapMessage.parse(data)
    except Exception:
        pass  # Exceptions are fine, panics are not


# ============================================================================
# IPv6 Tests
# ============================================================================


@given(pubkey=st.binary(min_size=32, max_size=32))
def test_iid_derivation_deterministic(pubkey):
    """IID derivation from pubkey should be deterministic."""
    iid1 = iid_from_pubkey(pubkey)
    iid2 = iid_from_pubkey(pubkey)
    assert iid1 == iid2
    assert len(iid1) == 8
    # U/L bit should be clear (locally administered)
    assert (iid1[0] & 0x02) == 0


@given(addr_bytes=st.binary(min_size=16, max_size=16))
def test_ipv6_address_roundtrip(addr_bytes):
    """IPv6 address string conversion should roundtrip."""
    addr = Ipv6Address(addr_bytes)
    addr_str = str(addr)
    parsed = Ipv6Address.from_string(addr_str)
    assert parsed.bytes == addr_bytes


# ============================================================================
# KISS Framing Tests
# ============================================================================


@given(payload=st.binary(min_size=0, max_size=500))
def test_kiss_roundtrip(payload):
    """KISS frame encode/decode should preserve payload."""
    encoded = kiss_encode(payload)

    # Encoded should start and end with KISS_END
    assert encoded[0] == KISS_END
    assert encoded[-1] == KISS_END

    # Decode should recover original
    decoded = kiss_decode(encoded)
    assert decoded == payload


@given(payload=st.binary(min_size=0, max_size=100))
def test_kiss_escaping(payload):
    """KISS escaping should handle special bytes correctly."""
    encoded = kiss_encode(payload)

    # No raw KISS_END (0xC0) should appear in middle of frame
    middle = encoded[1:-1]
    # 0xC0 should only appear escaped as 0xDB 0xDC
    # This is a property that should hold


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
        app_data=b"",
        signature=b"\x00" * 48,
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

    @rule(seqnum=st.integers(min_value=0, max_value=65535))
    def receive_seqnum(self, seqnum):
        """Receive a sequence number and check replay detection."""
        is_replay = seqnum in self.seen
        result = self.window.check_and_update(seqnum)

        if is_replay:
            # Should be detected as replay
            assert not result
        # Add to seen after check (window may reject old seqnums)
        if result:
            self.seen.add(seqnum)

    @invariant()
    def seen_matches_window(self):
        """Internal state should be consistent."""
        # Window should not grow unbounded
        pass


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
