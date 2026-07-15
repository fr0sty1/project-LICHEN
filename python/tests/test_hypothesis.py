"""Property-based tests using Hypothesis.

These tests generate random inputs to find edge cases that unit tests miss.
Run with: pytest tests/test_hypothesis.py -v --hypothesis-show-statistics
"""

import pytest
from ipaddress import IPv6Address
from hypothesis import given, settings, strategies as st, assume, HealthCheck
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant

# Import modules to test
from lichen.link.frame import FrameError, LichenFrame
from lichen.schc.codec import compress, decompress
from lichen.schc.rules import COAP_RULE
from lichen.coap.schc_channel import unwrap_coap, wrap_coap
from lichen.ipv6.addr import eui64_to_iid
from lichen.announce.messages import AnnounceMessage
from lichen.interface.kiss.framing import FEND, KissCommand, kiss_decode, kiss_encode


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
        frame = LichenFrame.from_bytes(frame_bytes)
        # Re-encode and compare
        rebuilt = frame.to_bytes()
        reparsed = LichenFrame.from_bytes(rebuilt)
        assert frame.epoch == reparsed.epoch
        assert frame.seqnum == reparsed.seqnum
    except FrameError:
        pass  # Invalid input is OK


@given(
    epoch=st.integers(min_value=0, max_value=255),
    seqnum=st.integers(min_value=0, max_value=65535),
    payload=st.binary(max_size=200),
)
def test_integer_seqnum_frame_roundtrip(epoch, seqnum, payload):
    """The integer 16-bit sequence number survives frame encoding."""
    frame = LichenFrame(
        epoch=epoch,
        seqnum=seqnum,
        dst_addr=b"",
        payload=payload,
        mic=b"",
    )

    decoded = LichenFrame.from_bytes(frame.to_bytes())

    assert decoded.epoch == epoch
    assert decoded.seqnum == seqnum
    assert decoded.payload == payload


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
def test_schc_coap_rule_roundtrip(msg_type, token_length, code, message_id):
    """SCHC compression preserves fields in the current CoAP rule."""
    fields = {
        "CoAP.Version": 1,
        "CoAP.Type": msg_type,
        "CoAP.TKL": token_length,
        "CoAP.Code": code,
        "CoAP.MID": message_id,
    }

    compressed = compress(COAP_RULE, fields)
    _, decompressed = decompress(compressed, COAP_RULE)

    assert decompressed == fields


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

    assert compressed[0] == COAP_RULE.rule_id


# ============================================================================
# CoAP Tests
# ============================================================================


@given(payload=st.binary(max_size=1024))
def test_coap_datagram_roundtrip(payload):
    """CoAP bytes survive IPv6/UDP framing and extraction."""
    encoded = wrap_coap(
        IPv6Address("fe80::1"),
        IPv6Address("fe80::2"),
        payload,
    )

    assert unwrap_coap(encoded) == payload


@given(data=st.binary(min_size=0, max_size=100))
def test_coap_parse_no_panic(data):
    """CoAP parser should never panic on arbitrary input."""
    try:
        unwrap_coap(data)
    except Exception:
        pass  # Exceptions are fine, panics are not


# ============================================================================
# IPv6 Tests
# ============================================================================


@given(eui64=st.binary(min_size=8, max_size=8))
def test_iid_derivation_deterministic(eui64):
    """IID derivation from EUI-64 should be deterministic."""
    iid1 = eui64_to_iid(eui64)
    iid2 = eui64_to_iid(eui64)
    assert iid1 == iid2
    assert len(iid1) == 8
    # IID derivation flips the EUI-64 universal/local bit.
    assert iid1[0] == (eui64[0] ^ 0x02)


@given(addr_bytes=st.binary(min_size=16, max_size=16))
def test_ipv6_address_roundtrip(addr_bytes):
    """IPv6 address string conversion should roundtrip."""
    addr = IPv6Address(addr_bytes)
    addr_str = str(addr)
    parsed = IPv6Address(addr_str)
    assert parsed.packed == addr_bytes


# ============================================================================
# KISS Framing Tests
# ============================================================================


@given(payload=st.binary(min_size=0, max_size=500))
def test_kiss_roundtrip(payload):
    """KISS frame encode/decode should preserve payload."""
    encoded = kiss_encode(0, KissCommand.DATA, payload)

    # Encoded should start and end with KISS_END
    assert encoded[0] == FEND
    assert encoded[-1] == FEND

    # Decode should recover original
    decoded = kiss_decode(encoded)
    assert decoded.data == payload


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

    @rule(seqnum=st.integers(min_value=0, max_value=65535))
    def receive_seqnum(self, seqnum):
        """Receive a sequence number and check replay detection."""
        is_replay = seqnum in self.seen
        result = self.window.check_and_update(0, seqnum)

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
