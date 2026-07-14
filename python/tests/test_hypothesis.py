"""Property-based tests using Hypothesis.

These tests generate random inputs to find edge cases that unit tests miss.
Run with: pytest tests/test_hypothesis.py -v --hypothesis-show-statistics
"""

import contextlib

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, rule

from lichen.announce.messages import SIGNATURE_LENGTH, AnnounceMessage
from lichen.crypto.identity import _pubkey_to_iid
from lichen.interface.kiss.framing import FEND, kiss_decode, kiss_encode
from lichen.ipv6.addr import eui64_to_iid, short_addr_to_iid
from lichen.link.frame import AddrMode, FrameError, LichenFrame, MicLength
from lichen.link.replay import ReplayWindow, logical_counter
from lichen.schc.codec import SchcError
from lichen.schc.headers import compress_packet, decompress_packet
from lichen.schc.rules import RULE_ID_UNCOMPRESSED, RULES

# ============================================================================
# Link Layer Tests
# ============================================================================


@given(
    epoch=st.integers(min_value=0, max_value=255),
    seqnum=st.integers(min_value=0, max_value=65535),
    addr_mode=st.sampled_from(list(AddrMode)),
    mic_length=st.sampled_from(list(MicLength)),
    payload=st.binary(min_size=0, max_size=200),
    signature_present=st.booleans(),
    encrypted=st.booleans(),
)
def test_frame_roundtrip(
    epoch, seqnum, addr_mode, mic_length, payload, signature_present, encrypted
):
    """Frame encode/decode should be inverse operations."""
    frame = LichenFrame(
        epoch=epoch,
        seqnum=seqnum,
        dst_addr=bytes(addr_mode.addr_len),
        payload=payload,
        mic=bytes(mic_length.mic_len),
        addr_mode=addr_mode,
        mic_length=mic_length,
        signature_present=signature_present,
        encrypted=encrypted,
    )
    try:
        encoded = frame.to_bytes()
    except FrameError:
        return  # body over 255 bytes; oversized frames are rejected
    reparsed = LichenFrame.from_bytes(encoded)
    assert reparsed == frame
    assert reparsed.to_bytes() == encoded


@given(data=st.binary(min_size=0, max_size=300))
def test_frame_parse_no_panic(data):
    """Frame parser should raise only FrameError on arbitrary input."""
    try:
        frame = LichenFrame.from_bytes(data)
        # Anything that parses must re-encode to the same bytes.
        assert frame.to_bytes() == data
    except FrameError:
        pass  # Invalid input is OK


@given(
    epoch=st.integers(min_value=0, max_value=255),
    seqnum=st.integers(min_value=0, max_value=65535),
)
def test_logical_counter_roundtrip(epoch, seqnum):
    """The 24-bit logical counter should decompose back to (epoch, seqnum)."""
    counter = logical_counter(epoch, seqnum)
    assert 0 <= counter <= 0xFFFFFF
    assert counter >> 16 == epoch
    assert counter & 0xFFFF == seqnum


@given(epoch=st.integers(min_value=0, max_value=254))
def test_logical_counter_wrap(epoch):
    """Seqnum wrap into the next epoch should advance the counter by one."""
    assert logical_counter(epoch + 1, 0) == logical_counter(epoch, 65535) + 1


@given(
    a=st.tuples(
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=65535),
    ),
    b=st.tuples(
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=65535),
    ),
)
def test_logical_counter_total_order(a, b):
    """Counter comparison should be a total order over (epoch, seqnum)."""
    ca = logical_counter(*a)
    cb = logical_counter(*b)
    if a == b:
        assert ca == cb
    else:
        assert ca != cb
        assert (ca > cb) != (cb > ca)


# ============================================================================
# SCHC Tests
# ============================================================================


@given(payload=st.binary(min_size=0, max_size=1280))
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_schc_roundtrip(payload):
    """SCHC compress/decompress should preserve the original packet."""
    compressed = compress_packet(payload)
    assert decompress_packet(compressed) == payload


@given(data=st.binary(min_size=0, max_size=200))
def test_schc_decompress_no_panic(data):
    """Decompression should raise only documented errors on arbitrary input."""
    # Malformed SCHC data may be rejected, but only with documented errors.
    with contextlib.suppress(SchcError, ValueError):
        decompress_packet(data)


def test_rule_id_validity():
    """Rule IDs should be distinct single-byte values."""
    assert all(0 <= rule_id <= 255 for rule_id in RULES)
    assert RULE_ID_UNCOMPRESSED not in RULES
    assert len({rule.rule_id for rule in RULES.values()}) == len(RULES)


# ============================================================================
# IPv6 Tests
# ============================================================================


@given(pubkey=st.binary(min_size=32, max_size=32))
def test_iid_derivation_deterministic(pubkey):
    """IID derivation from pubkey should be deterministic."""
    iid1 = _pubkey_to_iid(pubkey)
    iid2 = _pubkey_to_iid(pubkey)
    assert iid1 == iid2
    assert len(iid1) == 8
    # U/L bit should be clear (locally administered)
    assert (iid1[0] & 0x02) == 0


@given(eui64=st.binary(min_size=8, max_size=8))
def test_eui64_to_iid_flips_ul_bit(eui64):
    """EUI-64 to IID conversion should flip exactly the U/L bit."""
    iid = eui64_to_iid(eui64)
    assert len(iid) == 8
    assert iid[0] ^ eui64[0] == 0x02
    assert iid[1:] == eui64[1:]
    # Involution: converting back recovers the original EUI-64.
    assert eui64_to_iid(iid) == eui64


@given(short_addr=st.integers(min_value=0, max_value=0xFFFF))
def test_short_addr_to_iid_roundtrip(short_addr):
    """Short-address IIDs should follow RFC 4944 and preserve the address."""
    iid = short_addr_to_iid(short_addr)
    assert len(iid) == 8
    assert iid[:6] == bytes.fromhex("000000fffe00")
    assert int.from_bytes(iid[6:], "big") == short_addr


# ============================================================================
# KISS Framing Tests
# ============================================================================


@given(
    port=st.integers(min_value=0, max_value=15),
    command=st.integers(min_value=0, max_value=15),
    payload=st.binary(min_size=0, max_size=500),
)
def test_kiss_roundtrip(port, command, payload):
    """KISS frame encode/decode should preserve port, command, and payload."""
    encoded = kiss_encode(port, command, payload)

    # Encoded should start and end with FEND
    assert encoded[0] == FEND
    assert encoded[-1] == FEND

    # Decode should recover the original
    decoded = kiss_decode(encoded)
    assert decoded.port == port
    assert decoded.command == command
    assert decoded.data == payload


@given(payload=st.binary(min_size=0, max_size=100))
def test_kiss_escaping(payload):
    """KISS escaping should keep raw FEND out of the frame interior."""
    encoded = kiss_encode(0, 0, payload)

    # No raw FEND (0xC0) should appear in the middle of the frame
    assert FEND not in encoded[1:-1]


# ============================================================================
# Announce Tests
# ============================================================================


@given(
    seq_num=st.integers(min_value=0, max_value=65535),
    hop_count=st.integers(min_value=0, max_value=255),
    originator_iid=st.binary(min_size=8, max_size=8),
    pubkey=st.binary(min_size=32, max_size=32),
    app_data=st.binary(min_size=0, max_size=64),
)
def test_announce_roundtrip(seq_num, hop_count, originator_iid, pubkey, app_data):
    """Announce message fields should survive serialization."""
    msg = AnnounceMessage(
        originator_iid=originator_iid,
        pubkey=pubkey,
        seq_num=seq_num,
        hop_count=hop_count,
        app_data=app_data,
        signature=bytes(SIGNATURE_LENGTH),
    )

    parsed = AnnounceMessage.from_bytes(msg.to_bytes())
    assert parsed == msg


# ============================================================================
# Stateful Tests
# ============================================================================


class ReplayWindowMachine(RuleBasedStateMachine):
    """Stateful test for replay window behavior."""

    def __init__(self):
        super().__init__()
        self.window = ReplayWindow()
        self.seen = set()

    @rule(
        epoch=st.integers(min_value=0, max_value=3),
        seqnum=st.integers(min_value=0, max_value=127),
    )
    def receive_seqnum(self, epoch, seqnum):
        """Receive an (epoch, seqnum) pair and check replay detection."""
        is_replay = (epoch, seqnum) in self.seen
        result = self.window.check_and_update(epoch, seqnum)

        if is_replay:
            # Should be detected as replay
            assert not result
        # Add to seen after check (window may reject old seqnums)
        if result:
            self.seen.add((epoch, seqnum))
            # The window's high-water mark must cover every accepted frame.
            assert self.window.highest >= logical_counter(epoch, seqnum)


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
