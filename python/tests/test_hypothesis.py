"""Property-based tests using Hypothesis."""

import contextlib
from ipaddress import IPv6Address

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, rule

from lichen.announce.messages import SIGNATURE_LENGTH, AnnounceMessage
from lichen.coap.schc_channel import unwrap_coap, wrap_coap
from lichen.crypto.identity import _pubkey_to_iid
from lichen.interface.kiss.framing import FEND, kiss_decode, kiss_encode
from lichen.ipv6.addr import eui64_to_iid, short_addr_to_iid
from lichen.link.frame import AddrMode, FrameError, LichenFrame, MicLength
from lichen.link.replay import ReplayWindow, logical_counter
from lichen.schc.codec import SchcError, compress, decompress
from lichen.schc.headers import compress_packet, decompress_packet
from lichen.schc.rules import COAP_RULE, RULE_ID_UNCOMPRESSED, RULES


@given(
    epoch=st.integers(min_value=0, max_value=255),
    seqnum=st.integers(min_value=0, max_value=65535),
    addr_mode=st.sampled_from(list(AddrMode)),
    mic_length=st.sampled_from(list(MicLength)),
    payload=st.binary(max_size=200),
    signature_present=st.booleans(),
    encrypted=st.booleans(),
)
def test_frame_roundtrip(
    epoch, seqnum, addr_mode, mic_length, payload, signature_present, encrypted
):
    """Valid frames round-trip through the wire representation."""
    frame = LichenFrame(
        epoch=epoch,
        seqnum=seqnum,
        dst_addr=bytes(addr_mode.addr_len),
        payload=payload,
        mic=bytes(48 if signature_present else 0),
        addr_mode=addr_mode,
        mic_length=mic_length,
        signature_present=signature_present,
        encrypted=encrypted,
    )
    try:
        encoded = frame.to_bytes()
    except FrameError:
        return
    assert LichenFrame.from_bytes(encoded) == frame


@given(data=st.binary(max_size=300))
def test_frame_parse_no_panic(data):
    """Anything accepted by the frame parser re-encodes identically."""
    try:
        frame = LichenFrame.from_bytes(data)
        assert frame.to_bytes() == data
    except FrameError:
        pass


@given(
    epoch=st.integers(min_value=0, max_value=255),
    seqnum=st.integers(min_value=0, max_value=65535),
    payload=st.binary(max_size=200),
)
def test_integer_seqnum_frame_roundtrip(epoch, seqnum, payload):
    frame = LichenFrame(epoch=epoch, seqnum=seqnum, dst_addr=b"", payload=payload, mic=b"")
    decoded = LichenFrame.from_bytes(frame.to_bytes())
    assert (decoded.epoch, decoded.seqnum, decoded.payload) == (epoch, seqnum, payload)


@given(
    epoch=st.integers(min_value=0, max_value=255),
    seqnum=st.integers(min_value=0, max_value=65535),
)
def test_logical_counter_roundtrip(epoch, seqnum):
    counter = logical_counter(epoch, seqnum)
    assert counter >> 16 == epoch
    assert counter & 0xFFFF == seqnum


@given(epoch=st.integers(min_value=0, max_value=254))
def test_logical_counter_wrap(epoch):
    assert logical_counter(epoch + 1, 0) == logical_counter(epoch, 0xFFFF) + 1


@given(
    a=st.tuples(st.integers(0, 255), st.integers(0, 65535)),
    b=st.tuples(st.integers(0, 255), st.integers(0, 65535)),
)
def test_logical_counter_total_order(a, b):
    ca, cb = logical_counter(*a), logical_counter(*b)
    assert (ca == cb) == (a == b)
    if a != b:
        assert (ca > cb) != (cb > ca)


def test_replay_accepts_epoch_transition_at_seqnum_wrap():
    window = ReplayWindow()
    assert window.check_and_update(0, 0xFFFF)
    assert window.check_and_update(1, 0)
    assert not window.check_and_update(1, 0)


@given(
    msg_type=st.integers(0, 3),
    token_length=st.integers(0, 8),
    code=st.integers(0, 255),
    message_id=st.integers(0, 65535),
)
def test_schc_coap_rule_roundtrip(msg_type, token_length, code, message_id):
    fields = {
        "CoAP.version": 1,
        "CoAP.type": msg_type,
        "CoAP.tkl": token_length,
        "CoAP.code": code,
        "CoAP.mid": message_id,
    }
    _, decoded = decompress(compress(COAP_RULE, fields), COAP_RULE)
    assert decoded == fields


def test_schc_rule_id_is_encoded_as_one_byte():
    fields = {
        "CoAP.version": 1,
        "CoAP.type": 0,
        "CoAP.tkl": 0,
        "CoAP.code": 0,
        "CoAP.mid": 0,
    }
    assert compress(COAP_RULE, fields)[0] == COAP_RULE.rule_id


@given(payload=st.binary(max_size=1280))
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_schc_packet_roundtrip(payload):
    assert decompress_packet(compress_packet(payload)) == payload


@given(data=st.binary(max_size=200))
def test_schc_decompress_no_panic(data):
    with contextlib.suppress(SchcError, ValueError):
        decompress_packet(data)


def test_rule_id_validity():
    assert all(0 <= rule_id <= 255 for rule_id in RULES)
    assert RULE_ID_UNCOMPRESSED not in RULES
    assert len({rule.rule_id for rule in RULES.values()}) == len(RULES)


@given(payload=st.binary(max_size=1024))
def test_coap_datagram_roundtrip(payload):
    encoded = wrap_coap(IPv6Address("fe80::1"), IPv6Address("fe80::2"), payload)
    assert unwrap_coap(encoded) == payload


@given(data=st.binary(max_size=100))
def test_coap_parse_no_panic(data):
    with contextlib.suppress(Exception):
        unwrap_coap(data)


@given(pubkey=st.binary(min_size=32, max_size=32))
def test_pubkey_iid_derivation_deterministic(pubkey):
    iid = _pubkey_to_iid(pubkey)
    assert iid == _pubkey_to_iid(pubkey)
    assert len(iid) == 8
    assert iid[0] & 0x02 == 0


@given(eui64=st.binary(min_size=8, max_size=8))
def test_eui64_to_iid_flips_ul_bit(eui64):
    iid = eui64_to_iid(eui64)
    assert iid[0] ^ eui64[0] == 0x02
    assert iid[1:] == eui64[1:]
    assert eui64_to_iid(iid) == eui64


@given(short_addr=st.integers(0, 0xFFFF))
def test_short_addr_to_iid_roundtrip(short_addr):
    iid = short_addr_to_iid(short_addr)
    assert iid[:6] == bytes.fromhex("000000fffe00")
    assert int.from_bytes(iid[6:], "big") == short_addr


@given(addr_bytes=st.binary(min_size=16, max_size=16))
def test_ipv6_address_roundtrip(addr_bytes):
    assert IPv6Address(str(IPv6Address(addr_bytes))).packed == addr_bytes


@given(
    port=st.integers(0, 15),
    command=st.integers(0, 15),
    payload=st.binary(max_size=500),
)
def test_kiss_roundtrip(port, command, payload):
    encoded = kiss_encode(port, command, payload)
    assert encoded[0] == encoded[-1] == FEND
    decoded = kiss_decode(encoded)
    assert (decoded.port, decoded.command, decoded.data) == (port, command, payload)


@given(payload=st.binary(max_size=100))
def test_kiss_escaping(payload):
    assert FEND not in kiss_encode(0, 0, payload)[1:-1]


@given(
    seq_num=st.integers(0, 65535),
    hop_count=st.integers(0, 255),
    originator_iid=st.binary(min_size=8, max_size=8),
    pubkey=st.binary(min_size=32, max_size=32),
    app_data=st.binary(max_size=64),
)
def test_announce_roundtrip(seq_num, hop_count, originator_iid, pubkey, app_data):
    msg = AnnounceMessage(
        originator_iid=originator_iid,
        pubkey=pubkey,
        seq_num=seq_num,
        hop_count=hop_count,
        app_data=app_data,
        signature=bytes(SIGNATURE_LENGTH),
    )
    assert AnnounceMessage.from_bytes(msg.to_bytes()) == msg


class ReplayWindowMachine(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.window = ReplayWindow()
        self.seen = set()

    @rule(epoch=st.integers(0, 3), seqnum=st.integers(0, 127))
    def receive_seqnum(self, epoch, seqnum):
        is_replay = (epoch, seqnum) in self.seen
        result = self.window.check_and_update(epoch, seqnum)
        if is_replay:
            assert not result
        if result:
            self.seen.add((epoch, seqnum))
            assert self.window.highest >= logical_counter(epoch, seqnum)


TestReplayWindow = ReplayWindowMachine.TestCase

settings.register_profile(
    "ci-extended", max_examples=500, suppress_health_check=[HealthCheck.too_slow]
)
