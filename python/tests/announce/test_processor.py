# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for announce processor.
"""

from ipaddress import IPv6Address

import pytest

from lichen.announce.messages import (
    MAX_ANNOUNCE_HOPS,
    SIGNATURE_LENGTH,
    AnnounceMessage,
)
from lichen.announce.processor import (
    GRADIENT_TIMEOUT_MS,
    AnnounceProcessor,
    AnnounceRejectReason,
    seq_gt,
)
from lichen.crypto.identity import Identity
from lichen.crypto.schnorr48 import sign
from lichen.gradient import GradientSource, GradientTable


def make_signed_announce(
    identity: Identity,
    seq_num: int = 0,
    hop_count: int = 0,
    app_data: bytes = b"",
) -> AnnounceMessage:
    """Create a properly signed announce message.

    Why a helper: Tests need valid signatures. This ensures consistency.
    """
    msg = AnnounceMessage(
        originator_iid=identity.iid,
        pubkey=identity.pubkey,
        seq_num=seq_num,
        hop_count=hop_count,
        app_data=app_data,
    )
    signature = sign(identity.privkey, identity.pubkey, msg.signed_data())
    return AnnounceMessage(
        originator_iid=msg.originator_iid,
        pubkey=msg.pubkey,
        seq_num=msg.seq_num,
        hop_count=msg.hop_count,
        rx_channel=msg.rx_channel,
        signature=signature,
        app_data=msg.app_data,
    )


@pytest.fixture
def identity() -> Identity:
    """A test identity for the announcer."""
    return Identity.from_seed(bytes(32))


@pytest.fixture
def other_identity() -> Identity:
    """A different identity for negative tests."""
    return Identity.from_seed(bytes([1] + [0] * 31))


@pytest.fixture
def neighbor() -> IPv6Address:
    """Link-local address of the neighbor who forwarded the announce."""
    return IPv6Address("fe80::1")


@pytest.fixture
def processor() -> AnnounceProcessor:
    """An announce processor with empty gradient table."""
    # Why simple address_builder: Tests don't care about prefix.
    # Just prepend a fixed prefix to the IID.
    def build_address(iid: bytes) -> IPv6Address:
        prefix = bytes([0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        return IPv6Address(prefix + iid)

    return AnnounceProcessor(
        gradient_table=GradientTable(),
        address_builder=build_address,
    )


class TestSignatureVerification:
    """Tests for signature validation."""

    def test_accepts_valid_signature(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """A properly signed announce is accepted."""
        announce = make_signed_announce(identity, seq_num=1)
        result = processor.process(announce, neighbor, now_ms=0)

        assert result.accepted is True
        assert result.reject_reason is None

    def test_rejects_invalid_signature(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """An announce with garbage signature is rejected."""
        announce = AnnounceMessage(
            originator_iid=identity.iid,
            pubkey=identity.pubkey,
            seq_num=1,
            signature=bytes(SIGNATURE_LENGTH),  # Garbage signature
        )
        result = processor.process(announce, neighbor, now_ms=0)

        assert result.accepted is False
        assert result.reject_reason == AnnounceRejectReason.INVALID_SIGNATURE

    def test_rejects_signature_for_wrong_data(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """Signature computed over different data is rejected."""
        original = make_signed_announce(identity, seq_num=1)

        # Create message with different seq_num but same signature
        tampered = AnnounceMessage(
            originator_iid=identity.iid,
            pubkey=identity.pubkey,
            seq_num=2,  # Different!
            signature=original.signature,
        )
        result = processor.process(tampered, neighbor, now_ms=0)

        assert result.accepted is False
        assert result.reject_reason == AnnounceRejectReason.INVALID_SIGNATURE


class TestIIDBinding:
    """Tests for IID/pubkey binding validation."""

    def test_rejects_iid_mismatch(
        self,
        processor: AnnounceProcessor,
        identity: Identity,
        other_identity: Identity,
        neighbor: IPv6Address,
    ):
        """Rejects announce where IID doesn't match pubkey hash."""
        msg = AnnounceMessage(
            originator_iid=identity.iid,
            pubkey=other_identity.pubkey,
            seq_num=1,
        )
        signature = sign(other_identity.privkey, other_identity.pubkey, msg.signed_data())
        announce = AnnounceMessage(
            originator_iid=msg.originator_iid,
            pubkey=msg.pubkey,
            seq_num=msg.seq_num,
            signature=signature,
        )

        result = processor.process(announce, neighbor, now_ms=0)

        assert result.accepted is False
        assert result.reject_reason == AnnounceRejectReason.IID_MISMATCH

    def test_iid_check_is_before_signature(
        self, processor: AnnounceProcessor, neighbor: IPv6Address
    ):
        """IID check happens before signature verification (cheaper)."""
        bad_iid = bytes([0xFF] * 8)
        announce = AnnounceMessage(
            originator_iid=bad_iid,
            pubkey=bytes(32),
            seq_num=1,
            signature=bytes(SIGNATURE_LENGTH),
        )
        result = processor.process(announce, neighbor, now_ms=0)

        assert result.reject_reason == AnnounceRejectReason.IID_MISMATCH


class TestDuplicateDetection:
    """Tests for stale/duplicate announce detection."""

    def test_accepts_first_announce(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """First announce from an originator is always accepted."""
        announce = make_signed_announce(identity, seq_num=1)
        result = processor.process(announce, neighbor, now_ms=0)

        assert result.accepted is True

    def test_accepts_higher_seq_num(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """Announce with higher seq_num is accepted."""
        first = make_signed_announce(identity, seq_num=1)
        second = make_signed_announce(identity, seq_num=2)

        processor.process(first, neighbor, now_ms=0)
        result = processor.process(second, neighbor, now_ms=1000)

        assert result.accepted is True

    def test_rejects_equal_seq_num(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """Announce with equal seq_num is rejected (duplicate)."""
        # Why test: Duplicate announces waste bandwidth and could be replays.
        first = make_signed_announce(identity, seq_num=1)
        duplicate = make_signed_announce(identity, seq_num=1)

        processor.process(first, neighbor, now_ms=0)
        result = processor.process(duplicate, neighbor, now_ms=1000)

        assert result.accepted is False
        assert result.reject_reason == AnnounceRejectReason.STALE_SEQNUM

    def test_rejects_lower_seq_num(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """Announce with lower seq_num is rejected (stale)."""
        # Why test: Old announces might be delayed or replayed.
        newer = make_signed_announce(identity, seq_num=10)
        older = make_signed_announce(identity, seq_num=5)

        processor.process(newer, neighbor, now_ms=0)
        result = processor.process(older, neighbor, now_ms=1000)

        assert result.accepted is False
        assert result.reject_reason == AnnounceRejectReason.STALE_SEQNUM

    def test_different_originators_independent(
        self,
        processor: AnnounceProcessor,
        identity: Identity,
        other_identity: Identity,
        neighbor: IPv6Address,
    ):
        """seq_num tracking is per-originator."""
        # Why test: Originators have independent sequence spaces.
        ann1 = make_signed_announce(identity, seq_num=100)
        ann2 = make_signed_announce(other_identity, seq_num=1)  # Lower but different originator

        processor.process(ann1, neighbor, now_ms=0)
        result = processor.process(ann2, neighbor, now_ms=1000)

        assert result.accepted is True  # Different originator, so accepted

class TestGradientUpdate:
    """Tests for gradient table updates."""

    def test_address_failure_leaves_state_retryable(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        announce = make_signed_announce(identity, seq_num=1)
        build_address = processor.address_builder

        def fail_address(_iid: bytes) -> IPv6Address:
            raise RuntimeError("address unavailable")

        processor.address_builder = fail_address
        with pytest.raises(RuntimeError, match="address unavailable"):
            processor.process(announce, neighbor, now_ms=0)

        assert processor.known_originators() == []
        assert processor.pinned_pubkey_for(identity.iid) is None
        assert len(processor.gradient_table) == 0

        processor.address_builder = build_address
        result = processor.process(announce, neighbor, now_ms=1)

        assert result.accepted is True
        assert processor.known_originators() == [identity.iid]
        assert processor.pinned_pubkey_for(identity.iid) == identity.pubkey
        route = processor.gradient_table.lookup(build_address(identity.iid), now=1)
        assert route is not None
        assert route.next_hop == neighbor
        assert route.seq_num == 1
        assert route.source == GradientSource.ANNOUNCE

    def test_gradient_exception_leaves_state_retryable(
        self,
        processor: AnnounceProcessor,
        identity: Identity,
        neighbor: IPv6Address,
        monkeypatch: pytest.MonkeyPatch,
    ):
        announce = make_signed_announce(identity, seq_num=1)
        update = processor.gradient_table.update

        def fail_update(*_args: object, **_kwargs: object) -> bool:
            raise RuntimeError("gradient unavailable")

        monkeypatch.setattr(processor.gradient_table, "update", fail_update)
        with pytest.raises(RuntimeError, match="gradient unavailable"):
            processor.process(announce, neighbor, now_ms=0)

        assert processor.known_originators() == []
        assert processor.pinned_pubkey_for(identity.iid) is None
        assert len(processor.gradient_table) == 0

        monkeypatch.setattr(processor.gradient_table, "update", update)
        result = processor.process(announce, neighbor, now_ms=1)

        assert result.accepted is True
        assert processor.known_originators() == [identity.iid]
        assert processor.pinned_pubkey_for(identity.iid) == identity.pubkey
        destination = processor.address_builder(identity.iid)
        route = processor.gradient_table.lookup(destination, now=1)
        assert route is not None
        assert route.next_hop == neighbor
        assert route.seq_num == 1
        assert route.source == GradientSource.ANNOUNCE

    def test_installs_gradient_on_accept(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """Accepted announce creates gradient entry."""
        # Why test: The whole point is to build routing tables.
        announce = make_signed_announce(identity, seq_num=1, hop_count=3)
        processor.process(announce, neighbor, now_ms=0)

        # Build expected destination
        prefix = bytes([0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        expected_dest = IPv6Address(prefix + identity.iid)

        entry = processor.gradient_table.lookup(expected_dest, now=0)
        assert entry is not None
        assert entry.next_hop == neighbor
        assert entry.hop_count == 3
        assert entry.seq_num == 1
        assert entry.source == GradientSource.ANNOUNCE

    def test_gradient_expires_correctly(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """Gradient entry has correct expiration time."""
        # Why test: Stale gradients must expire.
        now = 10000
        announce = make_signed_announce(identity, seq_num=1)
        processor.process(announce, neighbor, now_ms=now)

        prefix = bytes([0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        dest = IPv6Address(prefix + identity.iid)

        entry = processor.gradient_table.lookup(dest, now=now)
        assert entry is not None
        assert entry.expires == now + GRADIENT_TIMEOUT_MS

        # Should be gone after timeout
        entry_later = processor.gradient_table.lookup(dest, now=now + GRADIENT_TIMEOUT_MS + 1)
        assert entry_later is None

    def test_updates_gradient_on_newer_announce(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """Newer announce updates existing gradient."""
        # Why test: Better routes should replace worse ones.
        first = make_signed_announce(identity, seq_num=1, hop_count=5)
        second = make_signed_announce(identity, seq_num=2, hop_count=3)  # Closer

        processor.process(first, neighbor, now_ms=0)
        processor.process(second, neighbor, now_ms=1000)

        prefix = bytes([0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        dest = IPv6Address(prefix + identity.iid)

        entry = processor.gradient_table.lookup(dest, now=1000)
        assert entry is not None
        assert entry.hop_count == 3
        assert entry.seq_num == 2

    def test_no_gradient_on_reject(
        self,
        processor: AnnounceProcessor,
        identity: Identity,
        other_identity: Identity,
        neighbor: IPv6Address,
    ):
        """Rejected announce does not create gradient."""
        # Why test: Invalid announces must not affect routing.
        # Create invalid announce (bad signature)
        announce = AnnounceMessage(
            originator_iid=identity.iid,
            pubkey=identity.pubkey,
            seq_num=1,
            signature=bytes(SIGNATURE_LENGTH),  # Garbage
        )
        processor.process(announce, neighbor, now_ms=0)

        assert len(processor.gradient_table) == 0


class TestRelayDecision:
    """Tests for should_relay determination."""

    def test_should_relay_true_below_max(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """should_relay is True when hop_count < MAX."""
        # Why test: Valid announces should propagate.
        announce = make_signed_announce(identity, seq_num=1, hop_count=5)
        result = processor.process(announce, neighbor, now_ms=0)

        assert result.accepted is True
        assert result.should_relay is True

    def test_should_relay_false_at_max(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """should_relay is False when hop_count == MAX."""
        # Why test: Prevents infinite flooding.
        announce = make_signed_announce(identity, seq_num=1, hop_count=MAX_ANNOUNCE_HOPS)
        result = processor.process(announce, neighbor, now_ms=0)

        assert result.accepted is True
        assert result.should_relay is False

    def test_should_relay_false_on_reject(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """should_relay is False when announce is rejected."""
        # Why test: Invalid announces must not be propagated.
        announce = AnnounceMessage(
            originator_iid=identity.iid,
            pubkey=identity.pubkey,
            seq_num=1,
            signature=bytes(SIGNATURE_LENGTH),  # Garbage
        )
        result = processor.process(announce, neighbor, now_ms=0)

        assert result.accepted is False
        assert result.should_relay is False

    def test_get_relay_message_increments_hop(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """get_relay_message() returns message with hop_count + 1."""
        # Why test: Relayed messages must have incremented hop count.
        announce = make_signed_announce(identity, seq_num=1, hop_count=5)
        result = processor.process(announce, neighbor, now_ms=0)

        assert result.should_relay is True
        relay_msg = processor.get_relay_message(announce)

        assert relay_msg is not None
        assert relay_msg.hop_count == 6
        # Signature unchanged (still valid because hop_count not signed)
        assert relay_msg.signature == announce.signature

    def test_get_relay_message_none_at_max(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """get_relay_message() returns None when at hop limit."""
        # Why test: Should not be able to create relay message at limit.
        announce = make_signed_announce(identity, seq_num=1, hop_count=MAX_ANNOUNCE_HOPS)

        relay_msg = processor.get_relay_message(announce)
        assert relay_msg is None


class TestResultMetadata:
    """Tests for AnnounceResult metadata."""

    def test_result_contains_peer(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """Successful result includes PeerIdentity."""
        # Why test: Caller may want to learn about the peer.
        announce = make_signed_announce(identity, seq_num=1)
        result = processor.process(announce, neighbor, now_ms=0)

        assert result.peer is not None
        assert result.peer.pubkey == identity.pubkey
        assert result.peer.iid == identity.iid

    def test_result_no_peer_on_reject(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """Rejected result has no peer."""
        # Why test: Can't trust peer identity if announce is invalid.
        announce = AnnounceMessage(
            originator_iid=identity.iid,
            pubkey=identity.pubkey,
            seq_num=1,
            signature=bytes(SIGNATURE_LENGTH),
        )
        result = processor.process(announce, neighbor, now_ms=0)

        assert result.peer is None


class TestKnownOriginators:
    """Tests for known_originators() debug method."""

    def test_empty_initially(self, processor: AnnounceProcessor):
        """No originators known before any announces."""
        assert processor.known_originators() == []

    def test_tracks_accepted_originators(
        self,
        processor: AnnounceProcessor,
        identity: Identity,
        other_identity: Identity,
        neighbor: IPv6Address,
    ):
        """known_originators() returns IIDs of accepted announces."""
        ann1 = make_signed_announce(identity, seq_num=1)
        ann2 = make_signed_announce(other_identity, seq_num=1)

        processor.process(ann1, neighbor, now_ms=0)
        processor.process(ann2, neighbor, now_ms=1000)

        originators = processor.known_originators()
        assert len(originators) == 2
        assert identity.iid in originators
        assert other_identity.iid in originators

    def test_does_not_track_rejected(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """Rejected announces do not appear in known_originators()."""
        announce = AnnounceMessage(
            originator_iid=identity.iid,
            pubkey=identity.pubkey,
            seq_num=1,
            signature=bytes(SIGNATURE_LENGTH),  # Garbage
        )
        processor.process(announce, neighbor, now_ms=0)

        assert processor.known_originators() == []


class TestKeyPinning:
    """Tests for TOFU key pinning and change detection."""

    def test_pins_pubkey_on_first_accept(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """After accepting the first announce, the pubkey is pinned for that IID."""
        announce = make_signed_announce(identity, seq_num=1)
        processor.process(announce, neighbor, now_ms=0)
        assert processor.pinned_pubkey_for(identity.iid) == identity.pubkey

    def test_not_pinned_before_any_announce(
        self, processor: AnnounceProcessor, identity: Identity
    ):
        """An IID that has never announced has no pin."""
        assert processor.pinned_pubkey_for(identity.iid) is None

    def test_same_pubkey_repeated_announce_accepted(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """A second announce from the same IID+pubkey is accepted (seq advances)."""
        ann1 = make_signed_announce(identity, seq_num=1)
        processor.process(ann1, neighbor, now_ms=0)

        ann2 = make_signed_announce(identity, seq_num=2)
        result = processor.process(ann2, neighbor, now_ms=1000)
        assert result.accepted
        # Pin unchanged
        assert processor.pinned_pubkey_for(identity.iid) == identity.pubkey


class TestSeqNumWrapAround:
    """Tests for RFC 1982 serial arithmetic on 16-bit seq_num."""

    def test_seq_gt_basic(self):
        """Basic seq_gt comparisons without wrap."""
        assert seq_gt(2, 1) is True
        assert seq_gt(1, 2) is False
        assert seq_gt(1, 1) is False
        assert seq_gt(100, 50) is True
        assert seq_gt(50, 100) is False

    def test_seq_gt_wrap_around(self):
        """seq_gt handles wrap from 65535 to 0 correctly."""
        # 0 is "greater" than 65535 (just wrapped)
        assert seq_gt(0, 65535) is True
        # 65535 is NOT greater than 0 (it's behind after wrap)
        assert seq_gt(65535, 0) is False
        # 1 is greater than 65535
        assert seq_gt(1, 65535) is True
        # 100 is greater than 65500 (wrapped recently)
        assert seq_gt(100, 65500) is True

    def test_seq_gt_half_space(self):
        """seq_gt boundary at half sequence space (32768)."""
        # Exactly half apart: ambiguous, but RFC 1982 says NOT greater
        # Because diff == 32768 is NOT < 32768
        assert seq_gt(32768, 0) is False
        assert seq_gt(0, 32768) is False
        # Just under half: is greater
        assert seq_gt(32767, 0) is True
        # Just over half: not greater (considered behind)
        assert seq_gt(32769, 0) is False

    def test_accepts_seq_after_wrap(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """Announce with seq_num=0 is accepted after seq_num=65535."""
        # Simulate a node near wrap point
        ann1 = make_signed_announce(identity, seq_num=65535)
        result1 = processor.process(ann1, neighbor, now_ms=0)
        assert result1.accepted is True

        # Next announce wraps to 0
        ann2 = make_signed_announce(identity, seq_num=0)
        result2 = processor.process(ann2, neighbor, now_ms=1000)
        assert result2.accepted is True  # Must accept, not reject as stale

    def test_rejects_old_after_wrap(
        self, processor: AnnounceProcessor, identity: Identity, neighbor: IPv6Address
    ):
        """After wrap, old seq_num=65535 is correctly rejected."""
        # Start after wrap
        ann1 = make_signed_announce(identity, seq_num=100)
        processor.process(ann1, neighbor, now_ms=0)

        # Old announce from before wrap is stale
        ann2 = make_signed_announce(identity, seq_num=65535)
        result = processor.process(ann2, neighbor, now_ms=1000)
        assert result.accepted is False
        assert result.reject_reason == AnnounceRejectReason.STALE_SEQNUM
