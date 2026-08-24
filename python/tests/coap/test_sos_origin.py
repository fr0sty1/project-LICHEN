# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for SOS origin signature generation (spec section 18.4.1)."""

from ipaddress import IPv6Address

import pytest

from lichen.coap.sos_origin import (
    SOS_ORIGIN_DOMAIN,
    SOS_ORIGIN_SIGNATURE_LENGTH,
    SosOriginSignature,
    canonicalize_sos_payload,
    compute_sos_transcript,
    sign_sos_origin,
)
from lichen.crypto.schnorr48 import derive_keypair, verify


class TestSosOriginDomain:
    """Tests for SOS origin domain separator."""

    def test_domain_length(self):
        """Domain separator must be exactly 20 bytes (matches DAO pattern)."""
        assert len(SOS_ORIGIN_DOMAIN) == 20

    def test_domain_ascii(self):
        """Domain separator must be ASCII only."""
        assert SOS_ORIGIN_DOMAIN.decode("ascii") == "LICHEN-SOS-ORIGIN-v1"


class TestSosOriginSignature:
    """Tests for SosOriginSignature dataclass."""

    def test_valid_construction(self):
        """Construct with valid sequence and signature."""
        sig = SosOriginSignature(origin_sequence=42, signature=b"\x00" * 48)
        assert sig.origin_sequence == 42
        assert len(sig.signature) == 48

    def test_max_sequence(self):
        """Maximum 64-bit sequence is valid."""
        sig = SosOriginSignature(
            origin_sequence=0xFFFFFFFFFFFFFFFF, signature=b"\x00" * 48
        )
        assert sig.origin_sequence == 0xFFFFFFFFFFFFFFFF

    def test_invalid_sequence_negative(self):
        """Negative sequence raises ValueError."""
        with pytest.raises(ValueError, match="origin_sequence"):
            SosOriginSignature(origin_sequence=-1, signature=b"\x00" * 48)

    def test_invalid_sequence_overflow(self):
        """Sequence > 64 bits raises ValueError."""
        with pytest.raises(ValueError, match="origin_sequence"):
            SosOriginSignature(
                origin_sequence=0x10000000000000000, signature=b"\x00" * 48
            )

    def test_invalid_signature_length(self):
        """Non-48-byte signature raises ValueError."""
        with pytest.raises(ValueError, match="48 bytes"):
            SosOriginSignature(origin_sequence=0, signature=b"\x00" * 32)

    def test_roundtrip_serialization(self):
        """to_bytes / from_bytes roundtrip preserves data."""
        original = SosOriginSignature(origin_sequence=12345, signature=bytes(range(48)))
        data = original.to_bytes()
        assert len(data) == SOS_ORIGIN_SIGNATURE_LENGTH
        recovered = SosOriginSignature.from_bytes(data)
        assert recovered.origin_sequence == original.origin_sequence
        assert recovered.signature == original.signature


class TestCanonicalizePayload:
    """Tests for canonical CBOR encoding of SOS payload."""

    def test_deterministic_encoding(self):
        """Same payload always produces same bytes."""
        payload = {"type": "sos", "node": "02001111", "ts": 1716742800}
        cbor1 = canonicalize_sos_payload(payload)
        cbor2 = canonicalize_sos_payload(payload)
        assert cbor1 == cbor2

    def test_key_order_independent(self):
        """Dict key order does not affect canonical output."""
        payload1 = {"type": "sos", "node": "02001111", "ts": 1716742800}
        payload2 = {"ts": 1716742800, "type": "sos", "node": "02001111"}
        assert canonicalize_sos_payload(payload1) == canonicalize_sos_payload(payload2)


class TestComputeTranscript:
    """Tests for SOS signature transcript computation."""

    def test_transcript_length(self):
        """Transcript is always 64 bytes (SHA-512)."""
        addr = IPv6Address("fe80::0200:1111:2222:3333")
        cbor = b"\xa0"  # empty map
        transcript = compute_sos_transcript(addr, 0, cbor)
        assert len(transcript) == 64

    def test_transcript_deterministic(self):
        """Same inputs produce same transcript."""
        addr = IPv6Address("fe80::0200:1111:2222:3333")
        cbor = canonicalize_sos_payload({"type": "sos", "ts": 123})
        t1 = compute_sos_transcript(addr, 42, cbor)
        t2 = compute_sos_transcript(addr, 42, cbor)
        assert t1 == t2

    def test_transcript_differs_on_sequence(self):
        """Different sequence produces different transcript."""
        addr = IPv6Address("fe80::0200:1111:2222:3333")
        cbor = canonicalize_sos_payload({"type": "sos", "ts": 123})
        t1 = compute_sos_transcript(addr, 1, cbor)
        t2 = compute_sos_transcript(addr, 2, cbor)
        assert t1 != t2

    def test_transcript_differs_on_address(self):
        """Different address produces different transcript."""
        addr1 = IPv6Address("fe80::0200:1111:2222:3333")
        addr2 = IPv6Address("fe80::0200:4444:5555:6666")
        cbor = canonicalize_sos_payload({"type": "sos", "ts": 123})
        t1 = compute_sos_transcript(addr1, 1, cbor)
        t2 = compute_sos_transcript(addr2, 1, cbor)
        assert t1 != t2


class TestSignSosOrigin:
    """Tests for SOS origin signature generation."""

    @pytest.fixture
    def keypair(self):
        """Generate a test keypair."""
        seed = bytes(range(32))
        return derive_keypair(seed)

    @pytest.fixture
    def origin_address(self):
        """Test origin IPv6 address."""
        return IPv6Address("fe80::0200:1111:2222:3333")

    def test_sign_produces_valid_signature(self, keypair, origin_address):
        """Signature generation produces verifiable signature."""
        privkey, pubkey = keypair
        payload = {"type": "sos", "node": "02001111", "ts": 1716742800}

        result = sign_sos_origin(privkey, pubkey, origin_address, 1, payload)

        assert isinstance(result, SosOriginSignature)
        assert result.origin_sequence == 1
        assert len(result.signature) == 48

        # Verify the signature is valid using the transcript
        cbor = canonicalize_sos_payload(payload)
        transcript = compute_sos_transcript(origin_address, 1, cbor)
        assert verify(pubkey, transcript, result.signature)

    def test_sign_invalid_key_length(self, origin_address):
        """Invalid key lengths raise ValueError."""
        with pytest.raises(ValueError, match="32 bytes"):
            sign_sos_origin(b"\x00" * 16, b"\x00" * 32, origin_address, 1, {})
        with pytest.raises(ValueError, match="32 bytes"):
            sign_sos_origin(b"\x00" * 32, b"\x00" * 16, origin_address, 1, {})

    def test_different_sequences_produce_different_signatures(
        self, keypair, origin_address
    ):
        """Different sequence numbers produce different signatures."""
        privkey, pubkey = keypair
        payload = {"type": "sos", "ts": 123}

        sig1 = sign_sos_origin(privkey, pubkey, origin_address, 1, payload)
        sig2 = sign_sos_origin(privkey, pubkey, origin_address, 2, payload)

        assert sig1.signature != sig2.signature

    def test_signature_serialization_roundtrip(self, keypair, origin_address):
        """Signature can be serialized and deserialized."""
        privkey, pubkey = keypair
        payload = {"type": "sos", "ts": 123}

        original = sign_sos_origin(privkey, pubkey, origin_address, 42, payload)
        data = original.to_bytes()
        recovered = SosOriginSignature.from_bytes(data)

        assert recovered.origin_sequence == 42
        assert recovered.signature == original.signature

        # Recovered signature still verifies
        cbor = canonicalize_sos_payload(payload)
        transcript = compute_sos_transcript(origin_address, 42, cbor)
        assert verify(pubkey, transcript, recovered.signature)
