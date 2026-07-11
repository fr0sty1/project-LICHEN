# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for crypto identity module.

Why these tests: Identity is security-critical. A bug here means:
- Wrong signatures (authentication failure)
- Wrong IIDs (routing failure)
- Key leakage (catastrophic)

Test categories:
1. Construction and validation
2. Key derivation determinism
3. IID derivation correctness
4. Edge cases and error handling
"""

import pytest

from lichen.crypto.identity import Identity, PeerIdentity, _pubkey_to_iid


class TestIdentityConstruction:
    """Tests for Identity creation and validation."""

    def test_generate_creates_valid_identity(self):
        """generate() produces a valid identity with all fields populated."""
        ident = Identity.generate()

        # Why check lengths: Crypto primitives are length-sensitive
        assert len(ident.seed) == 32
        assert len(ident.privkey) == 32
        assert len(ident.pubkey) == 32
        assert len(ident.iid) == 8

    def test_generate_is_random(self):
        """Each generate() call produces a different identity."""
        # Why test randomness: If RNG is broken, all nodes share keys
        ident1 = Identity.generate()
        ident2 = Identity.generate()

        assert ident1.seed != ident2.seed
        assert ident1.pubkey != ident2.pubkey
        assert ident1.iid != ident2.iid

    def test_from_seed_is_deterministic(self):
        """Same seed always produces same keys."""
        # Why test determinism: Key recovery requires reproducibility
        seed = bytes(range(32))

        ident1 = Identity.from_seed(seed)
        ident2 = Identity.from_seed(seed)

        assert ident1.seed == ident2.seed
        assert ident1.privkey == ident2.privkey
        assert ident1.pubkey == ident2.pubkey
        assert ident1.iid == ident2.iid

    def test_from_seed_different_seeds_different_keys(self):
        """Different seeds produce different keys."""
        seed1 = bytes(32)
        seed2 = bytes([1] + [0] * 31)

        ident1 = Identity.from_seed(seed1)
        ident2 = Identity.from_seed(seed2)

        assert ident1.pubkey != ident2.pubkey

    def test_from_seed_rejects_wrong_length(self):
        """from_seed rejects seeds that aren't exactly 32 bytes."""
        with pytest.raises(ValueError, match="seed must be 32 bytes"):
            Identity.from_seed(bytes(31))

        with pytest.raises(ValueError, match="seed must be 32 bytes"):
            Identity.from_seed(bytes(33))

        with pytest.raises(ValueError, match="seed must be 32 bytes"):
            Identity.from_seed(b"")

class TestIdentityRepr:
    """Tests for Identity string representation."""

    def test_repr_does_not_leak_seed(self):
        """repr() never shows the seed."""
        # Why: Seeds in logs are a security disaster
        ident = Identity.generate()
        r = repr(ident)

        assert "seed" not in r.lower() or "seed=" not in r
        assert ident.seed.hex() not in r

    def test_repr_does_not_leak_privkey(self):
        """repr() never shows the private key."""
        ident = Identity.generate()
        r = repr(ident)

        assert ident.privkey.hex() not in r

    def test_repr_shows_pubkey_prefix(self):
        """repr() shows truncated pubkey for identification."""
        ident = Identity.generate()
        r = repr(ident)

        # Should have first 16 hex chars (8 bytes) of pubkey
        assert ident.pubkey.hex()[:16] in r


class TestIIDDerivation:
    """Tests for Interface Identifier derivation from pubkey."""

    def test_iid_is_8_bytes(self):
        """IID is always exactly 8 bytes."""
        pubkey = bytes(range(32))
        iid = _pubkey_to_iid(pubkey)
        assert len(iid) == 8

    def test_iid_is_deterministic(self):
        """Same pubkey always produces same IID."""
        pubkey = bytes(range(32))
        iid1 = _pubkey_to_iid(pubkey)
        iid2 = _pubkey_to_iid(pubkey)
        assert iid1 == iid2

    def test_iid_different_pubkeys_different_iids(self):
        """Different pubkeys produce different IIDs."""
        pubkey1 = bytes(32)
        pubkey2 = bytes([1] + [0] * 31)

        iid1 = _pubkey_to_iid(pubkey1)
        iid2 = _pubkey_to_iid(pubkey2)

        assert iid1 != iid2

    def test_iid_has_local_bit_clear(self):
        """IID has the "universal/local" bit set to local (0)."""
        # Why: RFC 4291 requires this for non-EUI-64 derived IIDs
        pubkey = bytes(range(32))
        iid = _pubkey_to_iid(pubkey)

        # Bit 1 of byte 0 (the "u" bit) should be 0
        assert (iid[0] & 0b0000_0010) == 0

    def test_iid_rejects_wrong_pubkey_length(self):
        """_pubkey_to_iid rejects non-32-byte input."""
        with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
            _pubkey_to_iid(bytes(31))

        with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
            _pubkey_to_iid(bytes(33))


class TestPeerIdentity:
    """Tests for PeerIdentity (public-only identity)."""

    def test_from_pubkey_creates_valid_peer(self):
        """from_pubkey creates a peer with correct IID."""
        pubkey = bytes(range(32))
        peer = PeerIdentity.from_pubkey(pubkey)

        assert peer.pubkey == pubkey
        assert len(peer.iid) == 8

    def test_peer_iid_matches_identity_iid(self):
        """PeerIdentity.iid matches Identity.iid for same pubkey."""
        # Why: A node's self-identity and how peers see it must match
        ident = Identity.generate()
        peer = PeerIdentity.from_pubkey(ident.pubkey)

        assert peer.iid == ident.iid

    def test_peer_rejects_wrong_pubkey_length(self):
        """from_pubkey rejects non-32-byte pubkeys."""
        with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
            PeerIdentity.from_pubkey(bytes(31))

    def test_peer_is_frozen(self):
        """PeerIdentity fields cannot be modified."""
        peer = PeerIdentity.from_pubkey(bytes(32))

        with pytest.raises(AttributeError):
            peer.pubkey = bytes(32)

    def test_peer_repr_shows_info(self):
        """repr() shows useful identification info."""
        pubkey = bytes(range(32))
        peer = PeerIdentity.from_pubkey(pubkey)
        r = repr(peer)

        assert "PeerIdentity" in r
        assert pubkey.hex()[:16] in r


class TestKnownVectors:
    """Test against known vectors for determinism verification."""

    def test_zero_seed_produces_known_pubkey(self):
        """All-zero seed produces a specific known pubkey."""
        # Why: Regression test - if this changes, key derivation broke
        seed = bytes(32)
        ident = Identity.from_seed(seed)

        # This is the Ed25519 pubkey for the all-zero seed
        # Verified against draft-lichen-schnorr-00.md test vectors
        expected_pubkey = bytes.fromhex(
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        )
        assert ident.pubkey == expected_pubkey

    def test_zero_seed_iid(self):
        """All-zero seed produces a specific IID."""
        seed = bytes(32)
        ident = Identity.from_seed(seed)

        # Verify IID is derived from pubkey correctly
        expected_pubkey = bytes.fromhex(
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        )
        expected_iid = _pubkey_to_iid(expected_pubkey)

        assert ident.iid == expected_iid
        assert len(ident.iid) == 8
