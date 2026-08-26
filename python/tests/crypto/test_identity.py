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
4. X25519 key derivation (for EDHOC)
5. Edge cases and error handling
"""

from hashlib import sha512

import pytest
from nacl.bindings import crypto_scalarmult, crypto_scalarmult_base

from lichen.crypto.identity import (
    Identity,
    PeerIdentity,
    _pubkey_to_iid,
    iid_to_human_address,
    yggdrasil_address,
)
from lichen.crypto.schnorr48 import clamp, derive_keypair, sign, verify
from lichen.ipv6.addr import link_local_from_pubkey


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
        assert len(ident.ygg_addr) == 16

    def test_generate_is_random(self):
        """Each generate() call produces a different identity."""
        # Why test randomness: If RNG is broken, all nodes share keys
        ident1 = Identity.generate()
        ident2 = Identity.generate()

        assert ident1.seed != ident2.seed
        assert ident1.pubkey != ident2.pubkey
        assert ident1.iid != ident2.iid
        assert ident1.ygg_addr != ident2.ygg_addr

    def test_generate_uses_one_exact_os_rng_seed(self, monkeypatch: pytest.MonkeyPatch):
        """Generation requests exactly one 32-byte OS seed and derives from it."""
        seed = bytes(range(32))
        requested_sizes: list[int] = []

        def fixed_urandom(size: int) -> bytes:
            requested_sizes.append(size)
            return seed

        monkeypatch.setattr("lichen.crypto.identity.os.urandom", fixed_urandom)
        ident = Identity.generate()

        assert requested_sizes == [32]
        assert ident.seed == seed
        assert ident.pubkey.hex() == (
            "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
        )
        assert ident == Identity.from_seed(seed)

    def test_generate_propagates_os_rng_failure(self, monkeypatch: pytest.MonkeyPatch):
        """An unavailable OS CSPRNG fails closed with the original exception."""
        failure = OSError("OS entropy unavailable")

        def failed_urandom(size: int) -> bytes:
            assert size == 32
            raise failure

        monkeypatch.setattr("lichen.crypto.identity.os.urandom", failed_urandom)
        with pytest.raises(OSError) as caught:
            Identity.generate()
        assert caught.value is failure

    @pytest.mark.parametrize("length", [0, 1, 31, 33, 255])
    def test_generate_rejects_invalid_rng_seed_length(
        self, monkeypatch: pytest.MonkeyPatch, length: int
    ):
        """A broken RNG adapter cannot smuggle a non-32-byte seed downstream."""
        monkeypatch.setattr("lichen.crypto.identity.os.urandom", lambda requested: bytes(length))
        with pytest.raises(ValueError, match=rf"seed must be 32 bytes, got {length}"):
            Identity.generate()

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
        assert ident1.ygg_addr == ident2.ygg_addr

    def test_from_seed_different_seeds_different_keys(self):
        """Different seeds produce different keys."""
        seed1 = bytes(32)
        seed2 = bytes([1] + [0] * 31)

        ident1 = Identity.from_seed(seed1)
        ident2 = Identity.from_seed(seed2)

        assert ident1.pubkey != ident2.pubkey

    def test_identity_key_is_the_schnorr_signing_key(self):
        """The identity seed has one canonical keypair for signing and addressing."""
        seed = bytes(range(32))
        message = b"LICHEN identity signing-key binding v1"
        ident = Identity.from_seed(seed)
        expected_private, expected_public = derive_keypair(seed)

        assert ident.seed == seed
        assert ident.privkey == expected_private
        assert ident.pubkey == expected_public
        assert ident.iid == _pubkey_to_iid(ident.pubkey)
        assert ident.ygg_addr == yggdrasil_address(ident.pubkey).packed

        signature = sign(ident.privkey, ident.pubkey, message)
        assert signature == sign(ident.privkey, ident.pubkey, message)
        assert signature.hex() == (
            "e79cdb76ffbfb5d711fed7dddc5fc159"
            "f79885f1391c86780349a90193081746"
            "a035cb23218db114d28236f44a002e07"
        )
        assert verify(ident.pubkey, message, signature)

        other = Identity.from_seed(bytes(reversed(range(32))))
        assert not verify(other.pubkey, message, signature)

        mismatched_signature = sign(other.privkey, ident.pubkey, message)
        assert mismatched_signature != signature
        assert not verify(ident.pubkey, message, mismatched_signature)
        assert not verify(other.pubkey, message, mismatched_signature)

    def test_public_key_export_is_owned_and_drives_both_addresses(self):
        """Exported key bytes outlive the identity and remain the address input."""
        ident = Identity.from_seed(bytes(range(32)))
        exported_public = bytes(ident.pubkey)
        del ident

        assert exported_public.hex() == (
            "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
        )
        assert _pubkey_to_iid(exported_public).hex() == "ed4242ead4ac6948"
        assert yggdrasil_address(exported_public).packed.hex() == (
            "02ed4242ead4ac69ed4242ead4ac6948"
        )

        for malformed in (exported_public[:-1], exported_public + b"\x00"):
            with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
                _pubkey_to_iid(malformed)
            with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
                yggdrasil_address(malformed)

    def test_cold_starts_reconstruct_the_exact_same_identity_and_addresses(self):
        """A persisted seed is the only input to a cold-start identity snapshot."""

        def cold_start(seed: bytes) -> tuple[bytes, bytes, bytes, bytes, bytes]:
            ident = Identity.from_seed(seed)
            return (
                ident.privkey,
                ident.pubkey,
                ident.iid,
                link_local_from_pubkey(ident.pubkey).packed,
                ident.ygg_addr,
            )

        seed = bytes(range(32))
        first = cold_start(seed)
        # Exercise unrelated derivations between starts: no process-global key
        # or address cache may influence reconstruction from the persisted seed.
        different = cold_start(bytes(reversed(range(32))))
        second = cold_start(seed)

        assert first == second
        assert first == (
            bytes.fromhex("3894eea49c580aef816935762be049559d6d1440dede12e6a125f1841fff8e6f"),
            bytes.fromhex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"),
            bytes.fromhex("ed4242ead4ac6948"),
            bytes.fromhex("fe80000000000000ed4242ead4ac6948"),
            bytes.fromhex("02ed4242ead4ac69ed4242ead4ac6948"),
        )
        assert all(left != right for left, right in zip(first, different, strict=True))

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
        """repr() shows useful identification info (IID + human address)."""
        pubkey = bytes(range(32))
        peer = PeerIdentity.from_pubkey(pubkey)
        r = repr(peer)

        assert "PeerIdentity" in r
        assert peer.iid.hex()[:8] in r
        assert peer.human_address in r


class TestX25519KeyDerivation:
    """Tests for Ed25519 to X25519 key derivation (clamped per RFC 7748)."""

    def test_x25519_private_length(self):
        """x25519_private returns 32 bytes."""
        ident = Identity.generate()
        assert len(ident.x25519_private) == 32

    def test_x25519_public_length(self):
        """x25519_public returns 32 bytes."""
        ident = Identity.generate()
        assert len(ident.x25519_public) == 32

    def test_x25519_private_is_deterministic(self):
        """Same seed always produces same X25519 private key."""
        seed = bytes(range(32))
        ident1 = Identity.from_seed(seed)
        ident2 = Identity.from_seed(seed)
        assert ident1.x25519_private == ident2.x25519_private

    def test_x25519_public_is_deterministic(self):
        """Same seed always produces same X25519 public key."""
        seed = bytes(range(32))
        ident1 = Identity.from_seed(seed)
        ident2 = Identity.from_seed(seed)
        assert ident1.x25519_public == ident2.x25519_public

    def test_x25519_derivation_matches_spec(self):
        """X25519 derivation matches updated spec (clamped per RFC 7748 §5).

        x25519_private = clamp(SHA-512(ed25519_seed)[0:32])
        x25519_public  = X25519(x25519_private, basepoint)
        """
        seed = bytes(range(32))
        ident = Identity.from_seed(seed)

        # Verify private key derivation using clamp (independent oracle)
        h = sha512(seed).digest()[:32]
        expected_private = clamp(h)
        assert ident.x25519_private == expected_private

        # Verify public key derivation
        expected_public = crypto_scalarmult_base(expected_private)
        assert ident.x25519_public == expected_public

    def test_x25519_key_agreement_works(self):
        """Two nodes can perform X25519 key agreement using derived keys."""
        alice = Identity.generate()
        bob = Identity.generate()

        # Alice computes shared secret with Bob's public key
        shared_alice = crypto_scalarmult(alice.x25519_private, bob.x25519_public)

        # Bob computes shared secret with Alice's public key
        shared_bob = crypto_scalarmult(bob.x25519_private, alice.x25519_public)

        # Shared secrets must match (ECDH property)
        assert shared_alice == shared_bob
        assert len(shared_alice) == 32

    def test_x25519_keys_differ_from_ed25519_keys(self):
        """X25519 keys differ from Ed25519 keys (different curves).

        The private scalar bytes are identical (both clamped SHA-512(seed)[:32]),
        but interpreted on different curves (Ed25519 vs X25519) so public keys differ.
        """
        ident = Identity.from_seed(bytes(range(32)))

        # Private scalar bytes are the same (unified derivation)
        assert ident.x25519_private == ident.privkey

        # Public keys differ (Ed25519 vs Curve25519 basepoint multiplication)
        assert ident.x25519_public != ident.pubkey

    def test_different_seeds_produce_different_x25519_keys(self):
        """Different seeds produce different X25519 keys."""
        ident1 = Identity.from_seed(bytes(32))
        ident2 = Identity.from_seed(bytes([1] + [0] * 31))

        assert ident1.x25519_private != ident2.x25519_private
        assert ident1.x25519_public != ident2.x25519_public


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

    def test_zero_seed_x25519_keys(self):
        """All-zero seed produces specific X25519 keys (clamped).

        Verifies clamped derivation per RFC 7748 §5:
            x25519_private = clamp(SHA-512(seed)[0:32])
            x25519_public  = X25519(x25519_private, basepoint)
        """
        seed = bytes(32)
        ident = Identity.from_seed(seed)

        # Clamped SHA-512[:32] for zero seed (last byte 0x96 -> 0x56 after clamp)
        expected_x25519_private = bytes.fromhex(
            "5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f156"
        )
        assert ident.x25519_private == expected_x25519_private

        # X25519 public key (unchanged by this particular clamp)
        # Computed via cryptography.x25519 and nacl.crypto_scalarmult_base
        expected_x25519_public = bytes.fromhex(
            "5bf55c73b82ebe22be80f3430667af570fae2556a6415e6b30d4065300aa947d"
        )
        assert ident.x25519_public == expected_x25519_public

        # Cross-check: public key should be scalarmult_base of private key
        assert ident.x25519_public == crypto_scalarmult_base(ident.x25519_private)


class TestHumanAddressVectors:
    """Validate against canonical test/vectors/node_address.json (10 vectors).

    Each vector specifies (pubkey_hex, iid_hex, expected_human_address).
    The iid is SHA-512(pubkey)[:8] with U/L bit cleared.
    The human_address is Crockford Base32 of the IID, formatted XXXX-XXXX-XXXXX.
    """

    VECTORS = [
        ("0000000000000000000000000000000000000000000000000000000000000000",
         "5046adc1dba83886", "50HN-DR7D-TGE46"),
        ("0101010101010101010101010101010101010101010101010101010101010101",
         "5ce86efb75fa4e2c", "5ST3-EZDT-ZMKHC"),
        ("0202020202020202020202020202020202020202020202020202020202020202",
         "a83c626bc9c38c8c", "AGF3-2DF4-W734C"),
        ("0303030303030303030303030303030303030303030303030303030303030303",
         "98aebbb178a55187", "9HBN-VP5W-AAMC7"),
        ("0404040404040404040404040404040404040404040404040404040404040404",
         "493e3c145d7e680a", "4JFH-W2HE-QWT0A"),
        ("0505050505050505050505050505050505050505050505050505050505050505",
         "4d370d6146de919c", "4TDR-DC53-DX4CW"),
        ("0606060606060606060606060606060606060606060606060606060606060606",
         "ac3f248f80ff04de", "ARFS-4HY0-FY16Y"),
        ("0707070707070707070707070707070707070707070707070707070707070707",
         "2dad39fefd7fa3e2", "2VB9-SZVY-QZ8Z2"),
        ("0808080808080808080808080808080808080808080808080808080808080808",
         "3926c9c31226edde", "3J9P-9RC9-2DVEY"),
        ("0909090909090909090909090909090909090909090909090909090909090909",
         "3c8fe3ab30c0aabf", "3S3Z-3NCR-C1ANZ"),
    ]

    def test_pubkey_to_iid_matches_vectors(self):
        for pubkey_hex, iid_hex, _ in self.VECTORS:
            pubkey = bytes.fromhex(pubkey_hex)
            expected_iid = bytes.fromhex(iid_hex)
            actual = _pubkey_to_iid(pubkey)
            assert actual == expected_iid, (
                f"pubkey {pubkey_hex}: expected iid {iid_hex}, got {actual.hex()}"
            )

    def test_human_address_via_peer_identity(self):
        for pubkey_hex, _, expected in self.VECTORS:
            pubkey = bytes.fromhex(pubkey_hex)
            peer = PeerIdentity.from_pubkey(pubkey)
            assert peer.human_address == expected, (
                f"pubkey {pubkey_hex}: expected {expected}, got {peer.human_address}"
            )

    def test_iid_to_human_address_direct(self):
        for _, iid_hex, expected in self.VECTORS:
            iid = bytes.fromhex(iid_hex)
            actual = iid_to_human_address(iid)
            assert actual == expected, (
                f"iid {iid_hex}: expected {expected}, got {actual}"
            )
