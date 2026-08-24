# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for Trust Models oracle (GCP-3).

Tests TOFU key pinning, trust levels, cryptographic binding verification,
and key rotation per spec section 8.7.
"""

import inspect
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import lichen.crypto.trust as trust_module
from lichen.crypto import (
    DerivationMismatchError,
    Identity,
    KeyMismatchError,
    RevokedPeerError,
    TrustEntry,
    TrustError,
    TrustLevel,
    TrustStore,
    UnknownPeerError,
    generate_trust_vector,
    verify_pubkey_derivation,
    verify_pubkey_to_ygg_addr,
    verify_trust_vector,
)
from lichen.crypto.schnorr48 import sign as schnorr_sign
from lichen.crypto.schnorr48 import verify as schnorr_verify
from lichen.crypto.trust import compute_rotation_transcript

# Deterministic seeds for reproducible tests
SEED_ALICE = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
SEED_BOB = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")
SEED_CHARLIE = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")
GCP3_VECTORS = Path(__file__).parents[3] / "test" / "vectors" / "gcp3_trust_models.json"


def test_verify_or_pin_exposes_no_ineffective_upgrade_authorization() -> None:
    assert "allow_upgrade" not in inspect.signature(TrustStore.verify_or_pin).parameters


def test_canonical_gcp3_rotation_vectors_drive_python_production_oracle() -> None:
    document = json.loads(GCP3_VECTORS.read_bytes())
    rotations = [case for case in document["vectors"] if case["category"] == "rotation"]
    assert rotations

    for case in rotations:
        old_pubkey = bytes.fromhex(case["old_pubkey"])
        old_iid = bytes.fromhex(case["old_iid"])
        new_pubkey = bytes.fromhex(case["new_pubkey"])
        sequence = case["rotation_sequence"]
        signature = bytes.fromhex(case["rotation_signature"])
        transcript = compute_rotation_transcript(old_pubkey, new_pubkey, sequence)

        assert verify_pubkey_derivation(old_pubkey, old_iid)
        assert transcript.hex() == case["rotation_message"]
        assert schnorr_verify(old_pubkey, transcript, signature) is case["signature_valid"]

        store = TrustStore(auto_pin=True)
        store.verify_or_pin(old_pubkey, old_iid)
        if case["expected_result"] == "accept_rotation":
            rotated = store.rotate_key_semantics_for_test(
                old_pubkey, new_pubkey, sequence, signature
            )
            assert rotated.pubkey == new_pubkey
            assert rotated.iid == bytes.fromhex(case["new_iid"])
            assert rotated.rotation_sequence == sequence
        else:
            assert case["expected_result"] == "reject_invalid_signature"
            with pytest.raises(TrustError, match="signature verification failed"):
                store.rotate_key_semantics_for_test(old_pubkey, new_pubkey, sequence, signature)


class TestTrustEntry:
    """Tests for TrustEntry creation and validation."""

    def test_from_pubkey_creates_valid_entry(self):
        """TrustEntry.from_pubkey creates entry with derived IID/02xx."""
        alice = Identity.from_seed(SEED_ALICE)
        entry = TrustEntry.from_pubkey(alice.pubkey)

        assert entry.pubkey == alice.pubkey
        assert entry.iid == alice.iid
        assert entry.ygg_addr == alice.ygg_addr
        assert entry.trust_level == TrustLevel.TOFU
        assert not entry.revoked
        assert entry.first_seen > 0
        assert entry.last_seen >= entry.first_seen

    def test_from_pubkey_with_custom_trust_level(self):
        """TrustEntry.from_pubkey accepts custom trust level."""
        alice = Identity.from_seed(SEED_ALICE)
        entry = TrustEntry.from_pubkey(
            alice.pubkey,
            trust_level=TrustLevel.BR_PROVISIONED,
        )

        assert entry.trust_level == TrustLevel.BR_PROVISIONED

    def test_from_pubkey_with_metadata(self):
        """TrustEntry.from_pubkey stores metadata."""
        alice = Identity.from_seed(SEED_ALICE)
        entry = TrustEntry.from_pubkey(
            alice.pubkey,
            metadata={"name": "alice", "role": "sensor"},
        )

        assert entry.metadata["name"] == "alice"
        assert entry.metadata["role"] == "sensor"

    def test_from_pubkey_rejects_invalid_length(self):
        """TrustEntry.from_pubkey rejects invalid pubkey length."""
        with pytest.raises(ValueError, match="32 bytes"):
            TrustEntry.from_pubkey(b"\x00" * 16)

    def test_rejects_unrepresentable_integer_timestamp(self):
        alice = Identity.from_seed(SEED_ALICE)

        with pytest.raises(ValueError, match="finite non-negative"):
            TrustEntry(
                pubkey=alice.pubkey,
                iid=alice.iid,
                ygg_addr=alice.ygg_addr,
                trust_level=TrustLevel.TOFU,
                first_seen=10**309,
                last_seen=10**309,
            )

    def test_large_integer_timestamp_ordering_is_exact(self):
        alice = Identity.from_seed(SEED_ALICE)

        with pytest.raises(ValueError, match="must not precede"):
            TrustEntry(
                pubkey=alice.pubkey,
                iid=alice.iid,
                ygg_addr=alice.ygg_addr,
                trust_level=TrustLevel.TOFU,
                first_seen=2**53 + 1,
                last_seen=2**53,
            )

    def test_to_peer_identity(self):
        """TrustEntry.to_peer_identity converts to PeerIdentity."""
        alice = Identity.from_seed(SEED_ALICE)
        entry = TrustEntry.from_pubkey(alice.pubkey)
        peer = entry.to_peer_identity()

        assert peer.pubkey == alice.pubkey
        assert peer.iid == alice.iid

    def test_ipv6_address(self):
        """TrustEntry.ipv6_address returns IPv6Address."""
        alice = Identity.from_seed(SEED_ALICE)
        entry = TrustEntry.from_pubkey(alice.pubkey)
        addr = entry.ipv6_address()

        assert addr.packed[0] == 0x02  # Native 0200::/8

    def test_returned_entry_and_nested_metadata_are_immutable_detached_views(self):
        alice = Identity.from_seed(SEED_ALICE)
        store = TrustStore()
        stored = store.add_trust_anchor(alice.pubkey, metadata={"role": "sensor"})
        with pytest.raises(FrozenInstanceError):
            stored.revoked = True  # type: ignore[misc]
        with pytest.raises(TypeError):
            stored.metadata["role"] = "attacker"  # type: ignore[index]

        listed = store.list_entries()[0]
        assert listed is not stored
        assert listed.metadata is not stored.metadata
        current = store.verify_peer(alice.pubkey, alice.iid)
        assert not current.revoked
        assert current.metadata == {"role": "sensor"}


class TestVerifyPubkeyDerivation:
    """Tests for cryptographic binding verification."""

    def test_valid_derivation(self):
        """verify_pubkey_derivation returns True for valid binding."""
        alice = Identity.from_seed(SEED_ALICE)
        assert verify_pubkey_derivation(alice.pubkey, alice.iid)

    def test_invalid_iid(self):
        """verify_pubkey_derivation returns False for wrong IID."""
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)
        # Alice's pubkey should not derive to Bob's IID
        assert not verify_pubkey_derivation(alice.pubkey, bob.iid)

    def test_invalid_pubkey_length(self):
        """verify_pubkey_derivation returns False for invalid lengths."""
        alice = Identity.from_seed(SEED_ALICE)
        assert not verify_pubkey_derivation(b"\x00" * 16, alice.iid)
        assert not verify_pubkey_derivation(alice.pubkey, b"\x00" * 4)

    def test_verify_ygg_addr_valid(self):
        """verify_pubkey_to_ygg_addr returns True for valid binding."""
        alice = Identity.from_seed(SEED_ALICE)
        assert verify_pubkey_to_ygg_addr(alice.pubkey, alice.ygg_addr)

    def test_verify_ygg_addr_invalid(self):
        """verify_pubkey_to_ygg_addr returns False for wrong address."""
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)
        assert not verify_pubkey_to_ygg_addr(alice.pubkey, bob.ygg_addr)


class TestTrustStoreTofu:
    """Tests for TOFU (Trust On First Use) mode."""

    def test_auto_pin_on_first_contact(self):
        """TrustStore pins peer on first contact in auto_pin mode."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)

        entry = store.verify_or_pin(alice.pubkey, alice.iid)

        assert len(store) == 1
        assert alice.iid in store
        assert entry.pubkey == alice.pubkey
        assert entry.trust_level == TrustLevel.TOFU

    def test_verify_pinned_peer(self):
        """TrustStore verifies pinned peer on subsequent contact."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)

        # First contact - pins
        entry1 = store.verify_or_pin(alice.pubkey, alice.iid)
        # Subsequent contact - verifies
        entry2 = store.verify_or_pin(alice.pubkey, alice.iid)

        assert entry1.pubkey == entry2.pubkey
        assert entry2.last_seen >= entry1.first_seen

    def test_wall_clock_regression_never_decreases_last_seen(self, monkeypatch):
        alice = Identity.from_seed(SEED_ALICE)
        store = TrustStore(auto_pin=True)
        monkeypatch.setattr(trust_module.time, "time", lambda: 100.0)
        initial = store.verify_or_pin(alice.pubkey, alice.iid)

        monkeypatch.setattr(trust_module.time, "time", lambda: 10.0)
        verified_tofu = store.verify_or_pin(alice.pubkey, alice.iid)
        verified_strict = store.verify_peer(alice.pubkey, alice.iid)
        unchanged_anchor = store.add_trust_anchor(alice.pubkey, TrustLevel.TOFU)
        upgraded_anchor = store.add_trust_anchor(alice.pubkey, TrustLevel.BR_PROVISIONED)

        assert initial.last_seen == 100.0
        assert verified_tofu.last_seen == 100.0
        assert verified_strict.last_seen == 100.0
        assert unchanged_anchor.last_seen == 100.0
        assert upgraded_anchor.last_seen == 100.0
        assert upgraded_anchor.trust_level is TrustLevel.BR_PROVISIONED

    def test_reject_key_mismatch(self):
        """TrustStore rejects different pubkey for same IID."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)

        # Pin Alice
        store.verify_or_pin(alice.pubkey, alice.iid)

        # Try to present Bob's key with Alice's IID (attacker scenario)
        # This will fail derivation check first
        with pytest.raises(DerivationMismatchError):
            store.verify_or_pin(bob.pubkey, alice.iid)

    def test_reject_derivation_mismatch(self):
        """TrustStore rejects pubkey that doesn't derive to claimed IID."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)

        # Try Alice's pubkey with Bob's IID
        with pytest.raises(DerivationMismatchError):
            store.verify_or_pin(alice.pubkey, bob.iid)

    def test_no_auto_pin_mode(self):
        """TrustStore rejects unknown peers when auto_pin=False."""
        store = TrustStore(auto_pin=False)
        alice = Identity.from_seed(SEED_ALICE)

        with pytest.raises(UnknownPeerError):
            store.verify_or_pin(alice.pubkey, alice.iid)


class TestTrustStoreBrProvisioned:
    """Tests for BR-provisioned trust anchors."""

    def test_add_trust_anchor(self):
        """add_trust_anchor adds peer with specified trust level."""
        store = TrustStore(auto_pin=False)
        alice = Identity.from_seed(SEED_ALICE)

        entry = store.add_trust_anchor(alice.pubkey, TrustLevel.BR_PROVISIONED)

        assert entry.trust_level == TrustLevel.BR_PROVISIONED
        assert alice.iid in store

    def test_trust_anchor_allows_verification(self):
        """BR-provisioned anchors can be verified without TOFU."""
        store = TrustStore(auto_pin=False)
        alice = Identity.from_seed(SEED_ALICE)

        store.add_trust_anchor(alice.pubkey, TrustLevel.BR_PROVISIONED)
        entry = store.verify_or_pin(alice.pubkey, alice.iid)

        assert entry.trust_level == TrustLevel.BR_PROVISIONED

    def test_trust_level_upgrade(self):
        """add_trust_anchor upgrades trust level if higher."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)

        # First TOFU
        store.verify_or_pin(alice.pubkey, alice.iid)
        assert store.get(alice.iid).trust_level == TrustLevel.TOFU

        # Upgrade to BR_PROVISIONED
        store.add_trust_anchor(alice.pubkey, TrustLevel.BR_PROVISIONED)
        assert store.get(alice.iid).trust_level == TrustLevel.BR_PROVISIONED

        # Try to downgrade - should keep higher level
        store.add_trust_anchor(alice.pubkey, TrustLevel.TOFU)
        assert store.get(alice.iid).trust_level == TrustLevel.BR_PROVISIONED


class TestTrustStoreVerifyPeer:
    """Tests for verify_peer (strict mode, no auto-pin)."""

    def test_verify_known_peer(self):
        """verify_peer succeeds for pinned peer."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)

        store.verify_or_pin(alice.pubkey, alice.iid)
        entry = store.verify_peer(alice.pubkey, alice.iid)

        assert entry.pubkey == alice.pubkey

    def test_reject_unknown_peer(self):
        """verify_peer rejects unknown peer."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)

        with pytest.raises(UnknownPeerError):
            store.verify_peer(alice.pubkey, alice.iid)

    def test_reject_key_mismatch_in_verify(self):
        """verify_peer rejects pubkey mismatch."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)

        store.verify_or_pin(alice.pubkey, alice.iid)

        # Bob's key doesn't derive to Alice's IID
        with pytest.raises(DerivationMismatchError):
            store.verify_peer(bob.pubkey, alice.iid)


class TestTrustStoreRevocation:
    """Tests for peer revocation."""

    def test_revoke_peer(self):
        """revoke marks peer as revoked."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)

        store.verify_or_pin(alice.pubkey, alice.iid)
        result = store.revoke(alice.iid)

        assert result is True
        assert store.get(alice.iid).revoked is True

    def test_revoke_unknown_peer(self):
        """revoke returns False for unknown peer."""
        store = TrustStore()
        alice = Identity.from_seed(SEED_ALICE)

        result = store.revoke(alice.iid)
        assert result is False

    def test_reject_revoked_peer(self):
        """verify_or_pin rejects revoked peer."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)

        store.verify_or_pin(alice.pubkey, alice.iid)
        store.revoke(alice.iid)

        with pytest.raises(RevokedPeerError):
            store.verify_or_pin(alice.pubkey, alice.iid)

    def test_reject_revoked_in_verify_peer(self):
        """verify_peer rejects revoked peer."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)

        store.verify_or_pin(alice.pubkey, alice.iid)
        store.revoke(alice.iid)

        with pytest.raises(RevokedPeerError):
            store.verify_peer(alice.pubkey, alice.iid)

    def test_remove_peer(self):
        """remove deletes peer from store."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)

        store.verify_or_pin(alice.pubkey, alice.iid)
        result = store.remove(alice.iid)

        assert result is True
        assert alice.iid not in store
        assert len(store) == 0


class TestTrustStoreKeyRotation:
    """Tests for key rotation with signature from old key."""

    def test_rotate_key_with_valid_signature(self):
        """rotate_key accepts valid signature over canonical transcript."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        alice_new = Identity.from_seed(SEED_BOB)  # New key for rotation

        # Pin original key
        store.verify_or_pin(alice.pubkey, alice.iid)

        # Compute canonical rotation transcript
        rotation_seq = 1
        transcript = compute_rotation_transcript(alice.pubkey, alice_new.pubkey, rotation_seq)

        # Sign transcript with OLD key
        sig = schnorr_sign(alice.privkey, alice.pubkey, transcript)

        # Rotate
        new_entry = store.rotate_key_semantics_for_test(
            alice.pubkey, alice_new.pubkey, rotation_seq, sig
        )

        # Old IID removed, new IID present
        assert alice.iid not in store
        assert alice_new.iid in store
        assert new_entry.pubkey == alice_new.pubkey
        assert new_entry.trust_level == TrustLevel.TOFU
        assert new_entry.rotation_sequence == rotation_seq

    def test_public_rotate_key_requires_durable_persistence(self):
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        alice_new = Identity.from_seed(SEED_BOB)
        store.verify_or_pin(alice.pubkey, alice.iid)
        transcript = compute_rotation_transcript(alice.pubkey, alice_new.pubkey, 1)
        signature = schnorr_sign(alice.privkey, alice.pubkey, transcript)

        with pytest.raises(TrustError, match="persistence required"):
            store.rotate_key(alice.pubkey, alice_new.pubkey, 1, signature)

        assert alice.iid in store
        assert alice_new.iid not in store

    @pytest.mark.parametrize("method_name", ["rotate_key", "rotate_key_semantics_for_test"])
    def test_rotation_rejects_same_key_without_mutation(self, method_name: str):
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        original = store.verify_or_pin(alice.pubkey, alice.iid)
        transcript = compute_rotation_transcript(alice.pubkey, alice.pubkey, 1)
        signature = schnorr_sign(alice.privkey, alice.pubkey, transcript)

        with pytest.raises(TrustError, match="must change"):
            getattr(store, method_name)(alice.pubkey, alice.pubkey, 1, signature)

        assert store.get(alice.iid) == original
        assert len(store) == 1

    def test_rotate_key_rejects_invalid_signature(self):
        """rotate_key rejects invalid signature."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        alice_new = Identity.from_seed(SEED_BOB)
        charlie = Identity.from_seed(SEED_CHARLIE)

        store.verify_or_pin(alice.pubkey, alice.iid)

        rotation_seq = 1
        transcript = compute_rotation_transcript(alice.pubkey, alice_new.pubkey, rotation_seq)

        # Sign with WRONG key (Charlie's key, not Alice's)
        bad_sig = schnorr_sign(charlie.privkey, charlie.pubkey, transcript)

        with pytest.raises(TrustError, match="signature verification failed"):
            store.rotate_key_semantics_for_test(
                alice.pubkey, alice_new.pubkey, rotation_seq, bad_sig
            )

        # Original entry unchanged
        assert alice.iid in store
        assert alice_new.iid not in store

    def test_rotate_key_unknown_peer(self):
        """rotate_key rejects rotation for unknown peer."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        alice_new = Identity.from_seed(SEED_BOB)

        rotation_seq = 1
        transcript = compute_rotation_transcript(alice.pubkey, alice_new.pubkey, rotation_seq)
        sig = schnorr_sign(alice.privkey, alice.pubkey, transcript)

        with pytest.raises(UnknownPeerError):
            store.rotate_key_semantics_for_test(alice.pubkey, alice_new.pubkey, rotation_seq, sig)

    def test_rotate_key_revoked_peer(self):
        """rotate_key rejects rotation for revoked peer."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        alice_new = Identity.from_seed(SEED_BOB)

        store.verify_or_pin(alice.pubkey, alice.iid)
        store.revoke(alice.iid)

        rotation_seq = 1
        transcript = compute_rotation_transcript(alice.pubkey, alice_new.pubkey, rotation_seq)
        sig = schnorr_sign(alice.privkey, alice.pubkey, transcript)

        with pytest.raises(RevokedPeerError):
            store.rotate_key_semantics_for_test(alice.pubkey, alice_new.pubkey, rotation_seq, sig)

    def test_rotate_key_rejects_sequence_replay(self):
        """rotate_key rejects replay of same or lower rotation_sequence."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        alice_new = Identity.from_seed(SEED_BOB)
        alice_newer = Identity.from_seed(SEED_CHARLIE)

        store.verify_or_pin(alice.pubkey, alice.iid)

        # First rotation with seq=1
        rotation_seq = 1
        transcript = compute_rotation_transcript(alice.pubkey, alice_new.pubkey, rotation_seq)
        sig = schnorr_sign(alice.privkey, alice.pubkey, transcript)
        store.rotate_key_semantics_for_test(alice.pubkey, alice_new.pubkey, rotation_seq, sig)

        # Try to replay with same sequence - should fail
        transcript2 = compute_rotation_transcript(
            alice_new.pubkey, alice_newer.pubkey, rotation_seq
        )
        sig2 = schnorr_sign(alice_new.privkey, alice_new.pubkey, transcript2)
        with pytest.raises(TrustError, match="sequence replay"):
            store.rotate_key_semantics_for_test(
                alice_new.pubkey, alice_newer.pubkey, rotation_seq, sig2
            )

        # Try with sequence=0 (lower) - should fail
        transcript0 = compute_rotation_transcript(alice_new.pubkey, alice_newer.pubkey, 0)
        sig0 = schnorr_sign(alice_new.privkey, alice_new.pubkey, transcript0)
        with pytest.raises(TrustError, match="sequence replay"):
            store.rotate_key_semantics_for_test(alice_new.pubkey, alice_newer.pubkey, 0, sig0)

        # Rotation with seq=2 should work
        rotation_seq2 = 2
        transcript3 = compute_rotation_transcript(
            alice_new.pubkey, alice_newer.pubkey, rotation_seq2
        )
        sig3 = schnorr_sign(alice_new.privkey, alice_new.pubkey, transcript3)
        new_entry = store.rotate_key_semantics_for_test(
            alice_new.pubkey, alice_newer.pubkey, rotation_seq2, sig3
        )
        assert new_entry.rotation_sequence == 2

    def test_rotate_key_rejects_wrong_transcript_keys(self):
        """rotate_key rejects signature over transcript with wrong keys."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        alice_new = Identity.from_seed(SEED_BOB)
        charlie = Identity.from_seed(SEED_CHARLIE)

        store.verify_or_pin(alice.pubkey, alice.iid)

        # Sign transcript with DIFFERENT new_pubkey than what we pass to rotate_key
        rotation_seq = 1
        wrong_transcript = compute_rotation_transcript(alice.pubkey, charlie.pubkey, rotation_seq)
        sig = schnorr_sign(alice.privkey, alice.pubkey, wrong_transcript)

        # This should fail - signature is over transcript with charlie's key, not alice_new's
        with pytest.raises(TrustError, match="signature verification failed"):
            store.rotate_key_semantics_for_test(alice.pubkey, alice_new.pubkey, rotation_seq, sig)

    def test_rotate_key_rejects_existing_destination_pin_without_mutation(self):
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)
        store.verify_or_pin(alice.pubkey, alice.iid)
        store.add_trust_anchor(bob.pubkey, TrustLevel.PKIX, {"role": "root"})
        transcript = compute_rotation_transcript(alice.pubkey, bob.pubkey, 1)
        signature = schnorr_sign(alice.privkey, alice.pubkey, transcript)

        with pytest.raises(KeyMismatchError, match="already pinned"):
            store.rotate_key_semantics_for_test(alice.pubkey, bob.pubkey, 1, signature)

        assert store.get(alice.iid) is not None
        bob_entry = store.get(bob.iid)
        assert bob_entry is not None
        assert bob_entry.trust_level is TrustLevel.PKIX
        assert bob_entry.metadata == {"role": "root"}


class TestTrustStoreListEntries:
    """Tests for listing trust store entries."""

    def test_list_all_entries(self):
        """list_entries returns all entries."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)

        store.verify_or_pin(alice.pubkey, alice.iid)
        store.verify_or_pin(bob.pubkey, bob.iid)

        entries = store.list_entries()
        assert len(entries) == 2

    def test_list_excludes_revoked_by_default(self):
        """list_entries excludes revoked entries by default."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)

        store.verify_or_pin(alice.pubkey, alice.iid)
        store.verify_or_pin(bob.pubkey, bob.iid)
        store.revoke(alice.iid)

        entries = store.list_entries()
        assert len(entries) == 1
        assert entries[0].pubkey == bob.pubkey

    def test_list_includes_revoked_when_requested(self):
        """list_entries includes revoked when include_revoked=True."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)

        store.verify_or_pin(alice.pubkey, alice.iid)
        store.revoke(alice.iid)

        entries = store.list_entries(include_revoked=True)
        assert len(entries) == 1

    def test_list_by_trust_level(self):
        """list_entries filters by trust level."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)

        store.verify_or_pin(alice.pubkey, alice.iid)
        store.add_trust_anchor(bob.pubkey, TrustLevel.BR_PROVISIONED)

        tofu_entries = store.list_entries(trust_level=TrustLevel.TOFU)
        br_entries = store.list_entries(trust_level=TrustLevel.BR_PROVISIONED)

        assert len(tofu_entries) == 1
        assert len(br_entries) == 1
        assert tofu_entries[0].pubkey == alice.pubkey
        assert br_entries[0].pubkey == bob.pubkey


class TestTrustVectorGeneration:
    """Tests for test vector generation and verification."""

    def test_generate_trust_vector(self):
        """generate_trust_vector produces valid test vector."""
        vector = generate_trust_vector(SEED_ALICE)

        assert "seed_hex" in vector
        assert "pubkey_hex" in vector
        assert "iid_hex" in vector
        assert "ygg_addr_hex" in vector
        assert "ygg_addr_str" in vector
        assert "trust_level" in vector
        assert "derivation_valid" in vector

        # Verify determinism
        vector2 = generate_trust_vector(SEED_ALICE)
        assert vector["pubkey_hex"] == vector2["pubkey_hex"]
        assert vector["iid_hex"] == vector2["iid_hex"]

    def test_verify_trust_vector_valid(self):
        """verify_trust_vector returns True for valid vector."""
        vector = generate_trust_vector(SEED_ALICE)
        assert verify_trust_vector(vector)

    def test_verify_trust_vector_invalid(self):
        """verify_trust_vector returns False for tampered vector."""
        vector = generate_trust_vector(SEED_ALICE)
        # Tamper with IID
        vector["iid_hex"] = "00" * 8
        assert not verify_trust_vector(vector)


class TestTrustLevel:
    """Tests for TrustLevel enum."""

    def test_trust_level_ordering(self):
        """TrustLevel values are ordered by verification strength."""
        assert TrustLevel.TOFU < TrustLevel.BR_PROVISIONED
        assert TrustLevel.BR_PROVISIONED < TrustLevel.DANE
        assert TrustLevel.DANE < TrustLevel.PKIX

    def test_trust_level_names(self):
        """TrustLevel names are correct."""
        assert TrustLevel.TOFU.name == "TOFU"
        assert TrustLevel.BR_PROVISIONED.name == "BR_PROVISIONED"
        assert TrustLevel.DANE.name == "DANE"
        assert TrustLevel.PKIX.name == "PKIX"


class TestTrustStoreClear:
    """Tests for clearing the trust store."""

    def test_clear_removes_all_entries(self):
        """clear() removes all entries."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)

        store.verify_or_pin(alice.pubkey, alice.iid)
        store.verify_or_pin(bob.pubkey, bob.iid)
        assert len(store) == 2

        store.clear()
        assert len(store) == 0


class TestMixedModeDeployment:
    """Tests for mixed TOFU + BR-provisioned deployments."""

    def test_mixed_mode_interop(self):
        """TOFU and BR-provisioned nodes can coexist."""
        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)  # Self-provisioned (TOFU)
        bob = Identity.from_seed(SEED_BOB)  # BR-provisioned

        # Bob is pre-provisioned by BR
        store.add_trust_anchor(bob.pubkey, TrustLevel.BR_PROVISIONED)

        # Alice contacts us via TOFU
        store.verify_or_pin(alice.pubkey, alice.iid)

        # Both can be verified
        alice_entry = store.verify_peer(alice.pubkey, alice.iid)
        bob_entry = store.verify_peer(bob.pubkey, bob.iid)

        assert alice_entry.trust_level == TrustLevel.TOFU
        assert bob_entry.trust_level == TrustLevel.BR_PROVISIONED


class TestIdentityCollisionDetection:
    """Tests for identity collision detection (spec 8.7).

    SECURITY: When two different public keys derive to the same IID (a hash
    collision on the 64-bit truncated SHA-512), the TrustStore must reject
    the second key with KeyMismatchError. This prevents key substitution
    attacks even if an attacker finds a collision.

    Note: Finding such a collision is computationally infeasible (2^32 birthday
    bound on 64-bit IIDs), but the code path must handle it correctly.
    """

    def test_collision_detection_raises_key_mismatch(self):
        """TrustStore raises KeyMismatchError on identity collision.

        This test simulates a hash collision scenario by mocking the
        derivation check to pass for a different pubkey.
        """
        from unittest.mock import patch

        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)

        # Pin Alice's key for her IID
        store.verify_or_pin(alice.pubkey, alice.iid)

        # Simulate collision: Bob's key "derives" to Alice's IID
        # (In reality this is computationally infeasible, but we mock it)
        with (
            patch(
                "lichen.crypto.trust.verify_pubkey_derivation",
                return_value=True,
            ),
            pytest.raises(KeyMismatchError),
        ):
            # Bob presents his key claiming Alice's IID
            store.verify_or_pin(bob.pubkey, alice.iid)

    def test_collision_detection_in_verify_peer(self):
        """verify_peer also detects identity collisions."""
        from unittest.mock import patch

        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        charlie = Identity.from_seed(SEED_CHARLIE)

        # Pin Alice
        store.verify_or_pin(alice.pubkey, alice.iid)

        # Simulate collision with Charlie's key
        with (
            patch(
                "lichen.crypto.trust.verify_pubkey_derivation",
                return_value=True,
            ),
            pytest.raises(KeyMismatchError),
        ):
            store.verify_peer(charlie.pubkey, alice.iid)

    def test_collision_detection_preserves_pinned_key(self):
        """Collision attempt does not modify the pinned entry."""
        from unittest.mock import patch

        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)

        # Pin Alice
        store.verify_or_pin(alice.pubkey, alice.iid)
        original_entry = store.get(alice.iid)
        original_last_seen = original_entry.last_seen

        # Collision attempt should fail but not modify entry
        with (
            patch(
                "lichen.crypto.trust.verify_pubkey_derivation",
                return_value=True,
            ),
            pytest.raises(KeyMismatchError),
        ):
            store.verify_or_pin(bob.pubkey, alice.iid)

        # Entry unchanged
        entry = store.get(alice.iid)
        assert entry.pubkey == alice.pubkey
        assert entry.last_seen == original_last_seen
        assert len(store) == 1

    def test_key_mismatch_error_contains_details(self):
        """KeyMismatchError message contains useful debug info."""
        from unittest.mock import patch

        store = TrustStore(auto_pin=True)
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)

        store.verify_or_pin(alice.pubkey, alice.iid)

        with patch(
            "lichen.crypto.trust.verify_pubkey_derivation",
            return_value=True,
        ):
            with pytest.raises(KeyMismatchError) as exc_info:
                store.verify_or_pin(bob.pubkey, alice.iid)

            # Error message should mention IID for debugging
            assert alice.iid.hex() in str(exc_info.value)
