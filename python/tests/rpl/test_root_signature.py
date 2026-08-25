# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for root signature oracle (rpl.root_signature)."""

import pytest

from lichen.crypto.identity import Identity, yggdrasil_address
from lichen.crypto.schnorr48 import sign
from lichen.rpl.root_signature import (
    RootSignatureError,
    derive_dodagid_from_pubkey,
    generate_root_signature_vector,
    verify_dodagid_binding,
    verify_root_signature,
    verify_root_signature_vector,
)


class TestVerifyDodagidBinding:
    """Tests for verify_dodagid_binding."""

    def test_valid_binding(self) -> None:
        """Valid pubkey-DODAGID binding should return True."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)
        dodagid = yggdrasil_address(identity.pubkey)

        assert verify_dodagid_binding(identity.pubkey, dodagid.packed) is True
        assert verify_dodagid_binding(identity.pubkey, dodagid) is True

    def test_mismatched_dodagid(self) -> None:
        """Mismatched DODAGID should return False."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)
        # Use a different DODAGID
        wrong_dodagid = bytes(16)

        assert verify_dodagid_binding(identity.pubkey, wrong_dodagid) is False

    def test_wrong_pubkey_length(self) -> None:
        """Invalid pubkey length should return False."""
        dodagid = bytes(16)

        assert verify_dodagid_binding(b"short", dodagid) is False
        assert verify_dodagid_binding(bytes(64), dodagid) is False

    def test_wrong_dodagid_length(self) -> None:
        """Invalid DODAGID length should return False."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)

        assert verify_dodagid_binding(identity.pubkey, bytes(8)) is False
        assert verify_dodagid_binding(identity.pubkey, bytes(32)) is False


class TestVerifyRootSignature:
    """Tests for verify_root_signature."""

    def test_valid_signature_and_binding(self) -> None:
        """Valid signature + DODAGID binding should succeed."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)
        message = b"test DIO message"
        signature = sign(identity.privkey, identity.pubkey, message)
        dodagid = yggdrasil_address(identity.pubkey)

        result = verify_root_signature(
            identity.pubkey, message, signature, dodagid.packed
        )

        assert result.valid is True
        assert result.error is None
        assert result.derived_dodagid == dodagid

    def test_invalid_signature(self) -> None:
        """Invalid signature should fail with SIGNATURE_INVALID."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)
        message = b"test DIO message"
        bad_signature = bytes(48)  # All zeros
        dodagid = yggdrasil_address(identity.pubkey)

        result = verify_root_signature(
            identity.pubkey, message, bad_signature, dodagid.packed
        )

        assert result.valid is False
        assert result.error is RootSignatureError.SIGNATURE_INVALID
        assert result.derived_dodagid == dodagid

    def test_mismatched_dodagid(self) -> None:
        """Mismatched DODAGID should fail with DODAGID_MISMATCH."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)
        message = b"test DIO message"
        signature = sign(identity.privkey, identity.pubkey, message)
        # Use wrong DODAGID (attacker's address)
        wrong_dodagid = bytes(16)

        result = verify_root_signature(
            identity.pubkey, message, signature, wrong_dodagid
        )

        assert result.valid is False
        assert result.error is RootSignatureError.DODAGID_MISMATCH

    def test_invalid_pubkey_length(self) -> None:
        """Invalid pubkey length should fail with PUBKEY_INVALID."""
        result = verify_root_signature(
            b"short",
            b"message",
            bytes(48),
            bytes(16),
        )

        assert result.valid is False
        assert result.error is RootSignatureError.PUBKEY_INVALID
        assert result.derived_dodagid is None

    def test_wrong_message(self) -> None:
        """Signature over different message should fail."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)
        message1 = b"original message"
        message2 = b"tampered message"
        signature = sign(identity.privkey, identity.pubkey, message1)
        dodagid = yggdrasil_address(identity.pubkey)

        result = verify_root_signature(
            identity.pubkey, message2, signature, dodagid.packed
        )

        assert result.valid is False
        assert result.error is RootSignatureError.SIGNATURE_INVALID


class TestDeriveDodagidFromPubkey:
    """Tests for derive_dodagid_from_pubkey."""

    def test_valid_derivation(self) -> None:
        """Should derive correct DODAGID from pubkey."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)
        expected = yggdrasil_address(identity.pubkey)

        result = derive_dodagid_from_pubkey(identity.pubkey)

        assert result == expected
        # Should be a native 0200::/8 address
        assert result.packed[0] == 0x02

    def test_invalid_pubkey_length(self) -> None:
        """Invalid pubkey length should raise ValueError."""
        with pytest.raises(ValueError, match="must be 32 bytes"):
            derive_dodagid_from_pubkey(b"short")


class TestVectorGeneration:
    """Tests for canonical-schema vector helpers."""

    def test_generate_and_verify_vector(self) -> None:
        """Generated vector should verify correctly."""
        seed = bytes(range(32))
        vector = generate_root_signature_vector(seed, b"test message")

        assert vector["valid"] is True
        assert verify_root_signature_vector(vector) is True

    def test_tampered_vector_fails(self) -> None:
        """Tampered vector should fail verification with matching error."""
        seed = bytes(range(32))
        vector = generate_root_signature_vector(seed, b"test message")

        # Tamper with the message
        vector["message"] = b"tampered".hex()
        vector["valid"] = False
        vector["error"] = "SIGNATURE_INVALID"

        assert verify_root_signature_vector(vector) is True  # Now expects failure

    def test_description_is_seed_free(self) -> None:
        """Description must not embed the seed (it derives private keys)."""
        seed = bytes(range(32))
        vector = generate_root_signature_vector(seed)

        assert seed.hex() not in vector["description"]
        assert vector["description"] == "Generated root-signature vector"
        assert vector["error"] is None

    def test_unknown_error_name_rejected(self) -> None:
        """An unmapped/typo'd error name must fail, not silently pass."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)
        signature = sign(identity.privkey, identity.pubkey, b"msg")
        vector = {
            "pubkey": identity.pubkey.hex(),
            "message": b"other".hex(),
            "signature": signature.hex(),
            "dodagid": yggdrasil_address(identity.pubkey).packed.hex(),
            "valid": False,
            "error": "SIGNATURE_INVLAID",  # typo
        }

        assert verify_root_signature_vector(vector) is False

    def test_invalid_without_error_name_rejected(self) -> None:
        """Invalid expectation must declare its failure reason."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)
        signature = sign(identity.privkey, identity.pubkey, b"msg")
        vector = {
            "pubkey": identity.pubkey.hex(),
            "message": b"tampered".hex(),
            "signature": signature.hex(),
            "dodagid": yggdrasil_address(identity.pubkey).packed.hex(),
            "valid": False,
        }

        assert verify_root_signature_vector(vector) is False

    def test_valid_with_error_contradiction_rejected(self) -> None:
        """A success expectation cannot also declare a failure reason."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)
        signature = sign(identity.privkey, identity.pubkey, b"msg")
        vector = {
            "pubkey": identity.pubkey.hex(),
            "message": b"msg".hex(),
            "signature": signature.hex(),
            "dodagid": yggdrasil_address(identity.pubkey).packed.hex(),
            "valid": True,
            "error": "DODAGID_MISMATCH",
        }

        assert verify_root_signature_vector(vector) is False

    def test_binding_valid_is_exclusive(self) -> None:
        """binding_valid must not coexist with signature-expectation keys."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)
        base = {
            "description": "x",
            "pubkey": identity.pubkey.hex(),
            "dodagid": yggdrasil_address(identity.pubkey).packed.hex(),
            "binding_valid": True,
        }
        for extra in (
            {"valid": True},
            {"error": None},
            {"message": b"x".hex()},
            {"signature": bytes(48).hex()},
        ):
            with pytest.raises(ValueError, match="mutually exclusive"):
                verify_root_signature_vector({**base, **extra})

    def test_full_shape_requires_message_and_signature(self) -> None:
        """Full vectors without binding_valid need message and signature."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)
        base = {
            "pubkey": identity.pubkey.hex(),
            "dodagid": yggdrasil_address(identity.pubkey).packed.hex(),
            "valid": True,
        }
        with pytest.raises(KeyError):
            verify_root_signature_vector(dict(base))

    def test_wrong_length_hex_rejected(self) -> None:
        """Fixed-size fields are length-checked before hex decoding."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)
        base = {
            "description": "x",
            "dodagid": yggdrasil_address(identity.pubkey).packed.hex(),
            "binding_valid": True,
        }
        with pytest.raises(ValueError, match="64 hex chars"):
            verify_root_signature_vector(
                {**base, "pubkey": identity.pubkey.hex()[:-2]}
            )

    def test_vector_matches_canonical_schema_keys(self) -> None:
        """Vector should contain the canonical schema fields."""
        seed = bytes(range(32))
        vector = generate_root_signature_vector(seed)

        for key in (
            "description",
            "seed",
            "pubkey",
            "message",
            "signature",
            "dodagid",
            "dodagid_str",
            "valid",
            "error",
        ):
            assert key in vector, f"missing canonical key: {key}"

        # Verify field sizes
        assert len(bytes.fromhex(vector["pubkey"])) == 32
        assert len(bytes.fromhex(vector["signature"])) == 48
        assert len(bytes.fromhex(vector["dodagid"])) == 16

    def test_verify_consumes_committed_vectors(self) -> None:
        """Helper must accept the committed canonical vectors as-is.

        The expected outcomes come from the committed file (independently
        derived literals); this only proves schema compatibility of the
        helper with the canonical format.
        """
        import json
        from pathlib import Path

        vectors_path = (
            Path(__file__).resolve().parents[2] / ".." / "test" / "vectors" / "root_signature.json"
        ).resolve()
        doc = json.loads(vectors_path.read_text())
        for entry in doc["vectors"]:
            assert verify_root_signature_vector(entry), (
                f"helper mismatch on canonical vector: {entry['description']}"
            )


class TestSecurityProperties:
    """Security-focused tests for root signature verification."""

    def test_attacker_cannot_forge_dodagid(self) -> None:
        """Attacker with different key cannot claim victim's DODAGID.

        This is the core security property: the cryptographic binding between
        pubkey and DODAGID prevents impersonation attacks.
        """
        # Victim's identity
        victim_seed = bytes(range(32))
        victim = Identity.from_seed(victim_seed)
        victim_dodagid = yggdrasil_address(victim.pubkey)

        # Attacker's identity
        attacker_seed = bytes([x ^ 0xFF for x in range(32)])
        attacker = Identity.from_seed(attacker_seed)

        # Attacker signs a message
        message = b"malicious DIO"
        attacker_sig = sign(attacker.privkey, attacker.pubkey, message)

        # Attacker claims victim's DODAGID - should fail
        result = verify_root_signature(
            attacker.pubkey, message, attacker_sig, victim_dodagid.packed
        )

        assert result.valid is False
        assert result.error is RootSignatureError.DODAGID_MISMATCH

    def test_legitimate_root_passes_verification(self) -> None:
        """Legitimate root with matching pubkey/DODAGID should pass."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)
        dodagid = yggdrasil_address(identity.pubkey)
        message = b"legitimate DIO with DODAG configuration"
        signature = sign(identity.privkey, identity.pubkey, message)

        result = verify_root_signature(
            identity.pubkey, message, signature, dodagid.packed
        )

        assert result.valid is True
        assert result.derived_dodagid == dodagid

    def test_accepts_ipv6address_dodagid(self) -> None:
        """Should accept IPv6Address as DODAGID."""
        seed = bytes(range(32))
        identity = Identity.from_seed(seed)
        dodagid = yggdrasil_address(identity.pubkey)
        message = b"test"
        signature = sign(identity.privkey, identity.pubkey, message)

        result = verify_root_signature(
            identity.pubkey, message, signature, dodagid  # IPv6Address, not bytes
        )

        assert result.valid is True
