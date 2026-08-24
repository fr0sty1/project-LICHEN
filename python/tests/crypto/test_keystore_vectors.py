# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Cross-validation tests for Key Store against test vectors.

Validates Python implementation against test/vectors/keystore_iid.json
and test/vectors/keystore_cbor.json per spec section 17.5.5.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import cbor2
import pytest

from lichen.crypto.identity import _pubkey_to_iid

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


def _load(name: str) -> dict:
    return json.loads((VECTORS_DIR / name).read_text())


# ============================================================================
# IID Format Parsing and Validation
# ============================================================================

# IID format: xxxx:xxxx:xxxx:xxxx (4 groups of 4 hex digits, colon-separated)
IID_PATTERN = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}:[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$")


def parse_iid(path: str) -> tuple[bool, str | None, str | None]:
    """Parse IID from /keys/{iid} path.

    Returns:
        (valid, normalized_iid, reason) tuple.
        If valid=True, normalized_iid is lowercase IID.
        If valid=False, reason describes the error.
    """
    # Strip /keys/ prefix
    if not path.startswith("/keys/"):
        return False, None, "invalid_path_prefix"

    iid_part = path[6:]  # Skip "/keys/"

    if not iid_part:
        return False, None, "empty_iid"

    # Check for missing separators (raw hex without colons)
    if re.match(r"^[0-9a-fA-F]{16}$", iid_part):
        return False, None, "missing_separators"

    # Check for wrong separator (dash instead of colon)
    if re.match(r"^[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}$", iid_part):
        return False, None, "invalid_separator"

    # Split by colon and validate segment count
    segments = iid_part.split(":")
    if len(segments) < 4:
        return False, None, "wrong_segment_count"
    if len(segments) > 4:
        return False, None, "wrong_segment_count"

    # Validate each segment
    for seg in segments:
        if len(seg) < 4:
            return False, None, "segment_too_short"
        if len(seg) > 4:
            return False, None, "segment_too_long"
        # Check for non-hex characters
        if not re.match(r"^[0-9a-fA-F]{4}$", seg):
            return False, None, "invalid_hex_character"

    # Normalize to lowercase
    normalized = iid_part.lower()
    return True, normalized, None


def iid_text_to_bytes(iid_text: str) -> bytes:
    """Convert IID text format (xxxx:xxxx:xxxx:xxxx) to 8 bytes."""
    return bytes.fromhex(iid_text.replace(":", ""))


# ============================================================================
# IID Validation Test Vectors
# ============================================================================


def _iid_syntax_cases():
    """Get IID vectors that test syntactic format validation (not semantic)."""
    doc = _load("keystore_iid.json")
    assert doc["format_version"] == 2
    # Filter out semantic validation cases (pubkey derivation mismatch)
    return [
        (v["name"], v)
        for v in doc["vectors"]
        if v["expected"].get("reason") != "iid_pubkey_mismatch"
    ]


@pytest.mark.parametrize("name,vector", _iid_syntax_cases())
def test_iid_syntax_validation(name: str, vector: dict) -> None:
    """Test IID syntactic format validation against vectors."""
    path = vector["path"]
    expected = vector["expected"]

    valid, normalized, reason = parse_iid(path)

    assert valid == expected["valid"], f"{name}: validity mismatch"

    if expected["valid"]:
        # Check normalization if specified
        if "normalized" in expected:
            assert normalized == expected["normalized"], f"{name}: normalization mismatch"
        # Check bytes conversion if specified
        if "iid_bytes" in expected:
            iid_bytes = iid_text_to_bytes(normalized)
            assert iid_bytes.hex() == expected["iid_bytes"], f"{name}: bytes mismatch"
    else:
        # Check error reason if specified
        if "reason" in expected:
            assert reason == expected["reason"], f"{name}: reason mismatch"


def _iid_semantic_cases():
    """Get IID vectors that test semantic validation (pubkey derivation)."""
    doc = _load("keystore_iid.json")
    assert doc["format_version"] == 2
    return [
        (v["name"], v)
        for v in doc["vectors"]
        if v["expected"].get("reason") == "iid_pubkey_mismatch"
    ]


@pytest.mark.parametrize("name,vector", _iid_semantic_cases())
def test_iid_semantic_validation(name: str, vector: dict) -> None:
    """Test IID-pubkey derivation mismatch detection."""
    path = vector["path"]
    expected = vector["expected"]

    # IID format is syntactically valid
    valid_syntax, normalized, _ = parse_iid(path)
    assert valid_syntax, f"{name}: IID should be syntactically valid"

    # But semantic validation fails (IID doesn't match pubkey derivation)
    pubkey = bytes.fromhex(vector["pubkey_hex"])
    derived_iid = _pubkey_to_iid(pubkey)
    claimed_iid = iid_text_to_bytes(normalized)

    # IID should NOT match derived IID
    iid_matches = derived_iid == claimed_iid
    assert not iid_matches, f"{name}: IID should not match pubkey derivation"

    # Verify the expected derived IID is correct
    expected_derived = iid_text_to_bytes(vector["derived_iid"])
    assert derived_iid == expected_derived, f"{name}: derived IID mismatch"

    # Request should be rejected
    assert expected["valid"] is False
    assert expected["response_code"] == "4.00 Bad Request"


def test_iid_pubkey_derivation_match() -> None:
    """Test IID derivation from pubkey matches expected (spec 8.5/8.7)."""
    doc = _load("keystore_iid.json")
    for vector in doc["vectors"]:
        if "pubkey_hex" not in vector:
            continue

        pubkey = bytes.fromhex(vector["pubkey_hex"])
        derived_iid = _pubkey_to_iid(pubkey)

        path = vector["path"]
        # Extract IID from path
        iid_text = path.split("/keys/")[1]

        if vector["expected"].get("iid_matches_pubkey"):
            # IID in path should match derived IID
            expected_iid = iid_text_to_bytes(iid_text.lower())
            assert derived_iid == expected_iid, (
                f"IID derivation mismatch for {vector['name']}: "
                f"derived={derived_iid.hex()}, expected={expected_iid.hex()}"
            )
        elif "derived_iid" in vector:
            # Check the correct derived IID
            correct_iid = iid_text_to_bytes(vector["derived_iid"])
            assert derived_iid == correct_iid, (
                f"IID derivation mismatch for {vector['name']}: "
                f"derived={derived_iid.hex()}, expected={correct_iid.hex()}"
            )


# ============================================================================
# CBOR Encoding Tests
# ============================================================================


def test_empty_keystore_cbor() -> None:
    """Test CBOR encoding for empty keystore response."""
    doc = _load("keystore_cbor.json")
    for vector in doc["vectors"]["list_keys_response"]:
        if vector["name"] == "empty_keystore":
            expected_cbor = bytes.fromhex(vector["cbor_hex"])
            response = vector["response"]

            # Encode response to CBOR
            encoded = cbor2.dumps(response)

            # CBOR encoding should match
            assert encoded == expected_cbor, (
                f"CBOR mismatch for empty_keystore: "
                f"got={encoded.hex()}, expected={expected_cbor.hex()}"
            )

            # Decode should round-trip
            decoded = cbor2.loads(expected_cbor)
            assert decoded == response
            break


# ============================================================================
# Trust Level Tests
# ============================================================================

VALID_TRUST_LEVELS = frozenset({"tofu", "verified", "revoked"})


def _trust_level_cases():
    doc = _load("keystore_cbor.json")
    return [(v["name"], v) for v in doc["vectors"]["trust_levels"]]


@pytest.mark.parametrize("name,vector", _trust_level_cases())
def test_trust_level_validation(name: str, vector: dict) -> None:
    """Test trust level validation against vectors."""
    trust = vector["trust"]
    expected_valid = vector["valid"]

    # Check if trust level is valid
    is_valid = trust in VALID_TRUST_LEVELS

    assert is_valid == expected_valid, f"{name}: trust level validity mismatch"


# ============================================================================
# IID Format Tests (from CBOR vectors)
# ============================================================================


def _iid_format_cases():
    doc = _load("keystore_cbor.json")
    return [(v["name"], v) for v in doc["vectors"]["iid_format"]]


@pytest.mark.parametrize("name,vector", _iid_format_cases())
def test_cbor_iid_format(name: str, vector: dict) -> None:
    """Test IID format validation from CBOR vectors."""
    iid = vector["iid"]
    expected_valid = vector["valid"]

    # Validate IID format
    is_valid = bool(IID_PATTERN.match(iid))

    assert is_valid == expected_valid, f"{name}: IID format validity mismatch"

    if expected_valid and "normalized" in vector:
        # Check normalization
        normalized = iid.lower()
        assert normalized == vector["normalized"], f"{name}: normalization mismatch"


# ============================================================================
# CBOR Encoding Format Tests
# ============================================================================


def _cbor_encoding_cases():
    doc = _load("keystore_cbor.json")
    return [(v["name"], v) for v in doc["vectors"]["cbor_encoding"]]


@pytest.mark.parametrize("name,vector", _cbor_encoding_cases())
def test_cbor_encoding_format(name: str, vector: dict) -> None:
    """Test CBOR encoding format constraints."""
    if "pubkey" in vector:
        # Verify pubkey is 32 bytes
        pubkey_hex = vector["pubkey"]
        pubkey = bytes.fromhex(pubkey_hex)
        assert len(pubkey) == vector["pubkey_bytes"], f"{name}: pubkey length mismatch"
        assert len(pubkey) == 32, f"{name}: Ed25519 pubkey must be 32 bytes"

    if "timestamp" in vector:
        # Verify timestamp format is ISO 8601 with Z suffix
        timestamp = vector["timestamp"]
        assert timestamp.endswith("Z"), f"{name}: timestamp must end with Z"
        assert "T" in timestamp, f"{name}: timestamp must have T separator"

    if "pubkey_fp" in vector:
        # Verify fingerprint format is SHA256: prefix + hex hash
        fp = vector["pubkey_fp"]
        assert fp.startswith("SHA256:"), f"{name}: fingerprint must have SHA256: prefix"
        hash_part = fp.split(":")[1]
        hash_bytes = bytes.fromhex(hash_part)
        assert len(hash_bytes) == vector["fingerprint_bytes"], f"{name}: hash length mismatch"


# ============================================================================
# Response Code Tests
# ============================================================================


def test_get_key_response_codes() -> None:
    """Test expected CoAP response codes for GET /keys/{iid}."""
    doc = _load("keystore_cbor.json")
    for vector in doc["vectors"]["get_key_response"]:
        if "response_code" in vector:
            # Key not found returns 4.04
            assert vector["response_code"] == "4.04"
            assert vector["name"] == "key_not_found"


def test_put_key_response_codes() -> None:
    """Test expected CoAP response codes for PUT /keys/{iid}."""
    doc = _load("keystore_cbor.json")
    for vector in doc["vectors"]["put_key_request"]:
        if vector["name"] == "add_tofu_key":
            assert vector["response_code"] == "2.01"  # Created
        elif vector["name"] in ("update_to_verified", "revoke_key"):
            assert vector["response_code"] == "2.04"  # Changed


def test_delete_key_response_codes() -> None:
    """Test expected CoAP response codes for DELETE /keys/{iid}."""
    doc = _load("keystore_cbor.json")
    for vector in doc["vectors"]["delete_key"]:
        if vector["name"] == "delete_existing":
            assert vector["response_code"] == "2.02"  # Deleted
        elif vector["name"] == "delete_nonexistent":
            assert vector["response_code"] == "4.04"  # Not Found


# ============================================================================
# Key Data Structure Tests
# ============================================================================


def test_key_response_structure() -> None:
    """Test key response structure matches spec 17.5.5."""
    doc = _load("keystore_cbor.json")

    for vector in doc["vectors"]["get_key_response"]:
        if "response" not in vector:
            continue

        response = vector["response"]

        # Required fields for key details
        assert "iid" in response
        assert "pubkey" in response
        assert "trust" in response
        assert "first_seen" in response
        assert "last_seen" in response

        # Validate pubkey is hex string (32 bytes = 64 hex chars)
        assert len(response["pubkey"]) == 64

        # Validate IID format
        assert IID_PATTERN.match(response["iid"])


def test_list_keys_response_structure() -> None:
    """Test list keys response structure matches spec 17.5.5."""
    doc = _load("keystore_cbor.json")

    for vector in doc["vectors"]["list_keys_response"]:
        response = vector["response"]

        # Must have keys array
        assert "keys" in response
        assert isinstance(response["keys"], list)

        for key_info in response["keys"]:
            # List entries have fingerprint, not full pubkey
            assert "iid" in key_info
            assert "pubkey_fp" in key_info
            assert "trust" in key_info
            assert "first_seen" in key_info
            assert "last_seen" in key_info

            # Fingerprint format
            if "pubkey_fp" in key_info:
                assert key_info["pubkey_fp"].startswith("SHA256:")
