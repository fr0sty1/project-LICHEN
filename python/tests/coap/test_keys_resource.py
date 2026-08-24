# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for KeyStoreResource (/keys) CoAP resource."""

from __future__ import annotations

import base64

import cbor2
import pytest
from aiocoap import BAD_REQUEST, CHANGED, CREATED, DELETED, GET, NOT_FOUND, Message
from aiocoap.numbers.codes import Code

from lichen.coap.resources.keys import (
    InMemoryPeerKeyStore,
    KeyStoreResource,
)
from lichen.crypto.identity import _pubkey_to_iid

# Valid 32-byte public key for testing
VALID_PUBKEY = bytes(range(32))
VALID_PUBKEY_B64 = base64.b64encode(VALID_PUBKEY).decode()

# Derived IID for VALID_PUBKEY (SHA-512(pubkey)[0:8] with U/L bit cleared)
VALID_PUBKEY_IID = _pubkey_to_iid(VALID_PUBKEY)
VALID_PUBKEY_IID_TEXT = ":".join(VALID_PUBKEY_IID.hex()[i:i+4] for i in range(0, 16, 4))

# Second pubkey for multi-key tests
VALID_PUBKEY_2 = bytes(range(32, 64))
VALID_PUBKEY_2_IID = _pubkey_to_iid(VALID_PUBKEY_2)
VALID_PUBKEY_2_IID_TEXT = ":".join(VALID_PUBKEY_2_IID.hex()[i:i+4] for i in range(0, 16, 4))


def _make_request(
    code: Code,
    uri_path: tuple[str, ...],
    payload: bytes | None = None,
) -> Message:
    """Create a request message with the given path and payload."""
    msg = Message(code=code)
    msg.opt.uri_path = uri_path
    if payload is not None:
        msg.payload = payload
    return msg


def _cbor_payload(data: dict) -> bytes:
    """Encode data as CBOR payload."""
    return cbor2.dumps(data)


class TestGetList:
    """Tests for GET /keys (list all keys)."""

    @pytest.mark.asyncio
    async def test_get_list_empty(self) -> None:
        """GET /keys returns empty list when no keys stored."""
        resource = KeyStoreResource()
        request = _make_request(GET, ("keys",))
        response = await resource.render_get(request)

        assert response.code == Code.CONTENT
        body = cbor2.loads(response.payload)
        assert body == {"keys": []}

    @pytest.mark.asyncio
    async def test_get_list_with_keys(self) -> None:
        """GET /keys returns list of stored keys."""
        store = InMemoryPeerKeyStore()
        store.set_key(VALID_PUBKEY_IID_TEXT, VALID_PUBKEY, "tofu")
        store.set_key(VALID_PUBKEY_2_IID_TEXT, VALID_PUBKEY_2, "pinned")
        resource = KeyStoreResource(peer_store=store)

        request = _make_request(GET, ("keys",))
        response = await resource.render_get(request)

        assert response.code == Code.CONTENT
        body = cbor2.loads(response.payload)
        assert "keys" in body
        assert len(body["keys"]) == 2

        iids = {k["iid"] for k in body["keys"]}
        assert iids == {VALID_PUBKEY_IID_TEXT, VALID_PUBKEY_2_IID_TEXT}

        # Verify key metadata structure
        for key_info in body["keys"]:
            assert "iid" in key_info
            assert "pubkey_fp" in key_info
            assert "trust" in key_info
            assert "first_seen" in key_info
            assert "last_seen" in key_info


class TestGetSpecific:
    """Tests for GET /keys/{iid}."""

    @pytest.mark.asyncio
    async def test_get_specific_key_exists(self) -> None:
        """GET /keys/{iid} returns key details when found."""
        store = InMemoryPeerKeyStore()
        store.set_key(VALID_PUBKEY_IID_TEXT, VALID_PUBKEY, "verified")
        resource = KeyStoreResource(peer_store=store)

        iid_segments = VALID_PUBKEY_IID_TEXT.split(":")
        request = _make_request(GET, ("keys", *iid_segments))
        response = await resource.render_get(request)

        assert response.code == Code.CONTENT
        body = cbor2.loads(response.payload)
        assert body["iid"] == VALID_PUBKEY_IID_TEXT
        assert body["pubkey"] == VALID_PUBKEY_B64
        assert body["trust"] == "verified"
        assert "first_seen" in body
        assert "last_seen" in body

    @pytest.mark.asyncio
    async def test_get_specific_key_not_found(self) -> None:
        """GET /keys/{iid} returns NOT_FOUND when key doesn't exist."""
        resource = KeyStoreResource()
        request = _make_request(GET, ("keys", "1111", "2222", "3333", "4444"))
        response = await resource.render_get(request)

        assert response.code == NOT_FOUND


class TestPut:
    """Tests for PUT /keys/{iid}."""

    @pytest.mark.asyncio
    async def test_put_creates_new_key(self) -> None:
        """PUT /keys/{iid} with new IID returns CREATED."""
        resource = KeyStoreResource()
        payload = _cbor_payload({"pubkey": VALID_PUBKEY_B64, "trust": "tofu"})
        # Use correct derived IID for VALID_PUBKEY
        iid_segments = VALID_PUBKEY_IID_TEXT.split(":")
        request = _make_request(GET, ("keys", *iid_segments), payload)

        response = await resource.render_put(request)

        assert response.code == CREATED

    @pytest.mark.asyncio
    async def test_put_updates_existing_key(self) -> None:
        """PUT /keys/{iid} with existing IID returns CHANGED."""
        store = InMemoryPeerKeyStore()
        store.set_key(VALID_PUBKEY_IID_TEXT, VALID_PUBKEY, "tofu")
        resource = KeyStoreResource(peer_store=store)

        # Same pubkey, just updating trust level
        payload = _cbor_payload({"pubkey": VALID_PUBKEY_B64, "trust": "pinned"})
        iid_segments = VALID_PUBKEY_IID_TEXT.split(":")
        request = _make_request(GET, ("keys", *iid_segments), payload)

        response = await resource.render_put(request)

        assert response.code == CHANGED

        # Verify the key was updated
        key_data = store.get_key(VALID_PUBKEY_IID_TEXT)
        assert key_data is not None
        assert key_data["pubkey"] == VALID_PUBKEY_B64
        assert key_data["trust"] == "pinned"

    @pytest.mark.asyncio
    async def test_put_missing_pubkey_returns_bad_request(self) -> None:
        """PUT /keys/{iid} without pubkey returns BAD_REQUEST."""
        resource = KeyStoreResource()
        payload = _cbor_payload({"trust": "tofu"})
        request = _make_request(GET, ("keys", "alice"), payload)

        response = await resource.render_put(request)

        assert response.code == BAD_REQUEST

    @pytest.mark.asyncio
    async def test_put_empty_pubkey_returns_bad_request(self) -> None:
        """PUT /keys/{iid} with empty pubkey returns BAD_REQUEST."""
        resource = KeyStoreResource()
        payload = _cbor_payload({"pubkey": "", "trust": "tofu"})
        request = _make_request(GET, ("keys", "alice"), payload)

        response = await resource.render_put(request)

        assert response.code == BAD_REQUEST

    @pytest.mark.asyncio
    async def test_put_invalid_trust_returns_bad_request(self) -> None:
        """PUT /keys/{iid} with invalid trust level returns BAD_REQUEST."""
        resource = KeyStoreResource()
        payload = _cbor_payload({"pubkey": VALID_PUBKEY_B64, "trust": "invalid"})
        request = _make_request(GET, ("keys", "alice"), payload)

        response = await resource.render_put(request)

        assert response.code == BAD_REQUEST

    @pytest.mark.asyncio
    async def test_put_invalid_base64_returns_bad_request(self) -> None:
        """PUT /keys/{iid} with invalid base64 pubkey returns BAD_REQUEST."""
        resource = KeyStoreResource()
        payload = _cbor_payload({"pubkey": "not-valid-base64!!!", "trust": "tofu"})
        request = _make_request(GET, ("keys", "alice"), payload)

        response = await resource.render_put(request)

        assert response.code == BAD_REQUEST

    @pytest.mark.asyncio
    async def test_put_wrong_pubkey_length_returns_bad_request(self) -> None:
        """PUT /keys/{iid} with wrong pubkey length returns BAD_REQUEST."""
        resource = KeyStoreResource()
        # 16 bytes instead of 32
        short_pubkey = base64.b64encode(bytes(range(16))).decode()
        payload = _cbor_payload({"pubkey": short_pubkey, "trust": "tofu"})
        request = _make_request(GET, ("keys", "alice"), payload)

        response = await resource.render_put(request)

        assert response.code == BAD_REQUEST

    @pytest.mark.asyncio
    async def test_put_on_root_returns_method_not_allowed(self) -> None:
        """PUT /keys (root) returns METHOD_NOT_ALLOWED."""
        from aiocoap import METHOD_NOT_ALLOWED

        resource = KeyStoreResource()
        payload = _cbor_payload({"pubkey": VALID_PUBKEY_B64, "trust": "tofu"})
        request = _make_request(GET, ("keys",), payload)

        response = await resource.render_put(request)

        assert response.code == METHOD_NOT_ALLOWED

    @pytest.mark.asyncio
    async def test_put_default_trust_is_tofu(self) -> None:
        """PUT /keys/{iid} without trust defaults to 'tofu'."""
        store = InMemoryPeerKeyStore()
        resource = KeyStoreResource(peer_store=store)
        payload = _cbor_payload({"pubkey": VALID_PUBKEY_B64})
        iid_segments = VALID_PUBKEY_IID_TEXT.split(":")
        request = _make_request(GET, ("keys", *iid_segments), payload)

        response = await resource.render_put(request)

        assert response.code == CREATED
        key_data = store.get_key(VALID_PUBKEY_IID_TEXT)
        assert key_data is not None
        assert key_data["trust"] == "tofu"

    @pytest.mark.asyncio
    async def test_put_empty_payload_returns_bad_request(self) -> None:
        """PUT /keys/{iid} with empty payload returns BAD_REQUEST."""
        resource = KeyStoreResource()
        request = _make_request(GET, ("keys", "alice"))

        response = await resource.render_put(request)

        assert response.code == BAD_REQUEST

    @pytest.mark.asyncio
    async def test_put_invalid_cbor_returns_bad_request(self) -> None:
        """PUT /keys/{iid} with invalid CBOR returns BAD_REQUEST."""
        resource = KeyStoreResource()
        request = _make_request(GET, ("keys", "alice"), b"not-cbor")

        response = await resource.render_put(request)

        assert response.code == BAD_REQUEST

    @pytest.mark.asyncio
    async def test_put_non_dict_payload_returns_bad_request(self) -> None:
        """PUT /keys/{iid} with non-dict CBOR payload returns BAD_REQUEST."""
        resource = KeyStoreResource()
        request = _make_request(GET, ("keys", "alice"), cbor2.dumps(["array"]))

        response = await resource.render_put(request)

        assert response.code == BAD_REQUEST

    @pytest.mark.asyncio
    async def test_put_accepts_all_valid_trust_levels(self) -> None:
        """PUT /keys/{iid} accepts all valid trust levels."""
        valid_trusts = ["tofu", "pinned", "verified", "revoked"]
        iid_segments = VALID_PUBKEY_IID_TEXT.split(":")

        for trust in valid_trusts:
            resource = KeyStoreResource()
            payload = _cbor_payload({"pubkey": VALID_PUBKEY_B64, "trust": trust})
            request = _make_request(GET, ("keys", *iid_segments), payload)

            response = await resource.render_put(request)

            assert response.code in (CREATED, CHANGED), f"Failed for trust={trust}"


class TestPubkeyIidValidation:
    """Tests for pubkey-IID cryptographic binding validation (spec 8.7)."""

    @pytest.mark.asyncio
    async def test_put_valid_iid_binding_succeeds(self) -> None:
        """PUT /keys/{iid} with matching pubkey-IID binding succeeds."""
        resource = KeyStoreResource()
        # Use the correct derived IID for VALID_PUBKEY
        payload = _cbor_payload({"pubkey": VALID_PUBKEY_B64, "trust": "tofu"})
        # IID path segments for xxxx:xxxx:xxxx:xxxx format
        iid_segments = VALID_PUBKEY_IID_TEXT.split(":")
        request = _make_request(GET, ("keys", *iid_segments), payload)

        response = await resource.render_put(request)

        assert response.code == CREATED

    @pytest.mark.asyncio
    async def test_put_iid_mismatch_returns_bad_request(self) -> None:
        """PUT /keys/{iid} with non-matching pubkey returns BAD_REQUEST.

        Per spec 8.7, the IID must be SHA-512(pubkey)[0:8] with U/L bit cleared.
        A pubkey that doesn't derive to the claimed IID is rejected.
        """
        resource = KeyStoreResource()
        payload = _cbor_payload({"pubkey": VALID_PUBKEY_B64, "trust": "tofu"})
        # Use a different valid IID format that doesn't match the pubkey
        wrong_iid = ("keys", "1111", "2222", "3333", "4444")
        request = _make_request(GET, wrong_iid, payload)

        response = await resource.render_put(request)

        assert response.code == BAD_REQUEST

    @pytest.mark.asyncio
    async def test_put_invalid_iid_format_returns_bad_request(self) -> None:
        """PUT /keys/{iid} with invalid IID format returns BAD_REQUEST."""
        resource = KeyStoreResource()
        payload = _cbor_payload({"pubkey": VALID_PUBKEY_B64, "trust": "tofu"})
        # Use an IID format that doesn't match xxxx:xxxx:xxxx:xxxx
        request = _make_request(GET, ("keys", "not-valid-iid"), payload)

        response = await resource.render_put(request)

        assert response.code == BAD_REQUEST

    @pytest.mark.asyncio
    async def test_put_iid_validation_different_pubkeys(self) -> None:
        """PUT /keys/{iid} validates each pubkey against its IID."""
        resource = KeyStoreResource()

        # First pubkey and its derived IID
        pubkey1 = bytes(32)  # All zeros
        pubkey1_b64 = base64.b64encode(pubkey1).decode()
        iid1 = _pubkey_to_iid(pubkey1)
        iid1_text = ":".join(iid1.hex()[i:i+4] for i in range(0, 16, 4))
        iid1_segments = iid1_text.split(":")

        # Should succeed with matching pubkey-IID
        payload = _cbor_payload({"pubkey": pubkey1_b64, "trust": "tofu"})
        request = _make_request(GET, ("keys", *iid1_segments), payload)
        response = await resource.render_put(request)
        assert response.code == CREATED

        # Second pubkey with different IID
        pubkey2 = bytes([0xFF] * 32)  # All 0xFF
        pubkey2_b64 = base64.b64encode(pubkey2).decode()
        iid2 = _pubkey_to_iid(pubkey2)
        iid2_text = ":".join(iid2.hex()[i:i+4] for i in range(0, 16, 4))

        # Should succeed with matching pubkey-IID
        iid2_segments = iid2_text.split(":")
        payload = _cbor_payload({"pubkey": pubkey2_b64, "trust": "tofu"})
        request = _make_request(GET, ("keys", *iid2_segments), payload)
        response = await resource.render_put(request)
        assert response.code == CREATED

        # Should fail if pubkey2 tries to use pubkey1's IID
        payload = _cbor_payload({"pubkey": pubkey2_b64, "trust": "tofu"})
        request = _make_request(GET, ("keys", *iid1_segments), payload)
        response = await resource.render_put(request)
        assert response.code == BAD_REQUEST


class TestDelete:
    """Tests for DELETE /keys/{iid}."""

    @pytest.mark.asyncio
    async def test_delete_existing_key_returns_deleted(self) -> None:
        """DELETE /keys/{iid} for existing key returns DELETED."""
        store = InMemoryPeerKeyStore()
        store.set_key(VALID_PUBKEY_IID_TEXT, VALID_PUBKEY, "tofu")
        resource = KeyStoreResource(peer_store=store)

        # Request with IID path segments
        iid_segments = VALID_PUBKEY_IID_TEXT.split(":")
        request = _make_request(GET, ("keys", *iid_segments))
        response = await resource.render_delete(request)

        assert response.code == DELETED

        # Verify key was actually deleted
        assert store.get_key(VALID_PUBKEY_IID_TEXT) is None

    @pytest.mark.asyncio
    async def test_delete_missing_key_returns_not_found(self) -> None:
        """DELETE /keys/{iid} for missing key returns NOT_FOUND."""
        resource = KeyStoreResource()
        request = _make_request(GET, ("keys", "1111", "2222", "3333", "4444"))

        response = await resource.render_delete(request)

        assert response.code == NOT_FOUND

    @pytest.mark.asyncio
    async def test_delete_on_root_returns_method_not_allowed(self) -> None:
        """DELETE /keys (root) returns METHOD_NOT_ALLOWED."""
        from aiocoap import METHOD_NOT_ALLOWED

        resource = KeyStoreResource()
        request = _make_request(GET, ("keys",))

        response = await resource.render_delete(request)

        assert response.code == METHOD_NOT_ALLOWED


class TestIidExtraction:
    """Tests for IID extraction from path."""

    @pytest.mark.asyncio
    async def test_iid_with_colon_reconstructed(self) -> None:
        """IID containing colons is reconstructed from path segments."""
        store = InMemoryPeerKeyStore()
        # IID with colons like "fe80::1"
        iid = "fe80::1"
        store.set_key(iid, VALID_PUBKEY, "tofu")
        resource = KeyStoreResource(peer_store=store)

        # Path segments for coap://server/keys/fe80::1
        # becomes ("keys", "fe80", "", "1") - empty strings for consecutive colons
        request = _make_request(GET, ("keys", "fe80", "", "1"))
        response = await resource.render_get(request)

        assert response.code == Code.CONTENT
        body = cbor2.loads(response.payload)
        assert body["iid"] == iid


class TestInMemoryPeerKeyStore:
    """Tests for the InMemoryPeerKeyStore implementation."""

    def test_list_keys_empty(self) -> None:
        """list_keys returns empty list when no keys stored."""
        store = InMemoryPeerKeyStore()
        assert store.list_keys() == []

    def test_set_key_returns_true_for_new_key(self) -> None:
        """set_key returns True when creating new key."""
        store = InMemoryPeerKeyStore()
        result = store.set_key("alice", VALID_PUBKEY, "tofu")
        assert result is True

    def test_set_key_returns_false_for_existing_key(self) -> None:
        """set_key returns False when updating existing key."""
        store = InMemoryPeerKeyStore()
        store.set_key("alice", VALID_PUBKEY, "tofu")
        result = store.set_key("alice", VALID_PUBKEY, "pinned")
        assert result is False

    def test_delete_key_returns_true_when_deleted(self) -> None:
        """delete_key returns True when key existed."""
        store = InMemoryPeerKeyStore()
        store.set_key("alice", VALID_PUBKEY, "tofu")
        result = store.delete_key("alice")
        assert result is True

    def test_delete_key_returns_false_when_not_found(self) -> None:
        """delete_key returns False when key doesn't exist."""
        store = InMemoryPeerKeyStore()
        result = store.delete_key("nonexistent")
        assert result is False

    def test_get_key_returns_none_when_not_found(self) -> None:
        """get_key returns None when key doesn't exist."""
        store = InMemoryPeerKeyStore()
        result = store.get_key("nonexistent")
        assert result is None

    def test_list_keys_returns_fingerprints(self) -> None:
        """list_keys returns fingerprints, not full pubkeys."""
        store = InMemoryPeerKeyStore()
        store.set_key("alice", VALID_PUBKEY, "tofu")
        keys = store.list_keys()

        assert len(keys) == 1
        assert "pubkey_fp" in keys[0]
        assert keys[0]["pubkey_fp"].startswith("SHA256:")
        assert "pubkey" not in keys[0]  # Full pubkey not in list

    def test_get_key_returns_full_pubkey(self) -> None:
        """get_key returns full pubkey as base64."""
        store = InMemoryPeerKeyStore()
        store.set_key("alice", VALID_PUBKEY, "tofu")
        key_data = store.get_key("alice")

        assert key_data is not None
        assert key_data["pubkey"] == VALID_PUBKEY_B64
