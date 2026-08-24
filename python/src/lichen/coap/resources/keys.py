# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Key store CoAP resources (spec 17.5.5).

Provides:
- GET /keys: List known peer keys
- GET /keys/{iid}: Get specific peer key details
- PUT /keys/{iid}: Add/update peer key trust
- DELETE /keys/{iid}: Remove peer key
"""

from __future__ import annotations

import base64
import hmac
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

import cbor2
from aiocoap import CHANGED, CREATED, DELETED, NOT_FOUND, Message, resource

from lichen.coap.resources.base import CBOR, _cbor_response
from lichen.crypto.identity import _pubkey_to_iid


class PeerKeyStore(Protocol):
    """Interface for peer key storage."""

    def list_keys(self) -> list[dict[str, Any]]:
        """List all known peer keys with metadata."""
        ...

    def get_key(self, iid: str) -> dict[str, Any] | None:
        """Get peer key by IID. Returns None if not found."""
        ...

    def set_key(self, iid: str, pubkey: bytes, trust: str) -> bool:
        """Add or update peer key. Returns True if created, False if updated."""
        ...

    def delete_key(self, iid: str) -> bool:
        """Delete peer key. Returns True if deleted, False if not found."""
        ...


@dataclass
class InMemoryPeerKeyStore:
    """Simple in-memory peer key store for testing."""

    _keys: dict[str, dict[str, Any]] = field(default_factory=dict)

    def list_keys(self) -> list[dict[str, Any]]:
        return [
            {
                "iid": iid,
                "pubkey_fp": f"SHA256:{entry['pubkey'][:16].hex()}...",
                "trust": entry["trust"],
                "first_seen": entry["first_seen"],
                "last_seen": entry["last_seen"],
            }
            for iid, entry in self._keys.items()
        ]

    def get_key(self, iid: str) -> dict[str, Any] | None:
        entry = self._keys.get(iid)
        if entry is None:
            return None
        return {
            "iid": iid,
            "pubkey": base64.b64encode(entry["pubkey"]).decode("ascii"),
            "trust": entry["trust"],
            "first_seen": entry["first_seen"],
            "last_seen": entry["last_seen"],
        }

    def set_key(self, iid: str, pubkey: bytes, trust: str) -> bool:
        now = datetime.now(UTC).isoformat()
        is_new = iid not in self._keys
        if is_new:
            self._keys[iid] = {
                "pubkey": pubkey,
                "trust": trust,
                "first_seen": now,
                "last_seen": now,
            }
        else:
            self._keys[iid]["pubkey"] = pubkey
            self._keys[iid]["trust"] = trust
            self._keys[iid]["last_seen"] = now
        return is_new

    def delete_key(self, iid: str) -> bool:
        if iid in self._keys:
            del self._keys[iid]
            return True
        return False


VALID_TRUST_LEVELS = frozenset({"tofu", "pinned", "verified", "revoked"})
EXPECTED_PUBKEY_LENGTH = 32

# IID format: xxxx:xxxx:xxxx:xxxx (4 groups of 4 hex digits, colon-separated)
IID_PATTERN = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}:[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$")


def _validate_iid_format(iid: str) -> bool:
    """Validate IID text format (xxxx:xxxx:xxxx:xxxx).

    Returns True if the IID has valid syntactic format.
    """
    return bool(IID_PATTERN.match(iid))


def _iid_text_to_bytes(iid_text: str) -> bytes:
    """Convert IID text format (xxxx:xxxx:xxxx:xxxx) to 8 bytes."""
    return bytes.fromhex(iid_text.replace(":", ""))


def _validate_pubkey_iid_binding(pubkey: bytes, iid_text: str) -> bool:
    """Validate that pubkey derives to the given IID.

    SECURITY: This validates the cryptographic binding between pubkey and IID.
    Per spec 8.7, the IID MUST be SHA-512(pubkey)[0:8] with U/L bit cleared.
    Mismatches indicate MITM or key binding attack.

    Args:
        pubkey: 32-byte Ed25519 public key.
        iid_text: IID in text format (xxxx:xxxx:xxxx:xxxx).

    Returns:
        True if pubkey derives to the given IID.
    """
    if len(pubkey) != EXPECTED_PUBKEY_LENGTH:
        return False
    if not _validate_iid_format(iid_text):
        return False

    derived_iid = _pubkey_to_iid(pubkey)
    claimed_iid = _iid_text_to_bytes(iid_text.lower())

    # SECURITY: Constant-time comparison prevents timing attacks
    return hmac.compare_digest(derived_iid, claimed_iid)


class KeyStoreResource(resource.Resource):
    """Key store CoAP resource (spec 17.5.5).

    Mount at /keys; handles /keys and /keys/{iid} via uri_path.
    """

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "keystore", "ct": str(int(CBOR))}

    def __init__(self, peer_store: PeerKeyStore | None = None) -> None:
        super().__init__()
        self._peer_store = peer_store or InMemoryPeerKeyStore()

    def _extract_iid(self, request: Message) -> str | None:
        """Extract IID from path. Returns None if root /keys."""
        path = request.opt.uri_path or ()
        if len(path) <= 1:
            return None
        return ":".join(path[1:]) if len(path) > 2 else path[1]

    async def render_get(self, request: Message) -> Message:
        """GET /keys or GET /keys/{iid}."""
        iid = self._extract_iid(request)
        if iid is None:
            return _cbor_response({"keys": self._peer_store.list_keys()})
        key_data = self._peer_store.get_key(iid)
        if key_data is None:
            return Message(code=NOT_FOUND)
        return _cbor_response(key_data)

    async def render_put(self, request: Message) -> Message:
        """PUT /keys/{iid}."""
        from aiocoap import BAD_REQUEST, METHOD_NOT_ALLOWED

        iid = self._extract_iid(request)
        if iid is None:
            return Message(code=METHOD_NOT_ALLOWED)
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            payload = cbor2.loads(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        if not isinstance(payload, dict):
            return Message(code=BAD_REQUEST)
        pubkey_b64 = payload.get("pubkey", "")
        trust = payload.get("trust", "tofu")
        if not pubkey_b64:
            return Message(code=BAD_REQUEST)
        if trust not in VALID_TRUST_LEVELS:
            return Message(code=BAD_REQUEST)
        try:
            pubkey = base64.b64decode(pubkey_b64, validate=True)
        except Exception:
            return Message(code=BAD_REQUEST)
        if len(pubkey) != EXPECTED_PUBKEY_LENGTH:
            return Message(code=BAD_REQUEST)
        # SECURITY: Validate pubkey-IID cryptographic binding (spec 8.7).
        # The IID MUST be SHA-512(pubkey)[0:8] with U/L bit cleared.
        # Reject if pubkey doesn't derive to the claimed IID.
        if not _validate_pubkey_iid_binding(pubkey, iid):
            return Message(code=BAD_REQUEST)
        is_new = self._peer_store.set_key(iid, pubkey, trust)
        return Message(code=CREATED if is_new else CHANGED)

    async def render_delete(self, request: Message) -> Message:
        """DELETE /keys/{iid}."""
        from aiocoap import METHOD_NOT_ALLOWED

        iid = self._extract_iid(request)
        if iid is None:
            return Message(code=METHOD_NOT_ALLOWED)
        deleted = self._peer_store.delete_key(iid)
        if not deleted:
            return Message(code=NOT_FOUND)
        return Message(code=DELETED)


class KeyResource(resource.Resource):
    """Legacy GET /keys for local node pubkey only (deprecated).

    Use KeyStoreResource for full key store functionality.
    """

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "keystore", "ct": str(int(CBOR))}

    def __init__(self, pubkey: bytes) -> None:
        super().__init__()
        self._pubkey = pubkey

    async def render_get(self, request: Message) -> Message:
        data = {
            "fingerprint": self._pubkey[:8].hex(),
            "pubkey": self._pubkey,
        }
        return _cbor_response(data)
