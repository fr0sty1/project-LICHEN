# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""BR provisioning channel encryption.

Per spec section 8.7, BR provisioning channels MUST be encrypted and
authenticated. This module provides:

1. ProvisioningSession: EDHOC-based secure channel establishment
2. ProvisioningPayload: Encrypted seed + pubkey transfer format
3. Secure key deletion after transfer

The provisioning flow:
1. Node boots in commissioning mode
2. Node and BR establish EDHOC session (BR authenticates with Ed25519)
3. BR generates Ed25519 keypair for node
4. BR encrypts seed using session key (AES-CCM-16-64-128)
5. Node decrypts and stores keypair, derives IID/02xx
6. BR securely deletes the seed from memory

SECURITY: The channel MUST be encrypted and authenticated. Plaintext seed
transfer is a critical vulnerability - seed compromise = identity theft.

Transport bindings: USB/BLE/LCI per spec. The encryption layer is transport-
agnostic; callers provide framed bytes.
"""

from __future__ import annotations

import hmac
import os
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING

import cbor2
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from .edhoc import (
    CCM_KEY_LEN,
    CCM_NONCE_LEN,
    CCM_TAG_LEN,
    EdhocInitiator,
    EdhocResponder,
    OscoreContext,
)
from .identity import Identity

if TYPE_CHECKING:
    pass


class ProvisioningError(Exception):
    """Base class for provisioning errors."""


class ChannelNotEstablishedError(ProvisioningError):
    """Raised when attempting operations on an unestablished channel."""


class AuthenticationFailedError(ProvisioningError):
    """Raised when BR authentication fails (signature invalid or key mismatch)."""


class DecryptionFailedError(ProvisioningError):
    """Raised when payload decryption fails (tampered or wrong key)."""


class ProvisioningState(IntEnum):
    """State machine for provisioning channel."""

    IDLE = 0  # Not started
    EDHOC_IN_PROGRESS = 1  # EDHOC handshake ongoing
    ESTABLISHED = 2  # Channel encrypted and authenticated
    COMPLETED = 3  # Seed transferred and verified
    FAILED = 4  # Unrecoverable error


# Provisioning payload type identifiers
PAYLOAD_TYPE_SEED = 0x01  # 32-byte Ed25519 seed
PAYLOAD_TYPE_ACK = 0x02  # Node acknowledgment (derived pubkey)

# AEAD additional data prefix for domain separation
PROVISIONING_AAD_PREFIX = b"LICHEN-PROVISION-v1"


@dataclass
class ProvisioningPayload:
    """Encrypted provisioning payload (CBOR-encoded).

    Wire format:
        {
            "type": int,       # PAYLOAD_TYPE_SEED or PAYLOAD_TYPE_ACK
            "nonce": bytes,    # 13-byte AES-CCM nonce
            "ct": bytes        # Ciphertext + tag
        }

    Plaintext for SEED type: 32-byte Ed25519 seed
    Plaintext for ACK type: 32-byte Ed25519 pubkey (derived from seed)
    """

    payload_type: int
    nonce: bytes
    ciphertext: bytes

    def encode(self) -> bytes:
        """Encode payload as CBOR for transmission."""
        return cbor2.dumps(
            {
                "type": self.payload_type,
                "nonce": self.nonce,
                "ct": self.ciphertext,
            }
        )

    @classmethod
    def decode(cls, data: bytes) -> ProvisioningPayload:
        """Decode CBOR payload from wire format.

        SECURITY: Use generic error messages to prevent oracle attacks. Do not
        reveal WHY decoding failed (CBOR parse error, missing fields, wrong
        types, invalid payload type, wrong nonce length) - all failures return
        the same message.

        Raises:
            ProvisioningError: If payload is malformed or fields are invalid
        """
        # SECURITY: All failures produce the same generic error message to
        # prevent oracle attacks that could distinguish failure modes.
        try:
            obj = cbor2.loads(data)
        except (cbor2.CBORDecodeError, OverflowError):
            raise ProvisioningError("decode failed") from None

        # Validate structure
        if (
            not isinstance(obj, dict)
            or "type" not in obj
            or "nonce" not in obj
            or "ct" not in obj
        ):
            raise ProvisioningError("decode failed")

        # Extract fields (safe after dict/key validation)
        payload_type = obj["type"]
        nonce = obj["nonce"]
        ciphertext = obj["ct"]

        # Validate field types
        # SECURITY: Check bool before int because bool is a subclass of int in Python.
        # isinstance(True, int) returns True, so we must explicitly reject booleans.
        if (
            isinstance(payload_type, bool)
            or not isinstance(payload_type, int)
            or not isinstance(nonce, bytes)
            or not isinstance(ciphertext, bytes)
        ):
            raise ProvisioningError("decode failed")

        # Validate payload type and nonce length
        if (
            payload_type not in (PAYLOAD_TYPE_SEED, PAYLOAD_TYPE_ACK)
            or len(nonce) != CCM_NONCE_LEN
        ):
            raise ProvisioningError("decode failed")

        return cls(
            payload_type=payload_type,
            nonce=nonce,
            ciphertext=ciphertext,
        )


def _derive_provisioning_key(oscore_ctx: OscoreContext) -> bytes:
    """Derive a provisioning-specific key from OSCORE context.

    Uses HKDF-Expand with a provisioning-specific info string to ensure
    the provisioning key is domain-separated from OSCORE traffic keys.
    """
    # SECURITY: Domain separation prevents key reuse attacks between
    # provisioning and normal OSCORE traffic.
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

    info = b"LICHEN-PROVISION-KEY"
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=CCM_KEY_LEN, info=info)
    return hkdf.derive(oscore_ctx.master_secret)


def _encrypt_seed(key: bytes, seed: bytes) -> ProvisioningPayload:
    """Encrypt a 32-byte seed using AES-CCM-16-64-128.

    Args:
        key: 16-byte AES key (derived from OSCORE context)
        seed: 32-byte Ed25519 seed to encrypt

    Returns:
        ProvisioningPayload ready for transmission
    """
    if len(seed) != 32:
        raise ValueError(f"Seed must be 32 bytes, got {len(seed)}")

    nonce = os.urandom(CCM_NONCE_LEN)
    aad = PROVISIONING_AAD_PREFIX + struct.pack(">B", PAYLOAD_TYPE_SEED)

    aesccm = AESCCM(key, tag_length=CCM_TAG_LEN)
    ciphertext = aesccm.encrypt(nonce, seed, aad)

    return ProvisioningPayload(
        payload_type=PAYLOAD_TYPE_SEED,
        nonce=nonce,
        ciphertext=ciphertext,
    )


def _decrypt_seed(key: bytes, payload: ProvisioningPayload) -> bytes:
    """Decrypt seed from provisioning payload.

    Args:
        key: 16-byte AES key (derived from OSCORE context)
        payload: Encrypted provisioning payload

    Returns:
        32-byte Ed25519 seed

    Raises:
        DecryptionFailedError: If decryption or authentication fails
    """
    # SECURITY: Use generic error messages to prevent oracle attacks. Do not
    # reveal WHY decryption failed (type mismatch, nonce length, tag verification,
    # plaintext length) - all failures return the same message. Note: Early exit
    # on malformed metadata (type/nonce) is acceptable since these are not secret.
    valid = True

    if payload.payload_type != PAYLOAD_TYPE_SEED:
        valid = False

    # SECURITY: Validate nonce length per AES-CCM-16-64-128 (13 bytes required).
    # Malformed nonces could cause cryptographic failures or oracle attacks.
    if len(payload.nonce) != CCM_NONCE_LEN:
        valid = False

    if not valid:
        raise DecryptionFailedError("decryption failed")

    aad = PROVISIONING_AAD_PREFIX + struct.pack(">B", PAYLOAD_TYPE_SEED)

    try:
        aesccm = AESCCM(key, tag_length=CCM_TAG_LEN)
        seed = aesccm.decrypt(payload.nonce, payload.ciphertext, aad)
    except Exception:
        # SECURITY: Do not chain exception - it may reveal internal state
        raise DecryptionFailedError("decryption failed") from None

    if len(seed) != 32:
        raise DecryptionFailedError("decryption failed")

    return seed


def _encrypt_ack(key: bytes, pubkey: bytes) -> ProvisioningPayload:
    """Encrypt acknowledgment (derived pubkey) for BR verification.

    Args:
        key: 16-byte AES key (derived from OSCORE context)
        pubkey: 32-byte Ed25519 pubkey (derived from provisioned seed)

    Returns:
        ProvisioningPayload ready for transmission
    """
    if len(pubkey) != 32:
        raise ValueError(f"Pubkey must be 32 bytes, got {len(pubkey)}")

    nonce = os.urandom(CCM_NONCE_LEN)
    aad = PROVISIONING_AAD_PREFIX + struct.pack(">B", PAYLOAD_TYPE_ACK)

    aesccm = AESCCM(key, tag_length=CCM_TAG_LEN)
    ciphertext = aesccm.encrypt(nonce, pubkey, aad)

    return ProvisioningPayload(
        payload_type=PAYLOAD_TYPE_ACK,
        nonce=nonce,
        ciphertext=ciphertext,
    )


def _decrypt_ack(key: bytes, payload: ProvisioningPayload) -> bytes:
    """Decrypt acknowledgment pubkey from node.

    Args:
        key: 16-byte AES key (derived from OSCORE context)
        payload: Encrypted acknowledgment payload

    Returns:
        32-byte Ed25519 pubkey

    Raises:
        DecryptionFailedError: If decryption or authentication fails
    """
    # SECURITY: Use generic error messages to prevent oracle attacks. Do not
    # reveal WHY decryption failed (type mismatch, nonce length, tag verification,
    # plaintext length) - all failures return the same message. Note: Early exit
    # on malformed metadata (type/nonce) is acceptable since these are not secret.
    valid = True

    if payload.payload_type != PAYLOAD_TYPE_ACK:
        valid = False

    # SECURITY: Validate nonce length per AES-CCM-16-64-128 (13 bytes required).
    # Malformed nonces could cause cryptographic failures or oracle attacks.
    if len(payload.nonce) != CCM_NONCE_LEN:
        valid = False

    if not valid:
        raise DecryptionFailedError("decryption failed")

    aad = PROVISIONING_AAD_PREFIX + struct.pack(">B", PAYLOAD_TYPE_ACK)

    try:
        aesccm = AESCCM(key, tag_length=CCM_TAG_LEN)
        pubkey = aesccm.decrypt(payload.nonce, payload.ciphertext, aad)
    except Exception:
        # SECURITY: Do not chain exception - it may reveal internal state
        raise DecryptionFailedError("decryption failed") from None

    if len(pubkey) != 32:
        raise DecryptionFailedError("decryption failed")

    return pubkey


@dataclass
class BRProvisioningSession:
    """Border router side of provisioning channel.

    The node's ephemeral pubkey must be provided for EDHOC authentication.
    This can be communicated out-of-band via:
    - Physical display on node (QR code, hex string)
    - Pre-provisioned in commissioning manifest
    - TOFU with physical proximity verification

    Usage:
        # Node displays its ephemeral pubkey, BR scans/enters it
        node_pubkey = get_node_pubkey_out_of_band()
        session = BRProvisioningSession(br_identity, node_pubkey)

        msg1_from_node = receive()  # Node initiates EDHOC
        msg2 = session.process_message_1(msg1_from_node)
        send(msg2)
        msg3_from_node = receive()
        session.process_message_3(msg3_from_node)

        # Channel established - provision the keypair
        node_seed = os.urandom(32)
        encrypted = session.encrypt_seed(node_seed)
        send(encrypted.encode())

        # Wait for ACK (decrypt_ack verifies pubkey with constant-time comparison)
        ack_data = receive()
        received_pubkey = session.decrypt_ack(ack_data)
        # Note: decrypt_ack() already validates pubkey match using hmac.compare_digest

        # CRITICAL: Securely delete seed from BR memory
        session.wipe()
    """

    br_identity: Identity
    node_pubkey: bytes  # Node's ephemeral pubkey (from out-of-band channel)

    _edhoc: EdhocResponder | None = field(default=None, repr=False)
    _oscore_ctx: OscoreContext | None = field(default=None, repr=False)
    _prov_key: bytes = field(default=b"", repr=False)
    _state: ProvisioningState = field(default=ProvisioningState.IDLE, repr=False)
    _provisioned_seed: bytes = field(default=b"", repr=False)

    def __post_init__(self) -> None:
        if len(self.node_pubkey) != 32:
            raise ValueError(f"node_pubkey must be 32 bytes, got {len(self.node_pubkey)}")

    def process_message_1(self, msg1: bytes) -> bytes:
        """Process EDHOC Message 1 from node, return Message 2.

        Args:
            msg1: EDHOC Message 1 from node

        Returns:
            EDHOC Message 2 to send to node
        """
        if self._state != ProvisioningState.IDLE:
            raise ProvisioningError(f"Invalid state for Message 1: {self._state}")

        self._edhoc = EdhocResponder.create(self.br_identity, c_r=b"\x01")
        msg2 = self._edhoc.process_message_1(msg1, self.node_pubkey)
        self._state = ProvisioningState.EDHOC_IN_PROGRESS

        return msg2

    def process_message_3(self, msg3: bytes) -> None:
        """Process EDHOC Message 3 from node, establish secure channel.

        Args:
            msg3: EDHOC Message 3 from node

        Raises:
            AuthenticationFailedError: If node authentication fails
        """
        if self._state != ProvisioningState.EDHOC_IN_PROGRESS:
            raise ProvisioningError(f"Invalid state for Message 3: {self._state}")

        if self._edhoc is None:
            raise ProvisioningError("EDHOC responder not initialized")

        try:
            self._edhoc.process_message_3(msg3, self.node_pubkey)
        except Exception:
            # SECURITY: Do not reveal exception details - could enable oracle attacks
            self._state = ProvisioningState.FAILED
            raise AuthenticationFailedError("authentication failed") from None

        # Export OSCORE context and derive provisioning key
        self._oscore_ctx = self._edhoc.export_oscore()
        self._prov_key = _derive_provisioning_key(self._oscore_ctx)
        self._state = ProvisioningState.ESTABLISHED

    def encrypt_seed(self, seed: bytes) -> ProvisioningPayload:
        """Encrypt a seed for transmission to the node.

        SECURITY: After calling this, the BR MUST securely delete the seed
        from memory once the node ACKs successful receipt.

        Args:
            seed: 32-byte Ed25519 seed to provision

        Returns:
            Encrypted payload for transmission
        """
        if self._state != ProvisioningState.ESTABLISHED:
            raise ChannelNotEstablishedError(f"Channel not established: {self._state}")

        if len(seed) != 32:
            raise ValueError(f"Seed must be 32 bytes, got {len(seed)}")

        # Store temporarily for verification (cleared on wipe())
        self._provisioned_seed = seed
        return _encrypt_seed(self._prov_key, seed)

    def decrypt_ack(self, ack_data: bytes) -> bytes:
        """Decrypt acknowledgment from node and verify.

        SECURITY: Pubkey verification is MANDATORY per spec 8.7. The BR MUST
        verify that the node derived the correct pubkey from the provisioned
        seed. Skipping this check would allow an attacker to substitute their
        own key.

        Args:
            ack_data: CBOR-encoded ProvisioningPayload from node

        Returns:
            32-byte pubkey derived by node from provisioned seed

        Raises:
            DecryptionFailedError: If decryption fails
            ProvisioningError: If pubkey doesn't match expected or seed not set
        """
        if self._state != ProvisioningState.ESTABLISHED:
            raise ChannelNotEstablishedError(f"Channel not established: {self._state}")

        # SECURITY: Seed MUST be available for verification. If encrypt_seed()
        # was not called before decrypt_ack(), this is a protocol violation.
        if not self._provisioned_seed:
            self._state = ProvisioningState.FAILED
            raise ProvisioningError(
                "Cannot verify ACK: no seed provisioned (encrypt_seed() not called)"
            )

        payload = ProvisioningPayload.decode(ack_data)
        received_pubkey = _decrypt_ack(self._prov_key, payload)

        # SECURITY: Verify node derived the correct pubkey (MANDATORY per spec 8.7)
        # SECURITY: Constant-time comparison prevents timing side-channel leakage
        expected = Identity.from_seed(self._provisioned_seed).pubkey
        if not hmac.compare_digest(received_pubkey, expected):
            self._state = ProvisioningState.FAILED
            raise ProvisioningError(
                "Node derived wrong pubkey - provisioning failed"
            )

        self._state = ProvisioningState.COMPLETED
        return received_pubkey

    def wipe(self) -> None:
        """Securely clear sensitive material from memory.

        SECURITY: Must be called after provisioning completes. Python cannot
        guarantee memory erasure (GC copies), but this is defense-in-depth.
        Production deployments should use HSMs or secure elements.

        After calling wipe(), the session returns to IDLE state and cannot
        perform any cryptographic operations.
        """
        # Overwrite with zeros before clearing references
        if self._provisioned_seed:
            # Python strings are immutable, so create new zero-filled bytes
            # This doesn't guarantee memory erasure but reduces exposure window
            self._provisioned_seed = bytes(len(self._provisioned_seed))
        if self._prov_key:
            self._prov_key = bytes(len(self._prov_key))

        self._provisioned_seed = b""
        self._prov_key = b""
        self._oscore_ctx = None
        self._edhoc = None
        # Session is no longer usable after wipe - return to initial state
        self._state = ProvisioningState.IDLE

    @property
    def state(self) -> ProvisioningState:
        """Current provisioning state."""
        return self._state


@dataclass
class NodeProvisioningSession:
    """Node side of provisioning channel (commissioning mode).

    Usage:
        # Node has ephemeral identity for initial EDHOC
        ephemeral_id = Identity.generate()
        session = NodeProvisioningSession(ephemeral_id)

        # Node initiates EDHOC with BR
        msg1 = session.create_message_1()
        send(msg1)
        msg2_from_br = receive()
        msg3 = session.process_message_2(msg2_from_br, br_pubkey)
        send(msg3)

        # Channel established - receive provisioned keypair
        seed_data = receive()
        new_identity = session.decrypt_seed(seed_data)

        # Send ACK with derived pubkey
        ack = session.create_ack(new_identity.pubkey)
        send(ack.encode())

        # Now use new_identity as permanent identity
        session.wipe()
    """

    ephemeral_identity: Identity

    _edhoc: EdhocInitiator | None = field(default=None, repr=False)
    _oscore_ctx: OscoreContext | None = field(default=None, repr=False)
    _prov_key: bytes = field(default=b"", repr=False)
    _state: ProvisioningState = field(default=ProvisioningState.IDLE, repr=False)
    _provisioned_pubkey: bytes = field(default=b"", repr=False)

    def create_message_1(self) -> bytes:
        """Create EDHOC Message 1 to initiate handshake with BR.

        Returns:
            EDHOC Message 1 bytes
        """
        if self._state != ProvisioningState.IDLE:
            raise ProvisioningError(f"Invalid state for Message 1: {self._state}")

        self._edhoc = EdhocInitiator.create(self.ephemeral_identity, c_i=b"\x00")
        msg1 = self._edhoc.create_message_1()
        self._state = ProvisioningState.EDHOC_IN_PROGRESS

        return msg1

    def process_message_2(self, msg2: bytes, br_pubkey: bytes) -> bytes:
        """Process EDHOC Message 2 from BR, return Message 3.

        Args:
            msg2: EDHOC Message 2 from BR
            br_pubkey: BR's public key for authentication (pre-provisioned or
                       displayed for manual verification)

        Returns:
            EDHOC Message 3 to send to BR

        Raises:
            AuthenticationFailedError: If BR authentication fails
        """
        if self._state != ProvisioningState.EDHOC_IN_PROGRESS:
            raise ProvisioningError(f"Invalid state for Message 2: {self._state}")

        if self._edhoc is None:
            raise ProvisioningError("EDHOC initiator not initialized")

        try:
            msg3 = self._edhoc.process_message_2(msg2, br_pubkey)
        except Exception:
            # SECURITY: Do not reveal exception details - could enable oracle attacks
            self._state = ProvisioningState.FAILED
            raise AuthenticationFailedError("authentication failed") from None

        # Export OSCORE context and derive provisioning key
        self._oscore_ctx = self._edhoc.export_oscore()
        self._prov_key = _derive_provisioning_key(self._oscore_ctx)
        self._state = ProvisioningState.ESTABLISHED

        return msg3

    def decrypt_seed(self, seed_data: bytes) -> Identity:
        """Decrypt provisioned seed and create new identity.

        SECURITY: After this call, the node MUST store the new identity
        securely and exit commissioning mode. The derived pubkey is stored
        internally for verification in create_ack().

        Args:
            seed_data: CBOR-encoded ProvisioningPayload from BR

        Returns:
            New Identity derived from provisioned seed

        Raises:
            DecryptionFailedError: If decryption fails
        """
        if self._state != ProvisioningState.ESTABLISHED:
            raise ChannelNotEstablishedError(f"Channel not established: {self._state}")

        payload = ProvisioningPayload.decode(seed_data)
        seed = _decrypt_seed(self._prov_key, payload)

        identity = Identity.from_seed(seed)
        # Store pubkey for verification in create_ack()
        self._provisioned_pubkey = identity.pubkey
        return identity

    def create_ack(self, pubkey: bytes) -> ProvisioningPayload:
        """Create encrypted acknowledgment with derived pubkey.

        SECURITY: Pubkey verification is MANDATORY per spec 8.7. The node MUST
        verify that the pubkey being sent matches what was derived from the
        provisioned seed. This provides defense-in-depth - the BR will also
        verify, but catching mismatches early prevents bugs from propagating.

        Args:
            pubkey: 32-byte pubkey derived from provisioned seed

        Returns:
            Encrypted ACK payload

        Raises:
            ChannelNotEstablishedError: If channel not established
            ProvisioningError: If decrypt_seed() not called or pubkey mismatch
        """
        if self._state != ProvisioningState.ESTABLISHED:
            raise ChannelNotEstablishedError(f"Channel not established: {self._state}")

        # SECURITY: Seed MUST have been decrypted before creating ACK. If
        # decrypt_seed() was not called, _provisioned_pubkey is empty.
        if not self._provisioned_pubkey:
            self._state = ProvisioningState.FAILED
            raise ProvisioningError(
                "Cannot create ACK: no seed decrypted (decrypt_seed() not called)"
            )

        # SECURITY: Verify pubkey matches what was derived from provisioned seed.
        # This is defense-in-depth; the BR will also verify. But catching
        # mismatches early prevents bugs from propagating over the wire.
        # SECURITY: Constant-time comparison prevents timing side-channel leakage
        if not hmac.compare_digest(pubkey, self._provisioned_pubkey):
            self._state = ProvisioningState.FAILED
            raise ProvisioningError(
                "Pubkey does not match derived value - possible bug or attack"
            )

        # SECURITY: State must only transition to COMPLETED after successful encryption.
        # If _encrypt_ack raises, state remains ESTABLISHED so caller can retry or fail cleanly.
        # SECURITY: Use stored pubkey after verification, not the input argument. This is
        # defense-in-depth: even if comparison had a weakness, we encrypt the trusted value.
        ack_payload = _encrypt_ack(self._prov_key, self._provisioned_pubkey)
        self._state = ProvisioningState.COMPLETED
        return ack_payload

    def wipe(self) -> None:
        """Securely clear sensitive material from memory.

        After calling wipe(), the session returns to IDLE state and cannot
        perform any cryptographic operations.
        """
        if self._prov_key:
            self._prov_key = bytes(len(self._prov_key))
        if self._provisioned_pubkey:
            self._provisioned_pubkey = bytes(len(self._provisioned_pubkey))
        self._prov_key = b""
        self._provisioned_pubkey = b""
        self._oscore_ctx = None
        self._edhoc = None
        # Session is no longer usable after wipe - return to initial state
        self._state = ProvisioningState.IDLE

    @property
    def state(self) -> ProvisioningState:
        """Current provisioning state."""
        return self._state
