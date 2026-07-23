# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""EDHOC (RFC 9528) Suite 0 implementation.

Ephemeral Diffie-Hellman Over COSE for establishing OSCORE security contexts.
Suite 0: X25519 + Ed25519 + AES-CCM-16-64-128 + SHA-256.

Why Suite 0: Matches link-layer Ed25519 (Schnorr48). Single seed derives both
signing key and X25519 key exchange key.
"""

from __future__ import annotations

import hmac
import io
import os
from dataclasses import dataclass, field
from enum import IntEnum
from hashlib import sha256
from typing import TYPE_CHECKING, Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from nacl.bindings import (
    crypto_scalarmult,
    crypto_scalarmult_base,
    crypto_sign_ed25519_pk_to_curve25519,
    crypto_sign_ed25519_sk_to_curve25519,
)
from nacl.signing import SigningKey, VerifyKey

if TYPE_CHECKING:
    from .identity import Identity

# Suite 0 constants (RFC 9528 Section 9.2)
SUITE_0 = 0
AEAD_AES_CCM_16_64_128 = 10  # COSE algorithm ID
HASH_SHA_256 = -16  # COSE algorithm ID
ECDH_X25519 = 4  # COSE algorithm ID
SIGN_EDDSA = -8  # COSE algorithm ID

# AES-CCM-16-64-128 parameters
CCM_KEY_LEN = 16
CCM_NONCE_LEN = 13
CCM_TAG_LEN = 8

# EDHOC constants
EDHOC_HASH_LEN = 32  # SHA-256 output
EDHOC_MAC_LEN = 8  # MAC length for Suite 0
X25519_KEY_LEN = 32
ED25519_SIG_LEN = 64


class Method(IntEnum):
    """EDHOC authentication methods (RFC 9528 Section 3.2)."""

    SIGN_SIGN = 0  # Both parties use signatures
    SIGN_STATIC = 1  # Initiator signs, responder static DH
    STATIC_SIGN = 2  # Initiator static DH, responder signs
    STATIC_STATIC = 3  # Both use static DH


class _InitiatorState(IntEnum):
    NEW = 0
    WAIT_MESSAGE_2 = 1
    COMPLETE = 2
    EXPORTED = 3
    FAILED = 4


class _ResponderState(IntEnum):
    NEW = 0
    WAIT_MESSAGE_3 = 1
    COMPLETE = 2
    EXPORTED = 3
    FAILED = 4


@dataclass
class EdhocKeys:
    """Derived EDHOC keys for a session."""

    prk_2e: bytes  # PRK for encryption
    prk_3e2m: bytes  # PRK for MAC_2
    prk_4e3m: bytes  # PRK for MAC_3 and key export
    th_2: bytes  # Transcript hash 2
    th_3: bytes  # Transcript hash 3
    th_4: bytes  # Transcript hash 4


@dataclass
class OscoreContext:
    """Exported OSCORE security context from EDHOC."""

    master_secret: bytes
    master_salt: bytes
    sender_id: bytes
    recipient_id: bytes


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract with SHA-256 (RFC 5869)."""
    if not salt:
        salt = b"\x00" * EDHOC_HASH_LEN
    return hmac.new(salt, ikm, "sha256").digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand with SHA-256 (RFC 5869)."""
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info)
    return hkdf.derive(prk)


def _edhoc_kdf(prk: bytes, th: bytes, label: str, context: bytes, length: int) -> bytes:
    """EDHOC-KDF (RFC 9528 Section 4.1.2).

    EDHOC-KDF(PRK, TH, label, context, length) =
        HKDF-Expand(PRK, info, length)

    where info = (length, TH, label, context) as CBOR sequence.
    """
    # info = (length, TH, label, context) - CBOR encoded
    info = cbor2.dumps(length) + cbor2.dumps(th) + cbor2.dumps(label) + cbor2.dumps(context)
    return _hkdf_expand(prk, info, length)


def _aead_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """AES-CCM-16-64-128 encryption."""
    aesccm = AESCCM(key, tag_length=CCM_TAG_LEN)
    return aesccm.encrypt(nonce, plaintext, aad)


def _aead_decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """AES-CCM-16-64-128 decryption."""
    aesccm = AESCCM(key, tag_length=CCM_TAG_LEN)
    return aesccm.decrypt(nonce, ciphertext, aad)


def _compute_th(th_input: bytes) -> bytes:
    """Compute transcript hash: H(th_input)."""
    return sha256(th_input).digest()


def _ed25519_to_x25519_private(ed_seed: bytes) -> bytes:
    """Convert Ed25519 seed to X25519 private key."""
    # Create full Ed25519 secret key (seed + public key)
    signing_key = SigningKey(ed_seed)
    ed_sk = signing_key.encode() + signing_key.verify_key.encode()
    return crypto_sign_ed25519_sk_to_curve25519(ed_sk)


def _ed25519_to_x25519_public(ed_pk: bytes) -> bytes:
    """Convert Ed25519 public key to X25519 public key."""
    return crypto_sign_ed25519_pk_to_curve25519(ed_pk)


def _x25519_keypair() -> tuple[bytes, bytes]:
    """Generate ephemeral X25519 keypair."""
    sk = os.urandom(X25519_KEY_LEN)
    pk = crypto_scalarmult_base(sk)
    return sk, pk


def _x25519_shared_secret(my_sk: bytes, their_pk: bytes) -> bytes:
    """Compute X25519 shared secret.

    Raises:
        ValueError: If shared secret is all zeros (small subgroup attack).
    """
    shared = crypto_scalarmult(my_sk, their_pk)
    # SECURITY: Reject all-zero shared secret - indicates peer sent a point
    # in a small subgroup (identity element or low-order point). Accepting
    # this enables attackers to predict the shared secret.
    if shared == b"\x00" * X25519_KEY_LEN:
        raise ValueError("X25519 shared secret is zero - possible small subgroup attack")
    return shared


def _encode_connection_id(c_x: bytes) -> bytes:
    """Encode connection identifier for CBOR.

    RFC 9528: Connection IDs are bstr. Empty bstr encoded as h''.
    One-byte values -24..23 can use int encoding for compactness.
    """
    if len(c_x) == 1:
        val = c_x[0]
        if val <= 23:
            return cbor2.dumps(val)
        if val >= 232:  # -24 in two's complement
            return cbor2.dumps(val - 256)
    return cbor2.dumps(c_x)


def _validate_connection_id(value: object, name: str) -> bytes:
    """Validate and normalize a connection identifier for this profile."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a byte string or compact integer")
    if isinstance(value, int):
        if not -24 <= value <= 23:
            raise ValueError(f"{name} compact integer is outside -24..23")
        return bytes([value if value >= 0 else value + 256])
    if not isinstance(value, bytes):
        raise ValueError(f"{name} must be a byte string or compact integer")
    if len(value) > 7:
        raise ValueError(f"{name} must be at most 7 bytes")
    return value


def _select_responder_connection_id(preferred_c_r: bytes, c_i: bytes) -> bytes:
    """Select C_R, replacing with non-colliding value if preferred equals C_I.

    Matches test expectation (0x00 collides with 0x00 -> chooses 0x01).
    Ensures interop with Rust implementation and RFC 9528 "MUST NOT use same CID".
    """
    if preferred_c_r == c_i:
        if preferred_c_r == b"\x00":
            return b"\x01"
        # General fallback: increment byte value
        val = preferred_c_r[0]
        return bytes([(val + 1) % 256])
    return preferred_c_r


def _decode_connection_id(encoded: object) -> bytes:
    """Decode CBOR connection identifier (int or bstr) to bytes.

    Used in message parsing for C_I / C_R to match Rust and test vectors.
    """
    return _validate_connection_id(encoded, "connection ID")


def _decode_cbor_sequence(data: bytes) -> list[Any]:
    """Decode a CBOR sequence (concatenated CBOR items) into a list."""
    items: list[Any] = []
    fp = io.BytesIO(data)
    while True:
        try:
            item = cbor2.load(fp)
            items.append(item)
        except cbor2.CBORDecodeEOF:
            break
        except cbor2.CBORDecodeError as exc:
            raise ValueError("truncated or malformed CBOR sequence") from exc
    return items


def _validate_bytes(value: object, name: str, length: int | None = None) -> bytes:
    if not isinstance(value, bytes):
        raise ValueError(f"{name} must be a byte string")
    if length is not None and len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")
    return value


@dataclass
class EdhocInitiator:
    """EDHOC Initiator role (RFC 9528).

    Usage:
        initiator = EdhocInitiator.create(identity, c_i=b'\\x00')
        msg1 = initiator.create_message_1()
        # send msg1, receive msg2
        msg3 = initiator.process_message_2(msg2, peer_pubkey)
        # send msg3
        oscore_ctx = initiator.export_oscore()
    """

    identity: Identity
    c_i: bytes  # Initiator's connection identifier
    method: Method = Method.SIGN_SIGN

    # Ephemeral keys (generated on create)
    _eph_sk: bytes = field(default=b"", repr=False)
    _eph_pk: bytes = field(default=b"", repr=False)

    # State accumulated during protocol
    _g_y: bytes = field(default=b"", repr=False)
    _c_i: bytes = field(default=b"", repr=False)
    _c_r: bytes = field(default=b"", repr=False)
    _prk_2e: bytes = field(default=b"", repr=False)
    _prk_3e2m: bytes = field(default=b"", repr=False)
    _prk_4e3m: bytes = field(default=b"", repr=False)
    _th_2: bytes = field(default=b"", repr=False)
    _th_3: bytes = field(default=b"", repr=False)
    _th_4: bytes = field(default=b"", repr=False)
    _msg1: bytes = field(default=b"", repr=False)
    _state: _InitiatorState = field(default=_InitiatorState.NEW, init=False, repr=False)

    def _clear_session_material(self) -> None:
        self._eph_sk = b""
        self._eph_pk = b""
        self._g_y = b""
        self._c_i = b""
        self._c_r = b""
        self._prk_2e = b""
        self._prk_3e2m = b""
        self._prk_4e3m = b""
        self._th_2 = b""
        self._th_3 = b""
        self._th_4 = b""
        self._msg1 = b""

    def _fail(self) -> None:
        self._clear_session_material()
        self._state = _InitiatorState.FAILED

    def _require_state(self, expected: _InitiatorState, operation: str) -> None:
        if self._state is not expected:
            self._fail()
            raise ValueError(f"EDHOC not complete or {operation} is invalid in the current state")

    @classmethod
    def create(
        cls, identity: Identity, c_i: bytes | None = None, method: Method = Method.SIGN_SIGN
    ) -> EdhocInitiator:
        """Create an EDHOC initiator with fresh ephemeral keys.

        Note: For SIGN_SIGN mode, we generate fresh ephemeral X25519 keys
        per-session rather than using Identity.x25519_*. The identity's
        Ed25519 keys are used only for signatures. Static-DH modes would
        use Identity.x25519_private for the DH exchange.
        """
        if c_i is None:
            c_i = os.urandom(1)
        eph_sk, eph_pk = _x25519_keypair()
        return cls(
            identity=identity,
            c_i=c_i,
            method=method,
            _eph_sk=eph_sk,
            _eph_pk=eph_pk,
        )

    def create_message_1(self, ead_1: bytes = b"") -> bytes:
        """Create EDHOC Message 1.

        message_1 = (METHOD, SUITES_I, G_X, C_I, ?EAD_1)

        Returns:
            CBOR-encoded Message 1.
        """
        self._require_state(_InitiatorState.NEW, "create_message_1")
        try:
            if self.method is not Method.SIGN_SIGN:
                raise ValueError("only EDHOC SIGN_SIGN is supported")
            c_i = _validate_connection_id(self.c_i, "C_I")
            ead = _validate_bytes(ead_1, "EAD_1")
            msg1_content = [self.method * 4 + 1, SUITE_0, self._eph_pk, c_i]
            if ead:
                msg1_content.append(ead)
            msg1 = b"".join(cbor2.dumps(item) for item in msg1_content)
        except Exception as exc:
            self._fail()
            if isinstance(exc, ValueError):
                raise
            raise ValueError("Message 1 creation failed") from exc
        self._msg1 = msg1
        self._c_i = c_i
        self._state = _InitiatorState.WAIT_MESSAGE_2
        return msg1

    def process_message_2(self, msg2: bytes, peer_pubkey: bytes) -> bytes:
        """Process EDHOC Message 2 and create Message 3.

        Args:
            msg2: CBOR-encoded Message 2 from responder.
            peer_pubkey: Responder's Ed25519 public key (for signature verification).

        Returns:
            CBOR-encoded Message 3.

        Raises:
            ValueError: If message validation fails.
        """
        # Decode message_2 = (G_Y || CIPHERTEXT_2, C_R) as CBOR sequence
        # First item: bstr containing G_Y (32 bytes) concatenated with CIPHERTEXT_2
        # Second item: C_R (connection identifier)
        items = _decode_cbor_sequence(msg2)
        if len(items) < 2:
            raise ValueError(f"Malformed message_2: expected 2 CBOR items, got {len(items)}")
        g_y_ciphertext_2 = items[0]
        c_r_raw = items[1]

        if len(g_y_ciphertext_2) < X25519_KEY_LEN:
            raise ValueError(
                f"Message 2 too short: G_Y requires {X25519_KEY_LEN} bytes, "
                f"got {len(g_y_ciphertext_2)}"
            )
        self._g_y = g_y_ciphertext_2[:X25519_KEY_LEN]
        ciphertext_2 = g_y_ciphertext_2[X25519_KEY_LEN:]
        self._c_r = _decode_connection_id(c_r_raw)

        # Compute shared secret
        g_xy = _x25519_shared_secret(self._eph_sk, self._g_y)

        # TH_2 = H(G_Y, H(message_1))
        h_msg1 = _compute_th(self._msg1)
        th_2_input = self._g_y + h_msg1
        self._th_2 = _compute_th(th_2_input)

        # PRK_2e = HKDF-Extract(salt=TH_2, IKM=G_XY)
        self._prk_2e = _hkdf_extract(self._th_2, g_xy)

        # Derive KEYSTREAM_2 and decrypt CIPHERTEXT_2
        keystream_2 = _edhoc_kdf(
            self._prk_2e, self._th_2, "KEYSTREAM_2", b"", len(ciphertext_2)
        )
        plaintext_2 = bytes(a ^ b for a, b in zip(ciphertext_2, keystream_2))

        # PLAINTEXT_2 = (ID_CRED_R, Signature_or_MAC_2, ?EAD_2)
        # For SIGN_SIGN, ID_CRED_R is bstr (pubkey), followed by Signature_2
        pt2_items = _decode_cbor_sequence(plaintext_2)
        if len(pt2_items) < 2:
            raise ValueError(
                f"Malformed PLAINTEXT_2: expected at least 2 CBOR items, got {len(pt2_items)}"
            )

        id_cred_r = pt2_items[0]
        if id_cred_r != peer_pubkey:
            raise ValueError("ID_CRED_R mismatch")
        signature_2 = pt2_items[1]

        if id_cred_r != peer_pubkey:
            raise ValueError("ID_CRED_R mismatch")

        # PRK_3e2m = PRK_2e for Suite 0 SIGN_SIGN (needed for MAC_2)
        self._prk_3e2m = self._prk_2e

        # SECURITY: Verify Signature_2 from responder per RFC 9528 Section 4.3.2
        # For SIGN_SIGN: Signature_2 = Sign(SK_R, M_2)
        cred_r = peer_pubkey  # CRED_R = pubkey for simplified case

        # Recompute MAC_2
        context_2 = cbor2.dumps(id_cred_r) + cbor2.dumps(cred_r)
        mac_2 = _edhoc_kdf(self._prk_3e2m, self._th_2, "MAC_2", context_2, EDHOC_MAC_LEN)

        # M_2 = ["Signature1", << ID_CRED_R >>, TH_2, << CRED_R, ?EAD_2 >>, MAC_2]
        m_2 = cbor2.dumps([
            "Signature1",
            cbor2.dumps(id_cred_r),
            self._th_2,
            cbor2.dumps(cred_r),
            mac_2,
        ])
        verify_key = VerifyKey(peer_pubkey)
        try:
            peer_key = _validate_bytes(peer_pubkey, "peer public key", ED25519_SIG_LEN // 2)
            items = _decode_cbor_sequence(msg2)
            if len(items) != 2:
                raise ValueError(f"Malformed message_2: expected 2 CBOR items, got {len(items)}")
            combined = _validate_bytes(items[0], "G_Y || CIPHERTEXT_2")
            if len(combined) <= X25519_KEY_LEN:
                raise ValueError("Message 2 has no CIPHERTEXT_2")
            g_y = combined[:X25519_KEY_LEN]
            ciphertext_2 = combined[X25519_KEY_LEN:]
            c_r = _validate_connection_id(items[1], "C_R")
            if c_r == self._c_i:
                raise ValueError("C_R must differ from C_I")

            g_xy = _x25519_shared_secret(self._eph_sk, g_y)
            th_2 = _compute_th(g_y + _compute_th(self._msg1))
            prk_2e = _hkdf_extract(th_2, g_xy)
            keystream_2 = _edhoc_kdf(prk_2e, th_2, "KEYSTREAM_2", b"", len(ciphertext_2))
            plaintext_2 = bytes(
                a ^ b for a, b in zip(ciphertext_2, keystream_2, strict=True)
            )
            pt2_items = _decode_cbor_sequence(plaintext_2)
            if len(pt2_items) != 2:
                raise ValueError(
                    f"Malformed PLAINTEXT_2: expected 2 CBOR items, got {len(pt2_items)}"
                )
            id_cred_r = _validate_bytes(pt2_items[0], "ID_CRED_R", ED25519_SIG_LEN // 2)
            signature_2 = _validate_bytes(pt2_items[1], "Signature_2", ED25519_SIG_LEN)
            if id_cred_r != peer_key:
                raise ValueError("ID_CRED_R does not match the authenticated peer")

            prk_3e2m = prk_2e
            context_2 = cbor2.dumps(id_cred_r) + cbor2.dumps(peer_key)
            mac_2 = _edhoc_kdf(prk_3e2m, th_2, "MAC_2", context_2, EDHOC_MAC_LEN)
            m_2 = cbor2.dumps(
                ["Signature1", cbor2.dumps(id_cred_r), th_2, cbor2.dumps(peer_key), mac_2]
            )
            try:
                VerifyKey(peer_key).verify(m_2, signature_2)
            except Exception as exc:
                raise ValueError("Signature_2 verification failed") from exc

            th_3 = _compute_th(
                cbor2.dumps(th_2) + cbor2.dumps(ciphertext_2) + cbor2.dumps(id_cred_r)
            )
            prk_4e3m = prk_3e2m
            id_cred_i = _validate_bytes(
                self.identity.pubkey, "local credential", ED25519_SIG_LEN // 2
            )
            context_3 = cbor2.dumps(id_cred_i) + cbor2.dumps(id_cred_i)
            mac_3 = _edhoc_kdf(prk_4e3m, th_3, "MAC_3", context_3, EDHOC_MAC_LEN)
            m_3 = cbor2.dumps(
                ["Signature1", cbor2.dumps(id_cred_i), th_3, cbor2.dumps(id_cred_i), mac_3]
            )
            signature_3 = SigningKey(self.identity.seed).sign(m_3).signature
            plaintext_3 = cbor2.dumps(id_cred_i) + cbor2.dumps(signature_3)
            k_3 = _edhoc_kdf(prk_3e2m, th_3, "K_3", b"", CCM_KEY_LEN)
            iv_3 = _edhoc_kdf(prk_3e2m, th_3, "IV_3", b"", CCM_NONCE_LEN)
            a_3 = cbor2.dumps(["Encrypt0", b"", th_3])
            ciphertext_3 = _aead_encrypt(k_3, iv_3, a_3, plaintext_3)
            th_4 = _compute_th(cbor2.dumps(th_3) + cbor2.dumps(ciphertext_3))
        except Exception as exc:
            self._fail()
            if isinstance(exc, ValueError):
                raise
            raise ValueError("Message 2 processing failed") from exc

        # Create Message 3
        # CIPHERTEXT_3 contains ID_CRED_I and Signature_3

        # ID_CRED_I - our credential identifier (simplified: just pubkey)
        id_cred_i = self.identity.pubkey
        cred_i = self.identity.pubkey  # CRED_I = pubkey for simplified case

        # Compute MAC_3 per RFC 9528 Section 4.4.2
        # MAC_3 = EDHOC-KDF(PRK_4e3m, TH_3, "MAC_3", context_3, mac_length_3)
        # context_3 = << ID_CRED_I, CRED_I, ?EAD_3 >>
        context_3 = cbor2.dumps(id_cred_i) + cbor2.dumps(cred_i)
        mac_3 = _edhoc_kdf(self._prk_4e3m, self._th_3, "MAC_3", context_3, EDHOC_MAC_LEN)

        # Compute Signature_3 per RFC 9528 Section 4.4.2 (COSE Sig_structure)
        # M_3 = ["Signature1", << ID_CRED_I >>, TH_3, << CRED_I, ?EAD_3 >>, MAC_3]
        m_3 = cbor2.dumps([
            "Signature1",
            cbor2.dumps(id_cred_i),  # << ID_CRED_I >> bstr-wrapped
            self._th_3,
            cbor2.dumps(cred_i),     # << CRED_I >> bstr-wrapped
            mac_3,
        ])
        signing_key = SigningKey(self.identity.seed)
        signature_3 = signing_key.sign(m_3).signature

        # PLAINTEXT_3 = (ID_CRED_I, Signature_3, ?EAD_3)
        plaintext_3 = cbor2.dumps(id_cred_i) + cbor2.dumps(signature_3)

        # K_3 and IV_3 for AEAD
        k_3 = _edhoc_kdf(self._prk_3e2m, self._th_3, "K_3", b"", CCM_KEY_LEN)
        iv_3 = _edhoc_kdf(self._prk_3e2m, self._th_3, "IV_3", b"", CCM_NONCE_LEN)

        # A_3 = ["Encrypt0", h'', TH_3] - TH_3 only to match Rust lichen-oscore, RFC trace vectors,
        # and transcript binding for OSCORE export interop.
        a_3 = cbor2.dumps(["Encrypt0", b"", self._th_3])

        ciphertext_3 = _aead_encrypt(k_3, iv_3, a_3, plaintext_3)

        # TH_4 = H(TH_3, CIPHERTEXT_3)
        th_4_input = cbor2.dumps(self._th_3) + cbor2.dumps(ciphertext_3)
        self._th_4 = _compute_th(th_4_input)

        # message_3 = CIPHERTEXT_3
        return ciphertext_3

    def export_oscore(self, oscore_salt_len: int = 8, oscore_key_len: int = 16) -> OscoreContext:
        """Export OSCORE security context (RFC 9528 Section 7.2.1).

        Returns:
            OscoreContext with master secret, salt, and IDs.

        Raises:
            ValueError: If EDHOC is not complete.
        """
        self._require_state(_InitiatorState.COMPLETE, "export_oscore")
        try:
            master_secret = _edhoc_kdf(
                self._prk_4e3m, self._th_4, "OSCORE_Master_Secret", b"", oscore_key_len
            )
            master_salt = _edhoc_kdf(
                self._prk_4e3m, self._th_4, "OSCORE_Master_Salt", b"", oscore_salt_len
            )
            context = OscoreContext(master_secret, master_salt, self._c_i, self._c_r)
        except Exception:
            self._fail()
            raise
        self._state = _InitiatorState.EXPORTED
        self._clear_session_material()
        return context


@dataclass
class EdhocResponder:
    """EDHOC Responder role (RFC 9528).

    Usage:
        responder = EdhocResponder.create(identity, c_r=b'\\x01')
        msg2 = responder.process_message_1(msg1, peer_pubkey)
        # send msg2, receive msg3
        responder.process_message_3(msg3)
        oscore_ctx = responder.export_oscore()
    """

    identity: Identity
    c_r: bytes  # Responder's connection identifier
    method: Method = Method.SIGN_SIGN

    # Ephemeral keys
    _eph_sk: bytes = field(default=b"", repr=False)
    _eph_pk: bytes = field(default=b"", repr=False)

    # State
    _g_x: bytes = field(default=b"", repr=False)
    _c_i: bytes = field(default=b"", repr=False)
    _c_r: bytes = field(default=b"", repr=False)
    _prk_2e: bytes = field(default=b"", repr=False)
    _prk_3e2m: bytes = field(default=b"", repr=False)
    _prk_4e3m: bytes = field(default=b"", repr=False)
    _th_2: bytes = field(default=b"", repr=False)
    _th_3: bytes = field(default=b"", repr=False)
    _th_4: bytes = field(default=b"", repr=False)
    _msg1: bytes = field(default=b"", repr=False)
    _state: _ResponderState = field(default=_ResponderState.NEW, init=False, repr=False)

    def _clear_session_material(self) -> None:
        self._eph_sk = b""
        self._eph_pk = b""
        self._g_x = b""
        self._c_i = b""
        self._c_r = b""
        self._prk_2e = b""
        self._prk_3e2m = b""
        self._prk_4e3m = b""
        self._th_2 = b""
        self._th_3 = b""
        self._th_4 = b""
        self._msg1 = b""

    def _fail(self) -> None:
        self._clear_session_material()
        self._state = _ResponderState.FAILED

    def abort(self) -> None:
        """Erase session material and leave the responder terminally failed."""
        self._fail()

    def _require_state(self, expected: _ResponderState, operation: str) -> None:
        if self._state is not expected:
            self._fail()
            raise ValueError(f"EDHOC not complete or {operation} is invalid in the current state")

    @classmethod
    def create(
        cls, identity: Identity, c_r: bytes | None = None, method: Method = Method.SIGN_SIGN
    ) -> EdhocResponder:
        """Create an EDHOC responder with fresh ephemeral keys.

        Note: For SIGN_SIGN mode, we generate fresh ephemeral X25519 keys
        per-session rather than using Identity.x25519_*. The identity's
        Ed25519 keys are used only for signatures. Static-DH modes would
        use Identity.x25519_private for the DH exchange.
        """
        if c_r is None:
            c_r = os.urandom(1)
        eph_sk, eph_pk = _x25519_keypair()
        return cls(
            identity=identity,
            c_r=c_r,
            method=method,
            _eph_sk=eph_sk,
            _eph_pk=eph_pk,
        )

    def process_message_1(self, msg1: bytes, peer_pubkey: bytes) -> bytes:
        """Process EDHOC Message 1 and create Message 2.

        Args:
            msg1: CBOR-encoded Message 1 from initiator.
            peer_pubkey: Initiator's Ed25519 public key.

        Returns:
            CBOR-encoded Message 2.
        """
        self._require_state(_ResponderState.NEW, "process_message_1")
        try:
            if self.method is not Method.SIGN_SIGN:
                raise ValueError("only EDHOC SIGN_SIGN is supported")
            _validate_bytes(peer_pubkey, "peer public key", ED25519_SIG_LEN // 2)
            message_1 = _validate_bytes(msg1, "message_1")
            items = _decode_cbor_sequence(message_1)
            if len(items) not in (4, 5):
                raise ValueError(
                    f"Malformed message_1: expected 4 or 5 CBOR items, got {len(items)}"
                )
            expected_method_corr = self.method * 4 + 1
            if type(items[0]) is not int or items[0] != expected_method_corr:
                raise ValueError(f"Unsupported METHOD_CORR: {items[0]!r}")
            if type(items[1]) is not int or items[1] != SUITE_0:
                raise ValueError(f"Unsupported cipher suite: {items[1]!r}")
            g_x = _validate_bytes(items[2], "G_X", X25519_KEY_LEN)
            c_i = _validate_connection_id(items[3], "C_I")
            if len(items) == 5:
                _validate_bytes(items[4], "EAD_1")
            preferred_c_r = _validate_connection_id(self.c_r, "C_R")
            c_r = _select_responder_connection_id(preferred_c_r, c_i)
            self.c_r = c_r
            self._c_r = c_r

            g_xy = _x25519_shared_secret(self._eph_sk, g_x)
            th_2 = _compute_th(self._eph_pk + _compute_th(message_1))
            prk_2e = _hkdf_extract(th_2, g_xy)
            prk_3e2m = prk_2e
            id_cred_r = _validate_bytes(
                self.identity.pubkey, "local credential", ED25519_SIG_LEN // 2
            )
            context_2 = cbor2.dumps(id_cred_r) + cbor2.dumps(id_cred_r)
            mac_2 = _edhoc_kdf(prk_3e2m, th_2, "MAC_2", context_2, EDHOC_MAC_LEN)
            m_2 = cbor2.dumps(
                ["Signature1", cbor2.dumps(id_cred_r), th_2, cbor2.dumps(id_cred_r), mac_2]
            )
            signature_2 = SigningKey(self.identity.seed).sign(m_2).signature
            plaintext_2 = cbor2.dumps(id_cred_r) + cbor2.dumps(signature_2)
            keystream_2 = _edhoc_kdf(prk_2e, th_2, "KEYSTREAM_2", b"", len(plaintext_2))
            ciphertext_2 = bytes(
                a ^ b for a, b in zip(plaintext_2, keystream_2, strict=True)
            )
            th_3 = _compute_th(
                cbor2.dumps(th_2) + cbor2.dumps(ciphertext_2) + cbor2.dumps(id_cred_r)
            )
            msg2 = cbor2.dumps(self._eph_pk + ciphertext_2) + _encode_connection_id(c_r)
        except Exception as exc:
            self._fail()
            if isinstance(exc, ValueError):
                raise
            raise ValueError("Message 1 processing failed") from exc

        # Extract and validate METHOD from METHOD_CORR
        # METHOD_CORR = method * 4 + corr (RFC 9528 Section 3.2, project-LICHEN-g7mt)
        method_corr = items[0]
        received_method = method_corr // 4
        corr = method_corr % 4
        if received_method != self.method:
            raise ValueError(
                f"Method mismatch: initiator sent method={received_method}, "
                f"responder expects method={self.method}"
            )
        if corr not in (0, 1, 2, 3):
            raise ValueError(f"Invalid corr value: {corr}")

        suites_i = items[1]
        self._g_x = items[2]
        self._c_i = _decode_connection_id(items[3])

        # Select non-colliding C_R (updates public c_r for test interop)
        self.c_r = _select_responder_connection_id(
            _validate_connection_id(self.c_r, "C_R"), self._c_i
        )

        # Verify suite is supported
        if suites_i != SUITE_0:
            raise ValueError(f"Unsupported cipher suite: {suites_i}")

        # Compute shared secret
        g_xy = _x25519_shared_secret(self._eph_sk, self._g_x)

        # TH_2 = H(G_Y, H(message_1))
        h_msg1 = _compute_th(msg1)
        th_2_input = self._eph_pk + h_msg1
        self._th_2 = _compute_th(th_2_input)

        # PRK_2e = HKDF-Extract(salt=TH_2, IKM=G_XY)
        self._prk_2e = _hkdf_extract(self._th_2, g_xy)

        # PRK_3e2m = PRK_2e for SIGN_SIGN
        self._prk_3e2m = self._prk_2e

        # Create PLAINTEXT_2 = (ID_CRED_R, Signature_or_MAC_2, ?EAD_2)
        id_cred_r = self.identity.pubkey
        cred_r = self.identity.pubkey  # CRED_R = pubkey for simplified case

        # Compute MAC_2 per RFC 9528 Section 4.3.2
        # MAC_2 = EDHOC-KDF(PRK_3e2m, TH_2, "MAC_2", context_2, mac_length_2)
        # context_2 = << ID_CRED_R, CRED_R, ?EAD_2 >>
        context_2 = cbor2.dumps(id_cred_r) + cbor2.dumps(cred_r)
        mac_2 = _edhoc_kdf(self._prk_3e2m, self._th_2, "MAC_2", context_2, EDHOC_MAC_LEN)

        # Compute Signature_2 per RFC 9528 Section 4.3.2 (COSE Sig_structure)
        # M_2 = ["Signature1", << ID_CRED_R >>, TH_2, << CRED_R, ?EAD_2 >>, MAC_2]
        m_2 = cbor2.dumps([
            "Signature1",
            cbor2.dumps(id_cred_r),
            self._th_2,
            cbor2.dumps(cred_r),
            mac_2,
        ])
        signing_key = SigningKey(self.identity.seed)
        signature_2 = signing_key.sign(m_2).signature

        plaintext_2 = cbor2.dumps(id_cred_r) + cbor2.dumps(signature_2)

        # KEYSTREAM_2 for XOR encryption
        keystream_2 = _edhoc_kdf(
            self._prk_2e, self._th_2, "KEYSTREAM_2", b"", len(plaintext_2)
        )
        ciphertext_2 = bytes(a ^ b for a, b in zip(plaintext_2, keystream_2))

        # TH_3 = H(TH_2, CIPHERTEXT_2, ID_CRED_R)
        th_3_input = cbor2.dumps(self._th_2) + cbor2.dumps(ciphertext_2) + cbor2.dumps(id_cred_r)
        self._th_3 = _compute_th(th_3_input)

        # message_2 = (G_Y || CIPHERTEXT_2, C_R)
        g_y_ciphertext_2 = self._eph_pk + ciphertext_2
        msg2 = cbor2.dumps(g_y_ciphertext_2) + _encode_connection_id(self.c_r)

        return msg2

    def process_message_3(self, msg3: bytes, peer_pubkey: bytes) -> None:
        """Process EDHOC Message 3.

        Args:
            msg3: CBOR-encoded Message 3 (CIPHERTEXT_3).
            peer_pubkey: Initiator's Ed25519 public key.

        Raises:
            ValueError: If signature verification fails.
        """
        ciphertext_3 = msg3

        # K_3 and IV_3 for AEAD decryption
        k_3 = _edhoc_kdf(self._prk_3e2m, self._th_3, "K_3", b"", CCM_KEY_LEN)
        iv_3 = _edhoc_kdf(self._prk_3e2m, self._th_3, "IV_3", b"", CCM_NONCE_LEN)

        # A_3 = ["Encrypt0", h'', TH_3] per RFC 9528 §4.4.2 and Rust reference.
        # Using TH_3 only for AAD ensures transcript binding and interop with test vectors.
        a_3 = cbor2.dumps(["Encrypt0", b"", self._th_3])

        plaintext_3 = _aead_decrypt(k_3, iv_3, a_3, ciphertext_3)

        # Parse PLAINTEXT_3 = (ID_CRED_I, Signature_3, ?EAD_3)
        pt3_items = _decode_cbor_sequence(plaintext_3)
        if len(pt3_items) < 2:
            raise ValueError(
                f"Malformed PLAINTEXT_3: expected at least 2 CBOR items, got {len(pt3_items)}"
            )
        id_cred_i = pt3_items[0]
        if id_cred_i != peer_pubkey:
            raise ValueError("ID_CRED_I mismatch")
        signature_3 = pt3_items[1]

        if id_cred_i != peer_pubkey:
            raise ValueError("ID_CRED_I mismatch")

        # PRK_4e3m = PRK_3e2m for SIGN_SIGN (needed for MAC_3)
        self._prk_4e3m = self._prk_3e2m

        # Verify Signature_3 per RFC 9528 Section 4.4.2
        cred_i = peer_pubkey  # CRED_I = pubkey for simplified case

        # Recompute MAC_3
        context_3 = cbor2.dumps(id_cred_i) + cbor2.dumps(cred_i)
        mac_3 = _edhoc_kdf(self._prk_4e3m, self._th_3, "MAC_3", context_3, EDHOC_MAC_LEN)

        # M_3 = ["Signature1", << ID_CRED_I >>, TH_3, << CRED_I, ?EAD_3 >>, MAC_3]
        m_3 = cbor2.dumps([
            "Signature1",
            cbor2.dumps(id_cred_i),
            self._th_3,
            cbor2.dumps(cred_i),
            mac_3,
        ])
        verify_key = VerifyKey(peer_pubkey)
        try:
            peer_key = _validate_bytes(peer_pubkey, "peer public key", ED25519_SIG_LEN // 2)
            ciphertext_3 = _validate_bytes(msg3, "CIPHERTEXT_3")
            if len(ciphertext_3) <= CCM_TAG_LEN:
                raise ValueError("CIPHERTEXT_3 is too short")
            k_3 = _edhoc_kdf(self._prk_3e2m, self._th_3, "K_3", b"", CCM_KEY_LEN)
            iv_3 = _edhoc_kdf(self._prk_3e2m, self._th_3, "IV_3", b"", CCM_NONCE_LEN)
            a_3 = cbor2.dumps(["Encrypt0", b"", self._th_3])
            plaintext_3 = _aead_decrypt(k_3, iv_3, a_3, ciphertext_3)
            pt3_items = _decode_cbor_sequence(plaintext_3)
            if len(pt3_items) != 2:
                raise ValueError(
                    f"Malformed PLAINTEXT_3: expected 2 CBOR items, got {len(pt3_items)}"
                )
            id_cred_i = _validate_bytes(pt3_items[0], "ID_CRED_I", ED25519_SIG_LEN // 2)
            signature_3 = _validate_bytes(pt3_items[1], "Signature_3", ED25519_SIG_LEN)
            if id_cred_i != peer_key:
                raise ValueError("ID_CRED_I does not match the authenticated peer")
            prk_4e3m = self._prk_3e2m
            context_3 = cbor2.dumps(id_cred_i) + cbor2.dumps(peer_key)
            mac_3 = _edhoc_kdf(prk_4e3m, self._th_3, "MAC_3", context_3, EDHOC_MAC_LEN)
            m_3 = cbor2.dumps(
                ["Signature1", cbor2.dumps(id_cred_i), self._th_3, cbor2.dumps(peer_key), mac_3]
            )
            try:
                VerifyKey(peer_key).verify(m_3, signature_3)
            except Exception as exc:
                raise ValueError("Signature_3 verification failed") from exc
            th_4 = _compute_th(cbor2.dumps(self._th_3) + cbor2.dumps(ciphertext_3))
        except Exception as exc:
            self._fail()
            if isinstance(exc, ValueError):
                raise
            raise ValueError("Message 3 processing failed") from exc

        self._prk_4e3m = prk_4e3m
        self._th_4 = th_4
        self._state = _ResponderState.COMPLETE

    def export_oscore(self, oscore_salt_len: int = 8, oscore_key_len: int = 16) -> OscoreContext:
        """Export OSCORE security context.

        Note: Responder's sender/recipient IDs are swapped vs initiator.
        """
        self._require_state(_ResponderState.COMPLETE, "export_oscore")
        try:
            master_secret = _edhoc_kdf(
                self._prk_4e3m, self._th_4, "OSCORE_Master_Secret", b"", oscore_key_len
            )
            master_salt = _edhoc_kdf(
                self._prk_4e3m, self._th_4, "OSCORE_Master_Salt", b"", oscore_salt_len
            )
            context = OscoreContext(master_secret, master_salt, self._c_r, self._c_i)
        except Exception:
            self._fail()
            raise
        self._state = _ResponderState.EXPORTED
        self._clear_session_material()
        return context
