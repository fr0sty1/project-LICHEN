# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Protocol classes defining cross-implementation contracts.

These Protocol classes mirror Rust traits and C vtables to formalize the
interfaces that must be consistent across all LICHEN implementations. Use
them for type hints to enable mypy to catch parity bugs where implementations
diverge.

Design rationale:
- All protocols are runtime_checkable for isinstance() validation
- Method signatures match the canonical Rust traits in lichen-hal/lichen-link
- Async methods mirror the embassy-async-first design in Rust
- Sync methods where the Rust trait uses blocking (e.g., configure)

Cross-reference:
- Rust lichen-hal: Radio, Clock, Rng, NonVolatile, Display, Input, Power
- Rust lichen-link: ReplayWindow, LinkLayer (implicitly via methods)
- C lichen_meshcore_adapter_ops: vtable pattern for callbacks
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

# =============================================================================
# Radio / Physical Layer
# =============================================================================


@runtime_checkable
class RadioDriver(Protocol):
    """Radio driver interface (mirrors Rust lichen_hal::Radio trait).

    All radio implementations must satisfy this protocol for transmit/receive
    operations. Async-first design for embassy compatibility; blocking impls
    wrap in an executor.

    Cross-implementation parity:
    - Rust: lichen_hal::Radio trait
    - C: Radio HAL callbacks in Zephyr driver layer
    - Python: lichen.radio.base.Radio (existing, should migrate to this)
    """

    async def transmit(self, payload: bytes) -> bool:
        """Transmit a payload over the radio.

        Args:
            payload: Raw bytes to transmit (max 255 for LoRa).

        Returns:
            True if transmission succeeded, False on hardware error.
        """
        ...

    async def receive(self, timeout_ms: int) -> tuple[bytes, int, int] | None:
        """Receive a payload with timeout.

        Args:
            timeout_ms: Maximum wait time in milliseconds.

        Returns:
            Tuple of (payload, rssi_dbm, snr_db) on success,
            None on timeout without receiving a packet.
        """
        ...

    def configure(self, freq_hz: int, tx_power_dbm: int) -> None:
        """Configure radio parameters.

        Args:
            freq_hz: Center frequency in Hz (e.g., 915_000_000).
            tx_power_dbm: Transmit power in dBm.
        """
        ...

    async def cad(self, timeout_ms: int) -> bool:
        """Perform Channel Activity Detection.

        Listen briefly for LoRa preamble activity. Used for CSMA/CA.

        Args:
            timeout_ms: Maximum CAD duration.

        Returns:
            True if channel activity detected, False if clear.
        """
        ...


# =============================================================================
# Link Layer
# =============================================================================


@runtime_checkable
class FrameParser(Protocol):
    """Frame serialization/deserialization (mirrors Rust LichenFrame methods).

    Defines the wire format codec for LICHEN link-layer frames. The frame
    format is specified in spec section 4.

    Cross-implementation parity:
    - Rust: lichen_link::frame::LichenFrame::{from_bytes, write_to}
    - C: lichen_link_frame_parse / lichen_link_frame_build
    - Python: lichen.link.frame.LichenFrame
    """

    @classmethod
    def from_bytes(cls, data: bytes) -> FrameParser:
        """Parse a frame from wire bytes.

        Args:
            data: Raw received bytes including length prefix.

        Returns:
            Parsed frame instance.

        Raises:
            FrameError: If frame is malformed or truncated.
        """
        ...

    def to_bytes(self) -> bytes:
        """Serialize frame to wire format.

        Returns:
            Bytes ready for radio transmission.

        Raises:
            FrameError: If frame exceeds 255-byte body limit.
        """
        ...

    @property
    def epoch(self) -> int:
        """8-bit epoch counter."""
        ...

    @property
    def seqnum(self) -> int:
        """16-bit sequence number."""
        ...

    @property
    def dst_addr(self) -> bytes:
        """Destination address (0, 2, or 8 bytes per addr_mode)."""
        ...

    @property
    def payload(self) -> bytes:
        """Frame payload (typically a SCHC-compressed packet)."""
        ...

    @property
    def signature_present(self) -> bool:
        """Whether the MIC field contains a Schnorr-48 signature."""
        ...


@runtime_checkable
class LinkLayerTx(Protocol):
    """Link layer transmit interface.

    Cross-implementation parity:
    - Rust: lichen_link::link_layer::LinkLayer::build_frame
    - C: lichen_link_ctx_send
    - Python: lichen.link.link_layer.LinkLayer.send
    """

    async def send(
        self,
        payload: bytes,
        dst_addr: bytes = b"",
    ) -> bool:
        """Transmit a signed frame.

        Signs the frame with the node identity, stores the signature in MIC,
        and transmits it.
        Performs CAD with backoff if cad_enabled.

        Args:
            payload: Application data (typically SCHC-compressed).
            dst_addr: Destination address (empty for broadcast).

        Returns:
            True if transmitted successfully.
        """
        ...

    def get_sequence(self) -> tuple[int, int]:
        """Get current (epoch, seqnum) for persistence."""
        ...

    def set_sequence(self, epoch: int, seqnum: int) -> None:
        """Restore (epoch, seqnum) after reboot."""
        ...


@runtime_checkable
class LinkLayerRx(Protocol):
    """Link layer receive interface.

    Cross-implementation parity:
    - Rust: lichen_link::link_layer::LinkLayer::receive_frame
    - C: lichen_link_ctx_recv
    - Python: lichen.link.link_layer.LinkLayer.receive
    """

    async def receive(self, timeout_ms: int) -> RxResult | None:
        """Receive and validate a frame.

        Performs: parse -> signature verify -> replay check -> return.

        Args:
            timeout_ms: Maximum wait time.

        Returns:
            RxResult with validated frame and sender, or None on timeout.
            Returns None (not raises) for validation failures.
        """
        ...


@runtime_checkable
class RxResult(Protocol):
    """Received frame result (mirrors Rust AuthenticatedFrame).

    Contains the validated frame and authenticated sender identity.
    """

    @property
    def payload(self) -> bytes:
        """Authenticated frame payload, unchanged from the wire."""
        ...

    @property
    def sender_iid(self) -> bytes:
        """Sender's 8-byte Interface Identifier."""
        ...

    @property
    def sender_pubkey(self) -> bytes:
        """Sender's 32-byte Ed25519 public key."""
        ...

    @property
    def rssi_dbm(self) -> int:
        """Received signal strength in dBm."""
        ...

    @property
    def snr_db(self) -> int:
        """Signal-to-noise ratio in dB."""
        ...


# =============================================================================
# Cryptographic Primitives
# =============================================================================


@runtime_checkable
class Signer(Protocol):
    """Signature generation (mirrors schnorr module sign function).

    Produces 48-byte Schnorr signatures per draft-lichen-schnorr-00.

    Cross-implementation parity:
    - Rust: lichen_link::schnorr::sign_frame
    - C: lichen_schnorr_sign
    - Python: lichen.crypto.schnorr48.sign
    """

    def sign(self, privkey: bytes, pubkey: bytes, message: bytes) -> bytes:
        """Sign a message with Schnorr-48.

        Args:
            privkey: 32-byte Ed25519 private scalar (clamped).
            pubkey: 32-byte Ed25519 public key.
            message: Bytes to sign.

        Returns:
            48-byte signature (16-byte challenge + 32-byte response).
        """
        ...


@runtime_checkable
class Verifier(Protocol):
    """Signature verification (mirrors schnorr module verify function).

    Verifies 48-byte Schnorr signatures per draft-lichen-schnorr-00.

    Cross-implementation parity:
    - Rust: lichen_link::schnorr::verify_frame
    - C: lichen_schnorr_verify
    - Python: lichen.crypto.schnorr48.verify
    """

    def verify(self, pubkey: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a Schnorr-48 signature.

        Args:
            pubkey: 32-byte Ed25519 public key.
            message: Original signed message.
            signature: 48-byte signature to verify.

        Returns:
            True if signature is valid, False otherwise.
        """
        ...


# =============================================================================
# Replay Protection
# =============================================================================


@runtime_checkable
class ReplayWindow(Protocol):
    """Anti-replay sliding window for a single sender.

    Tracks highest counter seen + bitmap of recent accepted sequence numbers.
    Window size is implementation-defined (typically 32-64 slots).

    Cross-implementation parity:
    - Rust: lichen_link::replay::ReplayWindow
    - C: lichen_replay_window (in link_ctx.c)
    - Python: lichen.link.replay.ReplayWindow
    """

    def check_and_update(self, epoch: int, seqnum: int) -> bool:
        """Validate and record a frame's sequence.

        Returns:
            True if frame is fresh (accepted),
            False if replay or below window floor.
        """
        ...

    @property
    def highest(self) -> int:
        """Highest logical counter accepted, or -1 if none."""
        ...


@runtime_checkable
class ReplayProtector(Protocol):
    """Per-sender replay protection manager.

    Maintains independent ReplayWindow for each sender identity.

    Cross-implementation parity:
    - Rust: lichen_link::link_layer::ReplayProtector
    - C: Embedded in lichen_link_ctx peer table
    - Python: lichen.link.replay.ReplayProtector
    """

    def check_and_update(
        self, sender: bytes | str | int, epoch: int, seqnum: int
    ) -> bool:
        """Validate and record a frame from sender.

        Creates a new window for first-seen senders.

        Args:
            sender: Sender identifier (pubkey bytes, IID hex string, or node ID).
            epoch: 8-bit epoch from frame.
            seqnum: 16-bit sequence number from frame.

        Returns:
            True if fresh, False if replay.
        """
        ...

    def reset(self, sender: bytes | str | int) -> None:
        """Forget all state for a sender (e.g., on re-keying)."""
        ...


# =============================================================================
# Key Management
# =============================================================================


@runtime_checkable
class Identity(Protocol):
    """Node cryptographic identity.

    Cross-implementation parity:
    - Rust: lichen_link::identity::Identity
    - C: lichen_identity struct
    - Python: lichen.crypto.identity.Identity
    """

    @property
    def privkey(self) -> bytes:
        """32-byte Ed25519 private scalar (clamped)."""
        ...

    @property
    def pubkey(self) -> bytes:
        """32-byte Ed25519 public key."""
        ...

    @property
    def iid(self) -> bytes:
        """8-byte Interface Identifier derived from pubkey."""
        ...


@runtime_checkable
class PeerIdentity(Protocol):
    """Known peer's public identity.

    Cross-implementation parity:
    - Rust: lichen_link::identity::PeerIdentity
    - C: lichen_peer struct
    - Python: lichen.crypto.identity.PeerIdentity
    """

    @property
    def pubkey(self) -> bytes:
        """32-byte Ed25519 public key."""
        ...

    @property
    def iid(self) -> bytes:
        """8-byte Interface Identifier derived from pubkey."""
        ...


# =============================================================================
# Hardware Abstraction (optional traits)
# =============================================================================


@runtime_checkable
class Clock(Protocol):
    """Monotonic clock source (mirrors Rust lichen_hal::Clock).

    Cross-implementation parity:
    - Rust: lichen_hal::Clock
    - C: k_uptime_get_32() or platform equivalent
    """

    def now_us(self) -> int:
        """Current time in microseconds since arbitrary epoch."""
        ...


@runtime_checkable
class Rng(Protocol):
    """Random number generator (mirrors Rust lichen_hal::Rng).

    Cross-implementation parity:
    - Rust: lichen_hal::Rng
    - C: sys_rand_get or TRNG HAL
    """

    def fill_bytes(self, buf: bytearray) -> None:
        """Fill buffer with random bytes."""
        ...


@runtime_checkable
class NonVolatile(Protocol):
    """Persistent key-value storage (mirrors Rust lichen_hal::NonVolatile).

    Used for identity keys, routing state, sequence counters.

    Cross-implementation parity:
    - Rust: lichen_hal::NonVolatile
    - C: NVS or settings subsystem
    """

    def read(self, key: str, buf: bytearray) -> int | None:
        """Read value for key. Returns bytes read or None if not found."""
        ...

    def write(self, key: str, data: bytes) -> None:
        """Write value for key."""
        ...

    def delete(self, key: str) -> bool:
        """Delete key. Returns True if key existed."""
        ...
