# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN link layer with signature and replay protection (muq).

Why this exists: The link layer is the boundary between:
- Above: IPv6/SCHC packets that assume reliable, authenticated delivery
- Below: Raw radio bytes that can be forged, replayed, or corrupted

This module provides:
1. Frame construction with proper sequencing
2. Schnorr signature generation on TX
3. Signature verification on RX
4. Replay detection using per-sender sliding windows
5. MIC handling: unsigned frames have no MIC; signed frames carry Schnorr-48

Threading model: All methods are async. A single LinkLayer instance should be
used by one task at a time. For concurrent access, use external synchronization.
"""

from __future__ import annotations

import asyncio
import logging
import random
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..constants import (
    CAD_MAX_BACKOFF_EXPONENT,
    CAD_MAX_CYCLES,
    CAD_SLOT_MS,
    LORA_CAD_TIMEOUT_MS,
)
from ..crypto.identity import Identity, PeerIdentity
from ..crypto.schnorr48 import sign, verify
from .frame import MAX_FRAME_BODY, AddrMode, FrameError, LichenFrame, MicLength
from .replay import ReplayProtector
from .tx_queue import Priority, TxQueue

if TYPE_CHECKING:
    from ..radio.base import Radio

logger = logging.getLogger(__name__)

# A signed frame puts the full Schnorr-48 value in the MIC field.
SIGNATURE_LENGTH = 48

@dataclass
class RxFrame:
    """A received and validated frame with metadata.

    Why a separate class: Callers need both the frame content and reception
    metadata (RSSI, SNR) for link quality estimation and routing decisions.

    Attributes:
        frame: The parsed and validated LichenFrame.
        sender: The sender's identity (verified by signature).
        rssi_dbm: Received signal strength in dBm.
        snr_db: Signal-to-noise ratio in dB.
    """

    frame: LichenFrame
    sender: PeerIdentity
    rssi_dbm: int
    snr_db: int

    @property
    def payload(self) -> bytes:
        """Authenticated frame payload."""
        return self.frame.payload

    @property
    def sender_iid(self) -> bytes:
        """Authenticated sender IID."""
        return self.sender.iid

    @property
    def sender_pubkey(self) -> bytes:
        """Authenticated sender public key."""
        return self.sender.pubkey


@dataclass
class LinkLayer:
    """Link layer with signing, verification, and replay protection.

    Why dataclass: Clear field documentation, automatic __init__, works well
    with dependency injection for testing.

    Attributes:
        radio: The underlying radio for TX/RX.
        identity: This node's cryptographic identity.
        peer_lookup: Callback to resolve sender IID to PeerIdentity.
            Why a callback: The peer database is owned by upper layers.
            We don't want the link layer to own peer state.
        replay_protector: Per-sender replay detection.
        cad_enabled: If True, perform CAD before transmit with exponential
            backoff on busy channel. Defaults to True.
        _epoch: Current 8-bit epoch (increments on seqnum wrap).
        _seqnum: Current 16-bit sequence number.
    """

    radio: Radio
    identity: Identity
    peer_lookup: Callable[[bytes], PeerIdentity | None]
    replay_protector: ReplayProtector = field(default_factory=ReplayProtector)
    # peer_lookup_all: For brute-force sender identification when no hint available.
    # NOTE: O(n) verification is unavoidable without sender IID in frame format.
    # Protocol-level fix needed: add sender IID to frame header extension.
    peer_lookup_all: Callable[[], list[PeerIdentity]] | None = field(
        default=None, repr=False
    )
    cad_enabled: bool = field(default=True)
    tx_queue: TxQueue = field(default_factory=TxQueue)
    # ponytail: random epoch in [128,255] for reboot resilience without flash.
    # Half-space arithmetic treats upper-half counters as "ahead" of lower-half.
    # SECURITY: Use secrets module for cryptographically secure random epoch.
    _epoch: int = field(default_factory=lambda: secrets.randbelow(128) + 128, repr=False)
    _seqnum: int = field(default=0, repr=False)
    _sequence_exhausted: bool = field(default=False, repr=False)
    _sequence_started: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        # Why validate: Catch misconfiguration early
        if self.identity is None:
            raise ValueError("identity is required")
        if self.radio is None:
            raise ValueError("radio is required")
        if self.peer_lookup is None:
            raise ValueError("peer_lookup callback is required")

    def _next_seqnum(self) -> tuple[int, int]:
        """Get next (epoch, seqnum) pair and advance the counter.

        Why internal: Sequence management is link layer's responsibility.
        Upper layers should not manipulate sequence numbers.

        Returns:
            (epoch, seqnum) for the next frame.
        """
        if self._sequence_exhausted:
            raise OverflowError("link-layer sequence exhausted; rotate identity key")

        epoch, seqnum = self._epoch, self._seqnum
        self._sequence_started = True

        # Advance for next call
        if epoch == 0xFF and seqnum == 0xFFFF:
            self._sequence_exhausted = True
        elif seqnum == 0xFFFF:
            # Why wrap handling: seqnum is 16-bit, epoch is 8-bit
            # Together they form a 24-bit monotonic counter
            self._seqnum = 0
            self._epoch += 1
            logger.debug("epoch wrapped to %d", self._epoch)
        else:
            self._seqnum += 1

        return epoch, seqnum

    def _build_signable_data(
        self,
        epoch: int,
        seqnum: int,
        dst_addr: bytes,
        payload: bytes,
        length: int | None = None,
        llsec: int | None = None,
    ) -> bytes:
        """Construct the data that gets signed.

        Why explicit: The signature must cover all immutable fields. This
        function documents exactly what is signed, preventing subtle bugs
        where fields are added but not covered by the signature.

        Signed fields follow the draft exactly:
        LENGTH || LLSec || EPO || SEQ || DST || PLD.

        Returns:
            Bytes to be signed.
        """
        if length is None:
            length = 4 + len(dst_addr) + len(payload) + SIGNATURE_LENGTH
        if llsec is None:
            llsec = int(AddrMode.NONE) | (1 << 5)
        return (
            bytes([length, llsec, epoch])
            + seqnum.to_bytes(2, "big")
            + dst_addr
            + payload
        )

    async def send(
        self,
        payload: bytes,
        dst_addr: bytes = b"",
        addr_mode: AddrMode = AddrMode.NONE,
        priority: Priority = Priority.BULK,
        deadline_ms: int | None = None,
    ) -> bool:
        """Transmit a signed frame via the TX queue.

        Why async: Radio transmission may block waiting for channel clear
        (listen-before-talk) or TX completion.

        The frame is queued with the specified priority. Then the queue is
        drained: packets are transmitted in priority order until the queue
        is empty or CAD fails. Packets remaining in queue after CAD failure
        will be transmitted on the next send() call.

        If cad_enabled is True, performs CAD before transmitting. On busy
        channel, backs off with exponential delay (0 to 2^attempt - 1 slots,
        capped at 31 slots). After 3 full backoff cycles without clearing,
        packets remain queued for later retry.

        Args:
            payload: The data to send (typically SCHC-compressed packet).
            dst_addr: Destination address. Length must match addr_mode:
                NONE/ELIDED require empty (b''), SHORT requires 2 bytes,
                EXTENDED requires 8 bytes. ELIDED means address is derived
                from upper-layer IPv6 destination by the receiver.
            addr_mode: How to encode the destination.
            priority: Queue priority (ROUTING, ACK, URGENT, or BULK).
            deadline_ms: Absolute deadline in ms. If None, uses default
                         for the priority level.

        Returns:
            True if at least one packet was transmitted from the queue,
            False if CAD failed or queue was empty after expiry.

        Raises:
            QueueFullError: If queue is full and cannot preempt lower priority.
            FrameError: If the frame cannot be constructed (e.g., too large).
            ValueError: If dst_addr length does not match addr_mode.
            OverflowError: If every epoch/sequence tuple has been consumed.
        """
        # Validate dst_addr length matches addr_mode early
        expected_len = addr_mode.addr_len
        if len(dst_addr) != expected_len:
            raise ValueError(
                f"dst_addr is {len(dst_addr)} bytes but {addr_mode.name} "
                f"requires {expected_len} bytes"
            )

        llsec = int(addr_mode) | (1 << 5)
        frame_length = 4 + len(dst_addr) + len(payload) + SIGNATURE_LENGTH
        if frame_length > MAX_FRAME_BODY:
            raise FrameError(
                f"frame body is {frame_length} bytes, exceeds {MAX_FRAME_BODY}"
            )
        self.tx_queue.ensure_can_push(priority)
        epoch, seqnum = self._next_seqnum()
        signable = self._build_signable_data(
            epoch, seqnum, dst_addr, payload, frame_length, llsec
        )
        signature = sign(self.identity.privkey, self.identity.pubkey, signable)

        frame = LichenFrame(
            epoch=epoch,
            seqnum=seqnum,
            dst_addr=dst_addr,
            payload=payload,
            mic=signature,
            addr_mode=addr_mode,
            mic_length=MicLength.BITS32,
            signature_present=True,
            encrypted=False,
        )

        frame_bytes = frame.to_bytes()

        logger.debug(
            "TX queue: epoch=%d seqnum=%d dst=%s payload=%d bytes priority=%s",
            epoch,
            seqnum,
            dst_addr.hex() if dst_addr else "broadcast",
            len(payload),
            priority.name,
        )

        # Queue the frame (may raise QueueFullError)
        self.tx_queue.push(frame_bytes, priority=priority, deadline_ms=deadline_ms)

        # Drain the queue
        return await self.drain_tx_queue()

    async def drain_tx_queue(self) -> bool:
        """Transmit packets from the TX queue until empty or channel busy.

        Expires stale packets before attempting transmission. Transmits
        in priority order (highest priority = lowest numeric value first).

        Returns:
            True if at least one packet was transmitted, False otherwise.
        """
        transmitted_any = False

        while True:
            # Expire stale packets and check if queue has work
            self.tx_queue.expire_stale()
            if len(self.tx_queue) == 0:
                break  # Queue empty

            # CAD before pop - on failure, packets remain safely queued.
            # Why not pop first: Re-queuing after CAD failure can raise
            # QueueFullError if queue is full of same-priority packets
            # (e.g., ROUTING cannot preempt ROUTING), losing the packet.
            if self.cad_enabled and not await self._wait_for_clear_channel():
                logger.warning(
                    "TX deferred: channel busy after %d backoff cycles, "
                    "%d packets remain queued",
                    CAD_MAX_CYCLES,
                    len(self.tx_queue),
                )
                break

            # Channel clear (or CAD disabled) - now safe to pop and transmit
            frame_bytes = self.tx_queue.pop()
            if frame_bytes is None:
                break  # Packet expired during CAD (unlikely but possible)

            # Transmit
            if await self.radio.transmit(frame_bytes):
                transmitted_any = True
                logger.debug(
                    "TX success, %d packets remain queued",
                    len(self.tx_queue),
                )
            else:
                logger.warning("TX radio transmit failed")
                break  # Radio failure - stop draining

        return transmitted_any

    async def _wait_for_clear_channel(self) -> bool:
        """Perform CAD with exponential backoff until channel is clear.

        Algorithm: For each cycle, attempt CAD with increasing backoff.
        - attempt 0: CAD, if busy wait 0 slots (immediate retry)
        - attempt 1: CAD, if busy wait 0-1 slots
        - attempt 2: CAD, if busy wait 0-3 slots
        - ...
        - attempt 5: CAD, if busy wait 0-31 slots (max)

        If we complete CAD_MAX_BACKOFF_EXPONENT attempts and still busy,
        that's one cycle. After CAD_MAX_CYCLES full cycles, give up.

        Returns:
            True if channel became clear, False after max retries.
        """
        max_slots = (1 << CAD_MAX_BACKOFF_EXPONENT) - 1  # 31

        for cycle in range(CAD_MAX_CYCLES):
            for attempt in range(CAD_MAX_BACKOFF_EXPONENT + 1):
                channel_busy = await self.radio.cad(LORA_CAD_TIMEOUT_MS)

                if not channel_busy:
                    logger.debug(
                        "CAD clear: cycle=%d attempt=%d",
                        cycle,
                        attempt,
                    )
                    return True

                # Channel busy - compute backoff
                # Window size: 2^attempt, capped at 2^max_exponent
                window = min(1 << attempt, max_slots + 1)
                slots = random.randint(0, window - 1)
                backoff_ms = slots * CAD_SLOT_MS

                logger.debug(
                    "CAD busy: cycle=%d attempt=%d backoff=%dms (%d slots)",
                    cycle,
                    attempt,
                    backoff_ms,
                    slots,
                )

                if backoff_ms > 0:
                    await asyncio.sleep(backoff_ms / 1000.0)

        return False

    async def receive(self, timeout_ms: int) -> RxFrame | None:
        """Receive and validate a frame.

        Why async: Radio reception blocks until a packet arrives or timeout.

        Validation steps (in order):
        1. Parse frame structure (FrameError on malformed)
        2. Read signature from MIC
        3. Look up sender by IID (reject if unknown)
        4. Verify signature (reject if invalid)
        5. Check replay protection (reject if replay)

        Why this order:
        - Parsing first: Can't do anything else with garbage
        - Signature read: Need to know what to verify
        - Sender lookup: Need pubkey for verification
        - Signature verify: Proves authenticity before trusting content
        - Replay last: Only matters if signature is valid

        Args:
            timeout_ms: Maximum time to wait for a frame, in milliseconds.

        Returns:
            RxFrame with validated frame and metadata, or None on timeout.
            Returns None (not raises) for validation failures - they're
            expected in adversarial environments.
        """
        result = await self.radio.receive(timeout_ms)
        if result is None:
            return None

        raw_bytes, rssi_dbm, snr_db = result

        # Step 1: Parse frame structure
        try:
            frame = LichenFrame.from_bytes(raw_bytes)
        except FrameError as e:
            logger.warning("RX malformed frame: %s", e)
            return None

        # Why check signature_present: Unsigned frames are not authenticated.
        # In a real deployment, we might accept them for specific purposes
        # (e.g., discovery), but for now we require signatures.
        if not frame.signature_present:
            logger.warning("RX unsigned frame rejected (policy requires signatures)")
            return None

        # S=1 makes the MIC field the 48-byte Schnorr signature.
        signature = frame.mic
        inner_payload = frame.payload

        # Step 3: Look up sender
        # Why use IID from signature verification: We need the sender's pubkey
        # to verify. The frame itself doesn't contain the sender's IID directly;
        # we must try known peers.
        #
        # TODO: For broadcast frames, we need to try multiple potential senders
        # or have the sender IID embedded somewhere. For now, this is a
        # limitation: we need out-of-band knowledge of who might be sending.
        #
        # Workaround for now: Try all known peers. This is O(n) but n is small.
        sender = self._find_sender(frame, signature, inner_payload)
        if sender is None:
            logger.warning("RX frame from unknown sender or bad signature")
            return None

        # Step 4 happened inside _find_sender (signature verification)

        # Step 5: Replay protection
        # Why use pubkey as sender ID: It's the unique identifier for a node.
        # IID has a (tiny) collision risk; pubkey is definitive.
        if not self.replay_protector.check_and_update(
            sender.pubkey, frame.epoch, frame.seqnum
        ):
            logger.warning(
                "RX replay detected: epoch=%d seqnum=%d sender=%s",
                frame.epoch,
                frame.seqnum,
                sender.iid.hex(),
            )
            return None

        # Success! Return the validated frame
        logger.debug(
            "RX valid frame: epoch=%d seqnum=%d sender=%s payload=%d bytes",
            frame.epoch,
            frame.seqnum,
            sender.iid.hex(),
            len(inner_payload),
        )

        # Preserve the authenticated payload; signature bytes live in MIC.
        validated_frame = LichenFrame(
            epoch=frame.epoch,
            seqnum=frame.seqnum,
            dst_addr=frame.dst_addr,
            payload=inner_payload,
            mic=frame.mic,
            addr_mode=frame.addr_mode,
            mic_length=frame.mic_length,
            signature_present=True,
            encrypted=frame.encrypted,
        )

        return RxFrame(
            frame=validated_frame,
            sender=sender,
            rssi_dbm=rssi_dbm,
            snr_db=snr_db,
        )

    def _find_sender(
        self,
        frame: LichenFrame,
        signature: bytes,
        payload: bytes,
    ) -> PeerIdentity | None:
        """Find the sender by trying known peers' pubkeys.

        Why brute-force: Without sender IID in the frame, we must try each
        known peer. This is a design limitation we might address later by
        including sender IID in a header extension.

        Performance: O(n) where n = number of known peers. For mesh networks
        with <100 peers and fast Ed25519 verification, this is acceptable.
        If it becomes a bottleneck, we can add sender hints.

        Returns:
            PeerIdentity if found and signature valid, None otherwise.
        """
        signable = self._build_signable_data(
            frame.epoch,
            frame.seqnum,
            frame.dst_addr,
            payload,
            4 + len(frame.dst_addr) + len(payload) + SIGNATURE_LENGTH,
            frame.llsec_byte(),
        )

        # Why try self first: In loopback/testing scenarios, we might receive
        # our own broadcasts. Check self before iterating peers.
        if verify(self.identity.pubkey, signable, signature):
            # It's from us - might be a loopback or echo
            logger.debug("RX frame from self (loopback)")
            return PeerIdentity.from_pubkey(self.identity.pubkey)

        # Try peer lookup for broadcast (no specific destination)
        # TODO: This is inefficient. In production, the frame should contain
        # sender IID so we can look up directly.
        #
        # For now, we rely on the peer_lookup callback to iterate candidates.
        # The callback returns None if no match found. We pass empty bytes as
        # the hint since current frame format lacks sender IID.
        peer = self.peer_lookup(b"")
        if peer is not None and verify(peer.pubkey, signable, signature):
            return peer

        # Brute-force: try each known peer until signature verifies.
        # O(n) is unavoidable without sender IID in frame format.
        if self.peer_lookup_all is not None:
            for candidate in self.peer_lookup_all():
                if (peer is None or candidate.pubkey != peer.pubkey) and verify(
                    candidate.pubkey, signable, signature
                ):
                    return candidate

        return None

    def set_sequence(self, epoch: int, seqnum: int) -> None:
        """Set the sequence counter (for persistence across restarts).

        Why exposed: Sequence numbers must be monotonic across reboots to
        prevent replay attacks against peers who cached our old counter.
        The caller should persist and restore these values.

        Args:
            epoch: 8-bit epoch.
            seqnum: 16-bit sequence number.

        Raises:
            ValueError: If values are out of range.
        """
        if not 0 <= epoch <= 0xFF:
            raise ValueError(f"epoch out of range: {epoch}")
        if not 0 <= seqnum <= 0xFFFF:
            raise ValueError(f"seqnum out of range: {seqnum}")
        if self._sequence_exhausted:
            raise OverflowError("link-layer sequence exhausted; rotate identity key")
        if self._sequence_started:
            raise RuntimeError("link-layer sequence cannot be reset after use")
        self._epoch = epoch
        self._seqnum = seqnum
        if epoch == 0xFF and seqnum == 0xFFFF:
            self._sequence_exhausted = True
            raise OverflowError("link-layer sequence exhausted; rotate identity key")
        logger.info("sequence set to epoch=%d seqnum=%d", epoch, seqnum)

    def get_sequence(self) -> tuple[int, int]:
        """Get current sequence counter (for persistence).

        Returns:
            (epoch, seqnum) tuple.
        """
        if self._sequence_exhausted:
            raise OverflowError("link-layer sequence exhausted; rotate identity key")
        return self._epoch, self._seqnum
