# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN link layer with signature and replay protection (muq).

Why this exists: The link layer is the boundary between:
- Above: IPv6/SCHC packets that assume reliable, authenticated delivery
- Below: Raw radio bytes that can be forged, replayed, or corrupted

This module provides:
1. Frame construction with proper sequencing
2. Schnorr signature generation on TX
3. Signature verification on RX (integrity + authentication)
4. Replay detection using per-sender sliding windows
5. Key pinning (TOFU) for change detection

Threading model: Concurrent send() via per-entry TxReservations; TX serialized by _tx_lock.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import secrets
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING

from ..constants import (
    CAD_MAX_BACKOFF_EXPONENT,
    CAD_MAX_CYCLES,
    CAD_SLOT_MS,
    LORA_CAD_TIMEOUT_MS,
)
from ..crypto.identity import Identity, PeerIdentity
from ..crypto.schnorr48 import sign, verify
from ..gradient import MAX_ENTRIES
from .frame import AddrMode, FrameError, LichenFrame, MAX_FRAME_BODY, MicLength
from .replay import ReplayProtector
from .tx_queue import Priority, TxQueue

if TYPE_CHECKING:
    from ..radio.base import Radio

logger = logging.getLogger(__name__)

# A signed frame puts the full Schnorr-48 value in the MIC field.
SIGNATURE_LENGTH = 48

# Track whether we've warned about encrypted frames being rejected.
# Why reject: Encryption is not implemented. Frames claiming to be encrypted
# cannot be decrypted, so accepting them would misinterpret the payload.
_encrypted_frame_warned = False


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


class ReceiveError(IntEnum):
    MALFORMED = 1
    UNSIGNED = 2
    ENCRYPTED = 3
    BAD_SIGNATURE = 4
    KEY_CHANGE = 5
    MIC_FAILED = 6
    REPLAY = 7


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
    # Protocol-level fix needed: add sender IID to header extension.
    peer_lookup_all: Callable[[], list[PeerIdentity]] | None = field(
        default=None, repr=False
    )
    cad_enabled: bool = field(default=True)
    tx_queue: TxQueue = field(default_factory=TxQueue)
    persist_path: str | None = field(default=None, repr=False)
    # ponytail: random epoch in [128,255] for reboot resilience without flash.
    # Half-space arithmetic treats upper-half counters as "ahead" of lower-half.
    # SECURITY: Use secrets module for cryptographically secure random epoch.
    _epoch: int = field(default_factory=lambda: secrets.randbelow(128) + 128, repr=False)
    _seqnum: int = field(default=0, repr=False)
    _exhausted: bool = field(default=False, repr=False)
    _pinned_keys: OrderedDict[bytes, bytes] = field(
        default_factory=OrderedDict, repr=False
    )
    _tx_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    _sequence_started: bool = field(default=False, init=False, repr=False)


    def __post_init__(self) -> None:
        # Why validate: Catch misconfiguration early
        if self.identity is None:
            raise ValueError("identity is required")
        if self.radio is None:
            raise ValueError("radio is required")
        if self.peer_lookup is None:
            raise ValueError("peer_lookup callback is required")
        if self.persist_path is not None:
            self._load_persisted_state()

    def _next_seqnum(self) -> tuple[int, int]:
        """Get next (epoch, seqnum) pair and advance the counter.

        Why internal: Sequence management is link layer's responsibility.
        Upper layers should not manipulate sequence numbers.

        Returns:
            (epoch, seqnum) for the next frame.
        """
        if self._exhausted:
            logger.error("tuple space exhausted; key rotation required before further TX")
            # Fail closed per e220
            raise OverflowError("link tuple exhaustion")

        epoch, seqnum = self._epoch, self._seqnum
        self._sequence_started = True

        # Advance for next call
        if epoch == 0xFF and seqnum == 0xFFFF:
            self._exhausted = True
        elif seqnum == 0xFFFF:
            # Why wrap handling: seqnum is 16-bit, epoch is 8-bit
            # Together they form a 24-bit monotonic counter
            self._seqnum = 0
            self._epoch += 1
            logger.debug("epoch wrapped to %d", self._epoch)
            if self._epoch == 0:
                self._exhausted = True
                logger.warning("24-bit tuple space exhausted; will trigger rotation on next load")
        else:
            self._seqnum += 1

        self._save_persisted_state()
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

        Signed fields follow the draft exactly with dst_addr_len domain
        separation (per j7rk): LENGTH || LLSec || EPO || SEQ || DST_LEN(1)
        || DST || PLD.

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
            + bytes([len(dst_addr)])
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
        """Queue and transmit one frame while serializing TX state."""
        async with self._tx_lock:
            return await self._send_locked(payload, dst_addr, addr_mode, priority, deadline_ms)

    async def _send_locked(
        self,
        payload: bytes,
        dst_addr: bytes = b"",
        addr_mode: AddrMode = AddrMode.NONE,
        priority: Priority = Priority.BULK,
        deadline_ms: int | None = None,
    ) -> bool:
        """Build, enqueue, and drain while the TX lock is held.

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

        Raises:
            QueueFullError: If queue is full and cannot preempt lower priority.
            FrameError: If the frame cannot be constructed (e.g., too large).
            ValueError: If dst_addr length does not match addr_mode.
        """
        # Validate dst_addr length matches addr_mode early
        expected_len = addr_mode.addr_len
        if len(dst_addr) != expected_len:
            raise ValueError(
                f"dst_addr is {len(dst_addr)} bytes but {addr_mode.name} "
                f"requires {expected_len} bytes"
            )

        # Validate frame fits on-air size constraint BEFORE signing
        frame_length = 4 + len(dst_addr) + len(payload) + SIGNATURE_LENGTH
        if frame_length > MAX_FRAME_BODY:
            raise FrameError(
                f"frame body is {frame_length} bytes, exceeds {MAX_FRAME_BODY}"
            )

        # Peek at current sequence numbers without consuming
        # Why peek first: If push() raises QueueFullError, we don't want to
        # waste a sequence number. Only consume after successful push.
        epoch, seqnum = self._epoch, self._seqnum

        llsec = int(addr_mode) | (1 << 5)
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

        # Queue with per-entry reservation for concurrent safety and specific completion
        reservation = self.tx_queue.push(
            frame_bytes,
            priority=priority,
            deadline_ms=deadline_ms,
            return_reservation=True,
        )
        assert reservation is not None, "push with reservation failed"

        # Push succeeded - now consume the sequence number
        self._next_seqnum()

        # Drain (serialized via _tx_lock); our reservation will be completed when transmitted
        await self.drain_tx_queue()

        # Per-send completion result (avoids ambiguous return from drain)
        return await reservation.wait()

    async def drain_tx_queue(self) -> bool:
        transmitted_any = False
        while True:
            self.tx_queue.expire_stale()
            if len(self.tx_queue) == 0:
                break  # Queue empty
            if self.cad_enabled and not await self._wait_for_clear_channel():
                logger.warning(
                    "TX deferred: channel busy after %d backoff cycles, "
                    "%d packets remain queued",
                    CAD_MAX_CYCLES,
                    len(self.tx_queue),
                )
                break
            entry = self.tx_queue.reserve()
            if entry is None:
                break
            if await self.radio.transmit(entry.data):
                transmitted_any = True
                logger.debug(
                    "TX success, %d packets remain queued",
                    len(self.tx_queue),
                )
                self.tx_queue.complete(entry, True)
            else:
                logger.warning("TX radio transmit failed")
                self.tx_queue.complete(entry, False)
                break
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

        Note: radio.cad() False now documented as clear (timeout conflated per
        P4 design in project-LICHEN-b4pw); treats timeout as clear for TX.

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

    async def receive(self, timeout_ms: int) -> RxFrame | ReceiveError | None:
        """Receive and validate a frame.

        Why async: Radio reception blocks until a packet arrives or timeout.

        Validation steps (in order):
        1. Parse frame structure
        2. Extract signature from mic field (when signature_present)
        3. Look up sender by IID (reject if unknown)
        4. Verify signature (reject if invalid) — signature covers frame integrity
        5. Pin sender key (TOFU) after successful signature verification
        6. Check replay protection (reject if replay)

        Args:
            timeout_ms: Maximum time to wait for a frame, in milliseconds.

        Returns:
            RxFrame on success, ReceiveError on validation failure, None on timeout.
            problem where all failures collapsed to None; callers can now
            distinguish security events from malformed frames from timeouts.
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
            return ReceiveError.MALFORMED

        # Why check signature_present: Unsigned frames are not authenticated.
        # In a real deployment, we might accept them for specific purposes
        # (e.g., discovery), but for now we require signatures.
        if not frame.signature_present:
            logger.warning("RX unsigned frame rejected (policy requires signatures)")
            return ReceiveError.UNSIGNED

        # SECURITY: Reject frames with encrypted=True until encryption is implemented.
        # Why reject (not accept): An attacker could send a frame with encrypted=True
        # but plaintext payload. Without decryption, we would misinterpret the payload
        # (treating ciphertext as plaintext, or vice versa). Signature verification
        # might coincidentally succeed, leading to accepted but corrupted data.
        if frame.encrypted:
            global _encrypted_frame_warned
            if not _encrypted_frame_warned:
                logger.warning(
                    "Encrypted frames NOT SUPPORTED - rejecting. "
                    "Encryption is not implemented; frames with encrypted=True are dropped."
                )
                _encrypted_frame_warned = True
            else:
                logger.debug("RX encrypted frame rejected (encryption not implemented)")
            return ReceiveError.ENCRYPTED

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
            return ReceiveError.BAD_SIGNATURE

        # Step 4 happened inside _find_sender (signature verification)

        # Step 4.5: Key pinning check — TOFU anchor + change detection.
        # Why verify: The signature in _find_sender already authenticated the
        # sender's pubkey. Key pinning detects key changes for the same IID.
        pinned_pk = self._pinned_keys.get(sender.iid)
        if pinned_pk is not None and pinned_pk != sender.pubkey:
            logger.error(
                "link-layer KEY CHANGE DETECTED for IID %s: pinned=%s got=%s",
                sender.iid.hex(),
                pinned_pk.hex()[:16],
                sender.pubkey.hex()[:16],
            )
            return ReceiveError.KEY_CHANGE

        # Step 4.6: Pin key after signature verification succeeds.
        # Why after signature: The Schnorr signature covers the payload and
        # metadata (LLSec || epoch || seqnum || dst_addr || payload), so
        # successful verification already provides integrity. Pinning after
        # verification prevents attackers from injecting forged keys.
        self._pinned_keys[sender.iid] = sender.pubkey
        self._pinned_keys.move_to_end(sender.iid)
        while len(self._pinned_keys) > MAX_ENTRIES:
            self._pinned_keys.popitem(last=False)

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
            return ReceiveError.REPLAY

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
        #
        # Subtle optimization in the condition below: '(peer is None or
        # candidate.pubkey != peer.pubkey)'. If peer_lookup(b'') returned a
        # candidate that failed verification above, we skip re-verifying it
        # here. This avoids redundant (expensive) signature checks.
        #
        # Correct interaction between peer_lookup (hint-based, often first
        # match) and peer_lookup_all (exhaustive list). The logic ensures
        # we don't miss valid senders while optimizing common cases.
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
            RuntimeError: If any frame has already been accepted for transmission.
        """
        if not 0 <= epoch <= 0xFF:
            raise ValueError(f"epoch out of range: {epoch}")
        if not 0 <= seqnum <= 0xFFFF:
            raise ValueError(f"seqnum out of range: {seqnum}")
        if self._exhausted:
            raise OverflowError("link-layer sequence exhausted; rotate identity key")
        if self._sequence_started:
            raise RuntimeError("link-layer sequence cannot be reset after use")
        self._epoch = epoch
        self._seqnum = seqnum
        if epoch == 0xFF and seqnum == 0xFFFF:
            self._exhausted = True
            raise OverflowError("link-layer sequence exhausted; rotate identity key")
        logger.info("sequence set to epoch=%d seqnum=%d", epoch, seqnum)

    def get_sequence(self) -> tuple[int, int]:
        """Get current sequence counter (for persistence).

        Returns:
            (epoch, seqnum) tuple.
        """
        if self._exhausted:
            raise OverflowError("link-layer sequence exhausted; rotate identity key")
        return self._epoch, self._seqnum

    def _load_persisted_state(self) -> None:
        if self.persist_path is None:
            return
        path = self.persist_path
        if not os.path.exists(path):
            return
        try:
            with open(path) as f:
                data = json.load(f)
            self.set_sequence(data.get("epoch", 0), data.get("seqnum", 0))
        except Exception:
            pass

    def _save_persisted_state(self) -> None:
        if self.persist_path is None:
            return
        try:
            data = {"epoch": self._epoch, "seqnum": self._seqnum}
            with open(self.persist_path, "w") as f:
                json.dump(data, f)
        except Exception:
            pass
