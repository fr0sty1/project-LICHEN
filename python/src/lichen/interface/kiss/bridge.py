# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""
KISS-LICHEN bridge with port-based routing and APRS support.

Connects KISS interface to LICHEN LinkLayer with AX.25/APRS wrapping for
legacy TNC apps (port 0) and raw LICHEN frames (port 1).

APRSDroid users see proper messages in the Messages tab with delivery
confirmations (acks).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .aprs import (
    AprsAck,
    AprsMessage,
    AprsMessageTracker,
    AprsRej,
    create_ack,
    create_message,
    parse_aprs_packet,
)
from .aprs_synth import synthesize_aprs
from .ax25 import Ax25Error, ax25_decode, ax25_encode
from .callsign import (
    SimplePeerLookup,
    callsign_to_iid,
    iid_to_callsign,
    is_broadcast_callsign,
)
from .handler import KissHandler
from .payload_fmt import format_payload

KISS_REJ_PREFIX = b"\x7f\x15"
# STX prefix for messages with embedded msg_id (for ack tracking)
KISS_MSG_PREFIX = b"\x02"

if TYPE_CHECKING:
    from ...crypto.identity import Identity, PeerIdentity
    from ...link.link_layer import LinkLayer, ReceiveError, RxFrame

log = logging.getLogger(__name__)

# Runtime import for ReceiveError used in isinstance checks
from ...link.link_layer import ReceiveError

# Port assignments
PORT_AX25 = 0  # AX.25-wrapped frames (for legacy TNC apps)
PORT_RAW = 1  # Raw LICHEN frames (for native apps)


@dataclass
class KissBridge:
    """Bridge between KISS interface and LICHEN LinkLayer.

    Port routing:
    - Port 0 (AX25): TNC app sends AX.25/APRS, we parse and send via LinkLayer.
                     LinkLayer RX gets wrapped in APRS format for TNC app.
    - Port 1 (RAW): Passthrough, no AX.25 wrapping.

    APRS support:
    - Messages appear in APRSDroid's Messages tab
    - Acks sent automatically so delivery checkmarks appear
    - Message IDs tracked for retry/timeout

    Attributes:
        link_layer: The LICHEN link layer for TX/RX.
        identity: This node's identity (for IID → callsign).
        handler: KissHandler to encode RX frames for host.
        peer_lookup: Lookup for IID → PeerIdentity.
        on_send_kiss: Callback to send KISS frame to transport.
    """

    link_layer: LinkLayer
    identity: Identity
    handler: KissHandler
    peer_lookup: Callable[[bytes], PeerIdentity | None]
    on_send_kiss: Callable[[bytes], None] | None = None
    _peer_table: SimplePeerLookup = field(default_factory=SimplePeerLookup)
    _msg_tracker: AprsMessageTracker = field(default_factory=AprsMessageTracker)
    _rx_task: asyncio.Task | None = field(default=None, repr=False)
    _background_tasks: set[asyncio.Task] = field(default_factory=set, repr=False)
    _running: bool = False

    def __post_init__(self) -> None:
        # Wire handler's TX callback to our routing
        self.handler.on_tx_frame = self._on_kiss_tx
        # Add own identity to peer table
        self._peer_table.add(self.identity.iid)

    def _create_background_task(self, coro) -> None:
        """Create a background task with exception handling.

        Stores task reference to prevent GC and logs exceptions via done_callback.
        """
        task = asyncio.create_task(coro)
        self._background_tasks.add(task)
        task.add_done_callback(self._on_task_done)

    def _on_task_done(self, task: asyncio.Task) -> None:
        """Handle background task completion."""
        self._background_tasks.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            log.error("background task failed: %s", exc)

    @property
    def own_callsign(self) -> str:
        """This node's callsign derived from IID."""
        return iid_to_callsign(self.identity.iid)

    def add_peer(self, peer: PeerIdentity) -> None:
        """Add a peer to the lookup table."""
        self._peer_table.add(peer.iid)

    def _on_kiss_tx(self, port: int, payload: bytes) -> None:
        """Handle frame from TNC app → radio.

        Called synchronously from KissHandler. Schedules async send.
        """
        if port == PORT_AX25:
            self._handle_ax25_tx(payload)
        elif port == PORT_RAW:
            self._handle_raw_tx(payload)
        else:
            log.debug("ignoring KISS TX on unsupported port %d", port)

    def _handle_ax25_tx(self, payload: bytes) -> None:
        """Unwrap AX.25, parse APRS, and send via LinkLayer."""
        try:
            ax25 = ax25_decode(payload)
        except Ax25Error as e:
            log.warning("invalid AX.25 from host: %s", e)
            return

        # Parse APRS content
        aprs = parse_aprs_packet(ax25.payload)

        if isinstance(aprs, AprsMessage):
            self._handle_aprs_message_tx(ax25.src, aprs)
        elif isinstance(aprs, AprsAck):
            self._handle_aprs_ack_tx(aprs)
        elif isinstance(aprs, AprsRej):
            self._handle_aprs_rej_tx(aprs)
        else:
            # Not APRS or unrecognized - send raw payload
            self._handle_raw_ax25_tx(ax25.dst, ax25.payload)

    def _handle_aprs_message_tx(self, src_call: str, msg: AprsMessage) -> None:
        """Handle outgoing APRS message from app."""
        # Resolve destination callsign to IID
        if is_broadcast_callsign(msg.addressee):
            dst_addr = b""  # broadcast
        else:
            dst_iid = callsign_to_iid(msg.addressee, self._peer_table)
            if dst_iid is None:
                log.warning("unknown APRS addressee: %s", msg.addressee)
                return
            dst_addr = dst_iid

        # Track message for ack if it has an ID
        if msg.msg_id:
            self._msg_tracker.track_message(msg.addressee, msg.text, msg.msg_id)
            # Include msg_id in payload so receiver can ack with correct ID
            payload = _encode_msg_payload(msg.text, msg.msg_id)
        else:
            # No msg_id - send raw text (receiver won't auto-ack)
            payload = msg.text.encode("utf-8")

        self._create_background_task(self._send_frame(payload, dst_addr))
        log.debug("APRS TX: %s -> %s: %s", src_call, msg.addressee, msg.text[:50])

    def _handle_aprs_ack_tx(self, ack: AprsAck) -> None:
        """Handle outgoing APRS ack from app (forward to peer)."""
        dst_iid = callsign_to_iid(ack.addressee, self._peer_table)
        if dst_iid is None:
            log.warning("unknown ack addressee: %s", ack.addressee)
            return

        # Send ack as special payload (prefix with 0x06 ACK byte)
        ack_payload = b"\x06" + ack.msg_id.encode("utf-8")
        self._create_background_task(self._send_frame(ack_payload, dst_iid))

    def _handle_aprs_rej_tx(self, rej: AprsRej) -> None:
        """Handle outgoing APRS reject from app."""
        dst_iid = callsign_to_iid(rej.addressee, self._peer_table)
        if dst_iid is None:
            return

        # Keep KISS reject control outside the authenticated L2 dispatch namespace.
        rej_payload = KISS_REJ_PREFIX + rej.msg_id.encode("utf-8")
        self._create_background_task(self._send_frame(rej_payload, dst_iid))

    def _handle_raw_ax25_tx(self, dst_call: str, payload: bytes) -> None:
        """Handle non-APRS AX.25 payload."""
        if is_broadcast_callsign(dst_call):
            dst_addr = b""
        else:
            dst_iid = callsign_to_iid(dst_call, self._peer_table)
            if dst_iid is None:
                log.warning("unknown destination callsign: %s", dst_call)
                return
            dst_addr = dst_iid

        self._create_background_task(self._send_frame(payload, dst_addr))

    def _handle_raw_tx(self, payload: bytes) -> None:
        """Send raw LICHEN frame via LinkLayer."""
        # Raw frames go directly to LinkLayer
        # ponytail: no addressing, broadcast for now
        self._create_background_task(self._send_frame(payload, b""))

    async def _send_frame(self, payload: bytes, dst_addr: bytes) -> None:
        """Send frame via LinkLayer."""
        try:
            await self.link_layer.send(payload, dst_addr=dst_addr)
        except Exception as e:
            log.error("LinkLayer send failed: %s", e)

    async def _on_link_rx(self, rx: RxFrame) -> None:
        """Handle frame from radio → TNC app."""
        sender_call = iid_to_callsign(rx.sender.iid)
        own_call = self.own_callsign
        payload = rx.frame.payload

        # Add sender to peer table for future lookups
        self._peer_table.add(rx.sender.iid)

        # Check for special control bytes (ack/rej)
        if len(payload) > 1:
            if payload[0] == 0x06:  # ACK
                msg_id = payload[1:].decode("utf-8", errors="replace")
                self._handle_incoming_ack(sender_call, msg_id)
                return
            elif _is_kiss_rej_payload(payload):  # NAK/REJ
                msg_id = _kiss_rej_msg_id(payload)
                self._msg_tracker.handle_rej(msg_id)
                return

        # Try to synthesize proper APRS packet (position, weather, telemetry)
        synth = synthesize_aprs(payload)
        sender_msg_id: str | None = None  # msg_id from sender (for acking)
        if synth is not None:
            # Synthesized APRS packet - use directly
            aprs_payload = synth.aprs_payload
            log.debug("APRS RX synth %s from %s", synth.data_type.value, sender_call)
        else:
            # Check for embedded msg_id from sender
            decoded = _decode_msg_payload(payload)
            if decoded is not None:
                text, sender_msg_id = decoded
            else:
                # Raw text without msg_id - generate local ID for display only
                text = format_payload(payload, max_len=67)

            # Use sender's msg_id if present, else generate local for display
            msg_id = sender_msg_id if sender_msg_id else self._msg_tracker.next_msg_id()
            aprs_msg = create_message(own_call, text, msg_id)
            aprs_payload = aprs_msg.encode()
            log.debug("APRS RX msg from %s: %s", sender_call, text[:50])

        # Wrap in AX.25
        ax25_frame = ax25_encode(sender_call, own_call, aprs_payload)
        ax25_kiss = self.handler.rx_frame(ax25_frame, port=PORT_AX25)

        # Send to app
        if self.on_send_kiss:
            self.on_send_kiss(ax25_kiss)

        # Raw frame for port 1
        raw_kiss = self.handler.rx_frame(payload, port=PORT_RAW)
        if self.on_send_kiss:
            self.on_send_kiss(raw_kiss)

        # Auto-ack back to sender (only if sender included msg_id for tracking)
        if sender_msg_id is not None:
            await self._send_ack_to_sender(rx.sender.iid, sender_call, sender_msg_id)

    def _handle_incoming_ack(self, sender_call: str, msg_id: str) -> None:
        """Handle incoming ack from peer."""
        if self._msg_tracker.handle_ack(msg_id):
            log.debug("APRS ack received from %s for msg %s", sender_call, msg_id)

            # Forward ack to app so checkmark appears
            aprs_ack = create_ack(self.own_callsign, msg_id)
            ax25_frame = ax25_encode(sender_call, self.own_callsign, aprs_ack.encode())
            ax25_kiss = self.handler.rx_frame(ax25_frame, port=PORT_AX25)
            if self.on_send_kiss:
                self.on_send_kiss(ax25_kiss)

    async def _send_ack_to_sender(self, sender_iid: bytes, sender_call: str, msg_id: str) -> None:
        """Send ack back to message sender."""
        ack_payload = b"\x06" + msg_id.encode("utf-8")
        try:
            await self.link_layer.send(ack_payload, dst_addr=sender_iid)
            log.debug("sent ack %s to %s", msg_id, sender_call)
        except Exception as e:
            log.warning("failed to send ack: %s", e)

    async def start(self, rx_timeout_ms: int = 1000) -> None:
        """Start the RX task.

        Args:
            rx_timeout_ms: Timeout for each receive attempt.
        """
        if self._running:
            return
        self._running = True
        self._rx_task = asyncio.create_task(self._rx_loop(rx_timeout_ms))
        log.info("KISS bridge started")

    async def stop(self) -> None:
        """Stop the RX task."""
        self._running = False
        if self._rx_task is not None:
            self._rx_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._rx_task
            self._rx_task = None
        log.info("KISS bridge stopped")

    async def _rx_loop(self, timeout_ms: int) -> None:
        """Receive loop that forwards LinkLayer frames to KISS."""
        while self._running:
            try:
                rx = await self.link_layer.receive(timeout_ms)
                if rx is not None and not isinstance(rx, ReceiveError):
                    await self._on_link_rx(rx)
                elif isinstance(rx, ReceiveError):
                    if rx in (ReceiveError.KEY_CHANGE, ReceiveError.REPLAY, ReceiveError.MIC_FAILED):
                        log.warning("link RX security event: %s", rx)
                    else:
                        log.debug("link RX rejected: %s", rx)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("RX loop error: %s", e)
                await asyncio.sleep(0.1)

    def encode_rx_frames(self, rx: RxFrame) -> tuple[bytes, bytes]:
        """Encode a received frame for both KISS ports.

        Formats the payload as an APRS message so APRSDroid displays it
        in the Messages tab.

        Returns:
            (ax25_kiss, raw_kiss) tuple of encoded KISS frames.
        """
        sender_call = iid_to_callsign(rx.sender.iid)
        own_call = self.own_callsign
        payload = rx.frame.payload

        # Add sender to peer table
        self._peer_table.add(rx.sender.iid)

        # Check for ack/rej control bytes
        if len(payload) > 1 and (payload[0] == 0x06 or _is_kiss_rej_payload(payload)):
            # Ack or reject - format as APRS ack
            msg_id = (
                payload[1:].decode("utf-8", errors="replace")
                if payload[0] == 0x06
                else _kiss_rej_msg_id(payload)
            )
            if payload[0] == 0x06:
                aprs_ack = create_ack(own_call, msg_id)
            else:
                from .aprs import AprsRej
                aprs_ack = AprsRej(addressee=own_call, msg_id=msg_id)
            aprs_payload = aprs_ack.encode()
        else:
            # Try to synthesize proper APRS packet
            synth = synthesize_aprs(payload)
            if synth is not None:
                aprs_payload = synth.aprs_payload
            else:
                # Regular message - format as APRS message
                msg_id = self._msg_tracker.next_msg_id()
                text = format_payload(payload, max_len=67)
                aprs_msg = create_message(own_call, text, msg_id)
                aprs_payload = aprs_msg.encode()

        # Wrap in AX.25
        ax25_frame = ax25_encode(sender_call, own_call, aprs_payload)
        ax25_kiss = self.handler.rx_frame(ax25_frame, port=PORT_AX25)

        # Raw for port 1
        raw_kiss = self.handler.rx_frame(payload, port=PORT_RAW)

        return (ax25_kiss, raw_kiss)


def _is_kiss_rej_payload(payload: bytes) -> bool:
    return payload.startswith(KISS_REJ_PREFIX) and len(payload) > len(KISS_REJ_PREFIX)


def _kiss_rej_msg_id(payload: bytes) -> str:
    payload = payload[len(KISS_REJ_PREFIX) :]
    return payload.decode("utf-8", errors="replace")


def _encode_msg_payload(text: str, msg_id: str) -> bytes:
    """Encode message with embedded msg_id for ack tracking.

    Format: KISS_MSG_PREFIX + msg_id (null-terminated) + text
    """
    return KISS_MSG_PREFIX + msg_id.encode("utf-8") + b"\x00" + text.encode("utf-8")


def _decode_msg_payload(payload: bytes) -> tuple[str, str] | None:
    """Decode message with embedded msg_id.

    Returns (text, msg_id) if payload has MSG prefix, else None.
    """
    if not payload.startswith(KISS_MSG_PREFIX):
        return None
    payload = payload[len(KISS_MSG_PREFIX) :]
    try:
        null_idx = payload.index(b"\x00")
    except ValueError:
        return None  # Malformed - no null terminator
    msg_id = payload[:null_idx].decode("utf-8", errors="replace")
    text = payload[null_idx + 1 :].decode("utf-8", errors="replace")
    return (text, msg_id)
