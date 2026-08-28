# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SCHC fragment and compression handling extracted from LinkLayer.

This module provides SchcHandler, which manages SCHC fragmentation senders,
reassembly state, and compression operations. It delegates cryptographic
verification and state persistence to the owning LinkLayer.

Threading model: All public methods acquire the link security lock before
accessing shared state. Callers must not hold the lock when calling in.
"""

from __future__ import annotations

import logging
import threading
from ipaddress import IPv6Address
from typing import TYPE_CHECKING, Literal, Protocol

from .frame import MAX_FRAME_BODY, AddrMode
from .frames import RxFrame, _VerifiedReceipt
from .replay import logical_counter

if TYPE_CHECKING:
    from ..rpl.authenticated_dio import AuthenticatedDio
    from ..schc.context import AuthenticatedPeerSchcContext
    from ..schc.fragment import FragmentSender, SchcSessionManager
    from ..schc.reassembly import ReceiverResult, _AuthenticatedReassemblyManager

logger = logging.getLogger(__name__)

# Signature length used in frame overhead calculations
SIGNATURE_LENGTH = 48

# Maximum single-frame SCHC packet size (excludes fragmentation)
MAX_SINGLE_FRAME_SCHC_PACKET = (
    MAX_FRAME_BODY
    - 4
    - AddrMode.EXTENDED.addr_len
    - 8  # mandatory signer EUI-64 (SI)
    - SIGNATURE_LENGTH
    - 1  # L2 SCHC dispatch
)


class LinkLayerSchcDelegate(Protocol):
    """Protocol for LinkLayer methods required by SchcHandler.

    This protocol defines the minimal interface that SchcHandler needs
    from its owning LinkLayer. Using a protocol enables testing with
    mock implementations.
    """

    @property
    def _local_pubkey(self) -> bytes:
        """32-byte local signer public key."""
        ...

    @property
    def _local_eui64(self) -> bytes:
        """8-byte local EUI-64 address."""
        ...

    @property
    def _security_lock(self) -> threading.RLock:
        """Reentrant lock protecting security state."""
        ...

    @property
    def _schc_peer_contexts(self) -> dict[bytes, AuthenticatedPeerSchcContext]:
        """Mapping from peer pubkey to authenticated SCHC context."""
        ...

    @property
    def _schc_peer_context_issuances(self) -> dict[int, object]:
        """Mapping from context id to issuance metadata."""
        ...

    @property
    def _retired_remote_keys(self) -> set[bytes]:
        """Set of retired remote signer keys."""
        ...

    @property
    def _key_generations(self) -> dict[bytes, object]:
        """Mapping from peer pubkey to key generation object."""
        ...

    @property
    def _schc_session_manager(self) -> SchcSessionManager:
        """SCHC session manager for fragmentation senders."""
        ...

    @property
    def _schc_reassembly_manager(self) -> _AuthenticatedReassemblyManager:
        """SCHC reassembly manager for inbound fragments."""
        ...

    @property
    def _schc_control_issuer_token(self) -> object:
        """Token authorizing control frame issuance."""
        ...

    def _ensure_persistence_healthy(self) -> None:
        """Verify persistence state is healthy before proceeding."""
        ...

    def _save_persisted_state(self) -> None:
        """Persist current state to storage."""
        ...

    def _take_verified_receipt_unlocked(
        self, received: RxFrame, purpose: str
    ) -> _VerifiedReceipt:
        """Consume a verified receipt for a specific purpose."""
        ...

    def _validated_authenticated_peer_schc_context(
        self, peer: AuthenticatedPeerSchcContext
    ) -> tuple[int, bytes]:
        """Validate and return (version, signer) for a peer context."""
        ...

    def _register_authenticated_dio_unlocked(
        self, dio: AuthenticatedDio
    ) -> object:
        """Register an authenticated DIO and return its issuance."""
        ...


class SchcHandler:
    """Handler for SCHC fragmentation, reassembly, and compression.

    This class extracts SCHC-related functionality from LinkLayer to improve
    code organization. It manages:

    - Fragment sender creation and cancellation
    - SCHC packet compression for authenticated peers
    - Authenticated SCHC packet reception and decompression
    - Fragment reassembly with optional DIO evidence
    - Reassembly timeout expiration

    The handler delegates security verification and state persistence to the
    owning LinkLayer through the LinkLayerSchcDelegate protocol.

    Attributes:
        _link: Reference to the owning LinkLayer delegate.
    """

    def __init__(self, link: LinkLayerSchcDelegate) -> None:
        """Initialize the SCHC handler.

        Args:
            link: The LinkLayer delegate providing security and persistence.
        """
        self._link = link

    def create_fragment_sender(
        self,
        payload: bytes,
        remote_signer_identity: bytes,
        receiver_limit: int = 1281,
    ) -> FragmentSender:
        """Create the sole active T=0 SCHC sender for an authenticated link key.

        Creates a new FragmentSender for transmitting a fragmented SCHC packet
        to an authenticated peer. The payload must be a complete, valid SCHC
        packet (compressed or Rule 255).

        Args:
            payload: Complete SCHC packet to fragment. Must start with a valid
                SCHC data Rule ID (0-7 or 0xFF).
            remote_signer_identity: 32-byte public key of the authenticated peer.
            receiver_limit: Maximum reassembly buffer size at the receiver.
                Defaults to 1281 bytes (IPv6 minimum MTU + 1).

        Returns:
            FragmentSender configured for the authenticated session.

        Raises:
            FragmentError: If remote_signer_identity is not a 32-byte key.
            ValueError: If the signer is retired, no authenticated context exists,
                the context version is incompatible, or the payload is not a
                valid SCHC packet.
        """
        from ..schc.fragment import FragmentError, fragmentation_rule_for_sender

        if type(remote_signer_identity) is not bytes or len(remote_signer_identity) != 32:
            raise FragmentError("remote signer identity must be a 32-byte signer public key")
        derived_rule_id = fragmentation_rule_for_sender(
            self._link._local_pubkey, remote_signer_identity
        )
        self._link._ensure_persistence_healthy()
        with self._link._security_lock:
            self._link._ensure_persistence_healthy()
            if remote_signer_identity in self._link._retired_remote_keys:
                raise ValueError("cannot create a session for a retired signer identity")
            if not payload or payload[0] not in (*range(8), 0xFF):
                raise ValueError("fragmented packet contains an unknown SCHC data Rule ID")
            from ..schc.rules import RULE_SET_VERSION

            peer = self._link._schc_peer_contexts.get(remote_signer_identity)
            if peer is None:
                raise ValueError(
                    "SCHC data fragmentation requires a version-compatible, "
                    "authenticated replay-accepted DIO"
                )
            try:
                remote_version, signer = self._link._validated_authenticated_peer_schc_context(
                    peer
                )
            except ValueError as exc:
                raise ValueError(
                    "SCHC data fragmentation requires a current authenticated peer context"
                ) from exc
            if signer != remote_signer_identity or remote_version != RULE_SET_VERSION:
                raise ValueError(
                    "SCHC data fragmentation requires a version-compatible, "
                    "authenticated replay-accepted DIO"
                )
            from ..schc.headers import decode_rule255

            # Validate payload as a complete SCHC packet. SchcError propagates
            # with its specific message (empty packet, unknown rule, invalid
            # residue, etc.) so callers can distinguish packet/rule errors from
            # stale-peer conditions.
            if payload[0] == 0xFF:
                # The single-frame ceiling is an L2 serialization limit,
                # not a fragmentation limit. A Rule 255 packet admitted
                # here is about to be fragmented and may use the peer's
                # advertised reassembly budget.
                decode_rule255(payload)
            else:
                peer.decompress_packet(
                    payload,
                    single_frame_limit=MAX_SINGLE_FRAME_SCHC_PACKET,
                )
            return self._link._schc_session_manager.create_sender(
                payload=payload,
                remote_signer_identity=remote_signer_identity,
                key_generation=self._link._key_generations[remote_signer_identity],
                rule_id=derived_rule_id,
                receiver_limit=receiver_limit,
            )

    def cancel_fragment_sender(self, sender: FragmentSender) -> bytes | None:
        """Cancel one exact sender and return its one-use Sender-Abort authority.

        Cancels an active FragmentSender and returns the wire-format Sender-Abort
        message that should be transmitted to notify the receiver.

        Args:
            sender: The exact FragmentSender instance to cancel.

        Returns:
            Wire-format Sender-Abort message, or None if no abort needed.

        Raises:
            TypeError: If sender is not an exact FragmentSender instance.
        """
        from ..schc.fragment import FragmentSender as ExactFragmentSender

        if type(sender) is not ExactFragmentSender:
            raise TypeError("sender must be an exact FragmentSender")
        self._link._ensure_persistence_healthy()
        with self._link._security_lock:
            output = self._link._schc_session_manager.cancel_with_abort(sender)
        self._link._save_persisted_state()
        return output

    def compress_schc_for_peer(
        self,
        raw_ipv6: bytes,
        remote_signer_identity: bytes,
        *,
        single_frame_limit: int = MAX_SINGLE_FRAME_SCHC_PACKET,
        allow_fragmentation: bool = False,
    ) -> bytes:
        """Compress one unfragmented datagram under current peer policy.

        Compresses a raw IPv6 packet using the authenticated SCHC context
        established with the specified peer.

        Args:
            raw_ipv6: Raw IPv6 packet bytes to compress.
            remote_signer_identity: 32-byte public key of the authenticated peer.
            single_frame_limit: Maximum compressed size for single-frame delivery.
                Defaults to MAX_SINGLE_FRAME_SCHC_PACKET.
            allow_fragmentation: If True, allow compressed packets exceeding
                the single-frame limit (caller must handle fragmentation).

        Returns:
            SCHC-compressed packet bytes.

        Raises:
            TypeError: If raw_ipv6 is not bytes or allow_fragmentation is not bool.
            ValueError: If remote_signer_identity is invalid, no authenticated
                context exists, or the compressed packet exceeds the limit
                without fragmentation allowed.
        """
        if type(raw_ipv6) is not bytes:
            raise TypeError("raw_ipv6 must be bytes")
        if type(remote_signer_identity) is not bytes or len(remote_signer_identity) != 32:
            raise ValueError("remote signer identity must be a 32-byte public key")
        if type(allow_fragmentation) is not bool:
            raise TypeError("allow_fragmentation must be bool")
        with self._link._security_lock:
            self._link._ensure_persistence_healthy()
            peer = self._link._schc_peer_contexts.get(remote_signer_identity)
            if peer is None:
                raise ValueError("SCHC egress requires an authenticated replay-accepted peer DIO")
            self._link._validated_authenticated_peer_schc_context(peer)
            encoded = peer.compress_packet(
                raw_ipv6,
                single_frame_limit=single_frame_limit,
            )
            if len(encoded) > single_frame_limit and not allow_fragmentation:
                raise ValueError("SCHC packet requires authenticated fragmentation")
            return encoded

    def accept_authenticated_schc_packet(
        self,
        received: RxFrame,
        *,
        single_frame_limit: int = MAX_SINGLE_FRAME_SCHC_PACKET,
    ) -> bytes:
        """Consume one link receipt and decode it under current signer policy.

        Accepts a non-fragmented SCHC packet from an authenticated peer and
        decompresses it to raw IPv6.

        Args:
            received: Verified RxFrame containing the SCHC packet.
            single_frame_limit: Maximum allowed compressed packet size.
                Defaults to MAX_SINGLE_FRAME_SCHC_PACKET.

        Returns:
            Decompressed raw IPv6 packet bytes.

        Raises:
            TypeError: If received is not an exact RxFrame.
            ValueError: If the frame is not SCHC data, contains fragmentation
                packets, has no authenticated context, or predates current policy.
        """
        from ..l2_payload import L2PayloadKind, classify_l2_payload, l2_payload_body

        if type(received) is not RxFrame:
            raise TypeError("received must be an exact RxFrame")
        with self._link._security_lock:
            self._link._ensure_persistence_healthy()
            snapshot = self._link._take_verified_receipt_unlocked(received, "schc-data")
            if classify_l2_payload(snapshot.payload) is not L2PayloadKind.SCHC:
                raise ValueError("authenticated SCHC data requires the SCHC L2 dispatch")
            body = l2_payload_body(snapshot.payload)
            if not body or body[0] in (0x78, 0x79):
                raise ValueError("fragmentation packets require authenticated reassembly")
            peer = self._link._schc_peer_contexts.get(snapshot.sender_pubkey)
            if peer is None:
                raise ValueError("SCHC ingress requires an authenticated replay-accepted peer DIO")
            self._link._validated_authenticated_peer_schc_context(peer)
            issuance = self._link._schc_peer_context_issuances[id(peer)]
            if (
                snapshot.key_generation is not issuance.key_generation
                or logical_counter(snapshot.epoch, snapshot.seqnum) <= issuance.admitted_counter
            ):
                raise ValueError("SCHC ingress predates the current authenticated peer policy")
            return peer.decompress_packet(
                body,
                single_frame_limit=single_frame_limit,
            )

    def accept_authenticated_schc_fragment(
        self,
        received: RxFrame,
    ) -> tuple[ReceiverResult, bytes | None]:
        """Consume and apply one authenticated fragment/control frame.

        Processes a single SCHC fragmentation message from an authenticated
        peer, potentially completing reassembly of a full packet.

        Args:
            received: Verified RxFrame containing the fragmentation message.

        Returns:
            Tuple of (ReceiverResult with any response to send, reassembled
            IPv6 packet if complete or None).

        Raises:
            TypeError: If received is not an exact RxFrame.
            ValueError: If the frame is not a valid fragmentation message or
                lacks proper authentication.
        """
        result, ipv6, _authenticated_dio = self._accept_authenticated_schc_fragment(
            received,
            dio_scope=None,
        )
        return result, ipv6

    def accept_authenticated_schc_fragment_dio(
        self,
        received: RxFrame,
        *,
        expected_rpl_instance_id: int,
        expected_dodag_id: IPv6Address,
        expected_mop: int,
        expected_role: Literal["root", "peer"],
    ) -> tuple[ReceiverResult, bytes | None, AuthenticatedDio | None]:
        """Reassemble a fragment and issue DIO evidence in one link transaction.

        Like accept_authenticated_schc_fragment, but additionally issues
        authenticated DIO evidence if the reassembled packet is a DIO matching
        the expected parameters.

        Args:
            received: Verified RxFrame containing the fragmentation message.
            expected_rpl_instance_id: Expected RPL instance ID for DIO validation.
            expected_dodag_id: Expected DODAG ID for DIO validation.
            expected_mop: Expected Mode of Operation for DIO validation.
            expected_role: Expected role ("root" or "peer") for DIO validation.

        Returns:
            Tuple of (ReceiverResult, reassembled IPv6 or None, AuthenticatedDio
            evidence or None).

        Raises:
            TypeError: If received is not an exact RxFrame.
            ValueError: If the frame is invalid, lacks authentication, or DIO
                validation fails.
        """
        return self._accept_authenticated_schc_fragment(
            received,
            dio_scope=(
                expected_rpl_instance_id,
                expected_dodag_id,
                expected_mop,
                expected_role,
            ),
        )

    def _accept_authenticated_schc_fragment(
        self,
        received: RxFrame,
        *,
        dio_scope: tuple[int, IPv6Address, int, Literal["root", "peer"]] | None,
    ) -> tuple[ReceiverResult, bytes | None, AuthenticatedDio | None]:
        """Consume one fragment and optionally seal a completed RPL DIO.

        Internal implementation for fragment acceptance with optional DIO
        evidence generation.

        Args:
            received: Verified RxFrame containing the fragmentation message.
            dio_scope: Optional tuple of (rpl_instance_id, dodag_id, mop, role)
                for DIO validation. If provided and the reassembled packet is
                a matching DIO, authenticated evidence is issued.

        Returns:
            Tuple of (ReceiverResult, reassembled IPv6 or None, AuthenticatedDio
            evidence or None).

        Raises:
            TypeError: If received is not an exact RxFrame.
            ValueError: For various authentication and validation failures.
        """
        from ..ipv6.packet import HEADER_LENGTH, IPv6Header, NextHeader
        from ..l2_payload import L2PayloadKind, classify_l2_payload, l2_payload_body
        from ..rpl.authenticated_dio import _issue_authenticated_dio_from_ipv6
        from ..rpl.messages import RplCode
        from ..schc.codec import SchcError
        from ..schc.fragment import (
            fragmentation_message_is_response,
            fragmentation_rule_for_sender,
        )
        from ..schc.headers import decode_rule255
        from ..schc.reassembly import ReceiverResult
        from ..schc.rules import RULE_SET_VERSION

        if type(received) is not RxFrame:
            raise TypeError("received must be an exact RxFrame")
        with self._link._security_lock:
            self._link._ensure_persistence_healthy()
            snapshot = self._link._take_verified_receipt_unlocked(received, "schc-fragment")
            data = snapshot.payload
            if classify_l2_payload(data) is L2PayloadKind.SCHC:
                body = l2_payload_body(data)
                if body and body[0] in (0x78, 0x79):
                    raise ValueError(
                        "SCHC fragmentation Rules 0x78/0x79 require raw link dispatch"
                    )
            if not data or data[0] not in (0x78, 0x79):
                raise ValueError("authenticated frame is not a SCHC fragmentation message")
            target_frame = snapshot.frame
            if (
                target_frame.addr_mode is not AddrMode.EXTENDED
                or target_frame.dst_addr != self._link._local_eui64
            ):
                raise ValueError(
                    "authenticated SCHC fragmentation requires exact Extended local target"
                )
            peer = self._link._schc_peer_contexts.get(snapshot.sender_pubkey)
            if peer is None:
                raise ValueError(
                    "fragment ingress requires an authenticated replay-accepted peer DIO"
                )
            remote_version, signer = self._link._validated_authenticated_peer_schc_context(peer)
            if signer != snapshot.sender_pubkey or remote_version != RULE_SET_VERSION:
                raise ValueError("fragment ingress requires compatible Rule Set Version 3")
            generation = self._link._key_generations.get(signer)
            if generation is None or snapshot.key_generation is not generation:
                raise ValueError("fragment signer generation is stale")
            issuance = self._link._schc_peer_context_issuances[id(peer)]
            if logical_counter(snapshot.epoch, snapshot.seqnum) <= issuance.admitted_counter:
                raise ValueError("fragment ingress predates the current authenticated peer policy")
            is_response = fragmentation_message_is_response(
                data,
                sender_identity=signer,
                receiver_identity=self._link._local_pubkey,
            )
            expected_rule = fragmentation_rule_for_sender(
                self._link._local_pubkey if is_response else signer,
                signer if is_response else self._link._local_pubkey,
            )
            if data[0] != expected_rule:
                raise ValueError(
                    "fragmentation Rule ID does not match authenticated endpoint direction"
                )
            if is_response:
                return ReceiverResult(), None, None

            reassembled_schc_rule: int | None = None

            def validate(packet: bytes) -> bytes:
                nonlocal reassembled_schc_rule
                reassembled_schc_rule = packet[0] if packet else None
                try:
                    if packet and packet[0] == 0xFF:
                        # Reassembly has already enforced the receiver limit;
                        # validate the complete raw IPv6 packet without
                        # reapplying the smaller unfragmented-frame ceiling.
                        return decode_rule255(packet)
                    return peer.decompress_packet(
                        packet,
                        single_frame_limit=MAX_SINGLE_FRAME_SCHC_PACKET,
                    )
                except SchcError as exc:
                    raise ValueError("reassembled SCHC packet is invalid") from exc

            receiver_result, ipv6 = self._link._schc_reassembly_manager.receive(
                snapshot,
                data,
                generation,
                validate_packet=validate,
            )
            if receiver_result.response is not None:
                receiver_result.response = (
                    self._link._schc_session_manager._issue_link_transition_control_wire(
                        self._link._schc_control_issuer_token,
                        receiver_result.response,
                        signer,
                        generation,
                        response=True,
                    )
                )
            authenticated_dio = None
            dio_error: BaseException | None = None
            if ipv6 is not None and dio_scope is not None:
                try:
                    header = IPv6Header.from_bytes(ipv6)
                    icmp = ipv6[HEADER_LENGTH:]
                    if (
                        header.next_header == NextHeader.ICMPV6
                        and len(icmp) >= 2
                        and icmp[0] == 155
                        and icmp[1] == int(RplCode.DIO)
                    ):
                        authenticated_dio = _issue_authenticated_dio_from_ipv6(
                            snapshot,
                            ipv6,
                            schc_rule_id=(
                                reassembled_schc_rule
                                if reassembled_schc_rule is not None
                                else -1
                            ),
                            expected_rpl_instance_id=dio_scope[0],
                            expected_dodag_id=dio_scope[1],
                            expected_mop=dio_scope[2],
                            expected_role=dio_scope[3],
                        )
                        dio_issuance = self._link._register_authenticated_dio_unlocked(
                            authenticated_dio
                        )
                        if dio_issuance.sender_pubkey != signer:
                            raise ValueError("reassembled DIO signer evidence mismatch")
                except BaseException as exc:
                    dio_error = exc
        self._link._save_persisted_state()
        if dio_error is not None:
            raise dio_error
        return receiver_result, ipv6, authenticated_dio

    def expire_authenticated_schc_reassembly(self) -> list[tuple[bytes, bytes, bytes]]:
        """Drain proactive inactivity aborts as (peer_key, dst_eui64, wire).

        Checks all active reassembly contexts for timeout expiration and
        generates Receiver-Abort messages for any that have exceeded the
        inactivity timeout.

        Each due inbound context produces its exact Receiver-Abort once. The
        caller transmits wire to dst_eui64 with ACK priority; the full peer
        key is included so higher layers can retain authenticated ownership.

        Returns:
            List of (peer_pubkey, destination_eui64, wire_abort_message) tuples
            for each expired reassembly context.
        """
        self._link._ensure_persistence_healthy()
        with self._link._security_lock:
            self._link._ensure_persistence_healthy()
            pending = self._link._schc_reassembly_manager.expire_due()
            outputs = [
                (
                    peer_key,
                    destination,
                    self._link._schc_session_manager._issue_link_transition_control_wire(
                        self._link._schc_control_issuer_token,
                        wire,
                        peer_key,
                        self._link._key_generations[peer_key],
                        response=True,
                    ),
                )
                for peer_key, destination, wire in pending
                if peer_key in self._link._key_generations
            ]
        if outputs:
            self._link._save_persisted_state()
        return outputs

    def accept_authenticated_schc_sender_control(
        self,
        received: RxFrame,
    ) -> list[bytes] | None:
        """Apply a Link-registered sender ACK/abort before receiver dispatch.

        Processes a SCHC control message (ACK or abort) directed at an active
        sender session. This allows the sender to update its state before the
        message is processed by the receiver side.

        Args:
            received: Verified RxFrame containing the control message.

        Returns:
            List of fragment wire bytes to transmit, or None if no action needed.

        Raises:
            TypeError: If received is not an exact RxFrame.
            ValueError: If the control message Rule ID does not match the
                authenticated endpoint direction.
        """
        if type(received) is not RxFrame:
            raise TypeError("received must be an exact RxFrame")
        from ..schc.fragment import (
            fragmentation_message_is_response,
            fragmentation_rule_for_sender,
        )

        data = received.payload
        if fragmentation_message_is_response(
            data,
            sender_identity=received.sender_pubkey,
            receiver_identity=self._link._local_pubkey,
        ) and data[0] != (
            fragmentation_rule_for_sender(self._link._local_pubkey, received.sender_pubkey)
        ):
            raise ValueError("SCHC response Rule ID does not match authenticated endpoints")
        self._link._ensure_persistence_healthy()
        result = self._link._schc_session_manager.transition_verified_control(received)
        if result is not None:
            self._link._save_persisted_state()
        return result
