# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SCHC fragmentation session manager for T=0 sender sessions.

This module provides the SchcSessionManager class, which manages link-bound
sender sessions and terminal tombstones for SCHC fragmentation. The manager
handles session lifecycle, replay protection, capability issuance, and ACK
processing with authenticated receiver control frames.
"""
from __future__ import annotations

import math
import threading
import weakref
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from lichen.crypto.identity import PeerIdentity
from lichen.ipv6.addr import iid_to_eui64
from lichen.link.frame import AddrMode
from lichen.link.replay import ReplayProtector, logical_counter
from lichen.schc.fragment import (
    _ISSUED_MANAGER_LOCK,
    _ISSUED_MANAGERS,
    MAX_ACK_REQUESTS,
    MAX_ISSUED_FRAGMENT_WIRES_PER_SESSION,
    MAX_LINK_REPLAY_COUNTER,
    MAX_PENDING_ACK_RECEIPTS,
    MAX_PREPARED_SENDERS,
    MAX_SENDER_SESSION_RECORDS,
    PREPARED_SENDER_TTL_SECONDS,
    RETRANSMISSION_TIMEOUT_SECONDS,
    RULE_IDS,
    SESSION_HOLD_DOWN_SECONDS,
    SESSION_IDLE_TIMEOUT_SECONDS,
    SIGNER_PUBLIC_KEY_LENGTH,
    WINDOW_SIZE,
    Ack,
    Fragment,
    FragmentError,
    _check_rule,
    _IssuedFragmentWire,
    _register_issued_sender,
    _ValidatedSchcClock,
    ack_request,
    fragmentation_message_is_response,
    fragmentation_rule_for_sender,
    receiver_abort,
    sender_abort,
)

if TYPE_CHECKING:
    from lichen.link.link_layer import RxFrame
    from lichen.schc.fragment import FragmentSender


@dataclass
class _SessionRecord:
    sender: FragmentSender
    remote_signer_identity: bytes
    rule_id: int
    generation: int
    key_generation: object
    fragments: tuple[Fragment, ...]
    high_water: int
    attempts: int = 1
    status: str = "active"
    active: bool = True
    hold_down_until: float = 0.0
    idle_expires_at: float = 0.0
    retransmit_at: float | None = None
    outcome: str | None = None
    pending: OrderedDict[int, RxFrame] = field(default_factory=OrderedDict)


@dataclass
class _PreparedRecord:
    sender: weakref.ReferenceType[FragmentSender]
    remote_signer_identity: bytes
    rule_id: int
    generation: int
    key_generation: object
    fragments: tuple[Fragment, ...]
    expires_at: float


@dataclass
class _SessionTombstone:
    expires_at: float
    high_water: int
    generation: int
    key_generation: object
    status: str


class SchcSessionManager:
    """Link-bound owner for T=0 sender sessions and terminal tombstones."""

    def __init__(
        self,
        local_identity: bytes,
        replay_protector: ReplayProtector,
        *,
        security_lock: threading.RLock,
        replay_owner_token: object | None = None,
        receipt_consumer: Callable[[RxFrame, str], RxFrame] | None = None,
        control_issuer_token: object,
        key_generation_lookup: Callable[[bytes], object | None],
        state_change: Callable[[], None] | None = None,
        clock: object | None = None,
        max_records: int = MAX_SENDER_SESSION_RECORDS,
        max_prepared: int = MAX_PREPARED_SENDERS,
    ) -> None:
        if type(local_identity) is not bytes or len(local_identity) != SIGNER_PUBLIC_KEY_LENGTH:
            raise FragmentError("local_identity must be a 32-byte signer public key")
        if type(replay_protector) is not ReplayProtector:
            raise FragmentError("replay_protector must be ReplayProtector")
        if not hasattr(security_lock, "acquire") or not hasattr(security_lock, "release"):
            raise FragmentError("security_lock must be a reentrant lock")
        if not callable(key_generation_lookup):
            raise FragmentError("key_generation_lookup must be callable")
        if type(max_records) is not int or max_records < 1:
            raise FragmentError("max_records must be a positive integer")
        if type(max_prepared) is not int or max_prepared < 1:
            raise FragmentError("max_prepared must be a positive integer")
        from lichen.timing.time_sync import SYSTEM_MONOTONIC_CLOCK, MonotonicClock

        if clock is not None and type(clock) is not MonotonicClock:
            raise FragmentError("clock must be an exact MonotonicClock or None")
        clock_capability = clock or SYSTEM_MONOTONIC_CLOCK
        self._local_identity = local_identity
        self._local_eui64 = iid_to_eui64(PeerIdentity.from_pubkey(local_identity).iid)
        self._replay_protector = replay_protector
        self._replay_owner_token = replay_owner_token
        self._clock_capability = clock_capability
        self._validated_clock = _ValidatedSchcClock(clock_capability)
        self._receipt_consumer = receipt_consumer
        self._control_issuer_token = control_issuer_token
        self._key_generation_lookup = key_generation_lookup
        self._state_change = state_change
        self._max_records = max_records
        self._max_prepared = max_prepared
        self._max_issued_wires = max_records * MAX_ISSUED_FRAGMENT_WIRES_PER_SESSION
        self._lock = security_lock
        self._records: dict[tuple[bytes, bytes, int, int], _SessionRecord] = {}
        self._sender_records: dict[int, _SessionRecord] = {}
        self._generations: dict[bytes, int] = {}
        self._prepared: OrderedDict[int, _PreparedRecord] = OrderedDict()
        self._tombstones: dict[tuple[bytes, bytes, int, int], _SessionTombstone] = {}
        self._issued_wires: OrderedDict[
            int, tuple[_IssuedFragmentWire, FragmentSender, int, object]
        ] = OrderedDict()
        self._issued_controls: OrderedDict[
            int, tuple[_IssuedFragmentWire, bytes, object, float, FragmentSender | None]
        ] = OrderedDict()

    def _fail_clock_unlocked(self) -> None:
        """Release bounded capabilities after a terminal timer-source failure."""
        issued_senders = [
            *(prepared.sender() for prepared in self._prepared.values()),
            *(record.sender for record in self._records.values()),
        ]
        for prepared in self._prepared.values():
            sender = prepared.sender()
            if sender is not None:
                sender._set_security_state(status="invalidated")
        for key, record in self._records.items():
            record.active = False
            record.pending.clear()
            record.sender._set_security_state(status="invalidated")
            self._drop_issued_wires_unlocked(record.sender)
            self._unpin_replay(key[1])
        self._prepared.clear()
        self._records.clear()
        self._sender_records.clear()
        self._tombstones.clear()
        self._issued_wires.clear()
        self._issued_controls.clear()
        with _ISSUED_MANAGER_LOCK:
            for sender in issued_senders:
                if sender is None:
                    continue
                issuance = _ISSUED_MANAGERS.get(id(sender))
                if issuance is not None and issuance[0]() is sender and issuance[1]() is self:
                    _ISSUED_MANAGERS.pop(id(sender), None)

    def _now_unlocked(self) -> float:
        try:
            return self._validated_clock()
        except FragmentError:
            self._fail_clock_unlocked()
            raise

    @staticmethod
    def _retransmission_deadline(now: float) -> float:
        deadline = now + RETRANSMISSION_TIMEOUT_SECONDS
        if not math.isfinite(deadline) or deadline <= now:
            raise FragmentError("SCHC retransmission deadline is not representable")
        return deadline

    def _issue_fragment_wire_unlocked(
        self,
        sender: FragmentSender,
        record: _SessionRecord,
        fragment: Fragment,
    ) -> _IssuedFragmentWire:
        self._ensure_fragment_wire_capacity_unlocked(1)
        wire = _IssuedFragmentWire(fragment.to_bytes())
        self._issued_wires[id(wire)] = (
            wire,
            sender,
            record.generation,
            record.key_generation,
        )
        return wire

    def _ensure_fragment_wire_capacity_unlocked(self, count: int) -> None:
        """Fail before issuance rather than revoking another live capability."""
        if type(count) is not int or count < 0:
            raise FragmentError("fragment wire reservation count must be non-negative")
        if len(self._issued_wires) + len(self._issued_controls) + count > self._max_issued_wires:
            raise FragmentError("fragment wire capability registry is full")

    def _issue_control_wire_unlocked(
        self,
        data: bytes,
        remote_signer_identity: bytes,
        key_generation: object,
        *,
        response: bool,
        owner: FragmentSender | None = None,
    ) -> _IssuedFragmentWire:
        """Issue one target-bound control authority after a manager transition."""
        self._check_identity(remote_signer_identity, field_name="remote_signer_identity")
        if type(data) is not bytes or len(data) < 2 or data[0] not in RULE_IDS:
            raise FragmentError("fragmentation control must be canonical bytes")
        expected_rule = fragmentation_rule_for_sender(
            remote_signer_identity if response else self._local_identity,
            self._local_identity if response else remote_signer_identity,
        )
        if data[0] != expected_rule:
            raise FragmentError("fragmentation control Rule ID does not match its direction")
        window = data[1] >> 7
        if response:
            valid = data == receiver_abort(data[0])
            if not valid:
                try:
                    Ack.from_bytes(data)
                except FragmentError:
                    valid = False
                else:
                    valid = True
        else:
            valid = data in (ack_request(data[0], window), sender_abort(data[0]))
        if not valid:
            raise FragmentError("fragmentation control is invalid for its direction")
        self._ensure_fragment_wire_capacity_unlocked(1)
        wire = _IssuedFragmentWire(data)
        self._issued_controls[id(wire)] = (
            wire,
            remote_signer_identity,
            key_generation,
            self._now_unlocked() + SESSION_IDLE_TIMEOUT_SECONDS,
            owner,
        )
        return wire

    def _issue_link_transition_control_wire(
        self,
        issuer_token: object,
        data: bytes,
        remote_signer_identity: bytes,
        key_generation: object,
        *,
        response: bool,
    ) -> bytes:
        """Seal control bytes only for the owning LinkLayer transition."""
        if issuer_token is not self._control_issuer_token:
            raise FragmentError("SCHC control issuance lacks the link transition authority")
        with self._lock:
            self._expire_all_unlocked()
            current_generation = self._key_generation_lookup(remote_signer_identity)
            if current_generation is None or current_generation is not key_generation:
                raise FragmentError("SCHC control key generation is not current")
            return self._issue_control_wire_unlocked(
                data,
                remote_signer_identity,
                key_generation,
                response=response,
            )

    def _drop_issued_wires_unlocked(self, sender: FragmentSender) -> None:
        for wire_id in [
            wire_id
            for wire_id, (_, issued_sender, _, _) in self._issued_wires.items()
            if issued_sender is sender
        ]:
            self._issued_wires.pop(wire_id, None)

    def _drop_issued_controls_unlocked(self, remote_signer_identity: bytes) -> None:
        for wire_id in [
            wire_id
            for wire_id, (_, remote, _, _, _) in self._issued_controls.items()
            if remote == remote_signer_identity
        ]:
            self._issued_controls.pop(wire_id, None)

    def _drop_issued_sender_controls_unlocked(
        self,
        sender: FragmentSender,
        *,
        preserve: _IssuedFragmentWire | None = None,
    ) -> None:
        for wire_id in [
            wire_id
            for wire_id, (wire, _, _, _, owner) in self._issued_controls.items()
            if owner is sender and wire is not preserve
        ]:
            self._issued_controls.pop(wire_id, None)

    def consume_fragment_wire(self, wire: bytes, remote_eui64: bytes) -> bool:
        """Consume one active-session fragment capability for its exact peer."""
        if type(wire) is not _IssuedFragmentWire:
            return False
        if type(remote_eui64) is not bytes or len(remote_eui64) != 8:
            return False
        with self._lock:
            now = self._expire_all_unlocked()
            control = self._issued_controls.pop(id(wire), None)
            if control is not None:
                return (
                    control[0] is wire
                    and now < control[3]
                    and iid_to_eui64(PeerIdentity.from_pubkey(control[1]).iid) == remote_eui64
                    and self._key_generation_lookup(control[1]) is control[2]
                )
            issued = self._issued_wires.pop(id(wire), None)
            if issued is None or issued[0] is not wire:
                return False
            sender, generation, key_generation = issued[1], issued[2], issued[3]
            record = self._sender_records.get(id(sender))
            return (
                record is not None
                and record.sender is sender
                and record.active
                and record.generation == generation
                and record.key_generation is key_generation
                and self._key_generation_lookup(record.remote_signer_identity) is key_generation
                and self._generations.get(record.remote_signer_identity, 0) == generation
                and iid_to_eui64(PeerIdentity.from_pubkey(record.remote_signer_identity).iid)
                == remote_eui64
            )

    def _pin_replay(self, remote: bytes) -> None:
        if self._replay_owner_token is None:
            self._replay_protector.pin(remote)
        else:
            self._replay_protector._pin_owned(remote, self._replay_owner_token)

    def _unpin_replay(self, remote: bytes) -> None:
        if self._replay_owner_token is None:
            self._replay_protector.unpin(remote)
        else:
            self._replay_protector._unpin_owned(remote, self._replay_owner_token)

    @property
    def local_identity(self) -> bytes:
        return self._local_identity

    @staticmethod
    def _check_identity(identity: bytes, *, field_name: str) -> None:
        if type(identity) is not bytes or len(identity) != SIGNER_PUBLIC_KEY_LENGTH:
            raise FragmentError(f"{field_name} must be a 32-byte signer public key")

    def _key(
        self, remote_signer_identity: bytes, key_generation: object, rule_id: int
    ) -> tuple[bytes, bytes, int, int]:
        self._check_identity(remote_signer_identity, field_name="remote_signer_identity")
        _check_rule(rule_id)
        return self._local_identity, remote_signer_identity, id(key_generation), rule_id

    def _expire_records_unlocked(self, now: float | None = None) -> float:
        if now is None:
            now = self._now_unlocked()
        for record in self._records.values():
            if record.active and now >= record.idle_expires_at:
                record.active = False
                record.hold_down_until = now + SESSION_HOLD_DOWN_SECONDS
                record.outcome = "expired"
                record.status = "expired"
                record.pending.clear()
                record.sender._set_security_state(status="expired")
                self._drop_issued_wires_unlocked(record.sender)
                self._drop_issued_sender_controls_unlocked(record.sender)
        expired = [
            key
            for key, record in self._records.items()
            if not record.active and now >= record.hold_down_until
        ]
        for key in expired:
            self._unpin_replay(key[1])
            self._sender_records.pop(id(self._records[key].sender), None)
            del self._records[key]
        for key in [key for key, value in self._tombstones.items() if now >= value.expires_at]:
            del self._tombstones[key]
        return now

    def _expire_prepared_unlocked(self, now: float | None = None) -> float:
        if now is None:
            now = self._now_unlocked()
        expired = [
            sender_id for sender_id, record in self._prepared.items() if now >= record.expires_at
        ]
        for sender_id in expired:
            record = self._prepared.pop(sender_id)
            sender = record.sender()
            if sender is not None:
                sender._set_security_state(status="expired")
        return now

    def _discard_abandoned_prepared(
        self,
        sender_id: int,
        reference: weakref.ReferenceType[FragmentSender],
    ) -> None:
        """Release a never-started lease when its public handle is dropped."""
        with self._lock:
            prepared = self._prepared.get(sender_id)
            if prepared is not None and prepared.sender is reference:
                self._prepared.pop(sender_id, None)

    def _expire_all_unlocked(self) -> float:
        now = self._now_unlocked()
        self._expire_records_unlocked(now)
        self._expire_prepared_unlocked(now)
        for wire_id in [
            wire_id
            for wire_id, (_, _, _, expires_at, _) in self._issued_controls.items()
            if now >= expires_at
        ]:
            self._issued_controls.pop(wire_id, None)
        return now

    def create_sender(
        self,
        payload: bytes,
        remote_signer_identity: bytes,
        key_generation: object,
        rule_id: int = 0x78,
        receiver_limit: int | None = None,
    ) -> FragmentSender:
        """Prepare a sender; its bounded registry lease is acquired by ``start``."""
        from lichen.schc.fragment import DEFAULT_RECEIVER_LIMIT, FragmentSender

        if receiver_limit is None:
            receiver_limit = DEFAULT_RECEIVER_LIMIT
        sender = FragmentSender(payload, rule_id, receiver_limit)
        self._key(remote_signer_identity, key_generation, rule_id)
        with self._lock:
            now = self._expire_all_unlocked()
            if len(self._prepared) >= self._max_prepared:
                raise FragmentError("prepared fragmentation sender registry is full")
            generation = self._generations.get(remote_signer_identity, 0)
            sender._bind_session(self, remote_signer_identity, generation)
            sender_reference = _register_issued_sender(sender, self)
            self._prepared[id(sender)] = _PreparedRecord(
                sender=sender_reference,
                remote_signer_identity=remote_signer_identity,
                rule_id=rule_id,
                generation=generation,
                key_generation=key_generation,
                fragments=tuple(sender._fragments),
                expires_at=now + PREPARED_SENDER_TTL_SECONDS,
            )
        return sender

    def activate_and_start(self, sender: FragmentSender) -> list[bytes]:
        """Reserve one exact sender and emit its complete initial batch."""
        with self._lock:
            now = self._expire_all_unlocked()
            prepared = self._prepared.get(id(sender))
            if prepared is None or prepared.sender() is not sender:
                raise FragmentError("fragmentation sender capability is not link-issued")
            remote = prepared.remote_signer_identity
            key = self._key(remote, prepared.key_generation, prepared.rule_id)
            if prepared.generation != self._generations.get(remote, 0):
                raise FragmentError("fragmentation sender was invalidated by key rotation")
            record = self._records.get(key)
            if key in self._tombstones:
                raise FragmentError("fragmentation session is in terminal hold-down")
            if record is not None:
                if record.active:
                    raise FragmentError("a T=0 fragmentation session is already active")
                raise FragmentError("fragmentation session is in terminal hold-down")
            if len(self._records) + len(self._tombstones) >= self._max_records:
                raise FragmentError("fragmentation session registry is full")
            self._ensure_fragment_wire_capacity_unlocked(len(prepared.fragments))
            baseline = self._replay_protector.highest(remote)
            if baseline >= MAX_LINK_REPLAY_COUNTER:
                raise FragmentError("remote replay counter exhausted; link rekey required")
            retransmit_at = self._retransmission_deadline(now)
            self._pin_replay(remote)
            self._records[key] = _SessionRecord(
                sender=sender,
                remote_signer_identity=remote,
                rule_id=prepared.rule_id,
                generation=prepared.generation,
                key_generation=prepared.key_generation,
                fragments=prepared.fragments,
                high_water=baseline,
                idle_expires_at=now + SESSION_IDLE_TIMEOUT_SECONDS,
                retransmit_at=retransmit_at,
            )
            self._sender_records[id(sender)] = self._records[key]
            self._prepared.pop(id(sender), None)
            # The ordered initial batch includes All-1 exactly once.
            sender._set_security_state(status="active", attempts=1)
            if self._state_change is not None:
                self._state_change()
            record = self._records[key]
            return [
                self._issue_fragment_wire_unlocked(sender, record, fragment)
                for fragment in prepared.fragments
            ]

    def invalidate_remote_policy(self, remote: bytes) -> None:
        """Revoke every sender capability after authenticated policy changes."""
        self._check_identity(remote, field_name="remote_signer_identity")
        with self._lock:
            now = self._now_unlocked()
            self._drop_issued_controls_unlocked(remote)
            next_generation = self._generations.get(remote, 0) + 1
            if next_generation > MAX_LINK_REPLAY_COUNTER:
                raise FragmentError("SCHC policy generation exhausted")
            self._generations[remote] = next_generation
            for sender_id in [
                sender_id
                for sender_id, prepared in self._prepared.items()
                if prepared.remote_signer_identity == remote
            ]:
                prepared = self._prepared.pop(sender_id)
                sender = prepared.sender()
                if sender is not None:
                    sender._set_security_state(status="invalidated")
            for key in [key for key in self._records if key[1] == remote]:
                record = self._records.pop(key)
                record.active = False
                record.status = "invalidated"
                record.sender._set_security_state(status="invalidated")
                self._drop_issued_wires_unlocked(record.sender)
                self._sender_records.pop(id(record.sender), None)
                self._unpin_replay(remote)
                self._tombstones[key] = _SessionTombstone(
                    expires_at=now + SESSION_HOLD_DOWN_SECONDS,
                    high_water=record.high_water,
                    generation=next_generation,
                    key_generation=record.key_generation,
                    status="invalidated",
                )
            if self._state_change is not None:
                self._state_change()

    def export_persistence_state(self) -> list[dict[str, object]]:
        """Return conservative T=0 tombstones suitable for durable storage."""
        with self._lock:
            self._expire_records_unlocked()
            rows: list[dict[str, object]] = []
            for key, record in self._records.items():
                rows.append(
                    {
                        "remote": key[1].hex(),
                        "rule_id": key[3],
                        "high_water": record.high_water,
                        "generation": record.generation,
                        "status": record.status,
                    }
                )
            for key, tombstone in self._tombstones.items():
                rows.append(
                    {
                        "remote": key[1].hex(),
                        "rule_id": key[3],
                        "high_water": tombstone.high_water,
                        "generation": tombstone.generation,
                        "status": tombstone.status,
                    }
                )
            return rows

    def restore_persistence_state(self, raw: object, key_generations: dict[bytes, object]) -> None:
        """Restore every ambiguous pre-crash T=0 tuple as a fresh hold-down."""
        if type(raw) is not list or len(raw) > self._max_records:
            raise FragmentError("invalid persisted SCHC session state")
        restored: dict[tuple[bytes, bytes, int, int], _SessionTombstone] = {}
        now = self._now_unlocked()
        for item in raw:
            if type(item) is not dict or set(item) != {
                "remote",
                "rule_id",
                "high_water",
                "generation",
                "status",
            }:
                raise FragmentError("invalid persisted SCHC session record")
            remote_hex = item["remote"]
            rule_id = item["rule_id"]
            high_water = item["high_water"]
            generation = item["generation"]
            status = item["status"]
            if (
                type(remote_hex) is not str
                or type(rule_id) is not int
                or rule_id not in RULE_IDS
                or type(high_water) is not int
                or not -1 <= high_water <= MAX_LINK_REPLAY_COUNTER
                or type(generation) is not int
                or not 0 <= generation <= MAX_LINK_REPLAY_COUNTER
                or type(status) is not str
                or status
                not in {"active", "succeeded", "aborted", "expired", "invalidated", "restarted"}
            ):
                raise FragmentError("invalid persisted SCHC session record")
            try:
                remote = bytes.fromhex(remote_hex)
            except ValueError as exc:
                raise FragmentError("invalid persisted SCHC session signer") from exc
            key_generation = key_generations.get(remote)
            if key_generation is None:
                raise FragmentError("persisted SCHC session has no current key generation")
            key = self._key(remote, key_generation, rule_id)
            if key in restored or high_water > self._replay_protector.highest(remote):
                raise FragmentError("inconsistent persisted SCHC session record")
            restored[key] = _SessionTombstone(
                expires_at=now + SESSION_HOLD_DOWN_SECONDS,
                high_water=high_water,
                generation=generation,
                key_generation=key_generation,
                status="restarted",
            )
            self._generations[remote] = max(self._generations.get(remote, 0), generation)
        self._tombstones = restored

    def record_verified_frame(self, received: RxFrame) -> None:
        """Register an exact one-use ACK/abort receipt at link acceptance."""
        data = received.payload
        if not data or data[0] not in RULE_IDS:
            return
        frame = received.frame
        if frame.addr_mode is not AddrMode.EXTENDED or frame.dst_addr != self._local_eui64:
            return
        # Only reverse-direction Receiver-Abort and ACKs control our outbound
        # sender.  Direction disambiguates ACK REQ from the byte-identical
        # compressed negative ACK before generic ACK parsing.
        try:
            is_response = fragmentation_message_is_response(
                data,
                sender_identity=received.sender_pubkey,
                receiver_identity=self._local_identity,
            )
            expected_rule = fragmentation_rule_for_sender(
                self._local_identity, received.sender_pubkey
            )
        except FragmentError:
            # Equal identities do not form a peer pair.  Receipt registration
            # is opportunistic and must not make LinkLayer.receive raise.
            return
        if not is_response:
            return
        if data[0] != expected_rule:
            return
        if data != receiver_abort(data[0]):
            try:
                Ack.from_bytes(data)
            except FragmentError:
                return
        key = self._key(received.sender_pubkey, received.key_generation, data[0])
        with self._lock:
            self._expire_records_unlocked()
            record = self._records.get(key)
            if record is None or not record.active:
                return
            replay_counter = logical_counter(received.epoch, received.seqnum)
            if replay_counter <= record.high_water:
                return
            receipt_id = id(received)
            record.pending[receipt_id] = received
            record.pending.move_to_end(receipt_id)
            while len(record.pending) > MAX_PENDING_ACK_RECEIPTS:
                record.pending.popitem(last=False)

    def transition_verified_control(self, received: RxFrame) -> list[bytes] | None:
        """Apply a registered ACK/abort, or return ``None`` for receiver traffic."""
        from lichen.link.link_layer import RxFrame

        if type(received) is not RxFrame:
            raise FragmentError("SCHC control must be supplied as a verified RxFrame")
        data = received.payload
        if not data or data[0] not in RULE_IDS:
            return None
        is_response = fragmentation_message_is_response(
            data,
            sender_identity=received.sender_pubkey,
            receiver_identity=self._local_identity,
        )
        if not is_response:
            return None
        if data[0] != (fragmentation_rule_for_sender(self._local_identity, received.sender_pubkey)):
            raise FragmentError("SCHC response Rule ID does not match authenticated endpoints")
        key = self._key(received.sender_pubkey, received.key_generation, data[0])
        with self._lock:
            self._expire_records_unlocked()
            record = self._records.get(key)
            if (
                record is None
                or not record.active
                or record.pending.get(id(received)) is not received
            ):
                return None
            return self.transition_ack(record.sender, received)

    def _active_record_unlocked(self, sender: FragmentSender) -> _SessionRecord:
        record = self._sender_records.get(id(sender))
        if record is None or not record.active or record.sender is not sender:
            raise FragmentError("fragmentation session is not active for this sender")
        return record

    def sender_status(self, sender: FragmentSender) -> str:
        with self._lock:
            self._expire_all_unlocked()
            prepared = self._prepared.get(id(sender))
            if prepared is not None and prepared.sender() is sender:
                return "ready"
            record = self._sender_records.get(id(sender))
            if record is not None and record.sender is sender:
                return record.status
            return sender._status

    def sender_attempts(self, sender: FragmentSender) -> int:
        with self._lock:
            self._expire_all_unlocked()
            prepared = self._prepared.get(id(sender))
            if prepared is not None and prepared.sender() is sender:
                return 0
            record = self._sender_records.get(id(sender))
            if record is not None and record.sender is sender:
                return record.attempts
            return sender._attempts

    def sender_retransmission_deadline(self, sender: FragmentSender) -> float | None:
        with self._lock:
            self._expire_all_unlocked()
            record = self._sender_records.get(id(sender))
            if record is not None and record.sender is sender and record.active:
                return record.retransmit_at
            return None

    def sender_fragments(self, sender: FragmentSender) -> tuple[Fragment, ...]:
        with self._lock:
            prepared = self._prepared.get(id(sender))
            if prepared is not None and prepared.sender() is sender:
                return prepared.fragments
            record = self._sender_records.get(id(sender))
            if record is not None and record.sender is sender:
                return record.fragments
            return sender._fragments

    def _finish_unlocked(
        self,
        sender: FragmentSender,
        record: _SessionRecord,
        outcome: str,
        *,
        preserve_control: _IssuedFragmentWire | None = None,
    ) -> None:
        record.active = False
        record.hold_down_until = self._now_unlocked() + SESSION_HOLD_DOWN_SECONDS
        record.outcome = outcome
        record.status = outcome
        record.retransmit_at = None
        record.pending.clear()
        self._drop_issued_wires_unlocked(sender)
        self._drop_issued_sender_controls_unlocked(sender, preserve=preserve_control)
        sender._set_security_state(status=outcome)
        if self._state_change is not None:
            self._state_change()

    def transition_ack(self, sender: FragmentSender, received: RxFrame) -> list[bytes]:
        """Authenticate, transition, finish, and produce output in one transaction."""
        with self._lock:
            now = self._expire_records_unlocked()
            record = self._active_record_unlocked(sender)
            registered = record.pending.pop(id(received), None)
            if registered is not received:
                raise FragmentError("ACK lacks this link's authenticated receive receipt")
            if self._receipt_consumer is None:
                raise FragmentError("ACK manager lacks a link receipt consumer")
            try:
                authenticated = self._receipt_consumer(received, "schc-ack")
            except (TypeError, ValueError) as exc:
                raise FragmentError("ACK lacks this link's unconsumed verified receipt") from exc
            data = authenticated.payload
            if len(data) < 2:
                raise FragmentError("ACK too short")
            if data[0] != record.rule_id:
                raise FragmentError("ACK/control rule does not match the active transfer")
            if authenticated.sender_pubkey != record.remote_signer_identity:
                raise FragmentError("ACK/control signer does not match the active transfer")
            if authenticated.local_pubkey != self._local_identity:
                raise FragmentError("ACK/control local identity does not match the active transfer")
            if authenticated.key_generation is not record.key_generation:
                raise FragmentError("ACK/control key generation does not match the active transfer")
            replay_counter = logical_counter(authenticated.epoch, authenticated.seqnum)
            if replay_counter <= record.high_water:
                raise FragmentError(
                    "ACK/control replay counter is not newer than the session high-water"
                )
            if data == receiver_abort(record.rule_id):
                record.high_water = replay_counter
                self._finish_unlocked(sender, record, "aborted")
                return []
            ack_window = data[1] >> 7
            assigned_fcns = (
                fragment.fcn for fragment in record.fragments if fragment.window == ack_window
            )
            ack = Ack.from_bytes(data, assigned_fcns=assigned_fcns)
            final_window = record.fragments[-1].window
            if ack.window > final_window:
                raise FragmentError("ACK window is outside the active transfer")
            if ack.complete and ack.window != final_window:
                raise FragmentError("C=1 ACK must identify the final window")
            next_retransmit_at = None if ack.complete else self._retransmission_deadline(now)
            record.high_water = replay_counter
            # Only a structurally and semantically valid control is session
            # activity.  In particular, an authenticated malformed ACK must
            # not keep a stale transfer alive until an attacker stops sending.
            record.idle_expires_at = now + SESSION_IDLE_TIMEOUT_SECONDS
            if ack.complete:
                self._finish_unlocked(sender, record, "succeeded")
                return []
            record.retransmit_at = next_retransmit_at

            missing_regular: list[Fragment] = []
            missing_all_1: Fragment | None = None
            start = ack.window * WINDOW_SIZE
            for fragment in record.fragments[start : start + WINDOW_SIZE]:
                bitmap_position = 62 if fragment.is_all_1 else (62 - fragment.fcn)
                received_bit = ack.bitmap[bitmap_position]
                if received_bit:
                    continue
                if fragment.is_all_1:
                    missing_all_1 = fragment
                else:
                    missing_regular.append(fragment)

            if missing_all_1 is not None:
                if record.attempts >= MAX_ACK_REQUESTS:
                    output = self._issue_control_wire_unlocked(
                        sender_abort(record.rule_id),
                        record.remote_signer_identity,
                        record.key_generation,
                        response=False,
                        owner=sender,
                    )
                    self._finish_unlocked(sender, record, "aborted", preserve_control=output)
                    return [output]
                self._ensure_fragment_wire_capacity_unlocked(len(missing_regular) + 1)
                record.attempts += 1
                sender._set_security_state(attempts=record.attempts)
                # An All-1 retransmission itself solicits the next ACK; appending
                # ACK REQ would create a duplicate request and contradict S5.2.
                all1_output: list[bytes] = [
                    *(
                        self._issue_fragment_wire_unlocked(sender, record, fragment)
                        for fragment in missing_regular
                    ),
                    self._issue_fragment_wire_unlocked(sender, record, missing_all_1),
                ]
                if self._state_change is not None:
                    self._state_change()
                return all1_output

            if not missing_regular:
                # C=0 with every assigned bit received means RCS validation
                # failed but there is no fragment that can repair the packet.
                output = self._issue_control_wire_unlocked(
                    sender_abort(record.rule_id),
                    record.remote_signer_identity,
                    record.key_generation,
                    response=False,
                    owner=sender,
                )
                self._finish_unlocked(sender, record, "aborted", preserve_control=output)
                return [output]

            if record.attempts >= MAX_ACK_REQUESTS:
                output = self._issue_control_wire_unlocked(
                    sender_abort(record.rule_id),
                    record.remote_signer_identity,
                    record.key_generation,
                    response=False,
                    owner=sender,
                )
                self._finish_unlocked(sender, record, "aborted", preserve_control=output)
                return [output]
            self._ensure_fragment_wire_capacity_unlocked(len(missing_regular) + 1)
            record.attempts += 1
            sender._set_security_state(attempts=record.attempts)
            repair_output: list[bytes] = [
                *(
                    self._issue_fragment_wire_unlocked(sender, record, fragment)
                    for fragment in missing_regular
                ),
                self._issue_control_wire_unlocked(
                    ack_request(record.rule_id, final_window),
                    record.remote_signer_identity,
                    record.key_generation,
                    response=False,
                    owner=sender,
                ),
            ]
            if self._state_change is not None:
                self._state_change()
            return repair_output

    def _transition_timeout_unlocked(
        self,
        sender: FragmentSender,
        record: _SessionRecord,
        now: float,
    ) -> bytes:
        if record.attempts >= MAX_ACK_REQUESTS:
            output = self._issue_control_wire_unlocked(
                sender_abort(record.rule_id),
                record.remote_signer_identity,
                record.key_generation,
                response=False,
                owner=sender,
            )
            self._finish_unlocked(sender, record, "aborted", preserve_control=output)
            return output
        next_retransmit_at = self._retransmission_deadline(now)
        record.attempts += 1
        sender._set_security_state(attempts=record.attempts)
        record.idle_expires_at = now + SESSION_IDLE_TIMEOUT_SECONDS
        record.retransmit_at = next_retransmit_at
        output = self._issue_control_wire_unlocked(
            ack_request(record.rule_id, record.fragments[-1].window),
            record.remote_signer_identity,
            record.key_generation,
            response=False,
            owner=sender,
        )
        if self._state_change is not None:
            self._state_change()
        return output

    def transition_timeout(self, sender: FragmentSender) -> bytes:
        """Force one timeout transition after an external timer has fired."""
        with self._lock:
            now = self._expire_records_unlocked()
            record = self._sender_records.get(id(sender))
            if record is None or record.sender is not sender or not record.active:
                return b""
            return self._transition_timeout_unlocked(sender, record, now)

    def transition_timeout_if_due(self, sender: FragmentSender) -> bytes:
        """Poll the fixed 10-second timer without firing early or twice."""
        with self._lock:
            now = self._expire_records_unlocked()
            record = self._sender_records.get(id(sender))
            if record is None or record.sender is not sender or not record.active:
                return b""
            if record.retransmit_at is None or now < record.retransmit_at:
                return b""
            return self._transition_timeout_unlocked(sender, record, now)

    def cancel_with_abort(self, sender: FragmentSender) -> bytes | None:
        """Atomically terminate an active sender and issue its one-use abort."""
        with self._lock:
            self._expire_records_unlocked()
            record = self._sender_records.get(id(sender))
            if record is None or record.sender is not sender or not record.active:
                self.transition_cancel(sender)
                return None
            output = self._issue_control_wire_unlocked(
                sender_abort(record.rule_id),
                record.remote_signer_identity,
                record.key_generation,
                response=False,
                owner=sender,
            )
            self._finish_unlocked(sender, record, "aborted", preserve_control=output)
            return output

    def transition_cancel(self, sender: FragmentSender) -> None:
        """Cancel ready/active senders and tolerate terminal expiry."""
        with self._lock:
            self._expire_records_unlocked()
            prepared = self._prepared.get(id(sender))
            if prepared is not None and prepared.sender() is sender:
                self._prepared.pop(id(sender), None)
                sender._set_security_state(status="cancelled")
                return
            record = self._sender_records.get(id(sender))
            if record is None or record.sender is not sender or not record.active:
                return
            self._finish_unlocked(sender, record, "aborted")

    def replacement_occupied(self, remote: bytes) -> bool:
        """Return whether a replacement identity owns any live session capability."""
        self._check_identity(remote, field_name="new_remote_signer_identity")
        with self._lock:
            self._expire_all_unlocked()
            if any(key[1] == remote for key in self._records):
                return True
            return any(
                prepared.remote_signer_identity == remote for prepared in self._prepared.values()
            )

    def retire_remote(self, remote: bytes) -> None:
        """Forget an unoccupied peer's residual generation on TOFU eviction."""
        self._check_identity(remote, field_name="remote_signer_identity")
        with self._lock:
            self._expire_all_unlocked()
            if self.replacement_occupied(remote):
                raise FragmentError("cannot retire a peer with fragmentation state")
            self._drop_issued_controls_unlocked(remote)
            self._generations.pop(remote, None)

    def rotate_remote(self, old_remote: bytes, new_remote: bytes) -> None:
        """Invalidate old/new leases while the LinkLayer security lock is held."""
        next_generation = self.preflight_rotate_remote(old_remote, new_remote)
        with self._lock:
            self._drop_issued_controls_unlocked(old_remote)
            self._drop_issued_controls_unlocked(new_remote)
            keys = [key for key in self._records if key[1] == old_remote]
            for key in keys:
                self._records[key].sender._set_security_state(status="invalidated")
                self._records[key].status = "invalidated"
                self._drop_issued_wires_unlocked(self._records[key].sender)
                self._unpin_replay(key[1])
                self._sender_records.pop(id(self._records[key].sender), None)
                del self._records[key]
            self._generations.pop(old_remote, None)
            self._generations[new_remote] = next_generation
            stale = [
                sender_id
                for sender_id, prepared in self._prepared.items()
                if prepared.remote_signer_identity == old_remote
            ]
            for sender_id in stale:
                prepared = self._prepared.pop(sender_id, None)
                if prepared is not None:
                    sender = prepared.sender()
                    if sender is not None:
                        sender._set_security_state(status="invalidated")

    def preflight_rotate_remote(self, old_remote: bytes, new_remote: bytes) -> int:
        """Validate every fallible rotation condition without mutating state."""
        self._check_identity(old_remote, field_name="old_remote_signer_identity")
        self._check_identity(new_remote, field_name="new_remote_signer_identity")
        if old_remote == new_remote:
            raise FragmentError("key rotation requires a distinct replacement key")
        with self._lock:
            if self.replacement_occupied(new_remote):
                raise FragmentError("replacement signer identity already has SCHC state")
            next_generation = (
                max(
                    self._generations.get(old_remote, 0),
                    self._generations.get(new_remote, 0),
                )
                + 1
            )
            if next_generation > MAX_LINK_REPLAY_COUNTER:
                raise FragmentError("SCHC security generation exhausted")
            return next_generation

    def discard_prepared(self, sender: FragmentSender) -> None:
        """Drop a never-started exact-sender capability."""
        with self._lock:
            prepared = self._prepared.get(id(sender))
            if prepared is not None and prepared.sender() is sender:
                self._prepared.pop(id(sender), None)

    def fail_closed(self) -> None:
        """Invalidate every capability after a fatal owning-LinkLayer failure."""
        with self._lock:
            for prepared in self._prepared.values():
                sender = prepared.sender()
                if sender is not None:
                    sender._set_security_state(status="invalidated")
            for record in self._records.values():
                record.sender._set_security_state(status="invalidated")
                self._unpin_replay(record.remote_signer_identity)
            self._prepared.clear()
            self._records.clear()
            self._sender_records.clear()
            self._tombstones.clear()
            self._issued_wires.clear()
            self._issued_controls.clear()
