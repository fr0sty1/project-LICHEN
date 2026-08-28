# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Coordinator-managed short-address protocol and canonical vectors."""

from __future__ import annotations

import binascii
import json
import threading
from pathlib import Path

import pytest

from lichen.link.address_assignment import (
    SHORT_ADDRESS_OPTION_TYPE,
    AddressAssignmentAck,
    AddressAssignmentRequest,
    AssignmentOperation,
    AssignmentPersistenceError,
    AssignmentProtocolError,
    AssignmentStatus,
    MemoryAddressAssignmentStore,
    ShortAddressAssignmentClient,
    ShortAddressCoordinator,
    decode_assignment_state,
    encode_assignment_state,
)
from lichen.rpl.messages import DAO, DAOAck, RplOption

VECTORS = Path(__file__).parents[3] / "test" / "vectors" / "short_addr_assignment.json"
EUI = bytes.fromhex("0011223344556677")
OTHER_EUI = bytes.fromhex("8899aabbccddeeff")
THIRD_EUI = bytes.fromhex("1020304050607080")


class FakeClock:
    def __init__(self, now: int) -> None:
        self.now = now

    def __call__(self) -> float:
        return float(self.now)


def _vectors() -> dict[str, object]:
    return json.loads(VECTORS.read_text())  # type: ignore[no-any-return]


def test_canonical_request_and_ack_wires_round_trip() -> None:
    doc = _vectors()
    wire = doc["wire"]
    assert isinstance(wire, dict)
    request_wire = bytes.fromhex(str(wire["allocate_request_hex"]))
    dao = DAO.from_bytes(request_wire)
    request = AddressAssignmentRequest.from_dao(dao)
    assert request == AddressAssignmentRequest(EUI, requested_short=0x1234)
    assert request.to_dao(0, 7).to_bytes() == request_wire

    ack_wire = bytes.fromhex(str(wire["allocate_ack_hex"]))
    ack = DAOAck.from_bytes(ack_wire)
    result = AddressAssignmentAck.from_dao_ack(ack)
    assert result == AddressAssignmentAck(
        EUI,
        AssignmentOperation.ALLOCATE,
        AssignmentStatus.SUCCESS,
        0x1234,
        7,
    )
    assert result.to_dao_ack(0).to_bytes() == ack_wire

    release_wire = bytes.fromhex(str(wire["release_request_hex"]))
    release = AddressAssignmentRequest.from_dao(DAO.from_bytes(release_wire))
    assert release == AddressAssignmentRequest(EUI, AssignmentOperation.RELEASE)
    assert release.to_dao(0, int(str(wire["release_sequence"]))).to_bytes() == release_wire

    release_ack_wire = bytes.fromhex(str(wire["release_ack_hex"]))
    release_ack = AddressAssignmentAck.from_dao_ack(DAOAck.from_bytes(release_ack_wire))
    assert release_ack.operation is AssignmentOperation.RELEASE
    assert release_ack.status is AssignmentStatus.SUCCESS
    assert release_ack.assigned_short is None
    assert release_ack.to_dao_ack(0).to_bytes() == release_ack_wire


def test_coordinator_allocates_and_processes_idempotent_dao() -> None:
    coordinator = ShortAddressCoordinator()
    dao = AddressAssignmentRequest(EUI, requested_short=0x1234).to_dao(0, 7)
    first_wire = coordinator.handle_dao(dao).to_bytes()
    second_wire = coordinator.handle_dao(DAO.from_bytes(dao.to_bytes())).to_bytes()
    assert first_wire == second_wire
    assert coordinator.lookup_by_eui(EUI) == 0x1234
    assert coordinator.lookup_by_short(0x1234) == EUI
    assert len(coordinator) == 1


def test_end_to_end_dao_ack_assigns_node() -> None:
    coordinator = ShortAddressCoordinator()
    client = ShortAddressAssignmentClient(EUI)
    dao = AddressAssignmentRequest(EUI, requested_short=0x1234).to_dao(0, 17)
    ack = coordinator.handle_dao(DAO.from_bytes(dao.to_bytes()))
    assert client.apply_dao_ack(DAOAck.from_bytes(ack.to_bytes()), 17)
    assert client.assigned_short == 0x1234


def test_requested_collision_allocates_a_unique_derived_address() -> None:
    coordinator = ShortAddressCoordinator(initial_assignments={0x1234: OTHER_EUI})
    result = coordinator.process(AddressAssignmentRequest(EUI, requested_short=0x1234), 8)
    assert result.status is AssignmentStatus.SUCCESS
    assert result.assigned_short == 0x056E
    assert coordinator.lookup_by_short(0x1234) == OTHER_EUI
    assert coordinator.lookup_by_short(0x056E) == EUI


def test_pool_exhaustion_returns_negative_ack_without_mutation() -> None:
    occupied = {short: short.to_bytes(8, "big") for short in range(1, 0xFFFE)}
    coordinator = ShortAddressCoordinator(initial_assignments=occupied)
    request = AddressAssignmentRequest(bytes.fromhex("ffffffffffffffff"))
    result = coordinator.process(request, 9)
    assert result.status is AssignmentStatus.EXHAUSTED
    assert result.assigned_short is None
    assert len(coordinator) == 0xFFFD


def test_release_is_idempotent_and_survives_restart() -> None:
    store = MemoryAddressAssignmentStore()
    coordinator = ShortAddressCoordinator(store=store)
    allocation = AddressAssignmentRequest(EUI, requested_short=0x1234)
    coordinator.process(allocation, 10)

    restarted = ShortAddressCoordinator(store=store)
    assert restarted.lookup_by_eui(EUI) == 0x1234
    release = AddressAssignmentRequest(EUI, AssignmentOperation.RELEASE)
    first = restarted.process(release, 11)
    second = restarted.process(release, 11)
    assert first == second
    assert first.status is AssignmentStatus.SUCCESS
    assert first.assigned_short is None
    assert ShortAddressCoordinator(store=store).lookup_by_eui(EUI) is None


def test_stale_release_cannot_drop_a_newer_allocation() -> None:
    coordinator = ShortAddressCoordinator()
    allocate = AddressAssignmentRequest(EUI, requested_short=0x1234)
    release = AddressAssignmentRequest(EUI, AssignmentOperation.RELEASE)

    assert coordinator.process(allocate, 1).status is AssignmentStatus.SUCCESS
    assert coordinator.process(release, 2).status is AssignmentStatus.SUCCESS
    assert coordinator.process(allocate, 3).status is AssignmentStatus.SUCCESS

    same_sequence = coordinator.process(release, 3)
    assert same_sequence.status is AssignmentStatus.INVALID
    stale = coordinator.process(release, 2)
    assert stale.status is AssignmentStatus.INVALID
    assert coordinator.lookup_by_eui(EUI) == 0x1234


def test_release_sequence_tombstone_survives_restart() -> None:
    store = MemoryAddressAssignmentStore()
    coordinator = ShortAddressCoordinator(store=store)
    allocate = AddressAssignmentRequest(EUI, requested_short=0x1234)
    release = AddressAssignmentRequest(EUI, AssignmentOperation.RELEASE)
    coordinator.process(allocate, 1)
    coordinator.process(release, 2)

    restarted = ShortAddressCoordinator(store=store)
    stale_allocate = restarted.process(allocate, 1)
    assert stale_allocate.status is AssignmentStatus.INVALID
    assert restarted.lookup_by_eui(EUI) is None
    assert restarted.process(release, 2).status is AssignmentStatus.SUCCESS
    assert restarted.process(release, 3).status is AssignmentStatus.SUCCESS

    restarted_again = ShortAddressCoordinator(store=store)
    assert restarted_again.process(allocate, 2).status is AssignmentStatus.INVALID
    assert restarted_again.process(allocate, 4).assigned_short == 0x1234


def test_legacy_sat2_state_remains_restart_compatible() -> None:
    record = (
        (0x1234).to_bytes(2, "big")
        + EUI
        + (200).to_bytes(8, "big")
        + (7).to_bytes(2, "big")
    )
    body = b"SAT2" + (1).to_bytes(2, "big") + record
    state = body + binascii.crc32(body).to_bytes(4, "big")

    coordinator = ShortAddressCoordinator(
        store=MemoryAddressAssignmentStore(state), clock=FakeClock(100)
    )

    assert coordinator.lookup_by_eui(EUI) == 0x1234
    assert coordinator.expires_at(EUI) == 200
    same_sequence = coordinator.process(
        AddressAssignmentRequest(EUI, requested_short=0x1234), 7
    )
    assert same_sequence.status is AssignmentStatus.SUCCESS
    assert coordinator.expires_at(EUI) == 200


@pytest.mark.parametrize(
    ("old_sequence", "new_sequence", "renews"),
    [
        (1, 1, False),
        (1, 2, True),
        (2, 1, False),
        (255, 0, True),
        (0, 255, False),
        (0, 16, True),
        (0, 17, False),
        (239, 255, True),
        (238, 255, False),
        (240, 0, True),
        (239, 0, False),
        (10, 250, False),
        (250, 10, True),
        (250, 130, True),
        (130, 250, False),
    ],
)
def test_dao_sequence_freshness_controls_lease_renewal(
    old_sequence: int, new_sequence: int, renews: bool
) -> None:
    clock = FakeClock(100)
    coordinator = ShortAddressCoordinator(lease_seconds=10, clock=clock)
    request = AddressAssignmentRequest(EUI, requested_short=0x1234)
    coordinator.process(request, old_sequence)
    clock.now = 101

    result = coordinator.process(request, new_sequence)

    assert result.status is AssignmentStatus.SUCCESS
    assert coordinator.expires_at(EUI) == (111 if renews else 110)


def test_release_commit_failure_keeps_assignment_and_sequence() -> None:
    class FailingOnDemandStore(MemoryAddressAssignmentStore):
        fail = False

        def save(self, state: bytes) -> None:
            if self.fail:
                raise OSError("storage unavailable")
            super().save(state)

    store = FailingOnDemandStore()
    coordinator = ShortAddressCoordinator(store=store)
    allocate = AddressAssignmentRequest(EUI, requested_short=0x1234)
    coordinator.process(allocate, 1)
    store.fail = True

    with pytest.raises(AssignmentPersistenceError, match="commit"):
        coordinator.process(AddressAssignmentRequest(EUI, AssignmentOperation.RELEASE), 2)
    assert coordinator.lookup_by_eui(EUI) == 0x1234
    assert coordinator.process(allocate, 1).assigned_short == 0x1234


def test_concurrent_release_and_newer_allocate_publish_atomically() -> None:
    class BlockingStore(MemoryAddressAssignmentStore):
        armed = False

        def __init__(self) -> None:
            super().__init__()
            self.entered = threading.Event()
            self.proceed = threading.Event()

        def save(self, state: bytes) -> None:
            if self.armed:
                self.entered.set()
                if not self.proceed.wait(timeout=2):
                    raise TimeoutError("test did not release blocked save")
                self.armed = False
            super().save(state)

    store = BlockingStore()
    coordinator = ShortAddressCoordinator(store=store)
    allocate = AddressAssignmentRequest(EUI, requested_short=0x1234)
    release = AddressAssignmentRequest(EUI, AssignmentOperation.RELEASE)
    coordinator.process(allocate, 1)
    store.armed = True
    statuses: list[AssignmentStatus] = []

    def do_release() -> None:
        statuses.append(coordinator.process(release, 2).status)

    def do_allocate() -> None:
        statuses.append(coordinator.process(allocate, 3).status)

    release_thread = threading.Thread(target=do_release)
    release_thread.start()
    assert store.entered.wait(timeout=2)
    allocate_thread = threading.Thread(target=do_allocate)
    allocate_thread.start()
    store.proceed.set()
    release_thread.join(timeout=2)
    allocate_thread.join(timeout=2)

    assert not release_thread.is_alive()
    assert not allocate_thread.is_alive()
    assert statuses == [AssignmentStatus.SUCCESS, AssignmentStatus.SUCCESS]
    assert coordinator.lookup_by_eui(EUI) == 0x1234
    assert coordinator.process(release, 2).status is AssignmentStatus.INVALID


def test_bounded_table_exhaustion_release_and_reuse() -> None:
    coordinator = ShortAddressCoordinator(capacity=2)
    first = coordinator.process(AddressAssignmentRequest(EUI, requested_short=0x1001), 1)
    second = coordinator.process(AddressAssignmentRequest(OTHER_EUI, requested_short=0x1002), 2)
    assert first.assigned_short == 0x1001
    assert second.assigned_short == 0x1002
    exhausted = coordinator.process(
        AddressAssignmentRequest(THIRD_EUI, requested_short=0x1003), 3
    )
    assert exhausted.status is AssignmentStatus.EXHAUSTED
    assert coordinator.process(
        AddressAssignmentRequest(EUI, AssignmentOperation.RELEASE), 4
    ).status is AssignmentStatus.SUCCESS
    reused = coordinator.process(AddressAssignmentRequest(THIRD_EUI, requested_short=0x1001), 5)
    assert reused.assigned_short == 0x1001
    assert len(coordinator) == 2


def test_peer_mapping_stays_idempotent_when_preference_changes() -> None:
    coordinator = ShortAddressCoordinator()
    first = coordinator.process(AddressAssignmentRequest(EUI, requested_short=0x1001), 6)
    second = coordinator.process(AddressAssignmentRequest(EUI, requested_short=0x2002), 7)
    assert first.assigned_short == second.assigned_short == 0x1001
    assert coordinator.lookup_by_short(0x2002) is None
    assert len(coordinator) == 1


def test_lease_duplicate_renewal_expiry_and_restart_match_vector() -> None:
    maintenance = _vectors()["maintenance"]
    assert isinstance(maintenance, dict)
    clock = FakeClock(int(str(maintenance["allocated_at"])))
    store = MemoryAddressAssignmentStore()
    coordinator = ShortAddressCoordinator(
        store=store,
        capacity=int(str(maintenance["capacity"])),
        lease_seconds=int(str(maintenance["lease_seconds"])),
        clock=clock,
    )
    sequence = int(str(maintenance["initial_sequence"]))
    request = AddressAssignmentRequest(EUI, requested_short=0x1234)
    assert coordinator.process(request, sequence).assigned_short == 0x1234
    assert coordinator.expires_at(EUI) == int(str(maintenance["initial_expiry"]))

    clock.now = int(str(maintenance["duplicate_at"]))
    restarted = ShortAddressCoordinator(
        store=store,
        capacity=1,
        lease_seconds=60,
        clock=clock,
    )
    restarted.process(request, sequence)
    assert restarted.expires_at(EUI) == int(str(maintenance["duplicate_expiry"]))

    clock.now = int(str(maintenance["renewed_at"]))
    restarted.process(request, int(str(maintenance["renewed_sequence"])))
    assert restarted.expires_at(EUI) == int(str(maintenance["renewed_expiry"]))

    clock.now = int(str(maintenance["expires_at"]))
    after_expiry = ShortAddressCoordinator(
        store=store,
        capacity=1,
        lease_seconds=60,
        clock=clock,
    )
    assert after_expiry.lookup_by_eui(EUI) is None
    reused = after_expiry.process(AddressAssignmentRequest(OTHER_EUI, requested_short=0x1234), 23)
    assert reused.assigned_short == int(str(maintenance["reused_short"]))


def test_prune_expired_is_batched_and_idempotent() -> None:
    clock = FakeClock(100)
    coordinator = ShortAddressCoordinator(lease_seconds=10, clock=clock)
    coordinator.process(AddressAssignmentRequest(EUI, requested_short=0x1001), 1)
    coordinator.process(AddressAssignmentRequest(OTHER_EUI, requested_short=0x1002), 2)
    assert coordinator.prune_expired(109) == 0
    assert coordinator.prune_expired(110) == 2
    assert coordinator.prune_expired(110) == 0
    assert len(coordinator) == 0


@pytest.mark.parametrize("capacity", [True, 0, 0xFFFE])
def test_invalid_capacity_is_rejected(capacity: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        ShortAddressCoordinator(capacity=capacity)  # type: ignore[arg-type]


@pytest.mark.parametrize("eui64", [b"", b"short", bytearray(8), "0011223344556677"])
def test_invalid_peer_identifiers_are_rejected(eui64: object) -> None:
    coordinator = ShortAddressCoordinator()
    with pytest.raises(AssignmentProtocolError, match="EUI-64"):
        coordinator.lookup_by_eui(eui64)  # type: ignore[arg-type]


def test_node_applies_matching_ack_and_rejects_spoof_or_wrong_sequence() -> None:
    client = ShortAddressAssignmentClient(EUI)
    result = AddressAssignmentAck(
        EUI,
        AssignmentOperation.ALLOCATE,
        AssignmentStatus.SUCCESS,
        0x1234,
        12,
    )
    ack = result.to_dao_ack(0)
    assert not client.apply_dao_ack(ack, 11)
    spoof = AddressAssignmentAck(
        OTHER_EUI,
        AssignmentOperation.ALLOCATE,
        AssignmentStatus.SUCCESS,
        0x1234,
        12,
    ).to_dao_ack(0)
    assert not client.apply_dao_ack(spoof, 12)
    assert client.apply_dao_ack(ack, 12)
    assert client.apply_dao_ack(DAOAck.from_bytes(ack.to_bytes()), 12)
    assert client.assigned_short == 0x1234


def test_node_rejects_conflicting_ack_for_same_sequence() -> None:
    client = ShortAddressAssignmentClient(EUI)
    first = AddressAssignmentAck(
        EUI,
        AssignmentOperation.ALLOCATE,
        AssignmentStatus.SUCCESS,
        0x1234,
        13,
    ).to_dao_ack(0)
    conflict = AddressAssignmentAck(
        EUI,
        AssignmentOperation.ALLOCATE,
        AssignmentStatus.SUCCESS,
        0x1235,
        13,
    ).to_dao_ack(0)
    assert client.apply_dao_ack(first, 13)
    with pytest.raises(AssignmentProtocolError, match="conflicting DAO-ACK"):
        client.apply_dao_ack(conflict, 13)
    assert client.assigned_short == 0x1234


def test_node_accepts_a_new_sequence_and_release() -> None:
    client = ShortAddressAssignmentClient(EUI)
    allocate = AddressAssignmentAck(
        EUI,
        AssignmentOperation.ALLOCATE,
        AssignmentStatus.SUCCESS,
        0x1234,
        18,
    ).to_dao_ack(0)
    release = AddressAssignmentAck(
        EUI,
        AssignmentOperation.RELEASE,
        AssignmentStatus.SUCCESS,
        None,
        19,
    ).to_dao_ack(0)
    assert client.apply_dao_ack(allocate, 18)
    assert client.apply_dao_ack(release, 19)
    assert client.assigned_short is None


def test_snapshot_matches_vector_and_detects_corruption() -> None:
    doc = _vectors()
    snapshot_hex = str(doc["state_snapshot_hex"])
    state = encode_assignment_state({0x1234: EUI})
    assert state.hex() == snapshot_hex
    assert decode_assignment_state(state) == {0x1234: EUI}
    corrupted = state[:-1] + bytes((state[-1] ^ 1,))
    with pytest.raises(AssignmentProtocolError, match="checksum"):
        decode_assignment_state(corrupted)


def test_persistence_failure_does_not_publish_allocation() -> None:
    class FailingStore(MemoryAddressAssignmentStore):
        def save(self, state: bytes) -> None:
            raise OSError("storage unavailable")

    coordinator = ShortAddressCoordinator(store=FailingStore())
    with pytest.raises(AssignmentPersistenceError, match="commit"):
        coordinator.process(AddressAssignmentRequest(EUI, requested_short=0x1234), 14)
    assert len(coordinator) == 0


def test_corrupt_persisted_state_fails_closed_on_restart() -> None:
    state = encode_assignment_state({0x1234: EUI})
    store = MemoryAddressAssignmentStore(state[:-1] + bytes((state[-1] ^ 1,)))
    with pytest.raises(AssignmentProtocolError, match="checksum"):
        ShortAddressCoordinator(store=store)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        bytes.fromhex("02000000112233445566771234"),
        bytes.fromhex("01010000112233445566771234"),
        bytes.fromhex("01000900112233445566771234"),
    ],
)
def test_malformed_request_options_fail_closed(payload: bytes) -> None:
    option = RplOption(SHORT_ADDRESS_OPTION_TYPE, payload)
    with pytest.raises((AssignmentProtocolError, ValueError)):
        AddressAssignmentRequest.from_option(option)


def test_duplicate_or_missing_assignment_option_is_rejected() -> None:
    option = AddressAssignmentRequest(EUI).to_option()
    for options in ([], [option, option]):
        dao = DAO(0, 1, ack_requested=True, options=options)
        with pytest.raises(AssignmentProtocolError, match="exactly one"):
            AddressAssignmentRequest.from_dao(dao)
