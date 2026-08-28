# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Crash/restart security-state tests for the signed LinkLayer journal."""

from __future__ import annotations

import asyncio
import os
import threading
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.crypto.identity import Identity, PeerIdentity
from lichen.crypto.schnorr48 import sign
from lichen.ipv6.addr import iid_to_eui64
from lichen.ipv6.icmpv6 import EchoRequest
from lichen.ipv6.packet import IPv6Header, NextHeader
from lichen.link.frame import AddrMode, LichenFrame
from lichen.link.link_layer import (
    LinkLayer,
    LinkSecurityClockError,
    PersistenceRevisionAnchor,
    ReceiveError,
    RxFrame,
    _AuthenticatedPeerSchcIssuance,
    encode_rekey_request,
)
from lichen.link.tx_queue import Priority
from lichen.schc.context import AuthenticatedPeerSchcContext
from lichen.schc.fragment import FragmentError
from lichen.schc.headers import compress_packet
from lichen.schc.rules import SchcRuleVersionOption
from lichen.timing.time_sync import MonotonicClock


class MemoryRadio:
    def __init__(self) -> None:
        self.tx_history: list[bytes] = []
        self.rx_queue: list[tuple[bytes, int, int]] = []

    async def transmit(self, data: bytes) -> bool:
        self.tx_history.append(data)
        return True

    async def receive(self, timeout_ms: int) -> tuple[bytes, int, int] | None:
        del timeout_ms
        return self.rx_queue.pop(0) if self.rx_queue else None

    async def cad(self, timeout_ms: int) -> bool:
        del timeout_ms
        return False

    def queue(self, data: bytes) -> None:
        self.rx_queue.append((data, -90, 4))


LOCAL = Identity.from_seed(bytes(range(32)))
REMOTE = Identity.from_seed(bytes(range(32, 64)))
REPLACEMENT = Identity.from_seed(bytes(range(64, 96)))


class MemoryRevisionAnchor(PersistenceRevisionAnchor):
    def __init__(self) -> None:
        self.revisions: dict[bytes, int] = {}

    def read(self, local_pubkey: bytes) -> int | None:
        return self.revisions.get(local_pubkey)

    def advance(self, local_pubkey: bytes, expected: int | None, revision: int) -> None:
        if self.revisions.get(local_pubkey) != expected or revision != (expected or 0) + 1:
            raise RuntimeError("revision compare-and-advance failed")
        self.revisions[local_pubkey] = revision


_REVISION_ANCHORS: dict[Path, MemoryRevisionAnchor] = {}


def receiving_link(
    radio: MemoryRadio,
    path: Path,
    identity: Identity = LOCAL,
    *,
    revision_anchor: MemoryRevisionAnchor | None = None,
    bootstrap: bool | None = None,
    receipt_clock: MonotonicClock | None = None,
) -> LinkLayer:
    remote_peer = PeerIdentity.from_pubkey(REMOTE.pubkey)
    anchor = revision_anchor or _REVISION_ANCHORS.setdefault(path, MemoryRevisionAnchor())
    if bootstrap is None:
        bootstrap = anchor.read(identity.pubkey) is None
    return LinkLayer(
        radio=radio,  # type: ignore[arg-type]
        identity=identity,
        peer_lookup=lambda _hint: remote_peer,
        peer_lookup_all=lambda: [remote_peer],
        cad_enabled=False,
        persist_path=str(path),
        persistence_revision_anchor=anchor,
        allow_persistence_bootstrap=bootstrap,
        receipt_clock=receipt_clock,
    )


def sending_link(identity: Identity, radio: MemoryRadio) -> LinkLayer:
    return LinkLayer(
        radio=radio,  # type: ignore[arg-type]
        identity=identity,
        peer_lookup=lambda _hint: None,
        peer_lookup_all=lambda: [],
        cad_enabled=False,
    )


def authorize_schc(link: LinkLayer, remote_signer: bytes = REMOTE.pubkey) -> None:
    peer = PeerIdentity.from_pubkey(remote_signer)
    link._pinned_keys[peer.iid] = remote_signer
    generation = link._key_generations.setdefault(remote_signer, object())
    facade = AuthenticatedPeerSchcContext._issue_from_verified_dio(
        SchcRuleVersionOption.local(), remote_signer, owner=link
    )
    link._schc_peer_contexts[remote_signer] = facade
    link._schc_peer_context_issuances[id(facade)] = _AuthenticatedPeerSchcIssuance(
        facade=facade,
        remote_version=3,
        signer_identity=remote_signer,
        key_generation=generation,
    )


def canonical_schc_packet(label: bytes) -> bytes:
    src, dst = IPv6Address("fe80::1"), IPv6Address("fe80::2")
    icmp = EchoRequest(identifier=1, sequence=1, data=label).to_message().to_bytes(src, dst)
    raw = IPv6Header(src, dst, NextHeader.ICMPV6, payload_length=len(icmp)).to_bytes() + icmp
    return compress_packet(raw)


def test_persistence_requires_explicit_bootstrap_and_independent_anchor(tmp_path: Path) -> None:
    path = tmp_path / "link-state"
    anchor = MemoryRevisionAnchor()
    with pytest.raises(RuntimeError, match="explicit bootstrap"):
        receiving_link(MemoryRadio(), path, revision_anchor=anchor, bootstrap=False)
    bootstrapped = receiving_link(MemoryRadio(), path, revision_anchor=anchor, bootstrap=True)
    assert anchor.read(LOCAL.pubkey) == 1
    assert bootstrapped.get_sequence()


def test_complete_journal_deletion_after_bootstrap_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "link-state"
    anchor = MemoryRevisionAnchor()
    receiving_link(MemoryRadio(), path, revision_anchor=anchor, bootstrap=True)
    for suffix in (".0", ".1", ".anchor"):
        candidate = Path(f"{path}{suffix}")
        if candidate.exists():
            candidate.unlink()
    with pytest.raises(RuntimeError, match="deleted after bootstrap"):
        receiving_link(MemoryRadio(), path, revision_anchor=anchor, bootstrap=False)


@pytest.mark.asyncio
async def test_external_anchor_rejects_complete_old_signed_journal_restore(
    tmp_path: Path,
) -> None:
    path = tmp_path / "link-state"
    anchor = MemoryRevisionAnchor()
    local_radio = MemoryRadio()
    local = receiving_link(local_radio, path, revision_anchor=anchor, bootstrap=True)
    old_slot = Path(f"{path}.1").read_bytes()
    old_anchor = Path(f"{path}.anchor").read_bytes()
    remote_radio = MemoryRadio()
    remote = sending_link(REMOTE, remote_radio)
    assert await remote.send(b"advance")
    local_radio.queue(remote_radio.tx_history[-1])
    assert isinstance(await local.receive(100), RxFrame)
    assert anchor.read(LOCAL.pubkey) == 2

    Path(f"{path}.0").write_bytes(old_slot)
    Path(f"{path}.1").write_bytes(old_slot)
    Path(f"{path}.anchor").write_bytes(old_anchor)
    with pytest.raises(RuntimeError, match="rollback detected"):
        receiving_link(MemoryRadio(), path, revision_anchor=anchor, bootstrap=False)


@pytest.mark.asyncio
async def test_external_anchor_rejects_old_revision_one_when_local_anchor_deleted(
    tmp_path: Path,
) -> None:
    path = tmp_path / "link-state"
    anchor = MemoryRevisionAnchor()
    local_radio = MemoryRadio()
    local = receiving_link(local_radio, path, revision_anchor=anchor, bootstrap=True)
    old_slot = Path(f"{path}.1").read_bytes()
    remote_radio = MemoryRadio()
    remote = sending_link(REMOTE, remote_radio)
    assert await remote.send(b"advance")
    local_radio.queue(remote_radio.tx_history[-1])
    assert isinstance(await local.receive(100), RxFrame)

    Path(f"{path}.0").write_bytes(old_slot)
    Path(f"{path}.1").write_bytes(old_slot)
    Path(f"{path}.anchor").unlink()
    with pytest.raises(RuntimeError, match="rollback detected"):
        receiving_link(MemoryRadio(), path, revision_anchor=anchor, bootstrap=False)


@pytest.mark.asyncio
async def test_restart_preserves_exact_replay_rejection(tmp_path: Path) -> None:
    path = tmp_path / "link-state"
    local_radio = MemoryRadio()
    remote_radio = MemoryRadio()
    local = receiving_link(local_radio, path)
    remote = sending_link(REMOTE, remote_radio)
    remote._epoch = 0
    remote._seqnum = 7
    assert await remote.send(b"accepted-once")
    wire = remote_radio.tx_history[-1]
    local_radio.queue(wire)
    assert isinstance(await local.receive(100), RxFrame)

    restarted_radio = MemoryRadio()
    restarted = receiving_link(restarted_radio, path)
    restarted_radio.queue(wire)
    assert await restarted.receive(100) == ReceiveError.REPLAY


@pytest.mark.asyncio
async def test_restart_preserves_rekey_and_retired_key_tombstone(tmp_path: Path) -> None:
    path = tmp_path / "link-state"
    local_radio = MemoryRadio()
    remote_radio = MemoryRadio()
    local = receiving_link(local_radio, path)
    remote = sending_link(REMOTE, remote_radio)
    remote._epoch = 0
    remote._seqnum = 0

    assert await remote.send(b"baseline")
    local_radio.queue(remote_radio.tx_history[-1])
    assert isinstance(await local.receive(100), RxFrame)
    assert await remote.send(encode_rekey_request(REPLACEMENT.pubkey))
    local_radio.queue(remote_radio.tx_history[-1])
    evidence = await local.receive(100)
    assert isinstance(evidence, RxFrame)
    local.apply_authenticated_rekey(evidence)

    restarted_radio = MemoryRadio()
    restarted = receiving_link(restarted_radio, path)
    assert await remote.send(b"retired-key")
    restarted_radio.queue(remote_radio.tx_history[-1])
    assert await restarted.receive(100) == ReceiveError.KEY_CHANGE

    replacement_radio = MemoryRadio()
    replacement = sending_link(REPLACEMENT, replacement_radio)
    replacement._epoch = 0
    replacement._seqnum = 0
    assert await replacement.send(b"new-key")
    restarted_radio.queue(replacement_radio.tx_history[-1])
    accepted = await restarted.receive(100)
    assert isinstance(accepted, RxFrame)
    assert accepted.sender_pubkey == REPLACEMENT.pubkey


@pytest.mark.asyncio
async def test_signed_anchor_detects_rollback_to_older_valid_slot(tmp_path: Path) -> None:
    path = tmp_path / "link-state"
    local_radio = MemoryRadio()
    remote_radio = MemoryRadio()
    local = receiving_link(local_radio, path)
    old_revision = (tmp_path / "link-state.1").read_bytes()
    remote = sending_link(REMOTE, remote_radio)
    remote._epoch = 0
    remote._seqnum = 0
    for payload in (b"revision-one", b"revision-two"):
        assert await remote.send(payload)
        local_radio.queue(remote_radio.tx_history[-1])
        assert isinstance(await local.receive(100), RxFrame)

    (tmp_path / "link-state.0").write_bytes(old_revision)
    (tmp_path / "link-state.1").write_bytes(old_revision)
    with pytest.raises(RuntimeError, match="rollback detected"):
        receiving_link(MemoryRadio(), path)


@pytest.mark.asyncio
async def test_corrupt_persistence_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "link-state"
    local_radio = MemoryRadio()
    remote_radio = MemoryRadio()
    local = receiving_link(local_radio, path)
    remote = sending_link(REMOTE, remote_radio)
    remote._epoch = 0
    remote._seqnum = 0
    assert await remote.send(b"persist")
    local_radio.queue(remote_radio.tx_history[-1])
    assert isinstance(await local.receive(100), RxFrame)

    (tmp_path / "link-state.0").write_text("{}")
    (tmp_path / "link-state.1").write_text("{}")
    with pytest.raises(RuntimeError, match="missing or corrupt"):
        receiving_link(MemoryRadio(), path)


@pytest.mark.asyncio
async def test_restored_transmit_counter_cannot_be_reset(tmp_path: Path) -> None:
    path = tmp_path / "link-state"
    radio = MemoryRadio()
    link = receiving_link(radio, path)
    initial_epoch, initial_seqnum = link.get_sequence()
    assert await link.send(b"persist-counter")

    expected = (
        (initial_epoch + 1, 0) if initial_seqnum == 0xFFFF else (initial_epoch, initial_seqnum + 1)
    )

    restarted_radio = MemoryRadio()
    restarted = receiving_link(restarted_radio, path)
    assert restarted.get_sequence() == expected
    for attempted in ((0, 0), expected, (0xFF, 0xFFFE)):
        with pytest.raises(RuntimeError, match="cannot be reset"):
            restarted.set_sequence(*attempted)
        assert restarted.get_sequence() == expected
    assert await restarted.send(b"next")
    frame = LichenFrame.from_bytes(restarted_radio.tx_history[-1])
    assert (frame.epoch, frame.seqnum) == expected


def _raise_oserror(*_args: object, **_kwargs: object) -> None:
    raise OSError("injected persistence failure")


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["record", "fsync", "replace", "anchor", "external"])
async def test_persistence_fault_terminally_disables_link_and_drops_queue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    path = tmp_path / f"link-state-{stage}"
    radio = MemoryRadio()
    link = receiving_link(radio, path)
    if stage == "record":
        monkeypatch.setattr(link._persistence, "_write_signed_persistence_record", _raise_oserror)
    elif stage == "fsync":
        monkeypatch.setattr("lichen.link.persistence.os.fsync", _raise_oserror)
    elif stage == "replace":
        monkeypatch.setattr("lichen.link.persistence.os.replace", _raise_oserror)
    else:
        if stage == "anchor":
            monkeypatch.setattr(link._persistence, "_write_persistence_anchor", _raise_oserror)
        else:
            anchor = _REVISION_ANCHORS[path]
            monkeypatch.setattr(anchor, "advance", _raise_oserror)

    with pytest.raises(RuntimeError, match="permanently disabled"):
        await link.send(b"must-not-reach-radio")

    assert link.tx_queue.peek() is None
    assert radio.tx_history == []
    with pytest.raises(RuntimeError, match="disabled after a persistence failure"):
        await link.send(b"future")


@pytest.mark.asyncio
async def test_receive_anchor_failure_returns_no_receipt_and_disables_sessions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "link-state-rx-failure"
    local_radio = MemoryRadio()
    remote_radio = MemoryRadio()
    local = receiving_link(local_radio, path)
    remote = sending_link(REMOTE, remote_radio)
    remote._epoch = 0
    remote._seqnum = 0
    assert await remote.send(b"accepted-only-if-durable")
    local_radio.queue(remote_radio.tx_history[-1])
    monkeypatch.setattr(local._persistence, "_write_persistence_anchor", _raise_oserror)

    with pytest.raises(RuntimeError, match="permanently disabled"):
        await local.receive(100)

    assert not local._verified_receipts
    with pytest.raises(RuntimeError, match="disabled after a persistence failure"):
        await local.receive(100)


def test_restart_restores_active_t0_tuple_as_conservative_hold_down(tmp_path: Path) -> None:
    path = tmp_path / "link-state-session"
    anchor = MemoryRevisionAnchor()
    original = receiving_link(MemoryRadio(), path, revision_anchor=anchor, bootstrap=True)
    authorize_schc(original)
    active = original.create_fragment_sender(canonical_schc_packet(b"active"), REMOTE.pubkey)
    active.start()

    now = [0.0]
    restarted = receiving_link(
        MemoryRadio(),
        path,
        revision_anchor=anchor,
        bootstrap=False,
        receipt_clock=MonotonicClock(lambda: now[0]),
    )
    authorize_schc(restarted)
    blocked = restarted.create_fragment_sender(canonical_schc_packet(b"new"), REMOTE.pubkey)
    with pytest.raises(FragmentError, match="terminal hold-down"):
        blocked.start()

    deadline = max(
        tombstone.expires_at for tombstone in restarted._schc_session_manager._tombstones.values()
    )
    now[0] = deadline + 1.0
    recovered = restarted.create_fragment_sender(canonical_schc_packet(b"safe"), REMOTE.pubkey)
    assert recovered.start()


def test_restored_tombstones_count_against_live_session_capacity(tmp_path: Path) -> None:
    path = tmp_path / "link-state-session-capacity"
    anchor = MemoryRevisionAnchor()
    original = receiving_link(MemoryRadio(), path, revision_anchor=anchor, bootstrap=True)
    authorize_schc(original)
    original.create_fragment_sender(canonical_schc_packet(b"active"), REMOTE.pubkey).start()

    restarted = receiving_link(MemoryRadio(), path, revision_anchor=anchor, bootstrap=False)
    restarted._schc_session_manager._max_records = 1
    authorize_schc(restarted)
    authorize_schc(restarted, REPLACEMENT.pubkey)
    other_peer = restarted.create_fragment_sender(
        canonical_schc_packet(b"other-rule"),
        REPLACEMENT.pubkey,
    )

    with pytest.raises(FragmentError, match="registry is full"):
        other_peer.start()
    assert len(restarted._schc_session_manager.export_persistence_state()) == 1


def test_corrupt_restarted_t0_tombstone_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "link-state-session-corrupt"
    anchor = MemoryRevisionAnchor()
    original = receiving_link(MemoryRadio(), path, revision_anchor=anchor, bootstrap=True)
    authorize_schc(original)
    original.create_fragment_sender(canonical_schc_packet(b"active"), REMOTE.pubkey).start()
    current_path = Path(f"{path}.{original._persistence.revision % 2}")
    state, _ = original._persistence._read_signed_persistence_record(
        str(current_path), b"state"
    )
    state["revision"] = original._persistence.revision + 1
    sessions = state["schc_sessions"]
    assert type(sessions) is list and sessions
    sessions[0]["high_water"] = 0xFF_FFFF
    original._persistence._write_signed_persistence_record(
        f"{path}.{state['revision'] % 2}", state, b"state"
    )

    with pytest.raises(RuntimeError, match="invalid persisted SCHC session"):
        receiving_link(MemoryRadio(), path, revision_anchor=anchor, bootstrap=False)


def test_authenticated_reassembly_restores_as_hold_down_across_two_reboots(
    tmp_path: Path,
) -> None:
    path = tmp_path / "link-state-reassembly"
    anchor = MemoryRevisionAnchor()
    local_radio = MemoryRadio()
    remote_radio = MemoryRadio()
    original = receiving_link(
        local_radio,
        path,
        revision_anchor=anchor,
        bootstrap=True,
    )
    remote = sending_link(REMOTE, remote_radio)
    authorize_schc(original)
    authorize_schc(remote, LOCAL.pubkey)
    sender = remote.create_fragment_sender(
        canonical_schc_packet(bytes(400)),
        LOCAL.pubkey,
    )
    first_wire = sender.start()[0]
    assert asyncio.run(
        remote.send(first_wire, iid_to_eui64(LOCAL.iid), AddrMode.EXTENDED, Priority.BULK)
    )
    local_radio.queue(remote_radio.tx_history[-1])
    received = asyncio.run(original.receive(100))
    assert isinstance(received, RxFrame)
    result, decoded = original.accept_authenticated_schc_fragment(received)
    assert result.reassembled is None
    assert decoded is None

    restarted = receiving_link(
        MemoryRadio(),
        path,
        revision_anchor=anchor,
        bootstrap=False,
    )
    rows = restarted._schc_reassembly_manager.export_persistence_state()
    assert len(rows) == 1
    assert rows[0]["status"] == "restarted"
    restarted._save_persisted_state()

    second_restart = receiving_link(
        MemoryRadio(),
        path,
        revision_anchor=anchor,
        bootstrap=False,
    )
    second_rows = second_restart._schc_reassembly_manager.export_persistence_state()
    assert len(second_rows) == 1
    assert second_rows[0]["status"] == "restarted"


def test_malformed_first_fragment_rejection_survives_reboot(tmp_path: Path) -> None:
    path = tmp_path / "link-state-malformed-rejection"
    anchor = MemoryRevisionAnchor()
    local_radio = MemoryRadio()
    remote_radio = MemoryRadio()
    original = receiving_link(local_radio, path, revision_anchor=anchor, bootstrap=True)
    remote = sending_link(REMOTE, remote_radio)
    authorize_schc(original)
    remote._epoch = 0
    remote._seqnum = 0
    payload = b"\x79"
    destination = iid_to_eui64(LOCAL.iid)
    signer_eui64 = iid_to_eui64(REMOTE.iid)
    frame_length = 4 + len(destination) + len(signer_eui64) + len(payload) + 48
    llsec = int(AddrMode.EXTENDED) | (1 << 5) | (1 << 7)
    signable = remote._build_signable_data(
        0,
        0,
        destination,
        payload,
        frame_length,
        llsec,
        signer_eui64,
    )
    wire = LichenFrame(
        epoch=0,
        seqnum=0,
        dst_addr=destination,
        payload=payload,
        mic=sign(REMOTE.privkey, REMOTE.pubkey, signable),
        addr_mode=AddrMode.EXTENDED,
        signature_present=True,
        signer_eui64=signer_eui64,
    ).to_bytes()
    local_radio.queue(wire)
    received = asyncio.run(original.receive(100))
    assert isinstance(received, RxFrame)
    result, _ = original.accept_authenticated_schc_fragment(received)
    assert result.aborted and result.response is not None

    restarted_radio = MemoryRadio()
    restarted = receiving_link(
        restarted_radio,
        path,
        revision_anchor=anchor,
        bootstrap=False,
    )
    authorize_schc(restarted)
    rows = restarted._schc_reassembly_manager.export_persistence_state()
    assert len(rows) == 1 and rows[0]["status"] == "rejected"
    repeated_signable = remote._build_signable_data(
        0,
        1,
        destination,
        payload,
        frame_length,
        llsec,
        signer_eui64,
    )
    repeated_wire = LichenFrame(
        epoch=0,
        seqnum=1,
        dst_addr=destination,
        payload=payload,
        mic=sign(REMOTE.privkey, REMOTE.pubkey, repeated_signable),
        addr_mode=AddrMode.EXTENDED,
        signature_present=True,
        signer_eui64=signer_eui64,
    ).to_bytes()
    restarted_radio.queue(repeated_wire)
    repeated = asyncio.run(restarted.receive(100))
    assert isinstance(repeated, RxFrame)
    repeated_result, _ = restarted.accept_authenticated_schc_fragment(repeated)
    assert repeated_result.response is None
    assert restarted._schc_reassembly_manager.export_persistence_state()[0]["high_water"] == 1

    second_radio = MemoryRadio()
    second_restart = receiving_link(
        second_radio,
        path,
        revision_anchor=anchor,
        bootstrap=False,
    )
    authorize_schc(second_restart)
    round_trip_rows = second_restart._schc_reassembly_manager.export_persistence_state()
    assert len(round_trip_rows) == 1
    assert round_trip_rows[0]["status"] == "rejected"
    assert round_trip_rows[0]["high_water"] == 1

    final_signable = remote._build_signable_data(
        0,
        2,
        destination,
        payload,
        frame_length,
        llsec,
        signer_eui64,
    )
    final_wire = LichenFrame(
        epoch=0,
        seqnum=2,
        dst_addr=destination,
        payload=payload,
        mic=sign(REMOTE.privkey, REMOTE.pubkey, final_signable),
        addr_mode=AddrMode.EXTENDED,
        signature_present=True,
        signer_eui64=signer_eui64,
    ).to_bytes()
    second_radio.queue(final_wire)
    after_second_reboot = asyncio.run(second_restart.receive(100))
    assert isinstance(after_second_reboot, RxFrame)
    silent_result, _ = second_restart.accept_authenticated_schc_fragment(after_second_reboot)
    assert silent_result.response is None
    assert second_restart._schc_reassembly_manager.export_persistence_state()[0]["high_water"] == 2


@pytest.mark.asyncio
async def test_stale_writer_cannot_replace_cas_winner(tmp_path: Path) -> None:
    path = tmp_path / "fork-state"
    anchor = MemoryRevisionAnchor()
    winner_radio = MemoryRadio()
    winner = receiving_link(winner_radio, path, revision_anchor=anchor, bootstrap=True)
    stale = receiving_link(MemoryRadio(), path, revision_anchor=anchor, bootstrap=False)
    remote_radio = MemoryRadio()
    remote = sending_link(REMOTE, remote_radio)
    remote._epoch = 0
    remote._seqnum = 9
    assert await remote.send(b"winner-floor")
    wire = remote_radio.tx_history[-1]
    winner_radio.queue(wire)
    assert isinstance(await winner.receive(100), RxFrame)
    with pytest.raises(RuntimeError, match="permanently disabled"):
        await stale.send(b"fork")
    restarted_radio = MemoryRadio()
    restarted = receiving_link(restarted_radio, path, revision_anchor=anchor, bootstrap=False)
    restarted_radio.queue(wire)
    assert await restarted.receive(100) == ReceiveError.REPLAY


def test_persistence_does_not_follow_predictable_temp_symlink(tmp_path: Path) -> None:
    path = tmp_path / "safe-state"
    target = tmp_path / "target"
    target.write_bytes(b"untouched")
    os.symlink(target, Path(f"{path}.1.tmp"))
    receiving_link(MemoryRadio(), path)
    assert target.read_bytes() == b"untouched"


def test_permissive_persistence_directory_is_rejected(tmp_path: Path) -> None:
    directory = tmp_path / "shared"
    directory.mkdir(mode=0o777)
    directory.chmod(0o777)
    try:
        with pytest.raises(PermissionError, match="private"):
            receiving_link(MemoryRadio(), directory / "state")
    finally:
        directory.chmod(0o700)


@pytest.mark.asyncio
async def test_receipt_clock_regression_revokes_all_receipts() -> None:
    values = iter((10.0, 9.0))
    clock = MonotonicClock(lambda: next(values))
    radio = MemoryRadio()
    peer = PeerIdentity.from_pubkey(REMOTE.pubkey)
    link = LinkLayer(
        radio=radio,  # type: ignore[arg-type]
        identity=LOCAL,
        peer_lookup=lambda _hint: peer,
        peer_lookup_all=lambda: [peer],
        receipt_clock=clock,
    )
    remote_radio = MemoryRadio()
    remote = sending_link(REMOTE, remote_radio)
    remote._epoch = 0
    assert await remote.send(b"clocked")
    radio.queue(remote_radio.tx_history[-1])
    received = await link.receive(100)
    assert isinstance(received, RxFrame)
    with pytest.raises(LinkSecurityClockError, match="regressed"):
        link.consume_verified_receipt(received, purpose="schc-ack")
    assert not link._verified_receipts
    radio.queue(remote_radio.tx_history[-1])
    with pytest.raises(LinkSecurityClockError, match="disabled"):
        await link.receive(100)


def test_failed_rekey_preflight_preserves_replay_floor(tmp_path: Path) -> None:
    link = receiving_link(MemoryRadio(), tmp_path / "rekey-preflight")
    peer = PeerIdentity.from_pubkey(REMOTE.pubkey)
    link._pinned_keys[peer.iid] = REMOTE.pubkey
    link._key_generations[REMOTE.pubkey] = object()
    assert link.replay_protector._check_and_update_owned(
        REMOTE.pubkey, 1, 10, link._replay_owner_token
    )
    link._schc_session_manager._generations[REMOTE.pubkey] = 0xFF_FFFF
    with link._security_lock, pytest.raises(FragmentError, match="generation exhausted"):
        link._rotate_remote_unlocked(REMOTE.pubkey, REPLACEMENT.pubkey)
    assert link.replay_protector.highest(REMOTE.pubkey) == (1 << 16) | 10
    assert link._pinned_keys[peer.iid] == REMOTE.pubkey


@pytest.mark.asyncio
async def test_peer_callback_identity_is_snapshotted_once() -> None:
    class StatefulPeer:
        reads = 0

        @property
        def pubkey(self) -> bytes:
            self.reads += 1
            return REMOTE.pubkey if self.reads == 1 else REPLACEMENT.pubkey

    candidate = StatefulPeer()
    radio = MemoryRadio()
    link = LinkLayer(
        radio=radio,  # type: ignore[arg-type]
        identity=LOCAL,
        peer_lookup=lambda _hint: None,
        peer_lookup_all=lambda: [candidate],  # type: ignore[list-item]
    )
    remote_radio = MemoryRadio()
    remote = sending_link(REMOTE, remote_radio)
    remote._epoch = 0
    assert await remote.send(b"snapshot")
    radio.queue(remote_radio.tx_history[-1])
    received = await link.receive(100)
    assert isinstance(received, RxFrame)
    assert candidate.reads == 1
    assert received.sender_pubkey == REMOTE.pubkey
    assert link.replay_protector.highest(REMOTE.pubkey) == 0
    assert link.replay_protector.highest(REPLACEMENT.pubkey) == -1


def test_persistence_failure_revokes_cached_policy_capabilities(tmp_path: Path) -> None:
    link = receiving_link(MemoryRadio(), tmp_path / "revoke")
    authorize_schc(link)
    context = link._schc_peer_contexts[REMOTE.pubkey]
    generation = link._key_generations[REMOTE.pubkey]
    link._persistence._persistence_failed = True
    link.on_persistence_failure()
    with pytest.raises(RuntimeError, match="disabled"):
        link._validated_authenticated_peer_schc_context(context)
    assert not link.accepts_time_generation(REMOTE.pubkey, generation)


def test_async_revision_anchor_is_rejected_before_use(tmp_path: Path) -> None:
    class AsyncAnchor:
        async def read(self, _local_pubkey: bytes) -> int | None:
            return None

        async def advance(
            self, _local_pubkey: bytes, _expected: int | None, _revision: int
        ) -> None:
            return None

    with pytest.raises(TypeError, match="synchronous"):
        LinkLayer(
            radio=MemoryRadio(),  # type: ignore[arg-type]
            identity=LOCAL,
            peer_lookup=lambda _hint: None,
            persist_path=str(tmp_path / "async-anchor"),
            persistence_revision_anchor=AsyncAnchor(),  # type: ignore[arg-type]
            allow_persistence_bootstrap=True,
        )


@pytest.mark.asyncio
async def test_revision_anchor_cross_thread_reentry_fails_without_deadlock(
    tmp_path: Path,
) -> None:
    class ReentrantAnchor(MemoryRevisionAnchor):
        link: LinkLayer | None = None
        active = False
        child_alive = False

        def advance(self, local_pubkey: bytes, expected: int | None, revision: int) -> None:
            super().advance(local_pubkey, expected, revision)
            if not self.active or self.link is None:
                return

            def reenter() -> None:
                assert self.link is not None
                with pytest.raises(RuntimeError, match="persistence (callback|transition)"):
                    self.link.get_sequence()

            child = threading.Thread(target=reenter)
            child.start()
            child.join(0.5)
            self.child_alive = child.is_alive()

    anchor = ReentrantAnchor()
    link = receiving_link(
        MemoryRadio(),
        tmp_path / "reentrant-anchor",
        revision_anchor=anchor,
        bootstrap=True,
    )
    anchor.link = link
    anchor.active = True
    with pytest.raises(RuntimeError, match="permanently disabled"):
        await link.send(b"ambiguous-anchor")
    assert not anchor.child_alive
