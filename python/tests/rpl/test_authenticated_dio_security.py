# SPDX-License-Identifier: GPL-3.0-or-later
"""Ownership, mutation, and bounded-lifetime tests for sealed DIO evidence."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from ipaddress import IPv6Address

import pytest

from lichen.announce.messages import AnnounceMessage
from lichen.crypto.identity import Identity, PeerIdentity
from lichen.crypto.schnorr48 import sign
from lichen.ipv6.addr import iid_to_eui64
from lichen.ipv6.icmpv6 import Icmpv6Message
from lichen.ipv6.packet import IPv6Header, NextHeader
from lichen.l2_payload import wrap_routing_payload, wrap_schc_payload
from lichen.link.frame import LINK_SIGNATURE_DOMAIN, LichenFrame
from lichen.link.link_layer import (
    MAX_AUTHENTICATED_DIO_ISSUANCES_PER_PEER,
    LinkLayer,
    ReceiveError,
    RxFrame,
)
from lichen.rpl.authenticated_dio import AuthenticatedDio, DetachedAuthenticatedDio
from lichen.rpl.dodag import DodagState
from lichen.rpl.messages import DIO, RPL_ICMPV6_TYPE, RplCode, RplOption
from lichen.schc.context import AuthenticatedPeerSchcContext
from lichen.schc.headers import encode_rule255
from lichen.timing.time_sync import MonotonicClock

LOCAL = Identity.from_seed(bytes(range(32)))
REMOTE = Identity.from_seed(bytes(range(32, 64)))
OTHER_REMOTE = Identity.from_seed(bytes([91]) * 32)
DODAG_ID = IPv6Address("fe80::1")
DIO_MULTICAST = IPv6Address("ff02::1a")


class Clock:
    def __init__(self) -> None:
        self.capability = MonotonicClock(self)

    def __call__(self) -> float:
        return 100.0


class QueueRadio:
    def __init__(self) -> None:
        self.frames: list[tuple[bytes, int, int]] = []

    async def receive(self, timeout_ms: int) -> tuple[bytes, int, int] | None:
        del timeout_ms
        return self.frames.pop(0) if self.frames else None

    async def transmit(self, payload: bytes) -> bool:
        del payload
        return True

    async def cad(self, timeout_ms: int) -> bool:
        del timeout_ms
        return False


def dio_payload(
    rule_version: int = 3,
    *,
    rank: int = 512,
    remote: Identity = REMOTE,
    destination: IPv6Address = DIO_MULTICAST,
    hop_limit: int = 255,
    source_identity: Identity | None = None,
) -> bytes:
    dio = DIO(
        0,
        1,
        rank,
        1,
        DODAG_ID,
        mode_of_operation=1,
        options=[
            RplOption(0x13, bytes([rule_version])),
            RplOption(0x15, bytes.fromhex("6553f1000200")),
        ],
    )
    source_owner = remote if source_identity is None else source_identity
    src = IPv6Address(IPv6Address("fe80::").packed[:8] + source_owner.iid)
    dst = destination
    icmp = Icmpv6Message(RPL_ICMPV6_TYPE, int(RplCode.DIO), dio.to_bytes()).to_bytes(src, dst)
    ipv6 = (
        IPv6Header(
            src_addr=src,
            dst_addr=dst,
            next_header=NextHeader.ICMPV6,
            payload_length=len(icmp),
            hop_limit=hop_limit,
        ).to_bytes()
        + icmp
    )
    return wrap_schc_payload(encode_rule255(ipv6))


def signed_payload_wire(counter: int, payload: bytes, remote: Identity = REMOTE) -> bytes:
    """Sign one exact arbitrary authenticated L2 payload."""
    epoch, seqnum = counter >> 16, counter & 0xFFFF
    signer_eui64 = iid_to_eui64(remote.iid)
    length = 4 + len(signer_eui64) + len(payload) + 48
    signable = (
        LINK_SIGNATURE_DOMAIN
        + bytes((length, 0xA0, epoch))
        + seqnum.to_bytes(2, "big")
        + b"\x00"
        + signer_eui64
        + payload
    )
    return LichenFrame(
        epoch=epoch,
        seqnum=seqnum,
        dst_addr=b"",
        payload=payload,
        mic=sign(remote.privkey, remote.pubkey, signable),
        signature_present=True,
        signer_eui64=signer_eui64,
    ).to_bytes()


def signed_wire(
    counter: int,
    rule_version: int = 3,
    *,
    rank: int = 512,
    remote: Identity = REMOTE,
) -> bytes:
    payload = dio_payload(rule_version, rank=rank, remote=remote)
    return signed_payload_wire(counter, payload, remote)


def make_link(radio: QueueRadio, clock: Clock) -> LinkLayer:
    peer = PeerIdentity.from_pubkey(REMOTE.pubkey)
    return LinkLayer(
        radio=radio,  # type: ignore[arg-type]
        identity=LOCAL,
        peer_lookup=lambda _hint: peer,
        peer_lookup_all=lambda: [peer],
        receipt_clock=clock.capability,
        cad_enabled=False,
    )


def issue(
    link: LinkLayer,
    radio: QueueRadio,
    counter: int,
    rule_version: int = 3,
    *,
    remote: Identity = REMOTE,
) -> AuthenticatedDio:
    radio.frames.append((signed_wire(counter, rule_version, remote=remote), -90, 4))
    received = asyncio.run(link.receive(100))
    assert isinstance(received, RxFrame)
    return link.accept_authenticated_dio(
        received,
        expected_rpl_instance_id=0,
        expected_dodag_id=DODAG_ID,
        expected_mop=1,
        expected_role="peer",
    )


def receive_dio(
    link: LinkLayer,
    radio: QueueRadio,
    counter: int,
    *,
    rank: int = 512,
) -> RxFrame:
    radio.frames.append((signed_wire(counter, rank=rank), -90, 4))
    received = asyncio.run(link.receive(100))
    assert isinstance(received, RxFrame)
    return received


def issue_peer_context(
    link: LinkLayer,
    radio: QueueRadio,
    counter: int,
    rule_version: int = 3,
) -> tuple[AuthenticatedDio, AuthenticatedPeerSchcContext]:
    authenticated = issue(link, radio, counter, rule_version)
    return link.accept_authenticated_schc_dio(authenticated)


def mutate_ipv6(value: AuthenticatedDio) -> None:
    object.__setattr__(value, "_ipv6", value.ipv6 + b"\x00")


def mutate_dio_bytes(value: AuthenticatedDio) -> None:
    object.__setattr__(value, "_dio_bytes", bytes(24))


def mutate_option_data(value: AuthenticatedDio) -> None:
    object.__setattr__(value.options[0], "data", b"\x02")


def mutate_option_span(value: AuthenticatedDio) -> None:
    object.__setattr__(value.options[0], "ipv6_span", (0, 1))


def mutate_snapshot_signer(value: AuthenticatedDio) -> None:
    object.__setattr__(value._snapshot, "_authenticated_sender_pubkey", LOCAL.pubkey)


def mutate_snapshot_replay(value: AuthenticatedDio) -> None:
    object.__setattr__(value._snapshot, "_authenticated_seqnum", value.seqnum + 1)


def mutate_snapshot_generation(value: AuthenticatedDio) -> None:
    object.__setattr__(value._snapshot, "_authenticated_key_generation", object())


def mutate_snapshot_receipt_time(value: AuthenticatedDio) -> None:
    object.__setattr__(value._snapshot, "_authenticated_received_monotonic", 101.0)


@pytest.mark.parametrize(
    "mutator",
    [
        mutate_ipv6,
        mutate_dio_bytes,
        mutate_option_data,
        mutate_option_span,
        mutate_snapshot_signer,
        mutate_snapshot_replay,
        mutate_snapshot_generation,
        mutate_snapshot_receipt_time,
    ],
)
def test_post_issuance_mutation_is_rejected_by_all_link_consumers(
    mutator: Callable[[AuthenticatedDio], None],
) -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    authenticated = issue(link, radio, 0)
    assert link.accepts_authenticated_dio(authenticated)

    mutator(authenticated)

    assert not link.accepts_authenticated_dio(authenticated)
    with pytest.raises(ValueError, match="not issued unchanged"):
        link.accept_authenticated_schc_dio(authenticated)


def test_exact_forgery_and_other_link_evidence_are_rejected() -> None:
    shared_clock = Clock()
    first_radio, second_radio = QueueRadio(), QueueRadio()
    first = make_link(first_radio, shared_clock)
    second = make_link(second_radio, shared_clock)
    authenticated = issue(first, first_radio, 0)
    other = issue(second, second_radio, 0)
    assert authenticated.clock_domain_identity is other.clock_domain_identity
    assert authenticated.receiving_link_identity is not other.receiving_link_identity
    assert first.accepts_authenticated_dio(authenticated)
    assert not first.accepts_authenticated_dio(other)

    forged = object.__new__(AuthenticatedDio)
    for attribute in (
        "_snapshot",
        "_ipv6",
        "_dio_bytes",
        "_options",
        "_expected_rpl_instance_id",
        "_expected_dodag_id",
        "_expected_mop",
        "_expected_role",
    ):
        object.__setattr__(forged, attribute, getattr(authenticated, attribute))
    assert not first.accepts_authenticated_dio(forged)


def test_issuance_registry_is_bounded_and_evicts_oldest_without_touching_newest() -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    values = [
        issue(link, radio, counter)
        for counter in range(MAX_AUTHENTICATED_DIO_ISSUANCES_PER_PEER + 1)
    ]

    assert len(link._authenticated_dio_issuances) == MAX_AUTHENTICATED_DIO_ISSUANCES_PER_PEER
    assert not link.accepts_authenticated_dio(values[0])
    assert link.accepts_authenticated_dio(values[-1])


def test_one_signer_flood_cannot_evict_another_signers_live_dio() -> None:
    radio = QueueRadio()
    peers = {
        identity.iid: PeerIdentity.from_pubkey(identity.pubkey)
        for identity in (REMOTE, OTHER_REMOTE)
    }
    link = LinkLayer(
        radio=radio,  # type: ignore[arg-type]
        identity=LOCAL,
        peer_lookup=peers.get,
        peer_lookup_all=lambda: list(peers.values()),
        receipt_clock=Clock().capability,
        cad_enabled=False,
    )
    protected = issue(link, radio, 0, remote=OTHER_REMOTE)
    flooded = [
        issue(link, radio, counter, remote=REMOTE)
        for counter in range(MAX_AUTHENTICATED_DIO_ISSUANCES_PER_PEER + 1)
    ]

    assert link.accepts_authenticated_dio(protected)
    assert not link.accepts_authenticated_dio(flooded[0])
    assert link.accepts_authenticated_dio(flooded[-1])


@pytest.mark.parametrize(("older_version", "newer_version"), [(3, 3), (3, 4)])
def test_schc_policy_rejects_older_and_reused_dio_without_rollback(
    older_version: int,
    newer_version: int,
) -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    older = issue(link, radio, 0, older_version)
    newer = issue(link, radio, 1, newer_version)
    _, current = link.accept_authenticated_schc_dio(newer)

    with pytest.raises(ValueError, match="counter is not newer"):
        link.accept_authenticated_schc_dio(older)
    with pytest.raises(ValueError, match="counter is not newer"):
        link.accept_authenticated_schc_dio(newer)

    assert link._schc_peer_contexts[REMOTE.pubkey] is current
    assert current.remote_version == newer_version


def test_transactional_elevation_uses_link_owned_detached_snapshot() -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    authenticated = issue(link, radio, 0)

    detached = link.elevate_authenticated_dio(
        authenticated,
        elevate=lambda evidence: evidence,
    )

    assert type(detached) is DetachedAuthenticatedDio
    assert detached.ipv6 == authenticated.ipv6
    assert detached.sender_pubkey == REMOTE.pubkey
    assert detached.sender_iid == PeerIdentity.from_pubkey(REMOTE.pubkey).iid
    assert detached.receiving_link_identity is link.receiving_link_identity
    assert detached.key_generation is authenticated.key_generation

    mutate_ipv6(authenticated)
    with pytest.raises(ValueError, match="stale, mutated"):
        link.elevate_authenticated_dio(authenticated, elevate=lambda evidence: evidence)


def test_transactional_elevation_rejects_awaitable_callbacks() -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    authenticated = issue(link, radio, 0)

    async def asynchronous_elevation(_: DetachedAuthenticatedDio) -> None:
        return None

    with pytest.raises(TypeError, match="must be synchronous"):
        _ = link.elevate_authenticated_dio(authenticated, elevate=asynchronous_elevation)


def test_time_generation_elevation_is_current_and_synchronous() -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    authenticated = issue(link, radio, 0)
    generation = authenticated.key_generation
    committed: list[str] = []

    def commit() -> str:
        committed.append("committed")
        return "result"

    assert link.accepts_time_generation(REMOTE.pubkey, generation)
    assert (
        link.elevate_time_generation(
            REMOTE.pubkey,
            generation,
            elevate=commit,
        )
        == "result"
    )
    assert committed == ["committed"]

    async def asynchronous_elevation() -> None:
        return None

    with pytest.raises(TypeError, match="must be synchronous"):
        _ = link.elevate_time_generation(
            REMOTE.pubkey,
            generation,
            elevate=asynchronous_elevation,
        )


@pytest.mark.parametrize("lease_owner", ["authenticated-dio", "receipt", "time"])
def test_time_generation_validation_does_not_wait_behind_external_lock_callback(
    lease_owner: str,
) -> None:
    """A tracker-held validation must not wait on a callback needing its lock."""
    radio = QueueRadio()
    link = make_link(radio, Clock())
    authenticated = issue(link, radio, 0)
    generation = authenticated.key_generation
    receipt = receive_dio(link, radio, 1) if lease_owner == "receipt" else None
    external_tracker_lock = threading.Lock()
    owner_entered = threading.Event()
    owner_finished = threading.Event()
    validation_finished = threading.Event()
    failures: list[BaseException] = []

    def blocking_callback(*_args: object) -> None:
        owner_entered.set()
        with external_tracker_lock:
            pass

    def own_lease() -> None:
        try:
            if lease_owner == "authenticated-dio":
                link.elevate_authenticated_dio(authenticated, elevate=blocking_callback)
            elif lease_owner == "receipt":
                assert receipt is not None
                link.elevate_verified_receipt(
                    receipt,
                    purpose="dio-time",
                    elevate=blocking_callback,
                )
            else:
                link.elevate_time_generation(
                    REMOTE.pubkey,
                    generation,
                    elevate=blocking_callback,
                )
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            failures.append(exc)
        finally:
            owner_finished.set()

    def validate_generation() -> None:
        try:
            link.elevate_time_generation(
                REMOTE.pubkey,
                generation,
                elevate=lambda: None,
            )
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            failures.append(exc)
        finally:
            validation_finished.set()

    external_tracker_lock.acquire()
    owner = threading.Thread(target=own_lease)
    validator = threading.Thread(target=validate_generation)
    try:
        owner.start()
        assert owner_entered.wait(1), "lease-owning callback did not start"
        validator.start()
        assert validation_finished.wait(1), "generation validation deadlocked"
        assert not owner_finished.is_set()
    finally:
        external_tracker_lock.release()
    owner.join(1)
    validator.join(1)
    assert not owner.is_alive() and not validator.is_alive()
    assert not failures


def test_all_link_elevations_close_custom_awaitables() -> None:
    class CloseableAwaitable:
        def __init__(self) -> None:
            self.closed = False

        def __await__(self):  # type: ignore[no-untyped-def]
            if False:
                yield None
            return None

        def close(self) -> None:
            self.closed = True

    radio = QueueRadio()
    link = make_link(radio, Clock())
    authenticated = issue(link, radio, 0)
    generation = authenticated.key_generation
    dio_value = CloseableAwaitable()
    generation_value = CloseableAwaitable()
    receipt_value = CloseableAwaitable()

    with pytest.raises(TypeError, match="awaitable"):
        link.elevate_authenticated_dio(authenticated, elevate=lambda _evidence: dio_value)
    with pytest.raises(TypeError, match="awaitable"):
        link.elevate_time_generation(
            REMOTE.pubkey,
            generation,
            elevate=lambda: generation_value,
        )
    received = receive_dio(link, radio, 1)
    with pytest.raises(TypeError, match="awaitable"):
        link.elevate_verified_receipt(
            received,
            purpose="dio-time",
            elevate=lambda _snapshot: receipt_value,
        )
    assert dio_value.closed and generation_value.closed and receipt_value.closed


@pytest.mark.asyncio
async def test_all_link_elevations_cancel_tasks_and_futures() -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    radio.frames.append((signed_wire(10), -90, 4))
    received = await link.receive(100)
    assert isinstance(received, RxFrame)
    authenticated = link.accept_authenticated_dio(
        received,
        expected_rpl_instance_id=0,
        expected_dodag_id=DODAG_ID,
        expected_mop=1,
        expected_role="peer",
    )
    generation = authenticated.key_generation
    mutated: list[str] = []
    tasks: list[asyncio.Task[None]] = []

    async def later(name: str) -> None:
        await asyncio.sleep(0)
        mutated.append(name)

    def task(name: str) -> asyncio.Task[None]:
        result = asyncio.create_task(later(name))
        tasks.append(result)
        return result

    with pytest.raises(TypeError, match="awaitable"):
        link.elevate_authenticated_dio(
            authenticated,
            elevate=lambda _evidence: task("dio"),
        )
    with pytest.raises(TypeError, match="awaitable"):
        link.elevate_time_generation(
            REMOTE.pubkey,
            generation,
            elevate=lambda: task("generation"),
        )
    radio.frames.append((signed_wire(11), -90, 4))
    receipt = await link.receive(100)
    assert isinstance(receipt, RxFrame)
    with pytest.raises(TypeError, match="awaitable"):
        link.elevate_verified_receipt(
            receipt,
            purpose="dio-time",
            elevate=lambda _snapshot: task("receipt"),
        )
    await asyncio.sleep(0)
    assert tasks and all(value.cancelled() for value in tasks)
    assert not mutated

    loop = asyncio.get_running_loop()
    dio_future: asyncio.Future[None] = loop.create_future()
    generation_future: asyncio.Future[None] = loop.create_future()
    receipt_future: asyncio.Future[None] = loop.create_future()
    with pytest.raises(TypeError, match="awaitable"):
        link.elevate_authenticated_dio(
            authenticated,
            elevate=lambda _evidence: dio_future,
        )
    with pytest.raises(TypeError, match="awaitable"):
        link.elevate_time_generation(
            REMOTE.pubkey,
            generation,
            elevate=lambda: generation_future,
        )
    radio.frames.append((signed_wire(12), -90, 4))
    second_receipt = await link.receive(100)
    assert isinstance(second_receipt, RxFrame)
    with pytest.raises(TypeError, match="awaitable"):
        link.elevate_verified_receipt(
            second_receipt,
            purpose="dio-time",
            elevate=lambda _snapshot: receipt_future,
        )
    assert dio_future.cancelled()
    assert generation_future.cancelled()
    assert receipt_future.cancelled()


def test_dodag_identity_survives_forced_post_seal_rx_facade_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    received = receive_dio(link, radio, 0)
    original = LinkLayer.accept_authenticated_dio

    def accept_then_mutate(
        receiving_link: LinkLayer,
        frame: RxFrame,
        **kwargs: object,
    ) -> AuthenticatedDio:
        result = original(receiving_link, frame, **kwargs)  # type: ignore[arg-type]
        # Force the attacker-controlled interleave at the old check/use gap:
        # admission has sealed the DIO, but DODAG has not derived its neighbor.
        object.__setattr__(frame, "sender", PeerIdentity.from_pubkey(LOCAL.pubkey))
        return result

    monkeypatch.setattr(LinkLayer, "accept_authenticated_dio", accept_then_mutate)
    state = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=1)
    state.process_authenticated_dio(link, received, expected_role="peer")

    remote_neighbor = IPv6Address(
        b"\xfe\x80" + bytes(6) + PeerIdentity.from_pubkey(REMOTE.pubkey).iid
    )
    local_neighbor = IPv6Address(
        b"\xfe\x80" + bytes(6) + PeerIdentity.from_pubkey(LOCAL.pubkey).iid
    )
    assert state.preferred_parent == remote_neighbor
    assert local_neighbor not in state.parents


def test_peer_context_version_and_signer_flips_cannot_enable_compression() -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    authenticated, peer = issue_peer_context(link, radio, 0, rule_version=2)

    with pytest.raises(AttributeError):
        object.__setattr__(peer, "remote_version", 3)
    with pytest.raises(AttributeError):
        object.__setattr__(peer, "signer_identity", LOCAL.pubkey)

    assert peer.remote_version == 2
    assert peer.signer_identity == REMOTE.pubkey
    assert not peer.allows_dodag_join
    encoded = peer.compress_packet(authenticated.ipv6, single_frame_limit=512)
    assert encoded == b"\xff" + authenticated.ipv6
    assert peer.decompress_packet(encoded, single_frame_limit=512) == authenticated.ipv6


def test_exact_peer_context_forgery_has_no_owner_policy() -> None:
    forged = object.__new__(AuthenticatedPeerSchcContext)
    object.__setattr__(forged, "_remote_version", 3)
    object.__setattr__(forged, "_signer_identity", REMOTE.pubkey)

    with pytest.raises(ValueError, match="not a live LinkLayer issuance"):
        _ = forged.remote_version
    with pytest.raises(ValueError, match="not a live LinkLayer issuance"):
        forged.compress_packet(bytes(40), single_frame_limit=200)


def test_replaced_peer_context_is_stale_and_new_context_remains_valid() -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    _, stale = issue_peer_context(link, radio, 0, rule_version=2)
    authenticated, current = issue_peer_context(link, radio, 1, rule_version=3)

    with pytest.raises(ValueError, match="not an exact LinkLayer issuance"):
        _ = stale.remote_version
    assert current.remote_version == 3
    assert current.signer_identity == REMOTE.pubkey
    assert current.allows_dodag_join
    compressed = current.compress_packet(authenticated.ipv6, single_frame_limit=512)
    assert current.decompress_packet(compressed, single_frame_limit=512) == authenticated.ipv6


def test_rejected_authenticated_dio_does_not_commit_peer_policy() -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    received = receive_dio(link, radio, 0)
    state = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=2)

    state.process_authenticated_dio(link, received, expected_role="peer")

    assert state.version == 2
    assert state.parents == {}
    assert state.preferred_parent is None
    assert REMOTE.pubkey not in link._schc_peer_contexts
    assert link._schc_session_manager._generations.get(REMOTE.pubkey, 0) == 0


@pytest.mark.parametrize("link_etx", [float("nan"), float("inf"), -1.0])
def test_invalid_authenticated_dio_etx_has_no_policy_or_route_mutation(
    link_etx: float,
) -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    received = receive_dio(link, radio, 0)
    state = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=1)

    with pytest.raises(ValueError, match="link_etx"):
        state.process_authenticated_dio(
            link,
            received,
            expected_role="peer",
            link_etx=link_etx,
        )

    assert state.parents == {}
    assert state.preferred_parent is None
    assert REMOTE.pubkey not in link._schc_peer_contexts


def test_authenticated_root_requires_dodagid_key_binding_before_policy_commit() -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    received = receive_dio(link, radio, 0, rank=256)
    state = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=1)

    with pytest.raises(ValueError, match="DODAGID does not match signer key"):
        state.process_authenticated_dio(link, received, expected_role="root")

    assert state.parents == {}
    assert REMOTE.pubkey not in link._schc_peer_contexts


@pytest.mark.parametrize(
    "payload,error",
    [
        (
            (lambda payload: payload[:1] + b"\x03" + payload[2:])(dio_payload()),
            "Rule 255",
        ),
        (dio_payload(destination=IPv6Address("fe80::1")), "ff02::1a"),
        (dio_payload(hop_limit=64), "Hop Limit"),
        (dio_payload(source_identity=OTHER_REMOTE), "source IID"),
    ],
)
def test_authenticated_dio_rejects_noncanonical_envelope(
    payload: bytes,
    error: str,
) -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    radio.frames.append((signed_payload_wire(0, payload), -90, 4))
    received = asyncio.run(link.receive(100))
    assert isinstance(received, RxFrame)

    with pytest.raises(ValueError, match=error):
        link.accept_authenticated_dio(
            received,
            expected_rpl_instance_id=0,
            expected_dodag_id=DODAG_ID,
            expected_mop=1,
            expected_role="peer",
        )

    assert not link._authenticated_dio_issuances


def test_unknown_zero_hop_announce_bootstraps_only_after_both_signatures() -> None:
    unsigned = AnnounceMessage(
        originator_iid=REMOTE.iid,
        pubkey=REMOTE.pubkey,
        seq_num=7,
    )
    announce = AnnounceMessage(
        originator_iid=unsigned.originator_iid,
        pubkey=unsigned.pubkey,
        seq_num=unsigned.seq_num,
        signature=sign(REMOTE.privkey, REMOTE.pubkey, unsigned.signed_data()),
    )
    payload = wrap_routing_payload(announce.to_bytes())
    radio = QueueRadio()
    link = LinkLayer(
        radio=radio,  # type: ignore[arg-type]
        identity=LOCAL,
        peer_lookup=lambda _iid: None,
        peer_lookup_all=lambda: [],
        receipt_clock=Clock().capability,
        cad_enabled=False,
    )
    radio.frames.append((signed_payload_wire(0, payload), -90, 4))

    received = asyncio.run(link.receive(100))

    assert isinstance(received, RxFrame)
    assert received.sender_pubkey == REMOTE.pubkey
    assert link._pinned_keys[REMOTE.iid] == REMOTE.pubkey


@pytest.mark.parametrize("failure", ["inner", "outer", "relayed"])
def test_unknown_announce_bootstrap_fails_closed(failure: str) -> None:
    unsigned = AnnounceMessage(
        originator_iid=REMOTE.iid,
        pubkey=REMOTE.pubkey,
        seq_num=8,
        hop_count=1 if failure == "relayed" else 0,
    )
    signature = sign(REMOTE.privkey, REMOTE.pubkey, unsigned.signed_data())
    if failure == "inner":
        signature = bytes((signature[0] ^ 1,)) + signature[1:]
    announce = AnnounceMessage(
        originator_iid=unsigned.originator_iid,
        pubkey=unsigned.pubkey,
        seq_num=unsigned.seq_num,
        hop_count=unsigned.hop_count,
        signature=signature,
    )
    wire = signed_payload_wire(0, wrap_routing_payload(announce.to_bytes()))
    if failure == "outer":
        wire = wire[:-1] + bytes((wire[-1] ^ 1,))
    radio = QueueRadio()
    link = LinkLayer(
        radio=radio,  # type: ignore[arg-type]
        identity=LOCAL,
        peer_lookup=lambda _iid: None,
        peer_lookup_all=lambda: [],
        receipt_clock=Clock().capability,
        cad_enabled=False,
    )
    radio.frames.append((wire, -90, 4))

    assert asyncio.run(link.receive(100)) is ReceiveError.BAD_SIGNATURE
    assert REMOTE.iid not in link._pinned_keys
    assert link.replay_protector.highest(REMOTE.pubkey) == -1


def test_receipt_clock_callback_failure_revokes_live_dio_and_is_terminal() -> None:
    failed = [False]

    def callback() -> float:
        if failed[0]:
            raise RuntimeError("injected receipt clock failure")
        return 100.0

    radio = QueueRadio()
    capability = MonotonicClock(callback)
    peer = PeerIdentity.from_pubkey(REMOTE.pubkey)
    link = LinkLayer(
        radio=radio,  # type: ignore[arg-type]
        identity=LOCAL,
        peer_lookup=lambda _hint: peer,
        peer_lookup_all=lambda: [peer],
        receipt_clock=capability,
        cad_enabled=False,
    )
    authenticated = issue(link, radio, 0)
    assert link.accepts_authenticated_dio(authenticated)
    failed[0] = True

    assert not link.accepts_authenticated_dio(authenticated)
    assert not link._verified_receipts
    assert not link._authenticated_dio_issuances
    with pytest.raises(RuntimeError, match="disabled"):
        link._receipt_now()


def test_rejected_dio_keeps_existing_policy_and_fragment_state() -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    _, current = issue_peer_context(link, radio, 0, rule_version=2)
    generation_before = link._schc_session_manager._generations.get(REMOTE.pubkey, 0)
    received = receive_dio(link, radio, 1)
    state = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=2)

    state.process_authenticated_dio(link, received, expected_role="peer")

    assert link._schc_peer_contexts[REMOTE.pubkey] is current
    assert link._schc_session_manager._generations.get(REMOTE.pubkey, 0) == generation_before
    assert not state.parents


def test_policy_transaction_waits_for_foreign_generation_lease() -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    authenticated = issue(link, radio, 0)
    lease_entered = threading.Event()
    release_lease = threading.Event()
    transaction_started = threading.Event()
    prepare_started = threading.Event()
    failures: list[BaseException] = []

    def hold_generation(_evidence: DetachedAuthenticatedDio) -> None:
        lease_entered.set()
        if not release_lease.wait(2):
            raise AssertionError("test did not release generation lease")

    def own_lease() -> None:
        try:
            link.elevate_authenticated_dio(authenticated, elevate=hold_generation)
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            failures.append(exc)

    def transact() -> None:
        transaction_started.set()
        try:
            result = link.transact_authenticated_schc_dio(
                authenticated,
                prepare=lambda _detached: (
                    prepare_started.set(),
                    lambda peer: peer.remote_version,
                )[1],
            )
            assert result is not None
            peer, version = result
            assert version == peer.remote_version == 3
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            failures.append(exc)

    owner = threading.Thread(target=own_lease)
    transaction = threading.Thread(target=transact)
    owner.start()
    assert lease_entered.wait(1), "generation lease callback did not start"
    transaction.start()
    assert transaction_started.wait(1)
    assert not prepare_started.wait(0.05), "transaction crossed a live generation lease"
    release_lease.set()
    owner.join(2)
    transaction.join(2)

    assert not owner.is_alive()
    assert not transaction.is_alive()
    assert not failures
    assert prepare_started.is_set()


def test_dodag_transaction_waits_before_taking_consumer_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    authenticated = issue(link, radio, 0)
    state = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=1)
    lease_entered = threading.Event()
    transaction_waiting = threading.Event()
    release_callback = threading.Event()
    callback_acquired_dodag = threading.Event()
    failures: list[BaseException] = []
    original_wait = link._wait_for_foreign_generation_leases_unlocked

    def observed_wait(signer: bytes) -> None:
        transaction_waiting.set()
        original_wait(signer)

    monkeypatch.setattr(link, "_wait_for_foreign_generation_leases_unlocked", observed_wait)

    def lease_callback(_evidence: DetachedAuthenticatedDio) -> None:
        lease_entered.set()
        if not release_callback.wait(2):
            raise AssertionError("test did not release lease callback")
        with state._lock:
            callback_acquired_dodag.set()

    def own_lease() -> None:
        try:
            link.elevate_authenticated_dio(authenticated, elevate=lease_callback)
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            failures.append(exc)

    def admit() -> None:
        try:
            state.process_authenticated_dio_evidence(
                link,
                authenticated,
                expected_role="peer",
            )
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            failures.append(exc)

    owner = threading.Thread(target=own_lease, daemon=True)
    transaction = threading.Thread(target=admit, daemon=True)
    owner.start()
    assert lease_entered.wait(1)
    transaction.start()
    assert transaction_waiting.wait(1)
    release_callback.set()
    owner.join(2)
    transaction.join(2)

    assert callback_acquired_dodag.is_set()
    assert not owner.is_alive()
    assert not transaction.is_alive()
    assert not failures
    assert state.preferred_parent is not None


def test_dodag_scope_change_between_link_validation_and_commit_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    radio = QueueRadio()
    link = make_link(radio, Clock())
    received = receive_dio(link, radio, 0)
    state = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=1)
    changed_dodag = IPv6Address("fe80::2")
    original_accept = link.accept_authenticated_dio

    def accept_then_change_scope(
        frame: RxFrame,
        **scope: object,
    ) -> AuthenticatedDio:
        authenticated = original_accept(frame, **scope)  # type: ignore[arg-type]
        with state._lock:
            state.dodag_id = changed_dodag
        return authenticated

    monkeypatch.setattr(link, "accept_authenticated_dio", accept_then_change_scope)

    with pytest.raises(ValueError, match="scope changed"):
        state.process_authenticated_dio(link, received, expected_role="peer")

    assert state.dodag_id == changed_dodag
    assert not state.parents
    assert REMOTE.pubkey not in link._schc_peer_contexts
