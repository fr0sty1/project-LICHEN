# SPDX-License-Identifier: GPL-3.0-or-later
"""Production-path trust, freshness, rollback, and concurrency tests."""

from __future__ import annotations

import asyncio
import hashlib
import threading
from collections.abc import Callable, Mapping
from ipaddress import IPv6Address
from typing import cast

import pytest

from lichen.crypto.identity import Identity, PeerIdentity
from lichen.crypto.schnorr48 import sign
from lichen.ipv6.addr import iid_to_eui64
from lichen.ipv6.icmpv6 import Icmpv6Message
from lichen.ipv6.packet import IPv6Header, NextHeader
from lichen.l2_payload import l2_payload_body, wrap_schc_payload
from lichen.link.frame import LINK_SIGNATURE_DOMAIN, LichenFrame
from lichen.link.link_layer import (
    LinkLayer,
    LinkSecurityClockError,
    ReceiveError,
    RxFrame,
    encode_rekey_request,
)
from lichen.rpl.authenticated_dio import AuthenticatedDio
from lichen.rpl.messages import DIO, RPL_ICMPV6_TYPE, RplCode, RplOption
from lichen.schc.headers import compress_packet, decompress_packet
from lichen.timing.time_sync import (
    DIO_TIME_OPTION_LEN,
    DIO_TIME_OPTION_TOTAL,
    DIO_TIME_OPTION_TYPE,
    MAX_CORRECTION_RATE_PPM,
    DioTimeOption,
    DioTimeVerifier,
    EpochFloorAuthority,
    MonotonicClock,
    ProvisionClearedState,
    ProvisionEpochStatus,
    ProvisionRecord,
    ProvisionRollbackState,
    ProvisionVerifier,
    ProvisionVirginState,
    SourceClass,
    SourcePrecedencePolicy,
    Stratum,
    StratumTracker,
    TimeAdmin,
    TimeProvider,
    TimeSample,
    effective_epoch_floor,
    evaluate_epoch_floor,
)

FLOOR = 1_700_000_000
LOCAL = Identity.from_seed(bytes(range(32)))
REMOTE = Identity.from_seed(bytes(range(32, 64)))
OTHER = Identity.from_seed(bytes(reversed(range(32))))


class Clock:
    def __init__(self, value: float = 0) -> None:
        self.value = value
        self.lock = threading.Lock()
        self.capability = MonotonicClock(self)

    def __call__(self) -> float:
        with self.lock:
            return self.value

    def set(self, value: float) -> None:
        with self.lock:
            self.value = value


class QueueRadio:
    def __init__(self) -> None:
        self.frames: list[tuple[bytes, int, int]] = []

    async def receive(self, _timeout_ms: int, channel: int = 0) -> tuple[bytes, int, int] | None:
        del channel
        return self.frames.pop(0) if self.frames else None

    async def transmit(self, _payload: bytes, channel: int = 0) -> bool:
        del channel
        return True

    def configure(self, freq_hz: int, tx_power_dbm: int) -> None:
        del freq_hz, tx_power_dbm

    async def cad(self, _timeout_ms: int, channel: int = 0) -> bool:
        del channel
        return False


def signed_wire(identity: Identity, payload: bytes, *, counter: int) -> bytes:
    epoch, seqnum = counter >> 16, counter & 0xFFFF
    signer_eui64 = iid_to_eui64(identity.iid)
    length = 4 + len(signer_eui64) + len(payload) + 48
    signable = (
        LINK_SIGNATURE_DOMAIN
        + bytes((length, 0xA0, epoch))
        + seqnum.to_bytes(2, "big")
        + b"\x00"
        + signer_eui64
        + payload
    )
    signature = sign(identity.privkey, identity.pubkey, signable)
    return LichenFrame(
        epoch=epoch,
        seqnum=seqnum,
        dst_addr=b"",
        payload=payload,
        mic=signature,
        signature_present=True,
        signer_eui64=signer_eui64,
    ).to_bytes()


def receiver(radio: QueueRadio, clock: Clock, peer: Identity = REMOTE) -> LinkLayer:
    identity = PeerIdentity.from_pubkey(peer.pubkey)
    return LinkLayer(
        radio=radio,
        identity=LOCAL,
        peer_lookup=lambda _iid: identity,
        peer_lookup_all=lambda: [identity],
        receipt_clock=clock.capability,
    )


def dio_envelope(
    option: DioTimeOption | None,
    *,
    signer: Identity = REMOTE,
    source: IPv6Address | None = None,
    duplicate: bool = False,
) -> bytes:
    options: list[RplOption] = [
        RplOption(0),
        RplOption(0xEE, b"\xaa"),
        RplOption(0x13, b"\x03"),
    ]
    if option is not None:
        options.append(RplOption(DIO_TIME_OPTION_TYPE, option.encode()[2:]))
        if duplicate:
            options.append(RplOption(DIO_TIME_OPTION_TYPE, option.encode()[2:]))
    dio = DIO(0, 1, 512, 1, IPv6Address("fe80::1"), options=options)
    src = source or IPv6Address(b"\xfe\x80" + bytes(6) + signer.iid)
    dst = IPv6Address("ff02::1a")
    icmp = Icmpv6Message(RPL_ICMPV6_TYPE, int(RplCode.DIO), dio.to_bytes()).to_bytes(src, dst)
    ipv6 = (
        IPv6Header(
            src_addr=src,
            dst_addr=dst,
            next_header=NextHeader.ICMPV6,
            payload_length=len(icmp),
            hop_limit=255,
        ).to_bytes()
        + icmp
    )
    return wrap_schc_payload(compress_packet(ipv6))


def authenticate_dio(link: LinkLayer, received: RxFrame) -> AuthenticatedDio:
    return link.accept_authenticated_dio(
        received,
        expected_rpl_instance_id=0,
        expected_dodag_id=IPv6Address("fe80::1"),
        expected_mop=1,
        expected_role="peer",
    )


def policy(
    *sources: SourceClass, peers: frozenset[bytes] = frozenset(), **kw: object
) -> SourcePrecedencePolicy:
    values: dict[str, object] = {
        "accepted_wall_clock_sources": frozenset(sources),
        "authorized_network_peers": peers,
    }
    values.update(kw)
    return SourcePrecedencePolicy(**values)  # type: ignore[arg-type]


def provider(clock: Clock, *sources: SourceClass) -> TimeProvider:
    return TimeProvider("fixture-provider", frozenset(sources), clock=clock.capability)


def tracker(
    clock: Clock,
    authority: TimeProvider | DioTimeVerifier,
    configured: SourcePrecedencePolicy,
    *,
    floor: int = FLOOR,
    admin: TimeAdmin | None = None,
) -> StratumTracker:
    return StratumTracker(
        authorities=(authority,),
        policy=configured,
        floor_authority=EpochFloorAuthority(floor),
        clock=clock.capability,
        admin=admin,
    )


def gnss(authority: TimeProvider, timestamp: int = FLOOR, **kw: object) -> TimeSample:
    values: dict[str, object] = {
        "source_class": SourceClass.GNSS,
        "source_name": "onboard-gnss",
        "unix_time": timestamp,
        "stratum": Stratum.GNSS_GPSD,
        "accuracy_seconds": 0.1,
        "source_valid": True,
        "policy_accepted": True,
        "gnss_time_valid": True,
        "gnss_position_valid": True,
        "quality": {"fix": "3d", "satellites": [1, 2], "nested": {"hdop": 0.8}},
    }
    values.update(kw)
    return authority.sample(**values)  # type: ignore[arg-type]


def test_option_wire_and_no_sync_canonical_semantics() -> None:
    encoded = DioTimeOption(Stratum.NTS, FLOOR).encode()
    assert encoded.hex() == "150603006553f100"
    assert len(encoded) == DIO_TIME_OPTION_TOTAL
    assert encoded[:2] == bytes((DIO_TIME_OPTION_TYPE, DIO_TIME_OPTION_LEN))
    assert DioTimeOption.decode(encoded) == DioTimeOption(Stratum.NTS, FLOOR)
    assert DioTimeOption(Stratum.NO_SYNC, 0).encode().hex() == "1506000000000000"
    with pytest.raises(ValueError, match="NO_SYNC"):
        DioTimeOption(Stratum.NO_SYNC, 1)


def test_provider_requires_defined_quality_and_protocol_binding() -> None:
    clock = Clock(10)
    authority = provider(clock, SourceClass.NETWORK, SourceClass.MANUAL)
    with pytest.raises(ValueError, match="non-NO_SYNC"):
        authority.sample(
            source_class=SourceClass.MANUAL,
            source_name="console",
            unix_time=FLOOR,
            stratum=Stratum.NO_SYNC,
            accuracy_seconds=1,
            source_valid=True,
            policy_accepted=True,
        )
    with pytest.raises(ValueError, match="does not match stratum"):
        authority.sample(
            source_class=SourceClass.NETWORK,
            source_name="nts",
            unix_time=FLOOR,
            stratum=Stratum.MESH_DERIVED,
            accuracy_seconds=1,
            source_valid=True,
            policy_accepted=True,
            network_protocol="NTS",
            network_authenticated=True,
        )


def test_sample_capability_snapshot_and_deep_quality_are_immutable() -> None:
    clock = Clock(1)
    authority = provider(clock, SourceClass.GNSS)
    source = {"nested": {"values": [1, 2]}}
    sample = gnss(authority, quality=source)
    source["nested"]["values"].append(3)
    nested_quality = cast(Mapping[str, object], sample.evidence.quality["nested"])
    assert nested_quality["values"] == (1, 2)
    assert not hasattr(authority, "_issue")
    assert not hasattr(authority, "_remember")
    with pytest.raises(AttributeError):
        authority.allowed_sources = frozenset({SourceClass.NETWORK})  # type: ignore[misc]
    object.__setattr__(sample, "unix_time", FLOOR + 1)
    configured = policy(SourceClass.GNSS)
    state = tracker(clock, authority, configured)
    assert not state.adopt(sample)
    assert state.last_rejection_reason == "sample-authority-not-bound"


def test_authority_subclasses_are_rejected() -> None:
    class EvilProvider(TimeProvider):
        pass

    clock = Clock()
    evil = EvilProvider("evil", frozenset({SourceClass.GNSS}), clock=clock.capability)
    with pytest.raises(TypeError, match="exact"):
        StratumTracker(
            authorities=(evil,),
            policy=policy(SourceClass.GNSS),
            floor_authority=EpochFloorAuthority(FLOOR),
            clock=clock.capability,
        )


def test_tracker_binds_policy_floor_projects_and_expires_authoritative_reads() -> None:
    clock = Clock(10)
    authority = provider(clock, SourceClass.GNSS)
    configured = policy(SourceClass.GNSS, max_sample_age_s=10, max_initial_epoch_lead_s=100)
    state = tracker(clock, authority, configured)
    assert state.adopt(gnss(authority, FLOOR + 90))
    clock.set(20)
    assert state.current_time() == FLOOR + 100
    clock.set(20.001)
    status = state.status()
    assert not status.wall_clock_valid
    assert status.stratum is Stratum.NO_SYNC
    assert status.last_reason == "current-source-expired"
    assert status.epoch_floor == FLOOR


def test_clear_and_expiry_preserve_per_step_reference() -> None:
    clock = Clock(0)
    authority = provider(clock, SourceClass.GNSS)
    configured = policy(
        SourceClass.GNSS,
        max_sample_age_s=1,
        max_forward_step_s=10,
        max_cumulative_forward_correction_s=1000,
    )
    state = tracker(clock, authority, configured)
    assert state.adopt(gnss(authority))
    state.clear("reselect")
    clock.set(1)
    assert not state.adopt(gnss(authority, FLOOR + 100))
    assert state.last_rejection_reason == "forward-step-exceeds-policy"
    clock.set(3.001)
    assert state.current_time() is None
    assert not state.adopt(gnss(authority, FLOOR + 200))
    assert state.last_rejection_reason == "forward-step-exceeds-policy"


def test_admin_policy_replacement_preserves_anchor() -> None:
    clock = Clock()
    admin = TimeAdmin("console")
    authority = provider(clock, SourceClass.GNSS)
    state = tracker(clock, authority, policy(SourceClass.GNSS), admin=admin)
    assert state.adopt(gnss(authority))
    with pytest.raises(PermissionError):
        state.replace_policy(TimeAdmin("attacker"), policy(SourceClass.GNSS))
    state.replace_policy(admin, policy(SourceClass.GNSS, max_forward_step_s=1))
    state.clear()
    clock.set(1)
    assert not state.adopt(gnss(authority, FLOOR + 10))


@pytest.mark.asyncio
async def test_signed_canonical_dio_uses_link_receipt_time_and_exact_span() -> None:
    clock = Clock(10)
    radio = QueueRadio()
    link = receiver(radio, clock)
    option = DioTimeOption(Stratum.GNSS_GPSD, FLOOR)
    payload = dio_envelope(option)
    radio.frames.append((signed_wire(REMOTE, payload, counter=1), -91, 5))
    received = await link.receive(100)
    assert isinstance(received, RxFrame)
    verifier = DioTimeVerifier(
        "dio-verifier",
        link,
        peer_origins={REMOTE.pubkey: {Stratum.GNSS_GPSD: SourceClass.GNSS}},
        peer_accuracy_seconds={REMOTE.pubkey: 1},
        clock=clock.capability,
    )
    authenticated = authenticate_dio(link, received)
    _, peer = link.accept_authenticated_schc_dio(authenticated)
    assert peer.allows_dodag_join
    sample = verifier.verify(authenticated)
    assert sample.observed_monotonic == 10
    assert sample.evidence.authenticated_payload == authenticated.ipv6
    assert sample.evidence.option_span is not None
    start, end = sample.evidence.option_span
    assert authenticated.ipv6[start:end] == option.encode()
    admin = TimeAdmin("network-policy-admin")
    authorized = tracker(
        clock,
        verifier,
        policy(SourceClass.GNSS, SourceClass.NETWORK, peers=frozenset({REMOTE.pubkey})),
        admin=admin,
    )
    assert authorized.adopt(sample)
    authorized.replace_policy(admin, policy(SourceClass.GNSS, SourceClass.NETWORK))
    assert authorized.current_time() is None
    assert (
        authorized.last_rejection_reason == "policy-replaced:network-peer-not-authorized-for-time"
    )
    state = tracker(
        clock,
        verifier,
        policy(
            SourceClass.GNSS,
            SourceClass.NETWORK,
            peers=frozenset({REMOTE.pubkey}),
            max_sample_age_s=30,
        ),
    )
    clock.set(100)
    assert not state.consider(option, sample=sample)
    assert state.last_rejection_reason == "sample-already-considered"
    assert verifier.verify(authenticated).evidence.replay_counter == 1


@pytest.mark.asyncio
async def test_delayed_receipt_expires_before_elevation() -> None:
    clock = Clock(10)
    radio = QueueRadio()
    link = receiver(radio, clock)
    option = DioTimeOption(Stratum.GNSS_GPSD, FLOOR)
    radio.frames.append((signed_wire(REMOTE, dio_envelope(option), counter=6), -91, 5))
    received = await link.receive(100)
    assert isinstance(received, RxFrame)
    clock.set(71)
    with pytest.raises(ValueError, match="unconsumed"):
        authenticate_dio(link, received)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (dio_envelope(None), "dio-time-option-count"),
        (
            dio_envelope(DioTimeOption(Stratum.NTS, FLOOR), duplicate=True),
            "dio-time-option-count",
        ),
        (
            b"\x15" + dio_envelope(DioTimeOption(Stratum.NTS, FLOOR))[1:],
            "SCHC L2 dispatch",
        ),
    ],
)
async def test_dio_rejects_missing_duplicate_and_wrong_dispatch(
    payload: bytes, message: str
) -> None:
    clock = Clock(1)
    radio = QueueRadio()
    link = receiver(radio, clock)
    radio.frames.append((signed_wire(REMOTE, payload, counter=1), -80, 2))
    received = await link.receive(10)
    assert isinstance(received, RxFrame)
    verifier = DioTimeVerifier(
        "dio",
        link,
        peer_origins={REMOTE.pubkey: {Stratum.NTS: SourceClass.NETWORK}},
        peer_accuracy_seconds={REMOTE.pubkey: 1},
        clock=clock.capability,
    )
    with pytest.raises(ValueError, match=message):
        authenticated = authenticate_dio(link, received)
        verifier.verify(authenticated)


@pytest.mark.asyncio
async def test_dio_rejects_source_iid_not_owned_by_authenticated_signer() -> None:
    clock = Clock(1)
    radio = QueueRadio()
    link = receiver(radio, clock)
    payload = dio_envelope(
        DioTimeOption(Stratum.NTS, FLOOR),
        source=IPv6Address("fe80::2"),
    )
    radio.frames.append((signed_wire(REMOTE, payload, counter=1), -80, 2))
    received = await link.receive(10)
    assert isinstance(received, RxFrame)
    with pytest.raises(ValueError, match="source IID does not match signer"):
        authenticate_dio(link, received)


def test_dio_rejects_duck_typed_link() -> None:
    class Fake:
        def consume_verified_receipt(self, value: object, *, purpose: str) -> object:
            return value, purpose

    with pytest.raises(TypeError, match="exact LinkLayer"):
        DioTimeVerifier("fake", Fake(), peer_origins={}, peer_accuracy_seconds={})


@pytest.mark.asyncio
async def test_link_replay_is_rejected_before_time_verification() -> None:
    clock = Clock()
    radio = QueueRadio()
    link = receiver(radio, clock)
    wire = signed_wire(REMOTE, dio_envelope(DioTimeOption(Stratum.NTS, FLOOR)), counter=7)
    radio.frames.extend([(wire, -80, 2), (wire, -80, 2)])
    assert isinstance(await link.receive(10), RxFrame)
    assert await link.receive(10) is ReceiveError.REPLAY


@pytest.mark.asyncio
async def test_dio_evidence_is_revoked_if_key_rotates_before_time_issuance() -> None:
    clock = Clock()
    radio = QueueRadio()
    link = receiver(radio, clock)
    option = DioTimeOption(Stratum.GNSS_GPSD, FLOOR)
    radio.frames.extend(
        [
            (signed_wire(REMOTE, dio_envelope(option), counter=9), -80, 2),
            (signed_wire(REMOTE, encode_rekey_request(OTHER.pubkey), counter=10), -80, 2),
        ]
    )
    received = await link.receive(10)
    assert isinstance(received, RxFrame)
    rekey_received = await link.receive(10)
    assert isinstance(rekey_received, RxFrame)
    verifier = DioTimeVerifier(
        "dio",
        link,
        peer_origins={REMOTE.pubkey: {Stratum.GNSS_GPSD: SourceClass.GNSS}},
        peer_accuracy_seconds={REMOTE.pubkey: 1},
        clock=clock.capability,
    )
    elevated = threading.Event()
    allow_verify = threading.Event()
    samples: list[TimeSample] = []
    errors: list[ValueError] = []

    def elevate_then_verify() -> None:
        authenticated = authenticate_dio(link, received)
        elevated.set()
        assert allow_verify.wait(1)
        try:
            samples.append(verifier.verify(authenticated))
        except ValueError as error:
            errors.append(error)

    verify_thread = threading.Thread(target=elevate_then_verify)
    verify_thread.start()
    assert elevated.wait(1)
    link.apply_authenticated_rekey(rekey_received)
    allow_verify.set()
    verify_thread.join(1)
    assert not samples
    assert errors and "authenticated DIO" in str(errors[0])


def provision(
    *,
    integrity: bool = True,
    initial: ProvisionRollbackState | ProvisionVirginState | None = None,
    persisted: list[ProvisionRollbackState] | None = None,
) -> tuple[ProvisionVerifier, TimeAdmin]:
    admin = TimeAdmin("board-admin")
    saved = persisted if persisted is not None else []
    state = initial or admin.initialize_virgin_provision_state(lambda marker: marker)
    return (
        ProvisionVerifier(
            expected_board_identity=LOCAL.pubkey,
            rollback_state=state,
            verify_integrity=lambda _wire: integrity,
            persist_rollback_state=saved.append,
            persist_clear=lambda _reason: None,
            admin=admin,
        ),
        admin,
    )


def test_provision_requires_admin_integrity_and_atomic_digest_rollback() -> None:
    saved: list[ProvisionRollbackState] = []
    verifier, admin = provision(persisted=saved)
    record = ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 10)
    with pytest.raises(PermissionError):
        verifier.install(TimeAdmin("attacker"), record.encode())
    bad, bad_admin = provision(integrity=False)
    with pytest.raises(ValueError, match="unauthenticated"):
        bad.install(bad_admin, record.encode())
    metadata = verifier.install(admin, record.encode())
    assert saved == [
        ProvisionRollbackState(
            1, FLOOR + 10, hashlib.sha256(record.encode()).digest(), record.encode()
        )
    ]
    assert evaluate_epoch_floor(FLOOR, metadata, verifier=verifier).floor == FLOOR + 10
    with pytest.raises(ValueError, match="same-version-content-mismatch"):
        verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 9).encode())
    with pytest.raises(ValueError, match="non-zero uint64"):
        verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 0, FLOOR + 9).encode())


def test_provision_clear_revokes_generation_and_only_valid_install_recovers() -> None:
    verifier, admin = provision()
    old = verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 10).encode())
    verifier.clear(admin, reason="repair")
    assert not verifier.accepts(old)
    assert (
        evaluate_epoch_floor(FLOOR, old, verifier=verifier).provision_status
        is ProvisionEpochStatus.UNAUTHENTICATED
    )
    assert (
        evaluate_epoch_floor(FLOOR, None, verifier=verifier).provision_status
        is ProvisionEpochStatus.CLEARED
    )
    with pytest.raises(ValueError):
        verifier.install(admin, b"bad")
    assert verifier.cleared
    fresh = verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 2, FLOOR + 20).encode())
    assert verifier.accepts(fresh) and not verifier.cleared


def test_provision_persistence_failure_does_not_commit() -> None:
    admin = TimeAdmin("admin")

    def fail(_state: ProvisionRollbackState) -> None:
        raise OSError("disk")

    verifier = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=admin.initialize_virgin_provision_state(lambda marker: marker),
        verify_integrity=lambda _wire: True,
        persist_rollback_state=fail,
        persist_clear=lambda _reason: None,
        admin=admin,
    )
    with pytest.raises(OSError, match="disk"):
        verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 1).encode())
    assert verifier.current() is None and verifier.minimum_record_version == 0


def test_provision_concurrent_installs_cannot_regress_rollback_state() -> None:
    verifier, admin = provision()
    barrier = threading.Barrier(3)
    errors: list[ValueError] = []

    def install(version: int) -> None:
        barrier.wait()
        try:
            verifier.install(
                admin, ProvisionRecord(LOCAL.pubkey, version, FLOOR + version).encode()
            )
        except ValueError as error:
            errors.append(error)

    threads = [threading.Thread(target=install, args=(version,)) for version in (2, 3)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    assert verifier.minimum_record_version == 3
    assert verifier.current() is not None
    assert verifier.current().record_version == 3  # type: ignore[union-attr]
    assert len(errors) <= 1


def test_provision_trust_anchor_properties_cannot_be_rebound() -> None:
    verifier, _ = provision()
    with pytest.raises(AttributeError):
        verifier.expected_board_identity = OTHER.pubkey  # type: ignore[misc]
    with pytest.raises(AttributeError):
        verifier.minimum_record_version = 0  # type: ignore[misc]


def test_floor_authority_ignores_raw_and_beyond_lead_provision() -> None:
    verifier, admin = provision()
    metadata = verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 101).encode())
    result = evaluate_epoch_floor(FLOOR, metadata, verifier=verifier, max_provision_lead_s=100)
    assert result.floor == FLOOR and result.provision_status is ProvisionEpochStatus.BEYOND_LEAD
    with pytest.deprecated_call(match="unauthenticated"):
        assert effective_epoch_floor(FLOOR, FLOOR + 100, verifier=verifier) == FLOOR


def test_tracker_transitions_are_atomic_under_competing_samples() -> None:
    clock = Clock(1)
    authority = provider(clock, SourceClass.GNSS)
    older = gnss(authority, FLOOR + 1)
    clock.set(2)
    newer = gnss(authority, FLOOR + 2)
    state = tracker(clock, authority, policy(SourceClass.GNSS, max_forward_step_s=10))
    barrier = threading.Barrier(3)
    results: list[bool] = []

    def run(sample: TimeSample) -> None:
        barrier.wait()
        results.append(state.adopt(sample))

    threads = [threading.Thread(target=run, args=(sample,)) for sample in (older, newer)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    assert any(results)
    assert state.status().unix_time == FLOOR + 2


def test_package_exports_authoritative_tracker() -> None:
    from lichen.timing import StratumTracker as ExportedTracker

    assert ExportedTracker is StratumTracker


def test_local_client_stratum_requires_verified_gpsd_subtype() -> None:
    clock = Clock()
    authority = provider(clock, SourceClass.LOCAL_CLIENT)

    def local_sample(
        stratum: Stratum,
        *,
        verified: bool | None = None,
        quality: Mapping[str, object] | None = None,
    ) -> TimeSample:
        return authority.sample(
            source_class=SourceClass.LOCAL_CLIENT,
            source_name="local-client",
            unix_time=FLOOR,
            stratum=stratum,
            accuracy_seconds=1,
            source_valid=True,
            policy_accepted=True,
            source_subtype="gpsd",
            source_subtype_verified=verified,
            quality=quality,
        )

    with pytest.raises(ValueError, match="verified gpsd"):
        local_sample(Stratum.GNSS_GPSD)
    with pytest.raises(ValueError, match="stratum 1"):
        local_sample(Stratum.MESH_DERIVED, verified=True)
    for invalid_quality, reason in (
        ({}, "gpsd-fix-mode-not-valid"),
        ({"gpsd_mode": 1}, "gpsd-fix-mode-not-valid"),
        (
            {"gpsd_mode": 3, "gpsd_time_valid": False},
            "gpsd-time-not-valid",
        ),
        (
            {
                "gpsd_mode": 3,
                "gpsd_time_valid": True,
                "gpsd_time_accuracy_seconds": "unknown",
            },
            "gpsd-time-accuracy-not-valid",
        ),
        (
            {
                "gpsd_mode": 3,
                "gpsd_time_valid": True,
                "gpsd_time_accuracy_seconds": 2,
            },
            "gpsd-accuracy-exceeds-sample-claim",
        ),
    ):
        with pytest.raises(ValueError, match=reason):
            local_sample(Stratum.GNSS_GPSD, verified=True, quality=invalid_quality)
    sample = local_sample(
        Stratum.GNSS_GPSD,
        verified=True,
        quality={
            "gpsd_mode": 3,
            "gpsd_time_valid": True,
            "gpsd_time_accuracy_seconds": 1,
        },
    )
    assert sample.evidence.source_subtype == "gpsd"
    assert sample.evidence.quality["gpsd_mode"] == 3


def test_tracker_detaches_adopted_sample_from_caller_mutation() -> None:
    clock = Clock()
    authority = provider(clock, SourceClass.GNSS)
    state = tracker(clock, authority, policy(SourceClass.GNSS, max_sample_age_s=1))
    sample = gnss(authority)
    assert state.adopt(sample)
    object.__setattr__(sample, "observed_monotonic", 10_000.0)
    object.__setattr__(sample.evidence, "source_valid", False)
    clock.set(2)
    assert state.current_time() is None
    assert state.last_rejection_reason == "current-source-expired"


def test_policy_replacement_revokes_active_source_and_accuracy() -> None:
    clock = Clock()
    admin = TimeAdmin("policy-admin")
    authority = provider(clock, SourceClass.GNSS)
    state = tracker(clock, authority, policy(SourceClass.GNSS), admin=admin)
    assert state.adopt(gnss(authority, accuracy_seconds=2))
    state.replace_policy(
        admin,
        policy(
            SourceClass.GNSS,
            max_accuracy_seconds={
                SourceClass.GNSS: 1,
                SourceClass.NETWORK: 10,
                SourceClass.LOCAL_CLIENT: 10,
                SourceClass.MANUAL: 1,
                SourceClass.INTERNAL_RTC: 3600,
            },
        ),
    )
    assert state.current_time() is None
    assert state.last_rejection_reason == "policy-replaced:source-accuracy-exceeds-policy"

    clock.set(1)
    second = tracker(clock, authority, policy(SourceClass.GNSS), admin=admin)
    assert second.adopt(gnss(authority))
    second.replace_policy(admin, policy(SourceClass.MANUAL))
    assert second.current_time() is None
    assert second.last_rejection_reason == "policy-replaced:source-class-not-accepted"


def test_live_provision_floor_raise_invalidates_adopted_clock() -> None:
    clock = Clock()
    authority = provider(clock, SourceClass.GNSS)
    verifier, admin = provision()
    state = StratumTracker(
        authorities=(authority,),
        policy=policy(SourceClass.GNSS),
        floor_authority=EpochFloorAuthority(FLOOR, verifier=verifier),
        clock=clock.capability,
    )
    assert state.adopt(gnss(authority, FLOOR + 10))
    verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 20).encode())
    assert state.current_time() is None
    assert state.last_rejection_reason == "below-live-epoch-floor:accepted"


def test_concurrent_provision_raise_never_reports_valid_time_below_displayed_floor() -> None:
    clock = Clock()
    authority = provider(clock, SourceClass.GNSS)
    verifier, admin = provision()
    state = StratumTracker(
        authorities=(authority,),
        policy=policy(SourceClass.GNSS),
        floor_authority=EpochFloorAuthority(FLOOR, verifier=verifier),
        clock=clock.capability,
    )
    assert state.adopt(gnss(authority, FLOOR + 50))
    barrier = threading.Barrier(2)
    inconsistent: list[object] = []

    def install_floors() -> None:
        barrier.wait()
        for version in range(1, 7):
            verifier.install(
                admin,
                ProvisionRecord(LOCAL.pubkey, version, FLOOR + version * 10).encode(),
            )

    writer = threading.Thread(target=install_floors)
    writer.start()
    barrier.wait()
    while writer.is_alive():
        status = state.status()
        if (
            status.wall_clock_valid
            and status.unix_time is not None
            and status.unix_time < status.epoch_floor
        ):
            inconsistent.append(status)
    writer.join()
    final = state.status()
    assert not inconsistent
    assert not final.wall_clock_valid
    assert final.epoch_floor == FLOOR + 60


def test_live_floor_is_revalidated_at_adopt_consider_and_policy_transition() -> None:
    for action in ("adopt", "consider", "replace-policy"):
        clock = Clock()
        authority = provider(clock, SourceClass.GNSS)
        verifier, admin = provision()
        policy_admin = TimeAdmin(f"policy-{action}")
        state = StratumTracker(
            authorities=(authority,),
            policy=policy(SourceClass.GNSS),
            floor_authority=EpochFloorAuthority(FLOOR, verifier=verifier),
            clock=clock.capability,
            admin=policy_admin,
        )
        assert state.adopt(gnss(authority, FLOOR + 10))
        verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 20).encode())
        if action == "adopt":
            state.adopt(gnss(authority, FLOOR + 19))
        elif action == "consider":
            candidate = gnss(authority, FLOOR + 19)
            state.consider(DioTimeOption(Stratum.GNSS_GPSD, FLOOR + 19), sample=candidate)
        else:
            state.replace_policy(policy_admin, policy(SourceClass.GNSS))
        assert not state.status().wall_clock_valid, action


def test_floor_snapshot_commit_linearizes_against_concurrent_install() -> None:
    clock = Clock()
    authority = provider(clock, SourceClass.GNSS)
    verifier, admin = provision()
    state = StratumTracker(
        authorities=(authority,),
        policy=policy(SourceClass.GNSS),
        floor_authority=EpochFloorAuthority(FLOOR, verifier=verifier),
        clock=clock.capability,
    )
    sample = gnss(authority, FLOOR + 10)
    entered_claim = threading.Event()
    allow_claim = threading.Event()
    original_claim = authority._claim

    def blocking_claim(candidate: TimeSample) -> tuple[TimeSample, int] | None:
        entered_claim.set()
        assert allow_claim.wait(1)
        return original_claim(candidate)

    authority._claim = blocking_claim  # type: ignore[assignment]
    order: list[str] = []

    def do_adopt() -> None:
        assert state.adopt(sample)
        order.append("adopt")

    def do_install() -> None:
        verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 20).encode())
        order.append("install")

    adopter = threading.Thread(target=do_adopt)
    adopter.start()
    assert entered_claim.wait(1)
    installer = threading.Thread(target=do_install)
    installer.start()
    assert installer.is_alive()
    allow_claim.set()
    adopter.join(1)
    installer.join(1)
    assert order == ["adopt", "install"]
    assert state.current_time() is None


def test_monotonic_clock_domain_mismatch_is_rejected() -> None:
    raw = Clock()
    radio = QueueRadio()
    link = receiver(radio, raw)
    offset = MonotonicClock(lambda: 10_000.0)
    with pytest.raises(ValueError, match="different monotonic clock domain"):
        DioTimeVerifier(
            "dio",
            link,
            peer_origins={},
            peer_accuracy_seconds={},
            clock=offset,
        )
    authority = provider(raw, SourceClass.GNSS)
    with pytest.raises(ValueError, match="share one MonotonicClock"):
        StratumTracker(
            authorities=(authority,),
            policy=policy(SourceClass.GNSS),
            floor_authority=EpochFloorAuthority(FLOOR),
            clock=offset,
        )


def test_provision_uint64_version_bounds_and_reboot_restore() -> None:
    max_record = ProvisionRecord(LOCAL.pubkey, (1 << 64) - 1, FLOOR + 5)
    assert ProvisionRecord.decode(max_record.encode()) == max_record
    with pytest.raises(ValueError, match="uint64"):
        ProvisionRecord(LOCAL.pubkey, 1 << 64, FLOOR)
    with pytest.raises(ValueError, match="uint64"):
        ProvisionRollbackState(1 << 64, FLOOR, bytes(32), bytes(44))

    saved: list[ProvisionRollbackState] = []
    verifier, admin = provision(persisted=saved)
    record = ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 5)
    verifier.install(admin, record.encode())
    rebooted = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=saved[-1],
        verify_integrity=lambda _wire: True,
        persist_rollback_state=lambda _state: None,
        persist_clear=lambda _reason: None,
        admin=admin,
    )
    restored = rebooted.current()
    assert restored is not None
    assert evaluate_epoch_floor(FLOOR, restored, verifier=rebooted).floor == FLOOR + 5
    with pytest.raises(TypeError, match="explicit persisted"):
        ProvisionVerifier(
            expected_board_identity=LOCAL.pubkey,
            rollback_state=None,  # type: ignore[arg-type]
            verify_integrity=lambda _wire: True,
            persist_rollback_state=lambda _state: None,
            persist_clear=lambda _reason: None,
            admin=admin,
        )
    with pytest.raises(ValueError, match="invalid-persisted"):
        ProvisionVerifier(
            expected_board_identity=LOCAL.pubkey,
            rollback_state=saved[-1],
            verify_integrity=lambda _wire: False,
            persist_rollback_state=lambda _state: None,
            persist_clear=lambda _reason: None,
            admin=admin,
        )


@pytest.mark.asyncio
async def test_authenticated_dio_rejects_bad_checksum_and_wrong_scope() -> None:
    clock = Clock()
    radio = QueueRadio()
    link = receiver(radio, clock)
    valid = dio_envelope(DioTimeOption(Stratum.NTS, FLOOR))
    ipv6 = bytearray(decompress_packet(l2_payload_body(valid)))
    ipv6[42] ^= 1
    bad_checksum = wrap_schc_payload(compress_packet(bytes(ipv6)))
    radio.frames.append((signed_wire(REMOTE, bad_checksum, counter=20), -80, 2))
    received = await link.receive(10)
    assert isinstance(received, RxFrame)
    with pytest.raises(ValueError, match="valid RPL DIO"):
        authenticate_dio(link, received)

    scope_overrides: tuple[dict[str, object], ...] = (
        {"expected_rpl_instance_id": 1},
        {"expected_dodag_id": IPv6Address("fe80::99")},
        {"expected_mop": 2},
        {"expected_role": "root"},
    )
    for counter, expected in enumerate(scope_overrides, start=21):
        radio.frames.append((signed_wire(REMOTE, valid, counter=counter), -80, 2))
        scoped = await link.receive(10)
        assert isinstance(scoped, RxFrame)
        arguments: dict[str, object] = {
            "expected_rpl_instance_id": 0,
            "expected_dodag_id": IPv6Address("fe80::1"),
            "expected_mop": 1,
            "expected_role": "peer",
        }
        arguments.update(expected)
        with pytest.raises(ValueError, match="mismatch"):
            link.accept_authenticated_dio(scoped, **arguments)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_dio_time_verifier_rejects_other_link_in_same_clock_domain() -> None:
    clock = Clock()
    first_radio, second_radio = QueueRadio(), QueueRadio()
    first_link = receiver(first_radio, clock)
    second_link = receiver(second_radio, clock)
    payload = dio_envelope(DioTimeOption(Stratum.NTS, FLOOR))
    second_radio.frames.append((signed_wire(REMOTE, payload, counter=30), -80, 2))
    received = await second_link.receive(10)
    assert isinstance(received, RxFrame)
    authenticated = authenticate_dio(second_link, received)
    verifier = DioTimeVerifier(
        "first-link-only",
        first_link,
        peer_origins={REMOTE.pubkey: {Stratum.NTS: SourceClass.NETWORK}},
        peer_accuracy_seconds={REMOTE.pubkey: 1},
        clock=clock.capability,
    )
    with pytest.raises(ValueError, match="authenticated DIO"):
        verifier.verify(authenticated)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation", ["option-data", "option-span", "ipv6", "dio-bytes", "receipt-time"]
)
async def test_dio_time_verifier_rejects_post_issuance_mutation(mutation: str) -> None:
    clock = Clock()
    radio = QueueRadio()
    link = receiver(radio, clock)
    payload = dio_envelope(DioTimeOption(Stratum.NTS, FLOOR))
    radio.frames.append((signed_wire(REMOTE, payload, counter=40), -80, 2))
    received = await link.receive(10)
    assert isinstance(received, RxFrame)
    authenticated = authenticate_dio(link, received)
    verifier = DioTimeVerifier(
        "mutation-check",
        link,
        peer_origins={REMOTE.pubkey: {Stratum.NTS: SourceClass.NETWORK}},
        peer_accuracy_seconds={REMOTE.pubkey: 1},
        clock=clock.capability,
    )
    time_option = next(
        option for option in authenticated.options if option.type == DIO_TIME_OPTION_TYPE
    )
    if mutation == "option-data":
        object.__setattr__(time_option, "data", b"\x03\x00\x00\x00\x00\x01")
    elif mutation == "option-span":
        object.__setattr__(time_option, "ipv6_span", (0, 8))
    elif mutation == "ipv6":
        object.__setattr__(authenticated, "_ipv6", bytes(len(authenticated.ipv6)))
    elif mutation == "dio-bytes":
        object.__setattr__(authenticated, "_dio_bytes", bytes(24))
    else:
        assert mutation == "receipt-time"
        snapshot = object.__getattribute__(authenticated, "_snapshot")
        object.__setattr__(snapshot, "_authenticated_received_monotonic", 999.0)
    assert not link.accepts_authenticated_dio(authenticated)
    with pytest.raises(ValueError, match="authenticated DIO"):
        verifier.verify(authenticated)


def test_monotonic_clock_callback_and_domain_are_structurally_immutable() -> None:
    clock = Clock()
    original_callback = clock.capability.callback
    original_domain = clock.capability.domain_identity
    for name, value in (
        ("callback", lambda: 99_999.0),
        ("_callback", lambda: 99_999.0),
        ("_domain_identity", object()),
    ):
        with pytest.raises(AttributeError):
            object.__setattr__(clock.capability, name, value)
    assert clock.capability.callback == original_callback
    assert clock.capability.domain_identity is original_domain

    authority = provider(clock, SourceClass.GNSS)
    state = tracker(
        clock,
        authority,
        policy(
            SourceClass.GNSS,
            max_sample_age_s=2,
            max_forward_step_s=10,
            max_cumulative_forward_correction_s=10,
        ),
    )
    sample = gnss(authority)
    with pytest.raises(AttributeError):
        object.__setattr__(clock.capability, "callback", lambda: 50_000.0)
    assert state.adopt(sample)
    with pytest.raises(AttributeError):
        object.__setattr__(clock.capability, "callback", lambda: 50_000.0)
    assert state.status().wall_clock_valid
    clock.set(1)
    with pytest.raises(AttributeError):
        object.__setattr__(clock.capability, "callback", lambda: 50_000.0)
    assert state.adopt(gnss(authority, FLOOR + 1))
    clock.set(3.001)
    with pytest.raises(AttributeError):
        object.__setattr__(clock.capability, "callback", lambda: 0.0)
    assert state.current_time() is None


@pytest.mark.asyncio
async def test_clock_callback_cannot_change_before_receipt_or_dio_verification() -> None:
    clock = Clock(5)
    radio = QueueRadio()
    link = receiver(radio, clock)
    with pytest.raises(AttributeError):
        object.__setattr__(clock.capability, "callback", lambda: 90_000.0)
    radio.frames.append(
        (
            signed_wire(
                REMOTE,
                dio_envelope(DioTimeOption(Stratum.NTS, FLOOR)),
                counter=90,
            ),
            -80,
            2,
        )
    )
    received = await link.receive(10)
    assert isinstance(received, RxFrame)
    authenticated = authenticate_dio(link, received)
    verifier = DioTimeVerifier(
        "immutable-clock-dio",
        link,
        peer_origins={REMOTE.pubkey: {Stratum.NTS: SourceClass.NETWORK}},
        peer_accuracy_seconds={REMOTE.pubkey: 1},
        clock=clock.capability,
    )
    with pytest.raises(AttributeError):
        object.__setattr__(clock.capability, "callback", lambda: 90_000.0)
    assert verifier.verify(authenticated).observed_monotonic == 5


def test_floor_authority_binding_is_immutable_and_live_provision_still_advances() -> None:
    verifier, admin = provision()
    floor_authority = EpochFloorAuthority(FLOOR, verifier=verifier, max_provision_lead_s=100)
    clock = Clock()
    authority = provider(clock, SourceClass.GNSS)
    state = StratumTracker(
        authorities=(authority,),
        policy=policy(SourceClass.GNSS),
        floor_authority=floor_authority,
        clock=clock.capability,
    )
    for name, value in (
        ("_EpochFloorAuthority__build", FLOOR - 100),
        ("_EpochFloorAuthority__build", FLOOR + 100),
        ("_EpochFloorAuthority__verifier", None),
        ("_EpochFloorAuthority__lead", 1 << 32),
    ):
        with pytest.raises(AttributeError):
            object.__setattr__(floor_authority, name, value)
    assert state.adopt(gnss(authority, FLOOR + 10))
    verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 20).encode())
    assert state.current_time() is None
    assert state.status().epoch_floor == FLOOR + 20


def test_direct_samples_are_one_use_and_clear_invalidates_preissued_samples() -> None:
    clock = Clock()
    authority = provider(clock, SourceClass.GNSS)
    state = tracker(clock, authority, policy(SourceClass.GNSS, max_forward_step_s=10))
    first = gnss(authority)
    preclear = gnss(authority, FLOOR + 1)
    assert state.adopt(first)
    state.clear("operator-clear")
    assert not state.adopt(first)
    assert state.last_rejection_reason == "sample-already-considered"
    assert not state.adopt(preclear)
    assert state.last_rejection_reason == "sample-invalidated-or-replayed"
    postclear = gnss(authority, FLOOR + 2)
    assert state.adopt(postclear)
    state.clear("second-clear")
    assert not state.adopt(postclear)
    assert state.last_rejection_reason == "sample-already-considered"


def test_rejected_direct_sample_is_consumed_on_first_consideration() -> None:
    clock = Clock()
    authority = provider(clock, SourceClass.GNSS)
    state = tracker(clock, authority, policy(SourceClass.GNSS))
    rejected = gnss(authority, FLOOR - 1)
    assert not state.adopt(rejected)
    assert state.last_rejection_reason == "below-epoch-floor"
    assert not state.adopt(rejected)
    assert state.last_rejection_reason == "sample-already-considered"


def test_rtc_effective_age_boundary_expiry_regression_and_policy_replacement() -> None:
    clock = Clock()
    authority = provider(clock, SourceClass.INTERNAL_RTC)

    def rtc(age: int) -> TimeSample:
        return authority.sample(
            source_class=SourceClass.INTERNAL_RTC,
            source_name="retained-rtc",
            unix_time=FLOOR,
            stratum=Stratum.MESH_DERIVED,
            accuracy_seconds=1,
            source_valid=True,
            policy_accepted=True,
            rtc_initialized=True,
            rtc_age_seconds=age,
        )

    state = tracker(clock, authority, policy(SourceClass.INTERNAL_RTC, max_sample_age_s=300))
    assert state.adopt(rtc(299))
    clock.set(1)
    assert state.current_time() == FLOOR + 1
    clock.set(1.001)
    assert state.current_time() is None
    assert state.last_rejection_reason == "current-rtc-state-stale"

    clock.set(10)
    admin = TimeAdmin("rtc-policy")
    replaced = tracker(
        clock,
        authority,
        policy(SourceClass.INTERNAL_RTC, max_sample_age_s=300),
        admin=admin,
    )
    assert replaced.adopt(rtc(200))
    replaced.replace_policy(admin, policy(SourceClass.INTERNAL_RTC, max_sample_age_s=100))
    assert replaced.current_time() is None
    assert replaced.last_rejection_reason == "policy-replaced:rtc-state-stale"

    clock.set(9)
    regressed = tracker(clock, authority, policy(SourceClass.INTERNAL_RTC, max_sample_age_s=300))
    future = rtc(0)
    clock.set(8)
    assert not regressed.adopt(future)
    assert regressed.last_rejection_reason == "observation-is-in-the-future"


def test_correction_rate_policy_is_bounded_and_overflow_safe() -> None:
    assert SourcePrecedencePolicy(max_correction_rate_ppm=MAX_CORRECTION_RATE_PPM)
    with pytest.raises(ValueError, match="max_correction_rate_ppm"):
        SourcePrecedencePolicy(max_correction_rate_ppm=MAX_CORRECTION_RATE_PPM + 1)
    with pytest.raises(ValueError, match="max_correction_rate_ppm"):
        SourcePrecedencePolicy(max_correction_rate_ppm=10**400)


def test_provision_clear_reboot_same_record_reactivation_and_corruption() -> None:
    admin = TimeAdmin("persistent-admin")
    virgin = admin.initialize_virgin_provision_state(lambda marker: marker)
    rollback_saved: list[ProvisionRollbackState] = []
    clear_saved: list[ProvisionClearedState] = []
    verifier = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=virgin,
        verify_integrity=lambda _wire: True,
        persist_rollback_state=rollback_saved.append,
        persist_clear=clear_saved.append,
        admin=admin,
    )
    record = ProvisionRecord(LOCAL.pubkey, 2, FLOOR + 10)
    verifier.install(admin, record.encode())
    verifier.clear(admin, reason="operator-repair")
    cleared = clear_saved[-1]
    rebooted = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=cleared,
        verify_integrity=lambda _wire: True,
        persist_rollback_state=rollback_saved.append,
        persist_clear=clear_saved.append,
        admin=admin,
    )
    assert rebooted.cleared and rebooted.current() is None
    assert rebooted.minimum_record_version == 2
    with pytest.raises(ValueError, match="rollback"):
        rebooted.install(admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR).encode())
    restored = rebooted.install(admin, record.encode())
    assert restored.record_version == 2
    assert rollback_saved[-1] == ProvisionRollbackState(
        2, FLOOR + 10, hashlib.sha256(record.encode()).digest(), record.encode()
    )
    active_reboot = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=rollback_saved[-1],
        verify_integrity=lambda wire: wire == record.encode(),
        persist_rollback_state=lambda _state: None,
        persist_clear=lambda _state: None,
        admin=admin,
    )
    assert active_reboot.current() is not None

    object.__setattr__(cleared, "record_version", 0)
    with pytest.raises(ValueError, match="invalid-persisted-cleared-state"):
        ProvisionVerifier(
            expected_board_identity=LOCAL.pubkey,
            rollback_state=cleared,
            verify_integrity=lambda _wire: True,
            persist_rollback_state=lambda _state: None,
            persist_clear=lambda _state: None,
            admin=admin,
        )


def test_provision_detaches_caller_and_rejects_hook_mutation() -> None:
    record = ProvisionRecord(LOCAL.pubkey, 2, FLOOR + 20)
    original = ProvisionRollbackState(
        2, FLOOR + 20, hashlib.sha256(record.encode()).digest(), record.encode()
    )
    admin = TimeAdmin("alias-admin")
    verifier = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=original,
        verify_integrity=lambda _wire: True,
        persist_rollback_state=lambda _state: None,
        persist_clear=lambda _state: None,
        admin=admin,
    )
    object.__setattr__(original, "record_version", 1)
    assert verifier.minimum_record_version == 2
    with pytest.raises(ValueError, match="rollback"):
        verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 1).encode())

    virgin = admin.initialize_virgin_provision_state(lambda marker: marker)

    def mutate(state: ProvisionRollbackState) -> None:
        object.__setattr__(state, "record_version", 0)

    attacked = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=virgin,
        verify_integrity=lambda _wire: True,
        persist_rollback_state=mutate,
        persist_clear=lambda _state: None,
        admin=admin,
    )
    with pytest.raises(RuntimeError, match="mutated rollback"):
        attacked.install(admin, record.encode())
    assert attacked.minimum_record_version == 0 and attacked.current() is None


@pytest.mark.asyncio
async def test_peer_dio_can_attest_local_client_gpsd_origin_only_by_policy() -> None:
    clock = Clock()
    radio = QueueRadio()
    link = receiver(radio, clock)
    option = DioTimeOption(Stratum.GNSS_GPSD, FLOOR)
    radio.frames.append((signed_wire(REMOTE, dio_envelope(option), counter=100), -80, 2))
    received = await link.receive(10)
    assert isinstance(received, RxFrame)
    authenticated = authenticate_dio(link, received)
    verifier = DioTimeVerifier(
        "peer-gpsd",
        link,
        peer_origins={REMOTE.pubkey: {Stratum.GNSS_GPSD: SourceClass.LOCAL_CLIENT}},
        peer_accuracy_seconds={REMOTE.pubkey: 1},
        clock=clock.capability,
    )
    sample = verifier.verify(authenticated)
    assert sample.source_class is SourceClass.LOCAL_CLIENT
    assert sample.evidence.source_subtype == "gpsd"
    assert sample.evidence.source_subtype_verified is True
    state = tracker(
        clock,
        verifier,
        policy(
            SourceClass.LOCAL_CLIENT,
            SourceClass.NETWORK,
            peers=frozenset({REMOTE.pubkey}),
        ),
    )
    assert state.adopt(sample)
    with pytest.raises(ValueError, match="peer origin does not match stratum"):
        DioTimeVerifier(
            "wrong-stratum",
            link,
            peer_origins={REMOTE.pubkey: {Stratum.NTS: SourceClass.LOCAL_CLIENT}},
            peer_accuracy_seconds={REMOTE.pubkey: 1},
            clock=clock.capability,
        )


def test_virgin_bootstrap_requires_storage_ack_and_is_single_use() -> None:
    admin = TimeAdmin("virgin-admin")
    with pytest.raises(RuntimeError, match="not acknowledged"):
        admin.initialize_virgin_provision_state(lambda _marker: None)

    state = admin.initialize_virgin_provision_state(lambda marker: bytes(marker))
    with pytest.raises(RuntimeError, match="single-use"):
        admin.initialize_virgin_provision_state(lambda marker: marker)

    verifier = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=state,
        verify_integrity=lambda _wire: True,
        persist_rollback_state=lambda _state: None,
        persist_clear=lambda _state: None,
        admin=admin,
    )
    assert verifier.minimum_record_version == 0
    verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 2, FLOOR + 2).encode())
    with pytest.raises(RuntimeError, match="single-use"):
        admin.initialize_virgin_provision_state(lambda marker: marker)
    with pytest.raises(ValueError, match="virgin provision state"):
        ProvisionVerifier(
            expected_board_identity=LOCAL.pubkey,
            rollback_state=state,
            verify_integrity=lambda _wire: True,
            persist_rollback_state=lambda _state: None,
            persist_clear=lambda _state: None,
            admin=admin,
        )


def test_virgin_bootstrap_is_atomic_across_callers() -> None:
    admin = TimeAdmin("concurrent-virgin-admin")
    barrier = threading.Barrier(3)
    states: list[ProvisionVirginState] = []
    errors: list[RuntimeError] = []

    def bootstrap() -> None:
        barrier.wait()
        try:
            states.append(admin.initialize_virgin_provision_state(lambda marker: marker))
        except RuntimeError as error:
            errors.append(error)

    threads = [threading.Thread(target=bootstrap) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(1)
    assert len(states) == 1
    assert len(errors) == 1 and "single-use" in str(errors[0])


def test_provision_transitions_reject_reentrant_persistence_hooks() -> None:
    admin = TimeAdmin("reentry-admin")
    holder: dict[str, ProvisionVerifier] = {}
    mode = "install-install"
    record1 = ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 1).encode()
    record2 = ProvisionRecord(LOCAL.pubkey, 2, FLOOR + 2).encode()

    def persist_record(_state: ProvisionRollbackState) -> None:
        if mode == "install-install":
            holder["verifier"].install(admin, record2)
        elif mode == "install-clear":
            holder["verifier"].clear(admin, reason="nested")

    def persist_clear(_state: ProvisionClearedState) -> None:
        if mode == "clear-install":
            holder["verifier"].install(admin, record2)

    verifier = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=admin.initialize_virgin_provision_state(lambda marker: marker),
        verify_integrity=lambda _wire: True,
        persist_rollback_state=persist_record,
        persist_clear=persist_clear,
        admin=admin,
    )
    holder["verifier"] = verifier
    with pytest.raises(RuntimeError, match="reentry"):
        verifier.install(admin, record1)
    assert verifier.current() is None and verifier.minimum_record_version == 0

    mode = "none"
    with pytest.raises(RuntimeError, match="poisoned"):
        verifier.install(admin, record1)
    assert verifier.current() is None and verifier.cleared


def test_async_clock_and_provision_callbacks_are_closed_and_rejected() -> None:
    async def async_clock() -> float:
        return 1.0

    with pytest.raises(TypeError, match="synchronous"):
        MonotonicClock(async_clock)  # type: ignore[arg-type]

    class DeferredClock:
        def __call__(self) -> object:
            return async_clock()

    clock = MonotonicClock(DeferredClock())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="awaitable"):
        clock()

    class SwitchableClock:
        asynchronous = False

        def __call__(self) -> object:
            return async_clock() if self.asynchronous else 0.0

    switchable = SwitchableClock()
    clock_capability = MonotonicClock(switchable)  # type: ignore[arg-type]
    authority = TimeProvider(
        "async-clock-state", frozenset({SourceClass.GNSS}), clock=clock_capability
    )
    state = StratumTracker(
        authorities=(authority,),
        policy=policy(SourceClass.GNSS),
        floor_authority=EpochFloorAuthority(FLOOR),
        clock=clock_capability,
    )
    assert state.adopt(gnss(authority))
    switchable.asynchronous = True
    with pytest.raises(TypeError, match="awaitable"):
        state.current_time()
    switchable.asynchronous = False
    assert state.current_time() == FLOOR

    async def async_integrity(_wire: bytes) -> bool:
        return True

    admin = TimeAdmin("async-hook-admin")
    virgin = admin.initialize_virgin_provision_state(lambda marker: marker)
    with pytest.raises(TypeError, match="synchronous"):
        ProvisionVerifier(
            expected_board_identity=LOCAL.pubkey,
            rollback_state=virgin,
            verify_integrity=async_integrity,  # type: ignore[arg-type]
            persist_rollback_state=lambda _state: None,
            persist_clear=lambda _state: None,
            admin=admin,
        )

    async def deferred_persist() -> None:
        return None

    second_admin = TimeAdmin("deferred-hook-admin")
    second_virgin = second_admin.initialize_virgin_provision_state(lambda marker: marker)
    verifier = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=second_virgin,
        verify_integrity=lambda _wire: True,
        persist_rollback_state=lambda _state: deferred_persist(),  # type: ignore[arg-type]
        persist_clear=lambda _state: None,
        admin=second_admin,
    )
    with pytest.raises(TypeError, match="awaitable"):
        verifier.install(second_admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR).encode())
    assert verifier.current() is None and verifier.minimum_record_version == 0

    third_admin = TimeAdmin("async-marker-admin")
    with pytest.raises(TypeError, match="synchronous"):
        third_admin.initialize_virgin_provision_state(async_integrity)

    class DeferredMarker:
        def __call__(self, marker: bytes) -> object:
            return async_integrity(marker)

    with pytest.raises(TypeError, match="awaitable"):
        third_admin.initialize_virgin_provision_state(DeferredMarker())
    third_virgin = third_admin.initialize_virgin_provision_state(lambda marker: marker)

    class DeferredIntegrity:
        def __call__(self, wire: bytes) -> object:
            return async_integrity(wire)

    integrity_verifier = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=third_virgin,
        verify_integrity=DeferredIntegrity(),  # type: ignore[arg-type]
        persist_rollback_state=lambda _state: None,
        persist_clear=lambda _state: None,
        admin=third_admin,
    )
    with pytest.raises(TypeError, match="awaitable"):
        integrity_verifier.install(third_admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR).encode())
    assert integrity_verifier.current() is None

    fourth_admin = TimeAdmin("async-clear-admin")
    fourth_virgin = fourth_admin.initialize_virgin_provision_state(lambda marker: marker)
    clear_verifier = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=fourth_virgin,
        verify_integrity=lambda _wire: True,
        persist_rollback_state=lambda _state: None,
        persist_clear=lambda _state: deferred_persist(),  # type: ignore[arg-type]
        admin=fourth_admin,
    )
    clear_verifier.install(fourth_admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR).encode())
    with pytest.raises(TypeError, match="awaitable"):
        clear_verifier.clear(fourth_admin, reason="async-clear")
    assert clear_verifier.current() is None and clear_verifier.cleared
    assert (
        evaluate_epoch_floor(FLOOR, None, verifier=clear_verifier).provision_status
        is ProvisionEpochStatus.PERSISTENCE_FAILED
    )


def test_provision_floor_uses_detached_internal_primitives() -> None:
    verifier, admin = provision()
    metadata = verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 20).encode())
    floor = EpochFloorAuthority(FLOOR, verifier=verifier, max_provision_lead_s=100)
    object.__setattr__(metadata, "epoch", FLOOR - 100)
    object.__setattr__(metadata, "board_identity", OTHER.pubkey)
    object.__setattr__(metadata, "record_version", 0)
    object.__setattr__(metadata, "record_digest", bytes(32))
    object.__setattr__(metadata, "generation", 0)
    assert verifier.current() is None
    result = floor.current()
    assert result.floor == FLOOR + 20
    assert result.provision_status is ProvisionEpochStatus.ACCEPTED


def test_atomic_claim_detaches_all_tracker_security_fields() -> None:
    clock = Clock()
    authority = provider(clock, SourceClass.GNSS)
    state = tracker(clock, authority, policy(SourceClass.GNSS))
    sample = gnss(authority)
    claimed = threading.Event()
    release = threading.Event()
    original_claim = authority._claim

    def blocking_claim(candidate: TimeSample) -> tuple[TimeSample, int] | None:
        result = original_claim(candidate)
        claimed.set()
        assert release.wait(1)
        return result

    authority._claim = blocking_claim  # type: ignore[assignment]
    outcome: list[bool] = []
    thread = threading.Thread(target=lambda: outcome.append(state.adopt(sample)))
    thread.start()
    assert claimed.wait(1)
    object.__setattr__(sample, "source_class", SourceClass.NETWORK)
    object.__setattr__(sample, "unix_time", 0)
    object.__setattr__(sample, "accuracy_seconds", 999999.0)
    object.__setattr__(sample.evidence, "source_valid", False)
    object.__setattr__(sample.evidence, "quality", {"mutated": True})
    release.set()
    thread.join(1)
    assert outcome == [True]
    status = state.status()
    assert status.source_class is SourceClass.GNSS
    assert status.unix_time == FLOOR
    assert status.accuracy_seconds == 0.1
    assert status.evidence is not None and status.evidence.source_valid


@pytest.mark.asyncio
async def test_network_clear_and_option_mismatch_advance_replay_barriers() -> None:
    clock = Clock()
    radio = QueueRadio()
    link = receiver(radio, clock)
    option = DioTimeOption(Stratum.NTS, FLOOR)
    radio.frames.extend(
        [
            (signed_wire(REMOTE, dio_envelope(option), counter=200), -80, 2),
            (signed_wire(REMOTE, dio_envelope(option), counter=201), -80, 2),
            (signed_wire(REMOTE, dio_envelope(option), counter=202), -80, 2),
        ]
    )
    verifier = DioTimeVerifier(
        "barrier-verifier",
        link,
        peer_origins={REMOTE.pubkey: {Stratum.NTS: SourceClass.NETWORK}},
        peer_accuracy_seconds={REMOTE.pubkey: 1},
        clock=clock.capability,
    )
    state = tracker(
        clock,
        verifier,
        policy(SourceClass.NETWORK, peers=frozenset({REMOTE.pubkey})),
    )

    received1 = await link.receive(10)
    assert isinstance(received1, RxFrame)
    preclear = verifier.verify(authenticate_dio(link, received1))
    state.clear("network-clear")
    assert not state.adopt(preclear)
    assert state.last_rejection_reason == "sample-invalidated-or-replayed"

    received2 = await link.receive(10)
    assert isinstance(received2, RxFrame)
    authenticated2 = authenticate_dio(link, received2)
    mismatch = verifier.verify(authenticated2)
    assert not state.consider(DioTimeOption(Stratum.NTS, FLOOR + 1), sample=mismatch)
    assert state.last_rejection_reason == "sample-does-not-match-option"
    retry = verifier.verify(authenticated2)
    assert not state.consider(option, sample=retry)
    assert state.last_rejection_reason == "network-replay-counter-not-new"
    replay_keys = tuple(state._StratumTracker__network_high_water)  # type: ignore[attr-defined]
    assert len(replay_keys) == 1
    assert replay_keys[0][1] is retry.evidence.signer_key_generation
    received3 = await link.receive(10)
    assert isinstance(received3, RxFrame)
    assert state.consider(
        option,
        sample=verifier.verify(authenticate_dio(link, received3)),
    )


@pytest.mark.asyncio
async def test_dio_extraction_and_adoption_are_linearized_with_rekey() -> None:
    clock = Clock()
    radio = QueueRadio()
    link = receiver(radio, clock)
    option = DioTimeOption(Stratum.NTS, FLOOR)
    radio.frames.extend(
        [
            (signed_wire(REMOTE, dio_envelope(option), counter=210), -80, 2),
            (signed_wire(REMOTE, encode_rekey_request(OTHER.pubkey), counter=211), -80, 2),
        ]
    )
    received = await link.receive(10)
    rekey_received = await link.receive(10)
    assert isinstance(received, RxFrame) and isinstance(rekey_received, RxFrame)
    authenticated = authenticate_dio(link, received)
    verifier = DioTimeVerifier(
        "transactional-verifier",
        link,
        peer_origins={REMOTE.pubkey: {Stratum.NTS: SourceClass.NETWORK}},
        peer_accuracy_seconds={REMOTE.pubkey: 1},
        clock=clock.capability,
    )
    original_elevate = link.elevate_authenticated_dio
    entered = threading.Event()
    release = threading.Event()

    def blocking_elevate(authenticated_value: object, *, elevate: object) -> object:
        assert callable(elevate)

        def blocked(detached: object) -> object:
            entered.set()
            assert release.wait(1)
            return elevate(detached)

        return original_elevate(authenticated_value, elevate=blocked)

    link.elevate_authenticated_dio = blocking_elevate  # type: ignore[assignment]
    samples: list[TimeSample] = []
    verify_thread = threading.Thread(target=lambda: samples.append(verifier.verify(authenticated)))
    verify_thread.start()
    assert entered.wait(1)
    object.__setattr__(authenticated, "_ipv6", bytes(len(authenticated.ipv6)))
    rekey_done = threading.Event()

    def rekey() -> None:
        link.apply_authenticated_rekey(rekey_received)
        rekey_done.set()

    rekey_thread = threading.Thread(target=rekey)
    rekey_thread.start()
    assert not rekey_done.wait(0.05)
    release.set()
    verify_thread.join(1)
    rekey_thread.join(1)
    assert len(samples) == 1
    assert samples[0].unix_time == FLOOR
    state = tracker(
        clock,
        verifier,
        policy(SourceClass.NETWORK, peers=frozenset({REMOTE.pubkey})),
    )
    assert not state.adopt(samples[0])
    assert state.last_rejection_reason == "network-signer-generation-retired"


@pytest.mark.asyncio
async def test_active_network_time_is_revoked_when_signer_generation_retires() -> None:
    clock = Clock()
    radio = QueueRadio()
    link = receiver(radio, clock)
    option = DioTimeOption(Stratum.NTS, FLOOR)
    radio.frames.extend(
        [
            (signed_wire(REMOTE, dio_envelope(option), counter=220), -80, 2),
            (signed_wire(REMOTE, encode_rekey_request(OTHER.pubkey), counter=221), -80, 2),
        ]
    )
    received = await link.receive(10)
    rekey_received = await link.receive(10)
    assert isinstance(received, RxFrame) and isinstance(rekey_received, RxFrame)
    verifier = DioTimeVerifier(
        "active-generation-verifier",
        link,
        peer_origins={REMOTE.pubkey: {Stratum.NTS: SourceClass.NETWORK}},
        peer_accuracy_seconds={REMOTE.pubkey: 1},
        clock=clock.capability,
    )
    state = tracker(
        clock,
        verifier,
        policy(SourceClass.NETWORK, peers=frozenset({REMOTE.pubkey})),
    )
    assert state.adopt(verifier.verify(authenticate_dio(link, received)))
    assert state.current_time() == FLOOR
    original_elevate = link.elevate_time_generation
    entered = threading.Event()
    release = threading.Event()

    def blocking_elevate(signer: bytes, generation: object, *, elevate: object) -> object:
        assert callable(elevate)

        def blocked() -> object:
            entered.set()
            assert release.wait(1)
            return elevate()

        return original_elevate(signer, generation, elevate=blocked)

    link.elevate_time_generation = blocking_elevate  # type: ignore[assignment]
    reads: list[int | None] = []
    reader = threading.Thread(target=lambda: reads.append(state.current_time()))
    reader.start()
    assert entered.wait(1)
    rekey_done = threading.Event()

    def rekey() -> None:
        link.apply_authenticated_rekey(rekey_received)
        rekey_done.set()

    rekey_thread = threading.Thread(target=rekey)
    rekey_thread.start()
    assert not rekey_done.wait(0.05)
    release.set()
    reader.join(1)
    rekey_thread.join(1)
    assert reads == [FLOOR]
    assert state.current_time() is None
    assert state.last_rejection_reason == "current-network-signer-generation-retired"


@pytest.mark.asyncio
async def test_unrelated_peer_generation_retirement_does_not_revoke_active_time() -> None:
    clock = Clock()
    radio = QueueRadio()
    third = Identity.from_seed(bytes((value + 1) % 256 for value in reversed(range(32))))
    remote_peer = PeerIdentity.from_pubkey(REMOTE.pubkey)
    other_peer = PeerIdentity.from_pubkey(OTHER.pubkey)
    peers = {remote_peer.iid: remote_peer, other_peer.iid: other_peer}
    link = LinkLayer(
        radio=radio,
        identity=LOCAL,
        peer_lookup=peers.get,
        peer_lookup_all=lambda: list(peers.values()),
        receipt_clock=clock.capability,
    )
    option = DioTimeOption(Stratum.NTS, FLOOR)
    radio.frames.extend(
        [
            (signed_wire(REMOTE, dio_envelope(option), counter=230), -80, 2),
            (signed_wire(OTHER, dio_envelope(option, signer=OTHER), counter=1), -80, 2),
            (signed_wire(OTHER, encode_rekey_request(third.pubkey), counter=2), -80, 2),
        ]
    )
    received = await link.receive(10)
    unrelated_warmup = await link.receive(10)
    unrelated_rekey = await link.receive(10)
    assert (
        isinstance(received, RxFrame)
        and isinstance(unrelated_warmup, RxFrame)
        and isinstance(unrelated_rekey, RxFrame)
    )
    verifier = DioTimeVerifier(
        "unrelated-generation-verifier",
        link,
        peer_origins={REMOTE.pubkey: {Stratum.NTS: SourceClass.NETWORK}},
        peer_accuracy_seconds={REMOTE.pubkey: 1},
        clock=clock.capability,
    )
    state = tracker(
        clock,
        verifier,
        policy(SourceClass.NETWORK, peers=frozenset({REMOTE.pubkey})),
    )
    assert state.adopt(verifier.verify(authenticate_dio(link, received)))
    link.apply_authenticated_rekey(unrelated_rekey)
    assert state.current_time() == FLOOR


def test_public_floor_helpers_require_exact_transactional_verifier() -> None:
    verifier, admin = provision()
    old = verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 100).encode())

    class FakeVerifier:
        cleared = False

        def accepts(self, _metadata: object) -> bool:
            return True

    fake = FakeVerifier()
    with pytest.raises(TypeError, match="exact ProvisionVerifier"):
        evaluate_epoch_floor(FLOOR, old, verifier=fake)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="exact ProvisionVerifier"):
        effective_epoch_floor(FLOOR, old, verifier=fake)  # type: ignore[arg-type]

    entered = threading.Event()
    release = threading.Event()
    holder: dict[str, ProvisionVerifier] = {}
    race_admin = TimeAdmin("floor-race-admin")

    def persist(state: ProvisionRollbackState) -> None:
        if state.record_version == 2:
            entered.set()
            assert release.wait(1)

    race_verifier = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=race_admin.initialize_virgin_provision_state(lambda marker: marker),
        verify_integrity=lambda _wire: True,
        persist_rollback_state=persist,
        persist_clear=lambda _state: None,
        admin=race_admin,
    )
    holder["verifier"] = race_verifier
    first = race_verifier.install(
        race_admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 100).encode()
    )
    installer = threading.Thread(
        target=lambda: race_verifier.install(
            race_admin, ProvisionRecord(LOCAL.pubkey, 2, FLOOR + 500).encode()
        )
    )
    installer.start()
    assert entered.wait(1)
    # Persistence is pending outside the state lock, so the old transaction is
    # still authoritative and reads cannot deadlock behind the external hook.
    assert evaluate_epoch_floor(FLOOR, first, verifier=race_verifier).floor == FLOOR + 100
    release.set()
    installer.join(1)
    assert not installer.is_alive()
    current = race_verifier.current()
    assert current is not None
    assert evaluate_epoch_floor(FLOOR, current, verifier=race_verifier).floor == FLOOR + 500
    assert (
        evaluate_epoch_floor(FLOOR, first, verifier=race_verifier).provision_status
        is ProvisionEpochStatus.UNAUTHENTICATED
    )


def test_provision_external_hooks_do_not_hold_floor_or_tracker_locks() -> None:
    admin = TimeAdmin("threaded-hook-admin")
    holder: dict[str, object] = {}
    child_errors: list[RuntimeError] = []
    reads: list[object] = []
    phase = "install"

    def run_child(action: Callable[[], object]) -> None:
        thread = threading.Thread(target=lambda: reads.append(action()))
        thread.start()
        thread.join(0.5)
        assert not thread.is_alive()

    def attempt_nested_install() -> None:
        verifier = cast(ProvisionVerifier, holder["verifier"])
        try:
            verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 3, FLOOR + 3).encode())
        except RuntimeError as error:
            child_errors.append(error)

    def persist_record(_state: ProvisionRollbackState) -> None:
        if phase != "install":
            return
        verifier = cast(ProvisionVerifier, holder["verifier"])
        floor = cast(EpochFloorAuthority, holder["floor"])
        state = cast(StratumTracker, holder["tracker"])
        run_child(verifier.current)
        run_child(floor.current)
        run_child(state.status)
        nested = threading.Thread(target=attempt_nested_install)
        nested.start()
        nested.join(0.5)
        assert not nested.is_alive()

    def persist_clear(_state: ProvisionClearedState) -> None:
        if phase == "clear":
            nested = threading.Thread(target=attempt_nested_install)
            nested.start()
            nested.join(0.5)
            assert not nested.is_alive()

    verifier = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=admin.initialize_virgin_provision_state(lambda marker: marker),
        verify_integrity=lambda _wire: True,
        persist_rollback_state=persist_record,
        persist_clear=persist_clear,
        admin=admin,
    )
    clock = Clock()
    authority = provider(clock, SourceClass.GNSS)
    floor = EpochFloorAuthority(FLOOR, verifier=verifier)
    state = StratumTracker(
        authorities=(authority,),
        policy=policy(SourceClass.GNSS),
        floor_authority=floor,
        clock=clock.capability,
    )
    holder.update(verifier=verifier, floor=floor, tracker=state)
    with pytest.raises(RuntimeError, match="reentry"):
        verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 1).encode())
    assert verifier.current() is None
    assert child_errors and all("reentry" in str(error) for error in child_errors)
    assert len(reads) == 3

    phase = "none"
    with pytest.raises(RuntimeError, match="poisoned"):
        verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR + 1).encode())
    assert verifier.current() is None and verifier.cleared


@pytest.mark.asyncio
async def test_scheduled_and_custom_awaitables_are_cancelled_or_closed() -> None:
    mutated: list[str] = []
    tasks: list[asyncio.Task[None]] = []

    async def later(value: str) -> None:
        await asyncio.sleep(0)
        mutated.append(value)

    admin = TimeAdmin("scheduled-hook-admin")

    def scheduled_persist(_state: ProvisionRollbackState) -> object:
        task = asyncio.create_task(later("rollback"))
        tasks.append(task)
        return task

    verifier = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=admin.initialize_virgin_provision_state(lambda marker: marker),
        verify_integrity=lambda _wire: True,
        persist_rollback_state=scheduled_persist,  # type: ignore[arg-type]
        persist_clear=lambda _state: None,
        admin=admin,
    )
    with pytest.raises(TypeError, match="awaitable"):
        verifier.install(admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR).encode())
    await asyncio.sleep(0)
    assert tasks and all(task.cancelled() for task in tasks)
    assert not mutated and verifier.current() is None

    clear_admin = TimeAdmin("scheduled-clear-admin")

    def scheduled_clear(_state: ProvisionClearedState) -> object:
        task = asyncio.create_task(later("clear"))
        tasks.append(task)
        return task

    clear_verifier = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=clear_admin.initialize_virgin_provision_state(lambda marker: marker),
        verify_integrity=lambda _wire: True,
        persist_rollback_state=lambda _state: None,
        persist_clear=scheduled_clear,  # type: ignore[arg-type]
        admin=clear_admin,
    )
    clear_verifier.install(clear_admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR).encode())
    with pytest.raises(TypeError, match="awaitable"):
        clear_verifier.clear(clear_admin, reason="scheduled")
    await asyncio.sleep(0)
    assert tasks[-1].cancelled() and "clear" not in mutated
    assert clear_verifier.current() is None and clear_verifier.cleared

    loop = asyncio.get_running_loop()
    future: asyncio.Future[float] = loop.create_future()
    future_clock = MonotonicClock(lambda: future)  # type: ignore[arg-type,return-value]
    with pytest.raises(TypeError, match="awaitable"):
        future_clock()
    assert future.cancelled()

    integrity_future: asyncio.Future[bool] = loop.create_future()
    future_admin = TimeAdmin("future-integrity-admin")
    future_verifier = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=future_admin.initialize_virgin_provision_state(lambda marker: marker),
        verify_integrity=lambda _wire: integrity_future,  # type: ignore[arg-type,return-value]
        persist_rollback_state=lambda _state: None,
        persist_clear=lambda _state: None,
        admin=future_admin,
    )
    with pytest.raises(TypeError, match="awaitable"):
        future_verifier.install(future_admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR).encode())
    assert integrity_future.cancelled() and future_verifier.current() is None

    class CloseableAwaitable:
        closed = False

        def __await__(self):  # type: ignore[no-untyped-def]
            if False:
                yield None
            return 0.0

        def close(self) -> None:
            self.closed = True

    closeable = CloseableAwaitable()
    custom_clock = MonotonicClock(lambda: closeable)  # type: ignore[arg-type,return-value]
    with pytest.raises(TypeError, match="awaitable"):
        custom_clock()
    assert closeable.closed

    custom_admin = TimeAdmin("custom-persist-admin")
    custom_value = CloseableAwaitable()
    custom_verifier = ProvisionVerifier(
        expected_board_identity=LOCAL.pubkey,
        rollback_state=custom_admin.initialize_virgin_provision_state(lambda marker: marker),
        verify_integrity=lambda _wire: True,
        persist_rollback_state=lambda _state: custom_value,  # type: ignore[arg-type]
        persist_clear=lambda _state: None,
        admin=custom_admin,
    )
    with pytest.raises(TypeError, match="awaitable"):
        custom_verifier.install(custom_admin, ProvisionRecord(LOCAL.pubkey, 1, FLOOR).encode())
    assert custom_value.closed and custom_verifier.current() is None


@pytest.mark.asyncio
async def test_link_receipt_clock_requires_exact_immutable_capability() -> None:
    radio = QueueRadio()
    clock = Clock()
    peer = PeerIdentity.from_pubkey(REMOTE.pubkey)
    with pytest.raises(TypeError, match="exact MonotonicClock"):
        LinkLayer(
            radio=radio,
            identity=LOCAL,
            peer_lookup=lambda _hint: peer,
            receipt_clock=lambda: 0.0,  # type: ignore[arg-type]
        )

    class ImpostorClock:
        domain_identity = clock.capability.domain_identity

        def __call__(self) -> float:
            return 0.0

    with pytest.raises(TypeError, match="exact MonotonicClock"):
        LinkLayer(
            radio=radio,
            identity=LOCAL,
            peer_lookup=lambda _hint: peer,
            receipt_clock=ImpostorClock(),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="derived"):
        LinkLayer(
            radio=radio,
            identity=LOCAL,
            peer_lookup=lambda _hint: peer,
            receipt_clock=clock.capability,
            receipt_clock_domain=clock.capability.domain_identity,
        )

    link = receiver(radio, clock)
    object.__setattr__(link, "_receipt_clock", lambda: 0.0)
    radio.frames.append(
        (signed_wire(REMOTE, dio_envelope(DioTimeOption(Stratum.NTS, FLOOR)), counter=240), -80, 2)
    )
    with pytest.raises(LinkSecurityClockError) as failure:
        await link.receive(10)
    assert isinstance(failure.value.__cause__, RuntimeError)
    assert "binding changed" in str(failure.value.__cause__)
    assert link._receipt_clock_failed
    assert not link._verified_receipts
    assert not link._authenticated_dio_issuances
    with pytest.raises(LinkSecurityClockError, match="disabled"):
        link._receipt_now()


@pytest.mark.asyncio
async def test_active_tracker_fails_closed_if_link_clock_binding_changes() -> None:
    clock = Clock()
    radio = QueueRadio()
    link = receiver(radio, clock)
    option = DioTimeOption(Stratum.NTS, FLOOR)
    radio.frames.append((signed_wire(REMOTE, dio_envelope(option), counter=250), -80, 2))
    received = await link.receive(10)
    assert isinstance(received, RxFrame)
    verifier = DioTimeVerifier(
        "clock-binding-verifier",
        link,
        peer_origins={REMOTE.pubkey: {Stratum.NTS: SourceClass.NETWORK}},
        peer_accuracy_seconds={REMOTE.pubkey: 1},
        clock=clock.capability,
    )
    state = tracker(
        clock,
        verifier,
        policy(SourceClass.NETWORK, peers=frozenset({REMOTE.pubkey})),
    )
    assert state.adopt(verifier.verify(authenticate_dio(link, received)))
    object.__setattr__(link, "_clock_domain", object())
    assert state.current_time() is None
    assert state.last_rejection_reason == "current-network-signer-generation-retired"
