# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv6Address, IPv6Network

import cbor2
import pytest
from hypothesis import given
from hypothesis import strategies as st

from lichen.crypto import schnorr48
from lichen.crypto.identity import Identity
from lichen.gateway.tunnel_auth import (
    MAX_U64,
    SCHNORR48_ED25519_ALG,
    AuthorizationResult,
    RootTunnelAuthorizer,
    TunnelAuthError,
    TunnelAuthorization,
    TunnelAuthorizationPayload,
    TunnelAuthorizationTable,
    TunnelDenial,
    TunnelDirection,
    TunnelEgressGateway,
    compute_route_hash,
    create_tunnel_authorization,
)
from lichen.ipv6.packet import IPv6Header, IPv6Packet, NextHeader

NOW = 1_900_000_000
ROOT = Identity.from_seed(bytes(range(32)))
OTHER_ROOT = Identity.from_seed(bytes(range(1, 33)))
EGRESS = Identity.from_seed(bytes(range(32, 64)))
OTHER_EGRESS = Identity.from_seed(bytes(range(64, 96)))
TARGET = IPv6Network("0200:1234:5600::/40")
ROUTE = (
    IPv6Address("0200::0102:0304:0506:0708"),
    IPv6Address(EGRESS.ygg_addr),
)


def _authorization(
    *,
    identity: Identity = ROOT,
    target: IPv6Network = TARGET,
    route: tuple[IPv6Address, ...] = ROUTE,
    path_seq: int = 7,
    expiry: int = NOW + 300,
    egress_iid: bytes = EGRESS.iid,
) -> TunnelAuthorization:
    return create_tunnel_authorization(identity, target, route, path_seq, expiry, egress_iid)


def _table(*, max_entries: int = 256, max_history: int | None = None) -> TunnelAuthorizationTable:
    return TunnelAuthorizationTable(
        egress_iid=EGRESS.iid,
        root_iid=ROOT.iid,
        root_pubkey=ROOT.pubkey,
        max_entries=max_entries,
        max_history=max_history,
    )


def _post(
    table: TunnelAuthorizationTable,
    authorization: TunnelAuthorization,
    *,
    now: int = NOW,
    authenticated: bool = True,
    sender: bytes = ROOT.iid,
) -> AuthorizationResult:
    return table.receive_post(
        authorization.to_cose_sign1(),
        oscore_authenticated=authenticated,
        oscore_sender_iid=sender,
        now=now,
    )


def _packet(source: str = "0200:1234:56ab::1", destination: str = "2001:db8::1") -> IPv6Packet:
    return IPv6Packet(
        IPv6Header(
            src_addr=IPv6Address(source),
            dst_addr=IPv6Address(destination),
            next_header=NextHeader.UDP,
        ),
        b"payload",
    )


def _replace_cose(authorization: TunnelAuthorization, index: int, value: object) -> bytes:
    decoded = cbor2.loads(authorization.to_cose_sign1())
    decoded[index] = value
    return cbor2.dumps(decoded, canonical=True)


def test_canonical_fixed_vector_and_independent_signature_oracle() -> None:
    authorization = _authorization(path_seq=0x01020304, expiry=2_000_000_000)
    # Fixed regression vector built from the field encodings in spec 06 section 8.11.
    expected = bytes.fromhex(
        "8447a1013a00010000a10448ed4242ead4ac69485833a601450200123456"
        "02182803502e7e354dbb13f833200751c697c97e6a041a01020304051a77359400"
        "0648b19edad2958934e15830bdd50fa020071c849b14b9ebda98e6c54106c7738"
        "e788c877fb119d1c0044f671752dbe400d12ba3bda131f85fe72209"
    )
    assert authorization.to_cose_sign1() == expected

    protected, unprotected, payload, signature = cbor2.loads(expected)
    assert cbor2.loads(protected) == {1: SCHNORR48_ED25519_ALG}
    assert unprotected == {4: ROOT.iid}
    assert cbor2.loads(payload) == {
        1: bytes.fromhex("0200123456"),
        2: 40,
        3: bytes.fromhex("2e7e354dbb13f833200751c697c97e6a"),
        4: 0x01020304,
        5: 2_000_000_000,
        6: EGRESS.iid,
    }
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
    from hashlib import sha256

    assert schnorr48.verify(ROOT.pubkey, sha256(sig_structure).digest(), signature)


def test_root_route_installation_emits_oscore_post_only_for_bound_egress() -> None:
    requests = []
    result = RootTunnelAuthorizer(ROOT).route_installed(
        target=TARGET,
        route=ROUTE,
        path_seq=7,
        expiry=NOW + 10,
        egress_iid=EGRESS.iid,
        egress_capable=True,
        send=lambda request: requests.append(request) is None,
    )
    assert result.allowed
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert request.resource == "/.well-known/tunnel-auth"
    assert request.require_oscore
    assert request.peer_iid == EGRESS.iid
    assert TunnelAuthorization.from_cose_sign1(request.payload).verify(ROOT.pubkey)

    assert (
        not RootTunnelAuthorizer(ROOT)
        .route_installed(
            target=TARGET,
            route=ROUTE,
            path_seq=8,
            expiry=NOW + 10,
            egress_iid=EGRESS.iid,
            egress_capable=False,
            send=lambda _: pytest.fail("non-egress route must not emit an authorization"),
        )
        .allowed
    )
    failed = RootTunnelAuthorizer(ROOT).route_installed(
        target=TARGET,
        route=ROUTE,
        path_seq=8,
        expiry=NOW + 10,
        egress_iid=EGRESS.iid,
        egress_capable=True,
        send=lambda _: (_ for _ in ()).throw(OSError("transport down")),
    )
    assert failed.denial is TunnelDenial.DELIVERY_FAILED


@pytest.mark.parametrize(
    ("authenticated", "sender", "reason"),
    [
        (False, ROOT.iid, TunnelDenial.OSCORE_REQUIRED),
        (True, OTHER_ROOT.iid, TunnelDenial.WRONG_ROOT),
    ],
)
def test_post_requires_pairwise_oscore_root_binding(
    authenticated: bool, sender: bytes, reason: TunnelDenial
) -> None:
    table = _table()
    result = _post(table, _authorization(), authenticated=authenticated, sender=sender)
    assert result == AuthorizationResult.deny(reason)
    assert table.size == 0


def test_post_validates_signature_egress_expiry_and_is_atomic() -> None:
    table = _table()
    good = _authorization()
    assert _post(table, good).allowed
    assert table.size == 1

    tampered = bytearray(good.signature)
    tampered[-1] ^= 1
    bad_signature = TunnelAuthorization(
        good.payload, good.root_iid, bytes(tampered), good.protected, good.payload_bytes
    )
    assert _post(table, bad_signature).denial is TunnelDenial.SIGNATURE
    assert table.size == 1

    wrong_egress = _authorization(
        route=(ROUTE[0], IPv6Address(OTHER_EGRESS.ygg_addr)),
        egress_iid=OTHER_EGRESS.iid,
        path_seq=8,
    )
    assert _post(table, wrong_egress).denial is TunnelDenial.WRONG_EGRESS
    assert table.size == 1

    expired = _authorization(path_seq=8, expiry=NOW)
    assert _post(table, expired).denial is TunnelDenial.EXPIRED
    assert table.size == 1


def test_strict_cose_rejects_wrong_algorithm_unknown_headers_and_noncanonical() -> None:
    authorization = _authorization()
    table = _table()
    wrong_alg = cbor2.dumps({1: -65536}, canonical=True)
    assert (
        table.receive_post(
            _replace_cose(authorization, 0, wrong_alg),
            oscore_authenticated=True,
            oscore_sender_iid=ROOT.iid,
            now=NOW,
        ).denial
        is TunnelDenial.ALGORITHM
    )

    assert (
        table.receive_post(
            _replace_cose(authorization, 1, {4: ROOT.iid, 99: 0}),
            oscore_authenticated=True,
            oscore_sender_iid=ROOT.iid,
            now=NOW,
        ).denial
        is TunnelDenial.MALFORMED
    )

    # 0x98 0x04 is a valid but non-shortest array header, hence non-deterministic CBOR.
    noncanonical = b"\x98\x04" + authorization.to_cose_sign1()[1:]
    assert (
        table.receive_post(
            noncanonical,
            oscore_authenticated=True,
            oscore_sender_iid=ROOT.iid,
            now=NOW,
        ).denial
        is TunnelDenial.MALFORMED
    )
    assert table.size == 0


def test_replay_revocation_and_fresher_rearm() -> None:
    table = _table()
    first = _authorization(path_seq=7)
    assert _post(table, first).allowed
    assert _post(table, first).denial is TunnelDenial.REPLAY

    table.revoke(TARGET, first.payload.route_hash, 9)
    assert _post(table, _authorization(path_seq=9)).denial is TunnelDenial.REVOKED
    assert _post(table, _authorization(path_seq=10)).allowed
    assert _post(table, _authorization(path_seq=9)).denial is TunnelDenial.REPLAY


def test_lru_table_is_bounded_but_retains_replay_floor() -> None:
    table = _table(max_entries=1, max_history=2)
    first = _authorization(target=IPv6Network("0200:1111::/32"), path_seq=5)
    second = _authorization(target=IPv6Network("0200:2222::/32"), path_seq=1)
    assert _post(table, first).allowed
    assert _post(table, second).allowed
    assert table.size == 1
    assert _post(table, first).denial is TunnelDenial.REPLAY

    third = _authorization(target=IPv6Network("0200:3333::/32"), path_seq=1)
    assert _post(table, third).denial is TunnelDenial.CAPACITY
    assert table.size == 1


def test_root_change_and_clock_rollback_fail_closed() -> None:
    table = _table()
    assert _post(table, _authorization()).allowed
    table.change_root(OTHER_ROOT.iid, OTHER_ROOT.pubkey)
    assert table.size == 0
    old = table.receive_post(
        _authorization(path_seq=8).to_cose_sign1(),
        oscore_authenticated=True,
        oscore_sender_iid=ROOT.iid,
        now=NOW,
    )
    assert old.denial is TunnelDenial.WRONG_ROOT

    new = _authorization(identity=OTHER_ROOT, path_seq=1)
    assert table.receive_post(
        new.to_cose_sign1(),
        oscore_authenticated=True,
        oscore_sender_iid=OTHER_ROOT.iid,
        now=NOW,
    ).allowed
    rollback = table.authorize_decapsulation(
        _packet(), ROUTE, direction=TunnelDirection.MESH_TO_EXTERNAL, now=NOW - 1
    )
    assert rollback.denial is TunnelDenial.CLOCK_REGRESSION
    assert table.size == 0
    assert (
        table.receive_post(
            new.to_cose_sign1(),
            oscore_authenticated=True,
            oscore_sender_iid=OTHER_ROOT.iid,
            now=NOW,
        ).denial
        is TunnelDenial.REPLAY
    )


def test_egress_gateway_enforces_route_source_destination_and_direction() -> None:
    table = _table()
    assert _post(table, _authorization()).allowed
    gateway = TunnelEgressGateway(table)
    sent: list[IPv6Packet] = []

    result = gateway.forward(
        _packet(),
        ROUTE,
        direction=TunnelDirection.MESH_TO_EXTERNAL,
        now=NOW,
        external_send=lambda packet: sent.append(packet) is None,
    )
    assert result.allowed
    assert len(sent) == 1

    cases = [
        (
            _packet(),
            tuple(reversed(ROUTE)),
            TunnelDirection.MESH_TO_EXTERNAL,
            TunnelDenial.INVALID_ROUTE,
        ),
        (_packet(), ROUTE, TunnelDirection.EXTERNAL_TO_MESH, TunnelDenial.WRONG_DIRECTION),
        (
            _packet("0200:9999::1"),
            ROUTE,
            TunnelDirection.MESH_TO_EXTERNAL,
            TunnelDenial.NO_AUTHORIZATION,
        ),
        (
            _packet(destination="0200:abcd::1"),
            ROUTE,
            TunnelDirection.MESH_TO_EXTERNAL,
            TunnelDenial.DESTINATION_SCOPE,
        ),
    ]
    for packet, route, direction, reason in cases:
        before = len(sent)
        decision = gateway.forward(
            packet,
            route,
            direction=direction,
            now=NOW,
            external_send=lambda inner: sent.append(inner) is None,
        )
        assert decision.denial is reason
        assert len(sent) == before


def test_data_plane_reports_expiry_and_contains_sink_failure() -> None:
    table = _table()
    assert _post(table, _authorization(expiry=NOW + 1)).allowed
    assert (
        table.authorize_decapsulation(
            _packet(), ROUTE, direction=TunnelDirection.MESH_TO_EXTERNAL, now=NOW + 1
        ).denial
        is TunnelDenial.EXPIRED
    )

    assert _post(table, _authorization(path_seq=8, expiry=NOW + 20), now=NOW + 1).allowed
    calls = 0

    def fail(_: IPv6Packet) -> bool:
        nonlocal calls
        calls += 1
        raise OSError("TUN unavailable")

    result = TunnelEgressGateway(table).forward(
        _packet(),
        ROUTE,
        direction=TunnelDirection.MESH_TO_EXTERNAL,
        now=NOW + 1,
        external_send=fail,
    )
    assert result.denial is TunnelDenial.DELIVERY_FAILED
    assert calls == 1


def test_route_validation_rejects_empty_long_looped_and_wrong_egress() -> None:
    with pytest.raises(TunnelAuthError):
        compute_route_hash(())
    with pytest.raises(TunnelAuthError):
        compute_route_hash(tuple(bytes([i]) * 8 for i in range(9)))
    with pytest.raises(TunnelAuthError):
        compute_route_hash((bytes(8), bytes(8)))
    with pytest.raises((TunnelAuthError, IndexError)):
        create_tunnel_authorization(ROOT, TARGET, (), 1, NOW + 1, EGRESS.iid)
    with pytest.raises(TunnelAuthError):
        create_tunnel_authorization(ROOT, TARGET, ROUTE, 1, NOW + 1, OTHER_EGRESS.iid)


def test_concurrent_sequences_commit_only_monotonic_authority() -> None:
    table = _table()
    grants = [_authorization(path_seq=sequence) for sequence in range(1, 33)]
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda grant: _post(table, grant), grants))
    assert any(result.allowed for result in results)
    assert table.size == 1
    assert _post(table, _authorization(path_seq=32)).denial is TunnelDenial.REPLAY
    assert _post(table, _authorization(path_seq=33)).allowed


@given(prefix_len=st.integers(min_value=0, max_value=128), raw=st.binary(min_size=16, max_size=16))
def test_payload_prefix_property_round_trip(prefix_len: int, raw: bytes) -> None:
    network = IPv6Network((IPv6Address(raw), prefix_len), strict=False)
    payload = TunnelAuthorizationPayload(network, bytes(range(16)), 0, MAX_U64, EGRESS.iid)
    assert TunnelAuthorizationPayload.from_cbor(payload.to_cbor()) == payload


@given(data=st.binary(max_size=256))
def test_arbitrary_cose_input_never_mutates_or_escapes(data: bytes) -> None:
    table = _table()
    result = table.receive_post(
        data,
        oscore_authenticated=True,
        oscore_sender_iid=ROOT.iid,
        now=NOW,
    )
    assert not result.allowed
    assert result.response_code == 403
    assert table.size == 0
