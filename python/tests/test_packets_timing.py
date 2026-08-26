# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for packets/timing oracles against generated vectors."""

from __future__ import annotations

import asyncio
import hashlib
import json
import runpy
import warnings
from collections.abc import Callable
from ipaddress import IPv6Address
from pathlib import Path
from typing import Any, cast

import pytest

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"


def _load(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((VECTORS_DIR / name).read_text()))


def _execute_time_trust_vectors(trust: dict[str, Any]) -> None:
    """Execute link receipt and each vector's specified admission boundary."""
    from lichen.crypto.identity import Identity, PeerIdentity
    from lichen.ipv6.packet import IPv6Header
    from lichen.link.frame import LichenFrame
    from lichen.link.link_layer import LinkLayer, ReceiveError, RxFrame
    from lichen.schc.codec import SchcError
    from lichen.timing.time_sync import (
        DioTimeVerifier,
        EpochFloorAuthority,
        MonotonicClock,
        ProvisionClearedState,
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

    class Clock:
        value = 0.0

        def __init__(self) -> None:
            self.capability = MonotonicClock(self)

        def __call__(self) -> float:
            return self.value

    class Radio:
        def __init__(self, frames: list[tuple[bytes, int, int]]) -> None:
            self.frames = frames

        async def receive(
            self, _timeout_ms: int, channel: int = 0
        ) -> tuple[bytes, int, int] | None:
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

    local = Identity.from_seed(bytes(range(32)))
    remote_key = bytes.fromhex("29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7")

    async def execute_network(case: dict[str, Any]) -> None:
        wire = bytes.fromhex(case["wire_hex"])
        copies = case.get("receive_count", 1)
        radio = Radio([(wire, -80, 2)] * copies)
        remote = PeerIdentity.from_pubkey(remote_key)
        case_peer = PeerIdentity.from_pubkey(bytes.fromhex(case["signer_pubkey_hex"]))
        trusted_peers = [remote]
        if case_peer.pubkey != remote.pubkey:
            trusted_peers.append(case_peer)

        def peer_for_iid(iid: bytes) -> PeerIdentity | None:
            return next((peer for peer in trusted_peers if peer.iid == iid), None)

        clock = Clock()
        link = LinkLayer(
            radio=radio,
            identity=local,
            peer_lookup=peer_for_iid,
            peer_lookup_all=lambda: trusted_peers,
            receipt_clock=clock.capability,
        )
        received_values = [await link.receive(10) for _ in range(copies)]
        received = received_values[0]
        if case["rejection_stage"] == "link_receive":
            rejected = received_values[-1]
            assert isinstance(rejected, ReceiveError)
            assert rejected.name == case["rejection"]
            return
        assert isinstance(received, RxFrame), case["name"]
        assert received.sender_pubkey.hex() == case["signer_pubkey_hex"]
        assert (received.epoch << 16) | received.seqnum == case["counter"]
        envelope = trust["dio_envelope"]
        if case.get("rejection") == "source_signer_mismatch":
            frame = LichenFrame.from_bytes(wire)
            assert frame.payload[:2] == b"\x14\xff"
            source_iid = frame.payload[2 + 16 : 2 + 24]
            assert source_iid != case_peer.iid
            assert case["rejection_stage"] == "dio_admission"
            return
        try:
            authenticated = link.accept_authenticated_dio(
                received,
                expected_rpl_instance_id=case.get(
                    "expected_rpl_instance_id", envelope["rpl_instance_id"]
                ),
                expected_dodag_id=IPv6Address(case.get("expected_dodag_id", envelope["dodag_id"])),
                expected_mop=case.get("expected_mop", envelope["mop"]),
                expected_role=case.get("expected_role", envelope["role"]),
            )
        except (ValueError, SchcError) as error:
            assert case["rejection_stage"] == "dio_admission"
            assert str(error) == case["rejection"]
            with pytest.raises(ValueError, match="verified receipt"):
                link.accept_authenticated_dio(
                    received,
                    expected_rpl_instance_id=envelope["rpl_instance_id"],
                    expected_dodag_id=IPv6Address(envelope["dodag_id"]),
                    expected_mop=envelope["mop"],
                    expected_role=envelope["role"],
                )
            return
        assert case["rejection_stage"] != "dio_admission"
        assert authenticated.ipv6.hex() == case["ipv6_hex"]
        if case["expected_authoritative"]:
            assert authenticated.link_payload.hex() == envelope["link_payload_hex"]
            header = IPv6Header.from_bytes(authenticated.ipv6)
            assert str(header.src_addr) == envelope["src_ipv6"]
            assert str(header.dst_addr) == envelope["dst_ipv6"]
            dio = authenticated.dio
            assert dio.rpl_instance_id == envelope["rpl_instance_id"]
            assert str(dio.dodag_id) == envelope["dodag_id"]
            assert dio.mode_of_operation == envelope["mop"]
        _, peer_context = link.accept_authenticated_schc_dio(authenticated)
        assert peer_context.allows_dodag_join
        verifier = DioTimeVerifier(
            "vector-dio",
            link,
            peer_origins={remote_key: {Stratum.GNSS_GPSD: SourceClass.GNSS}},
            peer_accuracy_seconds={remote_key: 1},
            clock=clock.capability,
        )
        if case["rejection_stage"] == "time_verifier":
            try:
                verifier.verify(authenticated)
            except ValueError as error:
                assert str(error) == case["rejection"], case["name"]
                return
            raise AssertionError(f"{case['name']} unexpectedly elevated")
        sample = verifier.verify(authenticated)
        assert sample.evidence.signer_public_key is not None
        assert sample.evidence.signer_public_key.hex() == case["signer_pubkey_hex"]
        assert sample.evidence.replay_counter == case["counter"]
        assert sample.evidence.signer_key_generation is authenticated.key_generation
        assert sample.evidence.clock_domain_identity is authenticated.clock_domain_identity
        assert list(sample.evidence.option_span or ()) == envelope["option_ipv6_span"]
        assert sample.source_class.value == envelope["origin_source"]
        assert sample.evidence.transport_class is not None
        assert sample.evidence.transport_class.value == envelope["transport_source"]
        tracker = StratumTracker(
            authorities=(verifier,),
            policy=SourcePrecedencePolicy(
                accepted_wall_clock_sources=frozenset({SourceClass.GNSS, SourceClass.NETWORK}),
                authorized_network_peers=frozenset({remote_key}),
            ),
            floor_authority=EpochFloorAuthority(1_700_000_000),
            clock=clock.capability,
        )
        assert tracker.adopt(sample) is case["expected_authoritative"]

    for network_case in trust["network_cases"]:
        asyncio.run(execute_network(network_case))

    for case in trust["provider_cases"]:
        clock = Clock()
        source = SourceClass(case["source"])
        authority = TimeProvider(case["name"], frozenset({source}), clock=clock.capability)
        stratum = Stratum(case["stratum"])
        try:
            sample = authority.sample(
                source_class=source,
                source_name=case["name"],
                unix_time=1_700_000_000 + case.get("raw_lead_seconds", 0),
                stratum=stratum,
                accuracy_seconds=1,
                source_valid=case.get("source_valid", True),
                policy_accepted=True,
                gnss_time_valid=case.get("gnss_time_valid", True),
                gnss_position_valid=case.get("gnss_position_valid"),
                rtc_initialized=case.get("rtc_initialized"),
                rtc_age_seconds=(
                    case.get("rtc_age_seconds", 0) if source is SourceClass.INTERNAL_RTC else None
                ),
                network_protocol=case.get("network_protocol"),
                network_authenticated=case.get("network_authenticated"),
                source_subtype=case.get("source_subtype"),
                source_subtype_verified=case.get("source_subtype_verified"),
                quality=case.get("quality"),
            )
        except ValueError as error:
            assert case["rejection_stage"] == "provider"
            assert str(error) == case["rejection"]
            continue
        assert case["rejection_stage"] != "provider"
        clock.value = float(case.get("observation_delay_seconds", 0))
        state = StratumTracker(
            authorities=(authority,),
            policy=SourcePrecedencePolicy(
                accepted_wall_clock_sources=frozenset({source}),
                max_sample_age_s=case.get("maximum_sample_age_seconds", 300),
                max_initial_epoch_lead_s=case.get("maximum_initial_lead_seconds", 1000),
            ),
            floor_authority=EpochFloorAuthority(1_700_000_000),
            clock=clock.capability,
        )
        adopted = state.adopt(sample)
        if case.get("authoritative_read") and adopted:
            clock.value = float(case["sample_age_seconds"])
            adopted = state.current_time() is not None
        assert adopted is case["expected_authoritative"], case["name"]
        assert state.last_rejection_reason == case["rejection"], case["name"]

    correction_clock = Clock()
    correction_authority = TimeProvider(
        "vector-correction",
        frozenset({SourceClass.GNSS}),
        clock=correction_clock.capability,
    )

    def vector_gnss(timestamp: int) -> TimeSample:
        return correction_authority.sample(
            source_class=SourceClass.GNSS,
            source_name="vector-gnss",
            unix_time=timestamp,
            stratum=Stratum.GNSS_GPSD,
            accuracy_seconds=1,
            source_valid=True,
            policy_accepted=True,
            gnss_time_valid=True,
        )

    for case in trust["correction_cases"]:
        correction_clock.value = 0
        correction_policy = case["policy"]
        state = StratumTracker(
            authorities=(correction_authority,),
            policy=SourcePrecedencePolicy(
                accepted_wall_clock_sources=frozenset({SourceClass.GNSS}),
                max_sample_age_s=correction_policy["max_sample_age_s"],
                max_forward_step_s=correction_policy["max_forward_step_s"],
                max_cumulative_forward_correction_s=correction_policy[
                    "max_cumulative_forward_correction_s"
                ],
                max_correction_rate_ppm=correction_policy["max_correction_rate_ppm"],
            ),
            floor_authority=EpochFloorAuthority(1_700_000_000),
            clock=correction_clock.capability,
        )
        for transition in case["transitions"]:
            correction_clock.value = transition["clock"]
            if transition["action"] == "sample":
                result = state.adopt(vector_gnss(transition["timestamp"]))
            elif transition["action"] == "expire":
                result = state.current_time() is not None
            else:
                assert transition["action"] == "clear"
                state.clear(transition["rejection"])
                result = False
            assert result is transition["accepted"], case["name"]
            assert state.last_rejection_reason == transition["rejection"], case["name"]

    board, other = bytes(range(32)), bytes(range(32, 64))
    for case in trust["provision_cases"]:
        admin = TimeAdmin(f"vector-admin:{case['name']}")
        if case["action"] == "virgin_noop_reject":
            with pytest.raises(RuntimeError, match=case["status"]):
                admin.initialize_virgin_provision_state(lambda _marker: None)
            continue
        if case["action"] == "virgin_reuse_reject":
            virgin = admin.initialize_virgin_provision_state(lambda marker: marker)
            ProvisionVerifier(
                expected_board_identity=board,
                rollback_state=virgin,
                verify_integrity=lambda _wire: True,
                persist_rollback_state=lambda _state: None,
                persist_clear=lambda _state: None,
                admin=admin,
            )
            with pytest.raises(ValueError, match=case["status"]):
                ProvisionVerifier(
                    expected_board_identity=board,
                    rollback_state=virgin,
                    verify_integrity=lambda _wire: True,
                    persist_rollback_state=lambda _state: None,
                    persist_clear=lambda _state: None,
                    admin=admin,
                )
            continue
        if case["action"] == "raw_integer":
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                floor = effective_epoch_floor(case["build_epoch"], case["provision_epoch"])
            assert floor == case["expected_floor"]
            assert case["status"] == "unauthenticated"
            continue
        minimum = case.get("minimum_record_version")
        initial: ProvisionRollbackState | ProvisionVirginState
        if minimum is None:
            initial = admin.initialize_virgin_provision_state(lambda marker: marker)
        else:
            initial_record = ProvisionRecord(board, minimum, case["build_epoch"])
            initial_wire = initial_record.encode()
            initial = ProvisionRollbackState(
                minimum,
                case["build_epoch"],
                hashlib.sha256(initial_wire).digest(),
                initial_wire,
            )
        persisted: list[ProvisionRollbackState] = []
        cleared_persisted: list[ProvisionClearedState] = []
        verifier = ProvisionVerifier(
            expected_board_identity=board,
            rollback_state=initial,
            verify_integrity=lambda _wire: True,
            persist_rollback_state=persisted.append,
            persist_clear=cleared_persisted.append,
            admin=admin,
        )
        identity = board if case["record_board"] == "expected" else other
        wire = ProvisionRecord(identity, case["record_version"], case["provision_epoch"]).encode()
        if case["action"] == "clear_reboot_reactivate":
            verifier.install(admin, wire)
            verifier.clear(admin, reason="vector-clear")

            def vector_integrity(value: bytes, expected: bytes = wire) -> bool:
                return value == expected or value.startswith(b"LICHEN-PROVISION-CLEARED-V1\x00")

            rebooted = ProvisionVerifier(
                expected_board_identity=board,
                rollback_state=cleared_persisted[-1],
                verify_integrity=vector_integrity,
                persist_rollback_state=persisted.append,
                persist_clear=cleared_persisted.append,
                admin=admin,
            )
            assert rebooted.cleared and rebooted.current() is None
            restored = rebooted.install(admin, wire)
            floor_result = evaluate_epoch_floor(case["build_epoch"], restored, verifier=rebooted)
            assert floor_result.floor == case["expected_floor"]
            assert floor_result.provision_status.value == case["status"]
            assert persisted[-1].encoded_record == wire
            continue
        if case["action"] == "install_reject":
            try:
                verifier.install(admin, wire)
            except ValueError as error:
                assert str(error) == case["status"]
            else:
                raise AssertionError(f"{case['name']} unexpectedly installed")
            assert case["expected_floor"] == case["build_epoch"]
            continue
        assert case["action"] == "install_accept"
        metadata = verifier.install(admin, wire)
        floor_result = evaluate_epoch_floor(case["build_epoch"], metadata, verifier=verifier)
        assert floor_result.floor == case["expected_floor"]
        assert floor_result.provision_status.value == case["status"]
        assert persisted[-1].encoded_record == wire


def test_packets_formats_vectors_against_oracle() -> None:
    doc = _load("packets-formats.json")
    assert doc["format_version"] == 2
    assert len(doc["vectors"]) == 14
    by_name = {vector["name"]: vector for vector in doc["vectors"]}
    walkthrough = by_name["complete_packet_example_link_frame"]
    assert walkthrough["app_payload_len"] == 16
    assert walkthrough["schc_packet_len"] == 43
    assert walkthrough["l2_payload_len"] == 44
    assert walkthrough["body_bytes"] == 106
    assert walkthrough["total_on_wire"] == 107
    assert walkthrough["link_frame"] == {
        "Length": 106,
        "LLSec": 0xA1,
        "Epoch": 0x01,
        "SeqNum": 0x0042,
        "DstAddr": 0x0001,
        "signer_eui64_len": 8,
        "payload_dispatch": 0x14,
        "payload_len": 44,
        "signature_len": 48,
        "total_on_wire": 107,
    }
    assert 106 == 1 + 1 + 2 + 2 + 8 + 44 + 48

    summary = by_name["packet_size_summary"]
    assert summary["summary"] == {
        "app_payload": 16,
        "security_e2e": 0,
        "transport_network": 27,
        "routing_overhead": 3,
        "link_security": 61,
        "total": 107,
    }
    assert summary["link_security_breakdown"] == {
        "Length": 1,
        "LLSec": 1,
        "Epoch": 1,
        "SeqNum": 2,
        "SignerEui64": 8,
        "Signature": 48,
    }
    assert sum(summary["link_security_breakdown"].values()) == 61

    dio = by_name["rpl_dio_skeleton"]
    dio_bytes = bytes.fromhex(dio["example_hex"])
    assert dio["example_len"] == 27
    assert dio_bytes == bytes.fromhex(
        "000701000800000000000000000000000000000000000000130103"
    )
    assert dio["fields"] == {
        "link_layer": ["Len", "LLSec", "Epoch", "SeqNum", "SignerEUI64", "Payload", "Sig"],
        "ipv6_compressed": [
            "validated SCHC Rule 255",
            "full IPv6 header",
            "destination ff02::1a",
        ],
        "icmpv6": {"Type": 155, "Code": 1, "label": "DIO"},
        "dio_payload": [
            "RPLInstanceID",
            "Version",
            "Rank",
            "G/MOP/Prf",
            "DTSN",
            "Flags",
            "Reserved",
            "DODAGID",
        ],
        "options": ["Rule-Version 0x13/0x01/0x03 (mandatory)"],
    }
    assert dio["fields"]["options"] == ["Rule-Version 0x13/0x01/0x03 (mandatory)"]

    assert by_name["dio_rank_0"]["hex"] == (
        "000000000800000000000000000000000000000000000000130103"
    )
    assert by_name["dio_rank_256"]["hex"] == (
        "000001000800000000000000000000000000000000000000130103"
    )
    assert by_name["dio_rank_65535"]["hex"] == (
        "0000ffff0800000000000000000000000000000000000000130103"
    )

    from lichen.packets.formats import (
        COMPLETE_PACKET_EXAMPLE,
        PACKET_SIZE_SUMMARY,
        validate_complete_example,
    )

    assert validate_complete_example(COMPLETE_PACKET_EXAMPLE["link_frame"])  # type: ignore[arg-type]
    assert COMPLETE_PACKET_EXAMPLE["link_frame"] == walkthrough["link_frame"]
    assert summary["summary"] == PACKET_SIZE_SUMMARY


def test_packets_timing_vectors_against_oracle() -> None:
    doc = _load("packets-timing.json")
    assert doc["format_version"] == 2
    assert len(doc["vectors"]) == 38
    assert len({vector["name"] for vector in doc["vectors"]}) == len(doc["vectors"])
    assert all({"name", "description", "category"} <= vector.keys() for vector in doc["vectors"])
    assert {vector["category"] for vector in doc["vectors"]} == {
        "airtime",
        "airtime_sf9",
        "csma_backoff",
        "csma_params",
        "csma_retry",
        "dao_sequence",
        "dao_timing",
        "data_traffic",
        "density_startup",
        "desync_fsm",
        "dio_time_option",
        "duty_cycle",
        "duty_cycle_usage",
        "sfn_delta",
        "sfn_slot",
        "tdma_constants",
        "time_adoption",
        "monotonic_time",
        "time_stratum",
        "time_sync",
        "time_sync_trust",
        "trickle_constants",
        "trickle_state",
    }
    generator = runpy.run_path(str(VECTORS_DIR / "generate_packets_timing.py"))
    generate_vectors = cast(Callable[[], list[dict[str, Any]]], generator["packets_timing_vectors"])
    assert doc["vectors"] == generate_vectors()
    recovery_timeout = next(
        vector for vector in doc["vectors"] if vector["name"] == "desync_fsm_recovery_timeout"
    )
    assert recovery_timeout["cases"] == [
        {
            "valid_count": 1,
            "timeout_superframes": 3,
            "states": ["RECOVERING", "RECOVERING", "DESYNCED"],
            "final_consecutive": 0,
        },
        {
            "valid_count": 2,
            "timeout_superframes": 3,
            "states": ["RECOVERING", "RECOVERING", "DESYNCED"],
            "final_consecutive": 0,
        },
    ]

    # Spot-check a few oracles
    from lichen.timing.sfn import sfn_delta

    assert sfn_delta(0, 0xFFFFFFFF) == 1

    from lichen.timing.dao import dao_retry_delay

    assert dao_retry_delay(0) == 4000
    assert dao_retry_delay(3) is None

    from lichen.timing.time_sync import (
        DIO_TIME_OPTION_TYPE,
        STRATUM_SOURCE_CLASSES,
        DioTimeOption,
        ProvisionRecord,
        ProvisionVerifier,
        SourceClass,
        Stratum,
        TimeAdmin,
        effective_epoch_floor,
        evaluate_epoch_floor,
        should_adopt_time,
    )

    opt = DioTimeOption(stratum=Stratum.NTS, timestamp=1700000000)
    enc = opt.encode()
    assert DIO_TIME_OPTION_TYPE == 0x15
    assert enc.hex() == "150603006553f100"
    assert DioTimeOption.decode(enc).timestamp == 1700000000

    by_name = {vector["name"]: vector for vector in doc["vectors"]}
    profile = by_name["trickle_profile_math"]
    assert set(profile) == {
        "name",
        "description",
        "category",
        "Imin_ms",
        "Imax_doublings",
        "Imax_exact_ms",
        "Imax_seconds",
        "k",
        "interval_sequence_ms",
        "transmit_cases",
        "suppression_counter_boundary",
        "reset_interval_ms",
    }
    assert profile["Imin_ms"] == 4000
    assert profile["Imax_doublings"] == 8
    assert profile["Imax_exact_ms"] == profile["Imin_ms"] << profile["Imax_doublings"]
    assert profile["Imax_seconds"] == 1024
    assert profile["interval_sequence_ms"] == [
        4_000,
        8_000,
        16_000,
        32_000,
        64_000,
        128_000,
        256_000,
        512_000,
        1_024_000,
        1_024_000,
    ]
    for case in profile["transmit_cases"]:
        assert set(case) == {
            "interval_ms",
            "rand_offset_ms",
            "expected_transmit_offset_ms",
        }
        assert 0 <= case["rand_offset_ms"] < case["interval_ms"] // 2
        assert case["expected_transmit_offset_ms"] == (
            case["interval_ms"] // 2 + case["rand_offset_ms"]
        )
        assert case["expected_transmit_offset_ms"] < case["interval_ms"]

    consistency = by_name["trickle_consistency_detection"]
    assert set(consistency) == {
        "name",
        "description",
        "category",
        "Imin_ms",
        "k",
        "scope_dodag_id_hex",
        "scope_version",
        "cases",
    }
    assert len(bytes.fromhex(consistency["scope_dodag_id_hex"])) == 16
    assert consistency["scope_version"] == 7
    assert {case["name"] for case in consistency["cases"]} == {
        "stopped_exact_scope",
        "active_exact_scope",
        "active_wrong_version",
        "active_wrong_dodag",
        "waiting_expire_exact_scope",
        "suppression_boundary",
        "saturating_counter",
    }
    for case in consistency["cases"]:
        assert set(case) == {
            "name",
            "active",
            "after_transmit",
            "counter_before",
            "observed_dodag_id_hex",
            "observed_version",
            "expected_accepted",
            "expected_counter_after",
            "expected_should_transmit",
            "expected_interval_unchanged",
        }
        assert len(bytes.fromhex(case["observed_dodag_id_hex"])) == 16
        assert case["expected_interval_unchanged"] is True

    reset = by_name["trickle_inconsistency_resets"]
    assert set(reset) == {
        "name",
        "description",
        "category",
        "Imin_ms",
        "k",
        "initial_rand_offset_ms",
        "steps",
    }
    assert reset["Imin_ms"] == 4000
    assert [step["state_before"] for step in reset["steps"]] == [
        "waiting_transmit_at_imin",
        "waiting_expire_at_imin",
        "repeated_inconsistency_at_imin",
    ]
    for step in reset["steps"]:
        assert set(step) == {
            "state_before",
            "fire_before_reset",
            "now_ms",
            "rand_offset_ms",
            "expected_interval_ms",
            "expected_counter",
            "expected_transmit_time_ms",
            "expected_interval_end_ms",
        }
        assert type(step["fire_before_reset"]) is bool
        assert 0 <= step["rand_offset_ms"] < reset["Imin_ms"] // 2
        assert step["expected_interval_ms"] == reset["Imin_ms"]
        assert step["expected_counter"] == 0
        assert step["expected_transmit_time_ms"] == (
            step["now_ms"] + reset["Imin_ms"] // 2 + step["rand_offset_ms"]
        )
        assert step["expected_interval_end_ms"] == step["now_ms"] + reset["Imin_ms"]

    monotonic = by_name["monotonic_uptime_sequences"]
    assert set(monotonic) == {"name", "description", "category", "scope", "unit", "cases"}
    assert monotonic["scope"] == "single_power_cycle"
    assert monotonic["unit"] == "implementation_defined_ticks"
    assert {case["name"] for case in monotonic["cases"]} == {
        "boot_origin_zero",
        "strictly_increasing",
        "equal_observations_allowed",
        "regression_rejected",
        "wrap_to_zero_rejected",
    }

    from lichen.crypto.identity import Identity
    from lichen.link.link_layer import LinkLayer, LinkSecurityClockError
    from lichen.timing.time_sync import MonotonicClock

    identity = Identity.from_seed(bytes(range(32)))
    for case in monotonic["cases"]:
        assert set(case) == {"name", "observations", "expected_acceptance"}
        assert case["observations"]
        assert len(case["observations"]) == len(case["expected_acceptance"])
        assert all(
            type(value) is int and 0 <= value <= 0xFFFFFFFFFFFFFFFF
            for value in case["observations"]
        )
        assert all(type(value) is bool for value in case["expected_acceptance"])
        high_water = -1
        expected = []
        for observation in case["observations"]:
            accepted = observation >= high_water
            expected.append(accepted)
            if accepted:
                high_water = observation
        assert expected == case["expected_acceptance"]

        observations = iter(case["observations"])
        link = LinkLayer(
            radio=object(),  # type: ignore[arg-type]
            identity=identity,
            peer_lookup=lambda _iid: None,
            receipt_clock=MonotonicClock(lambda stream=observations: next(stream)),
        )
        acceptance = []
        for _ in case["observations"]:
            try:
                link._receipt_now()
            except LinkSecurityClockError:
                acceptance.append(False)
            else:
                acceptance.append(True)
        assert acceptance == case["expected_acceptance"], case["name"]

    assert by_name["dio_time_option"]["option_type"] == 21
    assert by_name["dio_time_option"]["no_sync_encoded_hex"] == "1506000000000000"
    board = bytes(range(32))
    for case in by_name["time_sync_epoch_floor"]["cases"]:
        if case["action"] == "firmware_only":
            result = evaluate_epoch_floor(case["build_epoch"], None)
        elif case["action"] == "raw_integer":
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                floor = effective_epoch_floor(case["build_epoch"], case["provision_epoch"])
            assert floor == case["expected_floor"]
            assert case["status"] == "unauthenticated"
            continue
        else:
            assert case["action"] == "authenticated_provision"
            admin = TimeAdmin("floor-vector-admin")
            verifier = ProvisionVerifier(
                expected_board_identity=board,
                rollback_state=admin.initialize_virgin_provision_state(lambda marker: marker),
                verify_integrity=lambda _wire: True,
                persist_rollback_state=lambda _state: None,
                persist_clear=lambda _reason: None,
                admin=admin,
            )
            metadata = verifier.install(
                admin,
                ProvisionRecord(board, case["record_version"], case["provision_epoch"]).encode(),
            )
            result = evaluate_epoch_floor(
                case["build_epoch"],
                metadata,
                verifier=verifier,
                max_provision_lead_s=case["max_provision_lead_s"],
            )
        assert result.floor == case["expected_floor"]
        assert result.provision_status.value == case["status"]

    for row in by_name["time_sync_stratum"]["strata"]:
        stratum = Stratum(row["value"])
        if row["value"] == 1:
            # The wire value is a provenance-neutral quality level. The shared
            # artifact intentionally does not expose a legacy implementation
            # enum label that implied a Network/mesh origin.
            assert row["name"] == "CONSERVATIVE_SYNC"
        else:
            assert stratum.name == row["name"]
        assert {source.value for source in STRATUM_SOURCE_CLASSES[stratum]} == set(
            row["source_classes"]
        )
        assert all(isinstance(source, SourceClass) for source in STRATUM_SOURCE_CLASSES[stratum])

    adoption = by_name["time_adoption"]
    assert adoption["authoritative"] is False
    for case in adoption["cases"]:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            decision = should_adopt_time(
                Stratum(case["local"]),
                Stratum(case["received"]),
                case["timestamp"],
                case["floor"],
            )
        assert decision is case["expected"]
    trust = by_name["time_sync_trust_policy"]
    assert {case["name"] for case in trust["network_cases"]} == {
        "signed-canonical-authorized",
        "signed-missing-time-option",
        "signed-duplicate-time-option",
        "signed-wrong-dispatch",
        "signed-bad-icmpv6-checksum",
        "signed-bare-dio",
        "signed-malformed-schc",
        "signed-wrong-ipv6-next-header",
        "signed-wrong-icmpv6-type",
        "signed-wrong-icmpv6-code",
        "signed-wrong-role",
        "signed-wrong-instance",
        "signed-wrong-dodag",
        "signed-wrong-mop",
        "signed-wrong-signer",
        "signed-replay",
    }
    from lichen.link.frame import LichenFrame

    envelope = trust["dio_envelope"]
    start, end = envelope["option_ipv6_span"]
    assert bytes.fromhex(envelope["ipv6_hex"])[start:end].hex() == envelope["option_hex"]
    assert any(
        LichenFrame.from_bytes(bytes.fromhex(case["wire_hex"])).payload.hex()
        == envelope["duplicate_link_payload_hex"]
        for case in trust["network_cases"]
    )
    _execute_time_trust_vectors(trust)


def test_packet_size_budget() -> None:
    from lichen.packets.formats import (
        LINK_SECURITY_OVERHEAD,
        link_frame_overhead,
        total_packet_size_range,
    )

    assert LINK_SECURITY_OVERHEAD == 61
    assert total_packet_size_range(routing_overhead=0) == (104, 104)
    assert total_packet_size_range(routing_overhead=3) == (107, 107)
    assert total_packet_size_range(routing_overhead=6) == (110, 110)
    assert link_frame_overhead(addr_mode="none", signed=True).total == 61
    assert link_frame_overhead(addr_mode="short", signed=True).total == 63
    assert link_frame_overhead(addr_mode="extended", signed=True).total == 69
    assert link_frame_overhead(addr_mode="extended", signed=False).total == 13


@pytest.mark.parametrize("invalid", [False, 1.0, "3", None])
def test_packet_size_routing_overhead_requires_exact_integer(invalid: object) -> None:
    from lichen.packets.formats import total_packet_size_range

    with pytest.raises(TypeError, match="exact integer"):
        total_packet_size_range(routing_overhead=invalid)  # type: ignore[arg-type]


@pytest.mark.parametrize("invalid", [0, 1, "false", None])
def test_link_frame_signed_requires_exact_boolean(invalid: object) -> None:
    from lichen.packets.formats import link_frame_overhead

    with pytest.raises(TypeError, match="exact boolean"):
        link_frame_overhead(signed=invalid)  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["instance_id", "version", "rank"])
@pytest.mark.parametrize("invalid", [False, 1.0, "1", None])
def test_dio_fields_require_exact_integers(field: str, invalid: object) -> None:
    from lichen.packets.formats import dio_packet_bytes

    arguments: dict[str, object] = {field: invalid}
    with pytest.raises(TypeError, match=rf"{field} must be an exact integer"):
        dio_packet_bytes(**arguments)  # type: ignore[arg-type]


def test_airtime_oracle_positive() -> None:
    from lichen.timing.airtime import airtime_ms, airtime_us

    for plen in (17, 22, 60, 77, 82):
        assert airtime_us(plen) > 0
        assert airtime_ms(plen) > 0


def test_trickle_constants_match_spec() -> None:
    from lichen.timing.trickle import TRICKLE_IMAX_EXACT_MS, TRICKLE_IMIN_MS, TRICKLE_K

    assert TRICKLE_IMIN_MS == 4000
    assert TRICKLE_IMAX_EXACT_MS == 1_024_000
    assert TRICKLE_K == 10


def test_duty_cycle_max_packets() -> None:
    from lichen.timing.duty_cycle import EU868_MAX_PACKETS_PER_HOUR, max_packets_per_hour

    assert EU868_MAX_PACKETS_PER_HOUR == 1800
    assert max_packets_per_hour(200, 10) == 1800


def test_csma_cw() -> None:
    from lichen.timing.csma import cw_for_exponent

    assert cw_for_exponent(0) == 0
    assert cw_for_exponent(5) == 31


def test_sfn_slot_deterministic() -> None:
    from lichen.timing.sfn import hash_32, slot_for

    eui = bytes.fromhex("0011223344556677")
    h = hash_32(eui)
    # hash is deterministic across runs
    assert hash_32(eui) == h
    s0 = slot_for(eui, 0, 8)
    s1 = slot_for(eui, 1, 8)
    assert 0 <= s0 < 8
    assert 0 <= s1 < 8
