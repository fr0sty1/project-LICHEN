#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate packets/timing vectors from Python oracles (spec 09-packets-timing.md)."""

from __future__ import annotations

import json
from pathlib import Path

VECTORS_DIR = Path(__file__).resolve().parent
FORMAT_VERSION = 2


def packets_formats_vectors() -> list[dict]:
    from lichen.packets.formats import (
        COMPLETE_PACKET_EXAMPLE,
        LINK_SECURITY_BREAKDOWN,
        LINK_SECURITY_OVERHEAD,
        PACKET_SIZE_SUMMARY,
        RPL_DIO_FIELDS,
        dio_packet_bytes,
        link_frame_overhead,
        total_packet_size_range,
    )

    vectors: list[dict] = []

    # 13.1 complete example
    vectors.append(
        {
            "name": "complete_packet_example_link_frame",
            "description": "13.1 Link-layer frame totals: Length 76 body, 77 on-wire, LLSec 0x21, Epoch 0x01, SeqNum 0x0042, DstAddr 0x0001, dispatch 0x14, signature 48B.",
            "category": "packet_walkthrough",
            "link_frame": COMPLETE_PACKET_EXAMPLE["link_frame"],
            "l2_payload_len": COMPLETE_PACKET_EXAMPLE["l2_payload_len"],
            "schc_packet_len": COMPLETE_PACKET_EXAMPLE["schc_packet_len"],
            "total_on_wire": 77,
            "body_bytes": 76,
        }
    )

    # 13.2 size summary
    vectors.append(
        {
            "name": "packet_size_summary",
            "description": "13.2 Packet Size Summary table; link security 53B, total 82-88 depending on routing overhead 0-6.",
            "category": "size_budget",
            "summary": {
                k: (list(v) if isinstance(v, tuple) else v)
                for k, v in PACKET_SIZE_SUMMARY.items()
            },
            "link_security_breakdown": LINK_SECURITY_BREAKDOWN,
            "link_security_overhead": LINK_SECURITY_OVERHEAD,
            "min_total": total_packet_size_range(routing_overhead=0)[0],
            "max_total": total_packet_size_range(routing_overhead=6)[0],
        }
    )

    # per-mode overhead
    for mode in ("none", "short", "extended", "elided"):
        for signed in (True, False):
            ov = link_frame_overhead(addr_mode=mode, signed=signed)
            vectors.append(
                {
                    "name": f"link_overhead_{mode}_{'signed' if signed else 'unsigned'}",
                    "description": f"Link frame overhead for addr_mode={mode} signed={signed}: total {ov.total}B, body {ov.body}B.",
                    "category": "link_overhead",
                    "addr_mode": mode,
                    "signed": signed,
                    "total": ov.total,
                    "body": ov.body,
                    "dst_addr_len": ov.dst_addr_len,
                }
            )

    # RPL DIO skeleton
    vectors.append(
        {
            "name": "rpl_dio_skeleton",
            "description": "13.3 RPL DIO packet fields and deterministic 21-byte skeleton (InstanceID, Version, Rank, Flags, DODAGID).",
            "category": "dio_format",
            "fields": RPL_DIO_FIELDS,
            "example_hex": dio_packet_bytes(instance_id=0, version=7, rank=256).hex(),
            "example_len": len(dio_packet_bytes(instance_id=0, version=7, rank=256)),
        }
    )

    # DIO encoding edge cases
    for rank in (0, 256, 0xFFFF):
        vectors.append(
            {
                "name": f"dio_rank_{rank}",
                "description": f"DIO encoding with rank={rank}.",
                "category": "dio_rank",
                "rank": rank,
                "hex": dio_packet_bytes(rank=rank).hex(),
            }
        )

    return vectors


def packets_timing_vectors() -> list[dict]:
    from lichen.timing.airtime import airtime_us, airtime_us_with_params
    from lichen.timing.csma import (
        CSMA_BACKOFF_MAX,
        CSMA_BACKOFF_UNIT_MS,
        CSMA_CAD_TIMEOUT_SYMBOLS,
        CSMA_RETRY_LIMIT,
        CsmaState,
        cw_for_exponent,
    )
    from lichen.timing.dao import (
        DAO_REFRESH_S,
        DAO_RETRY_DELAYS_MS,
        DAO_SOFT_STATE_LIFETIME_S,
        dao_retry_delay,
        is_valid_dao_sequence,
    )
    from lichen.timing.data_traffic import (
        HEARTBEAT_INTERVAL_S,
        TELEMETRY_INTERVAL_MAX_S,
        TELEMETRY_INTERVAL_MIN_S,
    )
    from lichen.timing.duty_cycle import (
        EU868_DUTY_CYCLE_PERCENT,
        EU868_MAX_PACKETS_PER_HOUR,
        EU868_SF9_AIRTIME_60B_MS,
        max_packets_per_hour,
    )
    from lichen.timing.sfn import (
        DESYNC_CONSTANTS,
        DesyncFSM,
        DesyncState,
        hash_32,
        initial_startup_delay,
        sfn_delta,
        slot_for,
    )
    from lichen.timing.time_sync import (
        DioTimeOption,
        Stratum,
        effective_epoch_floor,
        should_adopt_time,
    )
    from lichen.timing.trickle import TRICKLE_IMAX_EXACT_MS, TRICKLE_IMIN_MS, TRICKLE_K

    vectors: list[dict] = []

    # 14.1 Trickle constants
    vectors.append(
        {
            "name": "trickle_constants",
            "description": "14.1 Trickle Imin=4s, Imax=17min (exact 1_024_000ms = 4000*2^8), k=10.",
            "category": "trickle_constants",
            "Imin_ms": TRICKLE_IMIN_MS,
            "Imax_exact_ms": TRICKLE_IMAX_EXACT_MS,
            "k": TRICKLE_K,
        }
    )

    # Trickle state machine deterministic walk (rng=0.0 -> transmit at half)
    from lichen.timing.trickle import TrickleTimer

    t = TrickleTimer(
        imin_ms=TRICKLE_IMIN_MS, imax_doublings=8, k=TRICKLE_K, rng=lambda: 0.0
    )
    t.start(now=0)
    vectors.append(
        {
            "name": "trickle_interval_start",
            "description": "Trickle first interval: start 0, transmit at half (Imin/2) with rng=0.0, interval_end=4000.",
            "category": "trickle_state",
            "interval": t.interval,
            "interval_start": t.interval_start,
            "transmit_time": t.transmit_time,
            "interval_end": t.interval_end,
        }
    )
    # heard_consistent suppression
    t.heard_consistent()
    vectors.append(
        {
            "name": "trickle_heard_consistent",
            "description": "After 1 heard consistent, counter=1, should_transmit true (k=10).",
            "category": "trickle_state",
            "counter": t.counter,
            "should_transmit": t.should_transmit(),
        }
    )
    # saturate counter to k
    for _ in range(20):
        t.heard_consistent()
    vectors.append(
        {
            "name": "trickle_suppressed_at_k",
            "description": "After >=k heard consistent, should_transmit false (suppressed).",
            "category": "trickle_state",
            "counter": t.counter,
            "should_transmit": t.should_transmit(),
        }
    )
    t2 = TrickleTimer(
        imin_ms=TRICKLE_IMIN_MS, imax_doublings=8, k=TRICKLE_K, rng=lambda: 0.5
    )
    t2.start(now=0)
    t2.expire(now=t2.interval_end)
    vectors.append(
        {
            "name": "trickle_expire_double",
            "description": "After expire, interval doubles to 8000 (capped at 1_024_000).",
            "category": "trickle_state",
            "interval_after_expire": t2.interval,
        }
    )

    # 14.2 DAO timing
    vectors.append(
        {
            "name": "dao_retry_delays",
            "description": "14.2 DAO retry exponential backoff 4,8,16s.",
            "category": "dao_timing",
            "retry_delays_ms": list(DAO_RETRY_DELAYS_MS),
            "retry_0": dao_retry_delay(0),
            "retry_1": dao_retry_delay(1),
            "retry_2": dao_retry_delay(2),
            "retry_3_none": dao_retry_delay(3),
            "refresh_s": DAO_REFRESH_S,
            "lifetime_s": DAO_SOFT_STATE_LIFETIME_S,
            "refresh_is_half_lifetime": DAO_REFRESH_S == DAO_SOFT_STATE_LIFETIME_S // 2,
        }
    )
    vectors.append(
        {
            "name": "dao_sequence_validation",
            "description": "DAO Origin Sequence: starts above zero, monotonically increasing, must not wrap at 0xffffffffffffffff.",
            "category": "dao_sequence",
            "seq_0_invalid": is_valid_dao_sequence(0),
            "seq_1_valid": is_valid_dao_sequence(1),
            "seq_advance_valid": is_valid_dao_sequence(2, prev_max=1),
            "seq_no_advance_invalid": is_valid_dao_sequence(1, prev_max=1),
            "seq_max_invalid": is_valid_dao_sequence(0xFFFFFFFFFFFFFFFF),
        }
    )

    # 14.3 Data traffic
    vectors.append(
        {
            "name": "data_traffic_intervals",
            "description": "14.3 Periodic telemetry 5-60min, heartbeat 30min.",
            "category": "data_traffic",
            "telemetry_min_s": TELEMETRY_INTERVAL_MIN_S,
            "telemetry_max_s": TELEMETRY_INTERVAL_MAX_S,
            "heartbeat_s": HEARTBEAT_INTERVAL_S,
        }
    )

    # 14.4 Duty cycle
    vectors.append(
        {
            "name": "duty_cycle_eu868_10pct",
            "description": "14.4 EU 868 10% duty cycle, SF9 60B ~200ms => 1800 packets/hour, comfortable 100-300.",
            "category": "duty_cycle",
            "duty_cycle_percent": EU868_DUTY_CYCLE_PERCENT,
            "airtime_60b_ms": EU868_SF9_AIRTIME_60B_MS,
            "max_packets_per_hour": EU868_MAX_PACKETS_PER_HOUR,
            "max_via_formula": max_packets_per_hour(
                EU868_SF9_AIRTIME_60B_MS, EU868_DUTY_CYCLE_PERCENT
            ),
        }
    )
    # duty cycle usage examples
    vectors.append(
        {
            "name": "duty_cycle_usage_examples",
            "description": "Duty cycle usage percent for various airtime sums in 1-hour window.",
            "category": "duty_cycle_usage",
            "usage_3600s_window_36s_airtime_pct": (36 / 3600) * 100,  # 1% at 36s
            "usage_180s_airtime_pct": (180 / 3600) * 100,  # 5%
        }
    )

    # airtime calculations (using oracle)
    for plen in (17, 22, 60, 77, 82, 88, 127):
        at_us = airtime_us(plen)
        vectors.append(
            {
                "name": f"airtime_payload_{plen}",
                "description": f"Airtime for payload {plen}B at SF10/125kHz (sim default).",
                "category": "airtime",
                "payload_len": plen,
                "airtime_us": at_us,
                "airtime_ms": at_us / 1000.0,
            }
        )
    # SF9 example via explicit params (spec says ~200ms for 60B at SF9)
    sf9_at = airtime_us_with_params(60, sf=9, bw_hz=125_000)
    vectors.append(
        {
            "name": "airtime_sf9_60b",
            "description": "Airtime for 60B at SF9/125kHz (spec example ~200ms).",
            "category": "airtime_sf9",
            "payload_len": 60,
            "sf": 9,
            "bw_hz": 125_000,
            "airtime_us": sf9_at,
            "airtime_ms": sf9_at / 1000.0,
        }
    )

    # 14.5 CSMA/CA
    vectors.append(
        {
            "name": "csma_parameters",
            "description": "14.5 CSMA CAD 3 symbols, backoff 10ms, max 5 (CW 31), retry 3.",
            "category": "csma_params",
            "cad_timeout_symbols": CSMA_CAD_TIMEOUT_SYMBOLS,
            "backoff_unit_ms": CSMA_BACKOFF_UNIT_MS,
            "backoff_max": CSMA_BACKOFF_MAX,
            "retry_limit": CSMA_RETRY_LIMIT,
            "cw_values": [cw_for_exponent(e) for e in range(6)],
        }
    )
    # CSMA backoff state
    vectors.append(
        {
            "name": "csma_backoff_slots",
            "description": "CSMA slots: CW=0 for exp 0, CW=31 for exp 5, deterministic rng mapping.",
            "category": "csma_backoff",
            "cw_exp0": cw_for_exponent(0),
            "cw_exp5": cw_for_exponent(5),
            "slots_exp0_rng0": CsmaState(backoff_exp=0).next_backoff_slots(0.5),
            "slots_exp5_rng0": CsmaState(backoff_exp=5).next_backoff_slots(0.0),
            "slots_exp5_rng_half": CsmaState(backoff_exp=5).next_backoff_slots(0.5),
            "slots_exp5_rng_max": CsmaState(backoff_exp=5).next_backoff_slots(0.999),
        }
    )
    cs2 = CsmaState()
    results = []
    for _ in range(4):
        results.append(cs2.on_cad_busy().value)
    vectors.append(
        {
            "name": "csma_retry_exhaustion",
            "description": "CSMA retry exhaustion after 3 retries => 4th returns retry_exhausted.",
            "category": "csma_retry",
            "results": results,
        }
    )

    # 14.6 Time sync
    vectors.append(
        {
            "name": "time_sync_epoch_floor",
            "description": "Effective epoch floor = max(firmware_build_epoch, board_provision_epoch_if_valid).",
            "category": "time_sync",
            "floor_firmware_only": effective_epoch_floor(1700000000, None),
            "floor_max": effective_epoch_floor(1700000000, 1800000000),
            "floor_firmware_higher": effective_epoch_floor(1900000000, 1800000000),
        }
    )
    vectors.append(
        {
            "name": "time_sync_stratum",
            "description": "Time stratum 0..4 table and source class mapping.",
            "category": "time_stratum",
            "strata": [
                {"value": int(s), "name": s.name, "source": Stratum(s).name}
                for s in Stratum
            ],
        }
    )
    # DIO Time Option encode/decode
    dio_opt = DioTimeOption(stratum=Stratum.NTS, timestamp=1700000000)
    enc = dio_opt.encode()
    vectors.append(
        {
            "name": "dio_time_option",
            "description": "DIO Time Option Type TBD 8 bytes: Type(1)+Len(1)+Stratum(1)+Reserved(1)+Timestamp(4).",
            "category": "dio_time_option",
            "encoded_hex": enc.hex(),
            "decoded_stratum": int(DioTimeOption.decode(enc).stratum),
            "decoded_timestamp": DioTimeOption.decode(enc).timestamp,
        }
    )
    vectors.append(
        {
            "name": "time_adoption",
            "description": "Time adoption: higher stratum MAY adopt, lower MUST NOT, below floor MUST reject.",
            "category": "time_adoption",
            "adopt_higher": should_adopt_time(
                Stratum.NO_SYNC, Stratum.NTS, 1700000001, 1700000000
            ),
            "reject_lower": should_adopt_time(
                Stratum.NTS, Stratum.MESH_DERIVED, 1700000001, 1700000000
            ),
            "reject_below_floor": should_adopt_time(
                Stratum.NO_SYNC, Stratum.GNSS_GPSD, 1600000000, 1700000000
            ),
        }
    )

    # 14.7-14.8 SFN and slot
    eui = bytes.fromhex("0011223344556677")
    vectors.append(
        {
            "name": "sfn_delta_wrap",
            "description": "SFN delta unsigned 32-bit: (0 - 0xFFFFFFFF) mod 2^32 = 1.",
            "category": "sfn_delta",
            "delta_wrap": sfn_delta(0, 0xFFFFFFFF),
            "delta_normal": sfn_delta(100, 90),
            "delta_zero": sfn_delta(42, 42),
        }
    )
    vectors.append(
        {
            "name": "sfn_slot_assignment",
            "description": "Slot = (hash_32(eui64)+sfn) mod num_slots per spec 14.7.",
            "category": "sfn_slot",
            "eui64_hex": eui.hex(),
            "hash": hash_32(eui),
            "slot_sfn0_n8": slot_for(eui, 0, 8),
            "slot_sfn1_n8": slot_for(eui, 1, 8),
            "slot_sfn0_n16": slot_for(eui, 0, 16),
        }
    )
    # density-aware startup
    vectors.append(
        {
            "name": "density_startup_delay",
            "description": "Initial delay = min(300, nodes_heard*5); LISTEN 30-60s.",
            "category": "density_startup",
            "constants": DESYNC_CONSTANTS,
            "delay_0_nodes": initial_startup_delay(0),
            "delay_10_nodes": initial_startup_delay(10),
            "delay_100_nodes": initial_startup_delay(100),  # capped at 300
        }
    )
    # Desync FSM
    fsm = DesyncFSM()
    fsm.on_sfn_wrap(time_valid=False)
    vectors.append(
        {
            "name": "desync_fsm_wrap_invalid",
            "description": "SYNCED + SFN wrap invalid time => DESYNCED.",
            "category": "desync_fsm",
            "state_after_wrap": fsm.state.name,
        }
    )
    fsm2 = DesyncFSM()
    fsm2.state = DesyncState.DESYNCED
    fsm2.on_beacon(valid=True)
    vectors.append(
        {
            "name": "desync_fsm_recovering",
            "description": "DESYNCED + valid beacon => RECOVERING (needs 3 consecutive).",
            "category": "desync_fsm",
            "state_after_valid": fsm2.state.name,
            "consecutive": fsm2.consecutive_valid,
        }
    )
    fsm3 = DesyncFSM()
    fsm3.state = DesyncState.RECOVERING
    fsm3.consecutive_valid = 2
    fsm3.on_beacon(valid=True)
    vectors.append(
        {
            "name": "desync_fsm_recovered",
            "description": "RECOVERING + 3rd consecutive valid => SYNCED.",
            "category": "desync_fsm",
            "state_after_3rd": fsm3.state.name,
        }
    )

    # guard/slot constants
    from lichen.timing.sfn import TDMA_GUARD_MS, TDMA_SLOT_MS

    vectors.append(
        {
            "name": "tdma_slot_constants",
            "description": "14.8 Superframe guard 50ms (alt 100ms per table), slot 250ms, beacon timeout 3x superframe.",
            "category": "tdma_constants",
            "guard_ms": TDMA_GUARD_MS,
            "slot_ms": TDMA_SLOT_MS,
        }
    )

    return vectors


def main() -> None:
    pf = {
        "format_version": FORMAT_VERSION,
        "description": "Packets and Timing packet format vectors (spec 09 §13). Python oracle lichen.packets.",
        "vectors": packets_formats_vectors(),
    }
    pt = {
        "format_version": FORMAT_VERSION,
        "description": "Packets and Timing timing vectors (spec 09 §14 Trickle, DAO, duty cycle, airtime, CSMA, time sync, SFN, TDMA). Python oracle lichen.timing.",
        "vectors": packets_timing_vectors(),
    }
    (VECTORS_DIR / "packets-formats.json").write_text(json.dumps(pf, indent=2) + "\n")
    (VECTORS_DIR / "packets-timing.json").write_text(json.dumps(pt, indent=2) + "\n")
    print(f"Wrote {len(pf['vectors'])} vectors to packets-formats.json")
    print(f"Wrote {len(pt['vectors'])} vectors to packets-timing.json")


if __name__ == "__main__":
    main()
