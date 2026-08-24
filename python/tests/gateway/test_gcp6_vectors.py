# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for GCP-6 Slot Coordination test vectors.

Validates vectors in test/vectors/gcp6_slot_coordination.json against
spec 08-gateway-coordination.md Section 6.
"""

from __future__ import annotations

import json
from pathlib import Path

import cbor2
import pytest

from lichen.gateway.slot_claim import (
    compute_contiguous_slots,
    compute_interleaved_slots,
    validate_interleaved_pattern,
)
from lichen.link.slot_coordination import compare_iid, tx_allowed

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


@pytest.fixture(scope="module")
def gcp6_vectors() -> dict:
    """Load GCP-6 slot coordination vectors."""
    path = VECTORS_DIR / "gcp6_slot_coordination.json"
    if not path.exists():
        pytest.skip(f"Test vectors not found: {path}")
    with open(path) as f:
        return json.load(f)


class TestGcp6VectorsStructure:
    """Validate vector file structure."""

    def test_format_version(self, gcp6_vectors: dict) -> None:
        assert gcp6_vectors["format_version"] == 2

    def test_has_vectors(self, gcp6_vectors: dict) -> None:
        assert "vectors" in gcp6_vectors
        assert len(gcp6_vectors["vectors"]) > 0

    def test_all_vectors_have_names(self, gcp6_vectors: dict) -> None:
        for v in gcp6_vectors["vectors"]:
            assert "name" in v, f"Vector missing name: {v}"
            assert "type" in v, f"Vector {v.get('name')} missing type"


class TestSuperframeSyncVectors:
    """Test superframe synchronization vectors (GCP-6.1)."""

    def test_gps_epoch_calculation(self, gcp6_vectors: dict) -> None:
        for v in gcp6_vectors["vectors"]:
            if v["name"] == "superframe_sync_gps_epoch":
                # Verify superframe_id formula
                unix_ts = v["gps_epoch_unix"]
                duration = v["superframe_duration_s"]
                expected_sf_id = v["current_superframe_id"]
                assert unix_ts // duration == expected_sf_id
                break

    def test_time_master_election(self, gcp6_vectors: dict) -> None:
        for v in gcp6_vectors["vectors"]:
            if v["name"] == "superframe_sync_time_master_election":
                candidates = v["candidates"]
                elected = v["elected_master_iid"]

                # Verify lowest IID wins
                iids = [(c["iid_hex"], c["iid_decimal"]) for c in candidates]
                min_iid = min(iids, key=lambda x: x[1])
                assert min_iid[0] == elected
                break

    def test_slot_timing_calculation(self, gcp6_vectors: dict) -> None:
        for v in gcp6_vectors["vectors"]:
            if v["name"] == "superframe_slot_timing":
                ts = v["test_timestamp_unix"]
                sf_start = v["superframe_start_unix"]
                duration = v["superframe_duration_s"]
                expected_slot = v["expected_current_slot"]
                expected_remaining = v["expected_slots_remaining"]

                # Verify slot calculation
                current_slot = (ts - sf_start) % duration
                assert current_slot == expected_slot

                # Verify remaining slots
                slots_remaining = duration - current_slot
                assert slots_remaining == expected_remaining
                break


class TestSlotAllocationVectors:
    """Test slot allocation vectors (GCP-6.2)."""

    def test_interleaved_allocation(self, gcp6_vectors: dict) -> None:
        for v in gcp6_vectors["vectors"]:
            if v["name"] == "slot_allocation_interleaved_3gw":
                gw_count = v["gateway_count"]
                max_slots = v["slots_per_superframe"]

                for alloc in v["allocations"]:
                    ordinal = alloc["ordinal"]
                    expected_slots = alloc["slots"]

                    # Verify interleaved pattern
                    computed = compute_interleaved_slots(ordinal, gw_count, max_slots)
                    assert computed == expected_slots
                break

    def test_contiguous_allocation(self, gcp6_vectors: dict) -> None:
        for v in gcp6_vectors["vectors"]:
            if v["name"] == "slot_allocation_contiguous_blocks":
                max_slots = v["slots_per_superframe"]

                for alloc in v["allocations"]:
                    start = alloc["slot_start"]
                    count = alloc["slot_count"]
                    expected_slots = alloc["slots"]

                    # Verify contiguous pattern
                    computed = compute_contiguous_slots(start, count, max_slots)
                    assert computed == expected_slots
                break


class TestCoapMessageVectors:
    """Test CoAP message format vectors (GCP-6.4)."""

    def test_cbor_payload_decodable(self, gcp6_vectors: dict) -> None:
        """Verify all CBOR payloads are decodable."""
        for v in gcp6_vectors["vectors"]:
            if v.get("type") == "coap_message" and "cbor_payload_hex" in v:
                cbor_hex = v["cbor_payload_hex"]
                cbor_bytes = bytes.fromhex(cbor_hex)
                decoded = cbor2.loads(cbor_bytes)
                assert decoded is not None, f"Failed to decode {v['name']}"

    def test_slot_claim_interleaved_payload(self, gcp6_vectors: dict) -> None:
        for v in gcp6_vectors["vectors"]:
            if v["name"] == "coap_slots_post_interleaved":
                cbor_bytes = bytes.fromhex(v["cbor_payload_hex"])
                decoded = cbor2.loads(cbor_bytes)

                # Verify payload matches expected structure
                expected = v["payload"]
                assert decoded["gateway_iid"] == bytes.fromhex(expected["gateway_iid"])
                assert decoded["slots"] == expected["slots"]
                assert decoded["superframe_id"] == expected["superframe_id"]
                assert decoded["gateway_count"] == expected["gateway_count"]
                assert decoded["ordinal"] == expected["ordinal"]
                break

    def test_channel_map_payload(self, gcp6_vectors: dict) -> None:
        for v in gcp6_vectors["vectors"]:
            if v["name"] == "coap_channels_get_response":
                cbor_bytes = bytes.fromhex(v["cbor_payload_hex"])
                decoded = cbor2.loads(cbor_bytes)

                # Channel map has integer keys and bytestring values
                assert 0 in decoded
                assert 1 in decoded
                assert 2 in decoded
                assert isinstance(decoded[0], bytes)
                break


class TestConflictResolutionVectors:
    """Test conflict resolution vectors (GCP-6.3)."""

    def test_lowest_iid_wins(self, gcp6_vectors: dict) -> None:
        for v in gcp6_vectors["vectors"]:
            if v["name"] == "conflict_resolution_both_valid_lowest_iid_wins":
                claim_a = v["claim_a"]
                claim_b = v["claim_b"]

                # Verify IID comparison
                iid_a = int.from_bytes(bytes.fromhex(claim_a["gateway_iid"]), "big")
                iid_b = int.from_bytes(bytes.fromhex(claim_b["gateway_iid"]), "big")

                if iid_a < iid_b:
                    assert v["expected_winner"] == "claim_a"
                else:
                    assert v["expected_winner"] == "claim_b"
                break

    def test_valid_signature_wins(self, gcp6_vectors: dict) -> None:
        for v in gcp6_vectors["vectors"]:
            if v["name"] == "conflict_resolution_one_valid_wins":
                claim_a = v["claim_a"]
                claim_b = v["claim_b"]

                # The valid signature wins regardless of IID
                if claim_a["signature_valid"] and not claim_b["signature_valid"]:
                    assert v["expected_winner"] == "claim_a"
                elif claim_b["signature_valid"] and not claim_a["signature_valid"]:
                    assert v["expected_winner"] == "claim_b"
                break

    def test_iid_comparison_unsigned(self, gcp6_vectors: dict) -> None:
        for v in gcp6_vectors["vectors"]:
            if v["name"] == "iid_comparison_unsigned_bigendian":
                for cmp in v["comparisons"]:
                    iid_a = bytes.fromhex(cmp["iid_a_hex"])
                    iid_b = bytes.fromhex(cmp["iid_b_hex"])

                    # Use oracle function
                    result = compare_iid(iid_a, iid_b)

                    if cmp["winner"] == "iid_a":
                        assert result == -1, f"Expected iid_a to win: {cmp}"
                    elif cmp["winner"] == "iid_b":
                        assert result == 1, f"Expected iid_b to win: {cmp}"
                break


class TestSlotValidationVectors:
    """Test slot validation vectors."""

    def test_tx_allowed_check(self, gcp6_vectors: dict) -> None:
        for v in gcp6_vectors["vectors"]:
            if v["name"] == "tx_allowed_check":
                slot_map = v["slot_map"]
                num_slots = v["num_slots"]

                for check in v["checks"]:
                    current_slot = check["current_slot"]
                    expected = check["tx_allowed"]

                    result = tx_allowed(slot_map, current_slot, num_slots)
                    assert result == expected, (
                        f"tx_allowed({slot_map}, {current_slot}, {num_slots}) "
                        f"= {result}, expected {expected}"
                    )
                break

    def test_interleaved_pattern_validation(self, gcp6_vectors: dict) -> None:
        for v in gcp6_vectors["vectors"]:
            if v["name"] == "interleaved_pattern_validation":
                for tc in v["test_cases"]:
                    ordinal = tc["ordinal"]
                    gw_count = tc["gateway_count"]
                    slots = tc["slots"]
                    expected = tc["expected_valid"]

                    result = validate_interleaved_pattern(slots, ordinal, gw_count)
                    assert result == expected, (
                        f"validate_interleaved_pattern({slots}, {ordinal}, {gw_count}) "
                        f"= {result}, expected {expected}"
                    )
                break
