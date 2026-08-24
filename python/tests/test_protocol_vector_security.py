# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Independent security checks for shared protocol-vector artifacts."""

from __future__ import annotations

import hashlib
import json
import math
import sys
from ipaddress import IPv6Address
from pathlib import Path
from typing import Any

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from reference_schnorr48 import (  # noqa: E402
    LINK_SIGNATURE_DOMAIN,
    ReferenceIdentity,
    sign,
    signature_transcript,
    verify,
)


def _load(name: str) -> dict[str, Any]:
    return json.loads((VECTORS_DIR / name).read_text())  # type: ignore[no-any-return]


def _destination_length(llsec: int) -> int:
    return {0: 0, 1: 2, 2: 8, 3: 0}[llsec & 0x03]


def _iid_for_key(public_key: bytes) -> bytes:
    iid = bytearray(hashlib.sha512(public_key).digest()[:8])
    iid[0] &= 0xFD
    return bytes(iid)


def _eui64_for_key(public_key: bytes) -> bytes:
    eui64 = bytearray(_iid_for_key(public_key))
    eui64[0] ^= 0x02
    return bytes(eui64)


def _addr_for_key(public_key: bytes) -> bytes:
    digest = hashlib.sha512(public_key).digest()
    return b"\x02" + digest[:7] + _iid_for_key(public_key)


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(
        int.from_bytes(data[offset : offset + 2], "big") for offset in range(0, len(data), 2)
    )
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def _icmpv6_checksum_valid(ipv6: bytes) -> bool:
    if len(ipv6) < 44 or ipv6[0] >> 4 != 6:
        return False
    payload_length = int.from_bytes(ipv6[4:6], "big")
    if payload_length != len(ipv6) - 40:
        return False
    source, destination = ipv6[8:24], ipv6[24:40]
    icmp = ipv6[40:]
    pseudo_header = source + destination + len(icmp).to_bytes(4, "big") + b"\x00\x00\x00\x3a"
    return _ones_complement_sum(pseudo_header + icmp) == 0xFFFF


def _lora_airtime_us(
    payload_len: int,
    *,
    sf: int,
    bw_hz: int,
    coding_rate_denominator: int = 5,
    preamble_symbols: int = 8,
) -> int:
    """Independent Semtech airtime arithmetic for explicit-header, CRC-on vectors."""
    symbol_seconds = (2**sf) / bw_hz
    numerator = 8 * payload_len - 4 * sf + 28 + 16
    payload_symbols = 8 + max(
        math.ceil(numerator / (4 * sf)) * coding_rate_denominator,
        0,
    )
    total_symbols = preamble_symbols + 4.25 + payload_symbols
    return int(total_symbols * symbol_seconds * 1_000_000)


def _fnv1a32(data: bytes) -> int:
    """Independent FNV-1a32 oracle for SFN slot vectors."""
    value = 0x811C9DC5
    for octet in data:
        value ^= octet
        value = (value * 0x01000193) & 0xFFFF_FFFF
    return value


def _compressed_ack(rule_id: int, window: int, bitmap: str) -> bytes:
    """Encode a C=0 ACK from a complete 63-bit semantic bitmap."""
    assert len(bitmap) == 63 and set(bitmap) <= {"0", "1"}
    compressed = bitmap.rstrip("1")
    removed = len(bitmap) - len(compressed)
    padding = (-(8 + 1 + 1 + len(compressed))) % 8
    assert padding <= removed
    bits = f"{rule_id:08b}{window:01b}0" + compressed + "1" * padding
    assert len(bits) % 8 == 0
    return int(bits, 2).to_bytes(len(bits) // 8, "big")


def test_link_signatures_use_canonical_dst_len_transcript() -> None:
    signed = [vector for vector in _load("link_frame.json")["vectors"] if "crypto" in vector]
    assert signed
    for vector in signed:
        wire = bytes.fromhex(vector["encoded"])
        crypto = vector["crypto"]
        prefix, signature = wire[:-48], wire[-48:]
        destination_length = _destination_length(prefix[1])
        transcript = signature_transcript(prefix, destination_length)
        public_key = bytes.fromhex(crypto["public_key"])
        signer_start = 5 + destination_length
        assert prefix[1] & 0xA0 == 0xA0, vector["name"]
        assert prefix[signer_start : signer_start + 8] == _eui64_for_key(public_key)
        assert vector["fields"]["signer_eui64"] == _eui64_for_key(public_key).hex()
        assert prefix.hex() == crypto["wire_prefix"], vector["name"]
        assert transcript.hex() == crypto["preimage"], vector["name"]
        assert transcript.startswith(LINK_SIGNATURE_DOMAIN), vector["name"]
        assert signature.hex() == crypto["signature"], vector["name"]
        assert verify(public_key, transcript, signature), vector["name"]
        assert not verify(public_key, prefix, signature), vector["name"]


def test_link_signatures_are_cross_profile_domain_separated() -> None:
    vector = next(vector for vector in _load("link_frame.json")["vectors"] if "crypto" in vector)
    crypto = vector["crypto"]
    identity = ReferenceIdentity.from_seed(bytes.fromhex(crypto["seed"]))
    link_transcript = bytes.fromhex(crypto["preimage"])
    link_signature = bytes.fromhex(crypto["signature"])
    body = link_transcript.removeprefix(LINK_SIGNATURE_DOMAIN)
    other_transcript = b"LICHEN-DAO-v1\x00" + body
    other_signature = sign(identity, other_transcript)

    assert verify(identity.pubkey, link_transcript, link_signature)
    assert not verify(identity.pubkey, other_transcript, link_signature)
    assert verify(identity.pubkey, other_transcript, other_signature)
    assert not verify(identity.pubkey, link_transcript, other_signature)
    assert not verify(identity.pubkey, body, link_signature)


def test_link_frame_oracle_bits_are_literal_not_production_enums() -> None:
    for vector in _load("link_frame.json")["vectors"]:
        wire = bytes.fromhex(vector["encoded"])
        fields = vector["fields"]
        llsec = wire[1]
        assert wire[0] == len(wire) - 1, vector["name"]
        assert llsec & 0x03 == fields["addr_mode"], vector["name"]
        assert (llsec >> 2) & 0x07 == fields["mic_length"], vector["name"]
        assert bool(llsec & 0x20) is fields["signature_present"], vector["name"]
        assert bool(llsec & 0x40) is fields["encrypted"], vector["name"]
        assert bool(llsec & 0x80) is bool(fields["signer_eui64"]), vector["name"]


def test_mic_selector_signed_vectors_bind_mandatory_signer_eui64() -> None:
    signed = [
        vector
        for vector in _load("mic_length_selector.json")["vectors"]
        if vector["expected"].get("signature_present")
    ]
    assert {vector["name"] for vector in signed} == {
        "mic_length_0_signed",
        "mic_length_1_signed",
    }
    for vector in signed:
        wire = bytes.fromhex(vector["input_hex"])
        crypto = vector["crypto"]
        prefix, signature = wire[:-48], wire[-48:]
        public_key = bytes.fromhex(crypto["public_key"])
        transcript = signature_transcript(prefix, 0)
        assert prefix[1] & 0xA0 == 0xA0, vector["name"]
        assert prefix[5:13] == _eui64_for_key(public_key)
        assert crypto["signer_eui64"] == _eui64_for_key(public_key).hex()
        assert prefix.hex() == crypto["wire_prefix"]
        assert transcript.hex() == crypto["preimage"]
        assert signature.hex() == crypto["signature"]
        assert verify(public_key, transcript, signature), vector["name"]


def test_link_vector_schema_names_si_identifier_as_eui64() -> None:
    link_vectors = _load("link_frame.json")["vectors"]
    edge_vectors = _load("link-edge-fuzz.json")["vectors"]
    assert all("signer_iid" not in vector.get("fields", {}) for vector in link_vectors)
    for vector in edge_vectors:
        decoded = vector.get("decoded", {})
        assert "signer_iid" not in decoded
        assert "signer_iid_present" not in decoded
        fields = vector.get("fields", {})
        signer_hex = fields.get("signer_eui64", "")
        signer_bytes_are_structurally_present = (
            "error" not in vector.get("expect", {}) or vector["name"] == "edge_truncated_32_mic"
        )
        if (
            len(signer_hex) == 16
            and fields.get("signer_eui64_present")
            and signer_bytes_are_structurally_present
        ):
            wire = bytes.fromhex(vector["encoded"])
            signer_offset = 5 + _destination_length(wire[1])
            assert wire[signer_offset : signer_offset + 8].hex() == signer_hex
    truncated = next(
        vector for vector in edge_vectors if vector["name"] == "edge_signer_eui64_truncated"
    )
    assert truncated["fields"]["signer_eui64"] == "00112233"
    assert truncated["expect"]["error"] == "truncated_signer_eui64"


def test_extended_destination_is_peer_eui64_not_key_iid() -> None:
    document = _load("link-addressing.json")
    vector = next(vector for vector in document["vectors"] if vector["name"] == "extended_eui64")
    assert vector["addr_mode"] == 2
    assert vector["dst_len"] == 8
    assert vector["dst_addr"] == vector["peer_eui64"]
    assert vector["dst_addr"] != vector["key_derived_iid"]
    assert vector["must_not_use_key_derived_iid"] is True
    eui64 = bytearray.fromhex(vector["peer_eui64"])
    eui64[0] ^= 0x02
    expected_link_local = IPv6Address(IPv6Address("fe80::").packed[:8] + eui64)
    assert str(expected_link_local) == vector["expected_destination"]

    derived = next(
        vector for vector in document["vectors"] if vector["name"] == "key_derived_extended_eui64"
    )
    public_key = bytes.fromhex(derived["sender_pubkey_hex"])
    iid = _iid_for_key(public_key)
    assert iid.hex() == derived["key_derived_iid"]
    wire_eui64 = bytearray(iid)
    wire_eui64[0] ^= 0x02
    assert wire_eui64.hex() == derived["wire_eui64_hex"] == derived["dst_addr"]
    wire = bytes.fromhex(derived["encoded"])
    assert wire[0] == len(wire) - 1
    assert wire[1] & 0x03 == 2
    assert wire[5:13] == wire_eui64
    expected_link_local = IPv6Address(IPv6Address("fe80::").packed[:8] + iid)
    assert str(expected_link_local) == derived["expected_destination"]


def test_all_signed_dio_families_share_link_transcript() -> None:
    documents = [
        _load("authenticated_schc_dio.json")["vectors"],
        next(
            vector["network_cases"]
            for vector in _load("packets-timing.json")["vectors"]
            if vector["name"] == "time_sync_trust_policy"
        ),
    ]
    for vectors in documents:
        for vector in vectors:
            wire = bytes.fromhex(vector["wire_hex"])
            prefix, signature = wire[:-48], wire[-48:]
            transcript = signature_transcript(prefix, _destination_length(prefix[1]))
            public_key_hex = vector.get("sender_pubkey_hex", vector.get("signer_pubkey_hex"))
            public_key = bytes.fromhex(public_key_hex)
            assert wire[0] == len(wire) - 1, vector["name"]
            assert prefix[1] & 0xA0 == 0xA0, vector["name"]
            assert prefix[5:13] == _eui64_for_key(public_key), vector["name"]
            assert verify(public_key, transcript, signature), vector["name"]
            assert not verify(public_key, prefix, signature), vector["name"]


def test_authenticated_schc_dio_construction_has_independent_security_checks() -> None:
    for vector in _load("authenticated_schc_dio.json")["vectors"]:
        wire = bytes.fromhex(vector["wire_hex"])
        link_payload = bytes.fromhex(vector["link_payload_hex"])
        ipv6 = bytes.fromhex(vector["ipv6_hex"])
        public_key = bytes.fromhex(vector["sender_pubkey_hex"])

        assert wire[0] == len(wire) - 1, vector["name"]
        assert wire[1] == 0xA0, vector["name"]
        assert wire[5:13] == _eui64_for_key(public_key), vector["name"]
        assert wire[13:-48] == link_payload, vector["name"]
        assert link_payload == b"\x14\xff" + ipv6, vector["name"]

        assert len(ipv6) >= 44, vector["name"]
        assert ipv6[0] >> 4 == 6, vector["name"]
        payload_length = int.from_bytes(ipv6[4:6], "big")
        assert payload_length == len(ipv6) - 40, vector["name"]
        assert ipv6[6] == 58 and ipv6[7] == 255, vector["name"]
        source, destination = IPv6Address(ipv6[8:24]), IPv6Address(ipv6[24:40])
        assert str(source) == vector["source_ipv6"], vector["name"]
        assert source.packed[8:].hex() == vector["source_iid_hex"], vector["name"]
        assert str(destination) == vector["destination_ipv6"], vector["name"]

        icmp = ipv6[40:]
        assert icmp[:2] == b"\x9b\x01", vector["name"]
        assert _icmpv6_checksum_valid(ipv6), vector["name"]

        dio = icmp[4:]
        assert dio.hex() == vector["dio_hex"], vector["name"]
        assert dio[0] == vector["rpl_instance_id"], vector["name"]
        assert int.from_bytes(dio[2:4], "big") == vector["rank"], vector["name"]
        assert (dio[4] >> 3) & 0x07 == vector["mop"], vector["name"]
        assert dio[8:24].hex() == vector["dodag_id_hex"], vector["name"]
        assert dio[24:].hex() == vector["option_bytes_hex"], vector["name"]

        source_matches_signer = source.packed[8:] == _iid_for_key(public_key)
        assert source_matches_signer is (vector["expected"]["error"] != "source_signer_mismatch"), (
            vector["name"]
        )
        if vector["trusted_role"] == "root":
            root_binding = dio[8:24] == _addr_for_key(public_key)
            assert root_binding is (vector["expected"]["admitted"] is True), vector["name"]


def test_timing_dio_source_is_bound_to_authorized_signer() -> None:
    trust = next(
        vector
        for vector in _load("packets-timing.json")["vectors"]
        if vector["name"] == "time_sync_trust_policy"
    )
    canonical = next(
        case for case in trust["network_cases"] if case["name"] == "signed-canonical-authorized"
    )
    source = IPv6Address(trust["dio_envelope"]["src_ipv6"])
    signer = bytes.fromhex(canonical["signer_pubkey_hex"])
    assert source.packed[:8] == IPv6Address("fe80::").packed[:8]
    assert source.packed[8:] == _iid_for_key(signer)

    wrong = next(case for case in trust["network_cases"] if case["name"] == "signed-wrong-signer")
    assert source.packed[8:] != _iid_for_key(bytes.fromhex(wrong["signer_pubkey_hex"]))
    assert wrong["expected_authoritative"] is False
    assert wrong["rejection_stage"] == "dio_admission"
    assert wrong["rejection"] == "source_signer_mismatch"
    wire = bytes.fromhex(wrong["wire_hex"])
    prefix, signature = wire[:-48], wire[-48:]
    public_key = bytes.fromhex(wrong["signer_pubkey_hex"])
    assert verify(public_key, signature_transcript(prefix, 0), signature)


def test_timing_dio_envelope_has_independent_integrity_checks() -> None:
    trust = next(
        vector
        for vector in _load("packets-timing.json")["vectors"]
        if vector["name"] == "time_sync_trust_policy"
    )
    envelope = trust["dio_envelope"]
    canonical_ipv6 = bytes.fromhex(envelope["ipv6_hex"])
    canonical_payload = bytes.fromhex(envelope["link_payload_hex"])
    assert canonical_payload == b"\x14\xff" + canonical_ipv6
    assert _icmpv6_checksum_valid(canonical_ipv6)
    assert canonical_ipv6[6:8] == b"\x3a\xff"
    option_start, option_end = envelope["option_ipv6_span"]
    assert canonical_ipv6[option_start:option_end].hex() == envelope["option_hex"]

    expected_source = IPv6Address(envelope["src_ipv6"])
    expected_destination = IPv6Address(envelope["dst_ipv6"])
    assert canonical_ipv6[8:24] == expected_source.packed
    assert canonical_ipv6[24:40] == expected_destination.packed

    for case in trust["network_cases"]:
        wire = bytes.fromhex(case["wire_hex"])
        assert wire[0] == len(wire) - 1, case["name"]
        assert wire[1] & 0x03 == 0, case["name"]
        assert int.from_bytes(wire[2:5], "big") == case["counter"], case["name"]
        assert wire[1] == 0xA0, case["name"]
        assert wire[5:13] == _eui64_for_key(bytes.fromhex(case["signer_pubkey_hex"]))
        link_payload = wire[13:-48]
        if "ipv6_hex" in case:
            assert link_payload == b"\x14\xff" + bytes.fromhex(case["ipv6_hex"])

        if len(link_payload) < 42 or link_payload[1] != 0xFF:
            continue
        ipv6 = link_payload[2:]
        if len(ipv6) < 40:
            continue
        assert ipv6[8:24] == expected_source.packed, case["name"]
        assert ipv6[24:40] == expected_destination.packed, case["name"]
        assert _icmpv6_checksum_valid(ipv6) is (case["name"] != "signed-bad-icmpv6-checksum"), case[
            "name"
        ]
        source_matches_signer = ipv6[16:24] == _iid_for_key(
            bytes.fromhex(case["signer_pubkey_hex"])
        )
        assert source_matches_signer is (case["name"] != "signed-wrong-signer"), case["name"]


def test_root_vectors_use_native_addr_for_key_and_independent_signatures() -> None:
    for vector in _load("root_signature.json")["vectors"]:
        public_hex = vector.get("pubkey")
        if public_hex is None or len(public_hex) != 64:
            continue
        public_key = bytes.fromhex(public_hex)
        binding = bytes.fromhex(vector["dodagid"]) == _addr_for_key(public_key)
        assert binding is vector.get("binding_valid", vector.get("error") != "DODAGID_MISMATCH")
        if "signature" in vector and "message" in vector:
            valid_signature = verify(
                public_key,
                bytes.fromhex(vector["message"]),
                bytes.fromhex(vector["signature"]),
            )
            assert (valid_signature and binding) is vector["valid"]

    for vector in _load("root_authorization.json")["vectors"]:
        public_key = bytes.fromhex(vector["pubkey_hex"])
        if len(public_key) != 32:
            assert vector["expected_valid"] is False
            continue
        binding = bytes.fromhex(vector["dodagid_hex"]) == _addr_for_key(public_key)
        signature = verify(
            public_key,
            bytes.fromhex(vector["message_hex"]),
            bytes.fromhex(vector["signature_hex"]),
        )
        assert (binding and signature) is vector["expected_valid"]

    expected = ReferenceIdentity.from_seed(bytes(32)).ygg_addr
    for vector in _load("rpl_messages.json")["vectors"]:
        if vector["type"] == "dio":
            assert IPv6Address(vector["fields"]["dodag_id"]).packed == expected


def _rule7_valid(source: IPv6Address, destination: IPv6Address) -> bool:
    source_valid = not (
        source.is_unspecified
        or source.is_loopback
        or source.is_multicast
        or source.ipv4_mapped is not None
    )
    if not source_valid:
        return False
    if destination.is_unspecified or destination.is_loopback or destination.ipv4_mapped is not None:
        return False
    return not destination.is_multicast or 2 <= (destination.packed[1] & 0x0F) <= 14


def test_rule7_address_policy_vectors_are_semantic() -> None:
    vectors = [
        vector
        for vector in _load("schc_adaptation.json")["vectors"]
        if vector["category"] == "rule7_address_policy"
    ]
    required_names = {
        "rule7_link_local_unicast_valid",
        "rule7_global_to_multicast_valid",
        "rule7_multicast_scope_14_valid",
        "rule7_noncanonical_link_local_full_mode_valid",
        "rule7_unspecified_source_rejected",
        "rule7_loopback_source_rejected",
        "rule7_multicast_source_rejected",
        "rule7_ipv4_mapped_source_rejected",
        "rule7_unspecified_destination_rejected",
        "rule7_loopback_destination_rejected",
        "rule7_ipv4_mapped_destination_rejected",
        "rule7_reserved_multicast_scope_zero_rejected",
        "rule7_interface_local_multicast_rejected",
        "rule7_reserved_multicast_scope_rejected",
    }
    assert required_names <= {vector["name"] for vector in vectors}
    canonical_prefix = IPv6Address("fe80::").packed[:8]
    for vector in vectors:
        source = IPv6Address(vector["source_ipv6"])
        destination = IPv6Address(vector["destination_ipv6"])
        assert _rule7_valid(source, destination) is vector["expect_valid"], vector["name"]
        pair_encoding = (
            "link_local_iid"
            if source.packed[:8] == destination.packed[:8] == canonical_prefix
            else "full"
        )
        if vector["expect_valid"]:
            assert "source_encoding" in vector and "destination_encoding" in vector
        for field in ("source_encoding", "destination_encoding"):
            if field in vector:
                assert vector[field] == pair_encoding, vector["name"]


def test_fragment_endpoint_direction_vectors_use_full_key_order() -> None:
    vectors = [
        vector
        for vector in _load("schc_adaptation.json")["vectors"]
        if vector["category"] == "fragmentation_endpoint_direction"
    ]
    assert len(vectors) == 6
    for vector in vectors:
        local = bytes.fromhex(vector["local_public_key_hex"])
        peer = bytes.fromhex(vector["peer_public_key_hex"])
        assert len(local) == len(peer) == 32
        if local == peer:
            assert vector["expect_accept"] is False
            assert vector["expect_state_mutation"] is False
            continue
        local_endpoint = "A" if local < peer else "B"
        assert vector["local_endpoint"] == local_endpoint
        if vector["message_type"] == "data":
            sender = (
                local_endpoint
                if vector["message_origin"] == "local"
                else ("B" if local_endpoint == "A" else "A")
            )
        else:
            sender = vector["data_sender_endpoint"]
        expected_rule = 120 if sender == "A" else 121
        assert (vector["rule_id"] == expected_rule) is vector["expect_accept"], vector["name"]
        if not vector["expect_accept"]:
            assert vector["expect_state_mutation"] is False


def test_duplicate_tile_vector_is_idempotent() -> None:
    vector = next(
        vector
        for vector in _load("schc_adaptation.json")["vectors"]
        if vector["name"] == "frag_duplicate_tile_idempotent_discard"
    )
    assert vector["scenario"] == "receive_tile_0_then_tile_0_again"
    assert vector["expect_duplicate_discarded"] is True
    assert vector["expect_reassembly_reset"] is False
    assert vector["expect_tile_state_mutation"] is False
    assert vector["expect_high_water_counter_advanced"] is True


def test_schc_fixed_header_sizes_are_exact_field_arithmetic() -> None:
    vectors = {
        vector["rule_id"]: vector
        for vector in _load("schc_adaptation.json")["vectors"]
        if vector["category"] == "compressed_size" and vector["rule_id"] in {2, 3, 4}
    }
    assert set(vectors) == {2, 3, 4}
    assert {rule_id: vector["compressed_size"] for rule_id, vector in vectors.items()} == {
        2: 23,
        3: 40,
        4: 37,
    }
    for vector in vectors.values():
        residue_bits = sum(vector["fields"].values())
        residue_bytes = (residue_bits + 7) // 8
        assert vector["residue_bit_length"] == residue_bits
        assert vector["residue_byte_length"] == residue_bytes
        assert vector["compressed_size"] == 1 + residue_bytes


def test_minimal_rule255_packets_use_no_next_header() -> None:
    for filename in ("schc_adaptation.json", "rule_versioning.json"):
        vector = next(
            vector
            for vector in _load(filename)["vectors"]
            if vector.get("packet") and len(bytes.fromhex(vector["packet"])) == 40
        )
        packet = bytes.fromhex(vector["packet"])
        compressed = bytes.fromhex(vector["compressed"])
        assert packet[0] >> 4 == 6
        assert int.from_bytes(packet[4:6], "big") == len(packet) - 40 == 0
        assert packet[6] == 59
        assert compressed == b"\xff" + packet


def test_ack_bitmap_vectors_encode_complete_semantics() -> None:
    vectors = {
        vector["name"]: vector
        for vector in _load("schc_adaptation.json")["vectors"]
        if vector["category"] == "ack_bitmap"
    }
    single = vectors["frag_ack_bitmap_single_missing"]
    single_bitmap = (
        single["received_bitmap_bits"]
        + "0" * single["unassigned_zero_bits"]
        + ("1" if single["final_all_1_received"] else "0")
    )
    assert (
        _compressed_ack(single["rule_id"], single["window"], single_bitmap).hex() == single["wire"]
    )

    multiple = vectors["frag_ack_bitmap_multiple_missing"]
    multiple_bitmap = (
        multiple["received_bitmap_prefix_bits"] + "1" * multiple["trailing_received_bits"]
    )
    assert (
        _compressed_ack(multiple["rule_id"], multiple["window"], multiple_bitmap).hex()
        == multiple["wire"]
    )


def test_rpl_vectors_distinguish_root_propagation_and_dao_shape() -> None:
    vectors = {vector["name"]: vector for vector in _load("rpl_messages.json")["vectors"]}
    non_root = vectors["dio_non_root"]
    assert non_root["schc_version_mode"] == "propagate_root"
    assert non_root["root_originated_schc_version"] == 3
    assert non_root["options_hex"] == "130103"
    assert bytes.fromhex(non_root["encoded"]).endswith(bytes.fromhex(non_root["options_hex"]))

    dao = vectors["dao_base"]
    encoded = bytes.fromhex(dao["encoded"])
    assert len(encoded) == 4
    assert encoded[1] & 0x40 == 0
    assert dao["fields"]["dodag_id"] is None
    assert dao["matches_rule_4"] is False
    assert dao["schc_expected_rule_id"] == 255


def test_rule_version_zero_length_is_complete_but_wrong_length() -> None:
    vector = next(
        vector
        for vector in _load("rule_versioning.json")["vectors"]
        if vector["name"] == "dio_rule_version_parse_length_0"
    )
    wire = bytes.fromhex(vector["wire"])
    assert wire == bytes((0x13, 0))
    assert len(wire) == 2 + wire[1]
    assert vector["expect_length"] == 0
    assert vector["expect_error"] == "wrong_length"


def test_timing_vectors_use_exact_airtime_slot_and_neutral_stratum() -> None:
    vectors = {vector["name"]: vector for vector in _load("packets-timing.json")["vectors"]}
    duty = vectors["duty_cycle_eu868_10pct"]
    airtime_us = _lora_airtime_us(duty["payload_len"], sf=duty["sf"], bw_hz=duty["bw_hz"])
    assert airtime_us == duty["airtime_us"] == 369_664
    allowed_airtime_us = int(3600 * 1_000_000 * duty["duty_cycle_percent"] / 100)
    assert allowed_airtime_us // airtime_us == duty["max_packets_per_hour"] == 973

    slot = vectors["tdma_slot_constants"]
    maximum_airtime_us = _lora_airtime_us(
        slot["max_phy_payload_bytes"],
        sf=slot["sf"],
        bw_hz=slot["bw_hz"],
    )
    assert maximum_airtime_us == slot["max_payload_airtime_us"] == 2_295_808
    assert slot["guard_ms"] == 50
    assert slot["slot_ms"] == math.ceil(maximum_airtime_us / 1000) + slot["guard_ms"]

    strata = {entry["value"]: entry for entry in vectors["time_sync_stratum"]["strata"]}
    assert strata[1]["name"] == "CONSERVATIVE_SYNC"
    assert set(strata[1]["source_classes"]) == {
        "Network",
        "Local-client",
        "Manual/static",
        "Internal RTC",
    }


def test_production_derived_timing_categories_have_independent_oracles() -> None:
    """Pin every numeric/FSM category without calling lichen.timing."""
    vectors = {vector["name"]: vector for vector in _load("packets-timing.json")["vectors"]}

    assert {
        key: vectors["trickle_constants"][key] for key in ("Imin_ms", "Imax_exact_ms", "k")
    } == {"Imin_ms": 4_000, "Imax_exact_ms": 1_024_000, "k": 10}
    assert {
        name: {
            key: value
            for key, value in vectors[name].items()
            if key not in {"name", "description", "category"}
        }
        for name in (
            "trickle_interval_start",
            "trickle_heard_consistent",
            "trickle_suppressed_at_k",
            "trickle_expire_double",
        )
    } == {
        "trickle_interval_start": {
            "interval": 4_000,
            "interval_start": 0,
            "transmit_time": 2_000,
            "interval_end": 4_000,
        },
        "trickle_heard_consistent": {"counter": 1, "should_transmit": True},
        "trickle_suppressed_at_k": {"counter": 21, "should_transmit": False},
        "trickle_expire_double": {"interval_after_expire": 8_000},
    }

    dao = vectors["dao_retry_delays"]
    assert dao["retry_delays_ms"] == [4_000, 8_000, 16_000]
    assert [dao[f"retry_{index}"] for index in range(3)] == [4_000, 8_000, 16_000]
    assert dao["retry_3_none"] is None
    assert dao["refresh_s"] == 900 and dao["lifetime_s"] == 1_800
    assert dao["refresh_is_half_lifetime"] is True
    assert {
        key: vectors["dao_sequence_validation"][key]
        for key in (
            "seq_0_invalid",
            "seq_1_valid",
            "seq_advance_valid",
            "seq_no_advance_invalid",
            "seq_max_valid_terminal",
        )
    } == {
        "seq_0_invalid": False,
        "seq_1_valid": True,
        "seq_advance_valid": True,
        "seq_no_advance_invalid": False,
        "seq_max_valid_terminal": True,
    }

    airtime_rows = [vector for vector in vectors.values() if vector["category"] == "airtime"]
    assert {row["payload_len"] for row in airtime_rows} == {17, 22, 60, 77, 82, 88, 127}
    for row in airtime_rows:
        expected = _lora_airtime_us(row["payload_len"], sf=10, bw_hz=125_000)
        assert row["airtime_us"] == expected, row["name"]
        assert row["airtime_ms"] == expected / 1_000, row["name"]

    assert {
        key: vectors["csma_parameters"][key]
        for key in (
            "cad_timeout_symbols",
            "backoff_unit_ms",
            "backoff_max",
            "retry_limit",
            "cw_values",
        )
    } == {
        "cad_timeout_symbols": 3,
        "backoff_unit_ms": 10,
        "backoff_max": 5,
        "retry_limit": 3,
        "cw_values": [0, 1, 3, 7, 15, 31],
    }
    assert {
        key: vectors["csma_backoff_slots"][key]
        for key in (
            "cw_exp0",
            "cw_exp5",
            "slots_exp0_rng0",
            "slots_exp5_rng0",
            "slots_exp5_rng_half",
            "slots_exp5_rng_max",
        )
    } == {
        "cw_exp0": 0,
        "cw_exp5": 31,
        "slots_exp0_rng0": 0,
        "slots_exp5_rng0": 0,
        "slots_exp5_rng_half": 16,
        "slots_exp5_rng_max": 31,
    }
    assert vectors["csma_retry_exhaustion"]["results"] == [
        "cad_busy",
        "cad_busy",
        "cad_busy",
        "retry_exhausted",
    ]

    assert {
        key: vectors["sfn_delta_wrap"][key] for key in ("delta_wrap", "delta_normal", "delta_zero")
    } == {"delta_wrap": 1, "delta_normal": 10, "delta_zero": 0}
    slot = vectors["sfn_slot_assignment"]
    eui64 = bytes.fromhex(slot["eui64_hex"])
    expected_hash = _fnv1a32(eui64)
    assert slot["hash"] == expected_hash == 3_236_109_245
    assert slot["slot_sfn0_n8"] == expected_hash % 8 == 5
    assert slot["slot_sfn1_n8"] == (expected_hash + 1) % 8 == 6
    assert slot["slot_sfn0_n16"] == expected_hash % 16 == 13

    startup = vectors["density_startup_delay"]
    assert startup["constants"] == {
        "LISTEN_PERIOD_MIN_S": 30,
        "LISTEN_PERIOD_MAX_S": 60,
        "DELAY_PER_NODE_S": 5,
        "MAX_STARTUP_DELAY_S": 300,
    }
    assert [startup["delay_0_nodes"], startup["delay_10_nodes"], startup["delay_100_nodes"]] == [
        0,
        50,
        300,
    ]
    assert vectors["desync_fsm_wrap_invalid"]["state_after_wrap"] == "DESYNCED"
    assert vectors["desync_fsm_recovering"]["state_after_valid"] == "RECOVERING"
    assert vectors["desync_fsm_recovering"]["consecutive"] == 1
    assert vectors["desync_fsm_recovered"]["state_after_3rd"] == "SYNCED"
    assert vectors["desync_fsm_recovery_timeout"]["cases"] == [
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


def test_link_draft_examples_have_executable_length_arithmetic() -> None:
    draft = (VECTORS_DIR.parents[1] / "spec" / "drafts" / "draft-lichen-link-01.md").read_text()
    dio_body = 4 + 8 + 73 + 48
    coap_body = 4 + 8 + 8 + 31 + 48
    assert dio_body == 0x85
    assert coap_body == 0x63
    assert "LENGTH = 0x85  (133-byte body)" in draft
    assert "total frame is 134 bytes." in draft
    assert "LENGTH = 0x63  (99 bytes body)" in draft
    assert "14 00400000000000000001000000000000000233000448d0ff737461747573" in draft
    assert "complete frame is 100 bytes" in draft


def test_rule_version_dodag_admission_policy_vectors() -> None:
    document = _load("rule_versioning.json")
    vectors = document["admission_policy_vectors"]
    assert len(vectors) == 4
    for vector in vectors:
        if "use_rule_255" in vector:
            allowed = (
                vector["scope"] == "outside_incompatible_dodag"
                and vector["authenticated_peer_registry"]
                and vector["packet_fits_single_frame"]
            )
            assert vector["use_rule_255"] is allowed
        if "root_originated_version" in vector:
            propagated = vector["advertised_version"] == vector["root_originated_version"]
            assert vector["expect_parent_candidate"] is (
                vector["authenticated"] and vector["parent_selectable"] and propagated
            )
    outside = next(
        vector
        for vector in document["vectors"]
        if vector["name"] == "rule255_version_mismatch_fallback"
    )
    assert outside["scope"] == "outside_incompatible_dodag"
    assert outside["authenticated_peer_registry"] is True
    assert outside["packet_fits_single_frame"] is True
    assert outside["use_rule_255"] is True


def test_replay_security_domain_vectors_authenticate_before_mutation() -> None:
    vectors = _load("replay_window.json")["security_domain_vectors"]
    assert len(vectors) == 4
    for vector in vectors:
        if "restored_record" in vector:
            assert vector["restored_record"]["key_generation"] < vector["durable_trust_generation"]
            assert vector["expected"] == {
                "restore": "reject",
                "fail_closed": True,
                "expect_state_mutation": False,
                "expect_delivery": False,
                "requires_rekey_or_authenticated_recovery": True,
            }
            continue
        seen: set[tuple[str, int, int]] = set()
        retired: set[tuple[str, int]] = set()
        default_key = vector.get("replay_key", {})
        for event in vector["events"]:
            key_hex = event.get("signer_public_key_hex", default_key.get("signer_public_key_hex"))
            generation = event.get("key_generation", default_key.get("key_generation"))
            if event.get("action") == "retire_generation":
                retired.add((key_hex, generation))
                continue
            authenticated = event["authenticated"] and event.get("generation_active", True)
            replay_key = (key_hex, generation, event["counter"])
            expected = (
                authenticated and (key_hex, generation) not in retired and replay_key not in seen
            )
            assert event["expect_accept"] is expected, vector["name"]
            if expected:
                seen.add(replay_key)
            if not authenticated or (key_hex, generation) in retired:
                assert event.get("expect_state_mutation", False) is False
