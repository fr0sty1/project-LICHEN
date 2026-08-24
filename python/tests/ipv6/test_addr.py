# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for IPv6 address handling and IID derivation (spec 6.1, 6.2, 12).

Oracles are hand-computed or taken from the spec's worked example addresses
(spec 12.2), not from the code under test.
"""

from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.crypto.identity import Identity
from lichen.ipv6.addr import (
    AddrError,
    eui64_to_iid,
    link_local_from_pubkey,
    mac48_to_eui64,
    make_link_local,
    native_address_from_pubkey,
    short_addr_to_iid,
)

# Spec 12.2 example: link-local fe80::1234:5678:9abc:def0 has this IID.
# IID = EUI-64 XOR 0x0200_0000_0000_0000, so the source EUI-64 differs only in
# the U/L bit of the first octet: 0x12 XOR 0x02 = 0x10.
SPEC_EUI64 = bytes([0x10, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])
SPEC_IID = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])
VECTORS = Path(__file__).resolve().parents[3] / "test" / "vectors" / "ipv6-addresses.json"


def test_eui64_to_iid_flips_ul_bit() -> None:
    assert eui64_to_iid(SPEC_EUI64) == SPEC_IID


def test_eui64_to_iid_is_involutive_on_ul_bit() -> None:
    # Flipping twice returns the original EUI-64.
    assert eui64_to_iid(eui64_to_iid(SPEC_EUI64)) == SPEC_EUI64


def test_eui64_to_iid_rejects_wrong_length() -> None:
    with pytest.raises(AddrError):
        eui64_to_iid(b"\x00" * 7)


def test_mac48_to_eui64_inserts_fffe_without_flip() -> None:
    mac = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    assert mac48_to_eui64(mac) == bytes([0x00, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55])


def test_mac48_to_iid_full_chain() -> None:
    # Modified EUI-64 IID: insert ff:fe, then flip U/L bit (0x00 -> 0x02).
    mac = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    iid = eui64_to_iid(mac48_to_eui64(mac))
    assert iid == bytes([0x02, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55])


def test_mac48_to_eui64_rejects_wrong_length() -> None:
    with pytest.raises(AddrError):
        mac48_to_eui64(b"\x00" * 5)


def test_short_addr_to_iid() -> None:
    # RFC 4944 section 6: IID = 0000:00FF:FE00:XXXX (short addr in low bytes)
    # 0x0000_00FF_FE00_0000 | 0x0001 = 0x0000_00FF_FE00_0001
    assert short_addr_to_iid(0x0001) == bytes([0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x01])
    # Additional test vector: 0xABCD should give 0000:00FF:FE00:ABCD
    assert short_addr_to_iid(0xABCD) == bytes([0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0xAB, 0xCD])


def test_short_addr_to_iid_rejects_out_of_range() -> None:
    with pytest.raises(AddrError):
        short_addr_to_iid(0x10000)


def test_make_link_local_matches_spec_example() -> None:
    assert make_link_local(SPEC_IID) == IPv6Address("fe80::1234:5678:9abc:def0")


def test_make_link_local_rejects_bad_iid() -> None:
    with pytest.raises(AddrError):
        make_link_local(b"\x00" * 4)


def test_key_identity_exposes_only_bound_native_and_link_local_addresses() -> None:
    identity = Identity.from_seed(bytes(range(32)))
    assert native_address_from_pubkey(identity.pubkey) == IPv6Address(identity.ygg_addr)
    assert native_address_from_pubkey(identity.pubkey).packed[0] == 0x02
    assert link_local_from_pubkey(identity.pubkey) == make_link_local(identity.iid)


@pytest.mark.parametrize("pubkey", [b"", bytes(31), bytes(33), bytearray(32)])
def test_key_derived_address_helpers_reject_noncanonical_public_keys(pubkey) -> None:
    with pytest.raises(AddrError):
        native_address_from_pubkey(pubkey)
    with pytest.raises(AddrError):
        link_local_from_pubkey(pubkey)


def test_key_derived_ipv6_vectors_match_production_boundaries() -> None:
    document = json.loads(VECTORS.read_text())
    key_vectors = [
        vector for vector in document["vectors"]
        if vector["profile"] == "key_derived_identity"
    ]
    assert len(key_vectors) >= 5
    for vector in key_vectors:
        public_key = bytes.fromhex(vector["pubkey"])
        assert native_address_from_pubkey(public_key).packed.hex() == vector["native_packed"]
        assert str(native_address_from_pubkey(public_key)) == vector["native"]
        assert link_local_from_pubkey(public_key).packed.hex() == vector["link_local_packed"]
