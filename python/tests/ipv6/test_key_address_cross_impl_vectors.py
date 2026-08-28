# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Cross-corpus checks for canonical Ed25519-key IPv6 derivation."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.crypto.identity import _pubkey_to_iid, yggdrasil_address
from lichen.ipv6.addr import link_local_from_pubkey, native_address_from_pubkey

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


def _load(name: str) -> object:
    return json.loads((VECTORS_DIR / name).read_text())


def _independent_derivation(public_key: bytes) -> tuple[bytes, bytes, bytes]:
    digest = hashlib.sha512(public_key).digest()
    iid = bytearray(digest[:8])
    iid[0] &= 0xFD
    link_local = b"\xfe\x80" + bytes(6) + iid
    native = b"\x02" + digest[:7] + iid
    return bytes(iid), bytes(link_local), bytes(native)


def test_ipv6_address_vectors_bind_one_key_to_both_addresses_byte_exact() -> None:
    document = _load("ipv6-addresses.json")
    assert isinstance(document, dict)
    vectors = document["vectors"]
    assert isinstance(vectors, list)
    key_vectors = [item for item in vectors if item["profile"] == "key_derived_identity"]

    assert len(key_vectors) >= 5
    for vector in key_vectors:
        public_key = bytes.fromhex(vector["pubkey"])
        iid, link_local, native = _independent_derivation(public_key)

        assert iid.hex() == vector["iid"], vector["name"]
        assert link_local.hex() == vector["link_local_packed"], vector["name"]
        assert native.hex() == vector["native_packed"], vector["name"]
        assert str(IPv6Address(link_local)) == vector["link_local"], vector["name"]
        assert str(IPv6Address(native)) == vector["native"], vector["name"]

        assert _pubkey_to_iid(public_key) == iid, vector["name"]
        assert link_local_from_pubkey(public_key).packed == link_local, vector["name"]
        assert yggdrasil_address(public_key).packed == native, vector["name"]
        assert native_address_from_pubkey(public_key).packed == native, vector["name"]

        assert link_local[:8] == bytes.fromhex("fe80000000000000"), vector["name"]
        assert link_local[8:] == iid == native[8:], vector["name"]
        assert native[0] == 0x02, vector["name"]
        assert iid[0] & 0x02 == 0, vector["name"]


def test_native_corpora_agree_without_byte_reversal() -> None:
    ipv6_document = _load("ipv6-addresses.json")
    native_document = _load("yggdrasil_address.json")
    assert isinstance(ipv6_document, dict)
    assert isinstance(native_document, dict)

    ipv6_by_key = {
        item["pubkey"]: item
        for item in ipv6_document["vectors"]
        if item["profile"] == "key_derived_identity"
    }
    native_by_key = {
        item["public_key"]: item
        for item in native_document["vectors"]
        if item.get("profile") == "lichen_native_sha512"
    }
    shared_keys = ipv6_by_key.keys() & native_by_key.keys()

    assert len(shared_keys) >= 4
    for public_key in shared_keys:
        ipv6_vector = ipv6_by_key[public_key]
        native_vector = native_by_key[public_key]
        assert ipv6_vector["iid"] == native_vector["iid"]
        assert ipv6_vector["native_packed"] == native_vector["address"]
        assert ipv6_vector["native"] == native_vector["ipv6"]

    # An asymmetric anchor catches accidental word/byte-order reversal.
    rfc8032 = ipv6_by_key["d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"]
    assert rfc8032["iid"] == "0c02a50225b4baaa"
    assert rfc8032["native_packed"] == "020e02a50225b4ba0c02a50225b4baaa"


def test_address_derivation_accepts_exact_width_raw_key_octets() -> None:
    """Addressing is a 32-byte hash map; subgroup checks belong to signature use."""
    low_order_encoding = bytes(32)
    iid, link_local, native = _independent_derivation(low_order_encoding)

    assert _pubkey_to_iid(low_order_encoding) == iid
    assert link_local_from_pubkey(low_order_encoding).packed == link_local
    assert yggdrasil_address(low_order_encoding).packed == native


@pytest.mark.parametrize("public_key", [b"", bytes(31), bytes(33)])
def test_address_derivation_rejects_malformed_key_lengths(public_key: bytes) -> None:
    with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
        _pubkey_to_iid(public_key)
    with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
        yggdrasil_address(public_key)


def test_committed_ipv6_address_vectors_match_stdlib_generator() -> None:
    before = VECTORS_DIR.joinpath("ipv6-addresses.json").read_bytes()
    result = subprocess.run(
        [sys.executable, str(VECTORS_DIR / "generate_ipv6_addresses.py"), "--check"],
        cwd=VECTORS_DIR.parent.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert VECTORS_DIR.joinpath("ipv6-addresses.json").read_bytes() == before
