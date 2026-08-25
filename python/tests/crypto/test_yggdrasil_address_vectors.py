# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume test/vectors/yggdrasil_address.json through the real derivation.

The corpus holds three kinds of entries (see the ``profile`` discriminator):

1. ``upstream_go_addr_for_key`` — one verbatim anchor copied from the
   upstream yggdrasil-go ``AddrForKey`` test. Upstream bit-packs the inverted
   key without hashing, so it is intentionally NOT reproducible by the LICHEN
   native SHA-512 profile (spec/06-security.md §8.5); the anchor test asserts
   that documented divergence instead of byte equality.
2. ``lichen_native_sha512`` — driven byte-exact through
   ``yggdrasil_address`` / ``_pubkey_to_iid`` including the IID binding
   invariant and U/L-bit rule.
3. ``error_case`` — inputs the oracle MUST reject.

Sibling cross-checks recorded inside each vector were verified against
test/vectors/yggdrasil.json and test/vectors/yggdrasil-derivation.json when
the corpus was expanded.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.crypto.identity import _pubkey_to_iid, yggdrasil_address

VECTORS = Path(__file__).resolve().parents[3] / "test" / "vectors" / "yggdrasil_address.json"

ANCHOR_NAME = "upstream_addr_for_key"

# Constants lifted directly from upstream yggdrasil-go
# src/address/address_test.go @422836ee (the external oracle for the anchor;
# not derivable by any code under test here).
GO_ANCHOR_PUBKEY = "bdbacfd82240de3dcd123924cbb55256fb8dab08aa98e305528ab84f419e6efb"
GO_ANCHOR_ADDRESS = "0200848a604fbb7e438465db8db66895"
GO_ANCHOR_IPV6 = "200:848a:604f:bb7e:4384:65db:8db6:6895"


def _document() -> dict:
    document = json.loads(VECTORS.read_text())
    assert document["format_version"] == 1
    return document


def _anchor() -> dict:
    anchors = [v for v in _document()["vectors"] if v["name"] == ANCHOR_NAME]
    assert len(anchors) == 1, "exactly one upstream anchor expected"
    return anchors[0]


def _native_cases() -> list[tuple[str, dict]]:
    return [
        (v["name"], v) for v in _document()["vectors"] if v.get("profile") == "lichen_native_sha512"
    ]


def _error_cases() -> list[tuple[str, dict]]:
    return [
        (v["name"], v) for v in _document()["vectors"] if v.get("expect_error") == "pubkey_length"
    ]


def test_corpus_shape() -> None:
    """Guard against regression to the original single-vector corpus."""
    vectors = _document()["vectors"]
    assert len(_native_cases()) >= 10
    assert len(_error_cases()) >= 2
    assert len(vectors) == len(_native_cases()) + len(_error_cases()) + 1


def test_upstream_anchor_is_verbatim_go_reference() -> None:
    """The committed anchor still matches upstream byte-for-byte."""
    anchor = _anchor()
    assert anchor["public_key"] == GO_ANCHOR_PUBKEY
    assert anchor["address"] == GO_ANCHOR_ADDRESS
    assert anchor["ipv6"] == GO_ANCHOR_IPV6


def test_upstream_anchor_diverges_from_lichen_native_profile() -> None:
    """Upstream AddrForKey bit-packs the inverted key; LICHEN hashes SHA-512.

    The only shared byte is the leading 0x02 prefix. This pins the known,
    intentional difference so nobody 'fixes' either side by accident.
    """
    anchor = _anchor()
    derived = yggdrasil_address(bytes.fromhex(anchor["public_key"]))
    assert derived.packed.hex() != anchor["address"]
    assert derived.packed[0] == bytes.fromhex(anchor["address"])[0]


@pytest.mark.parametrize("name,vector", _native_cases())
def test_lichen_native_vectors_byte_exact(name: str, vector: dict) -> None:
    public_key = bytes.fromhex(vector["public_key"])
    derived = yggdrasil_address(public_key)
    iid = _pubkey_to_iid(public_key)

    # Byte-exact address and canonical text form.
    assert derived.packed.hex() == vector["address"], name
    assert str(derived) == vector["ipv6"], name
    assert derived.packed[0] == 0x02, name

    # IID agreement plus the spec §6 binding invariant: lower 64 bits of the
    # address MUST equal the key-derived IID.
    assert iid.hex() == vector["iid"], name
    assert derived.packed[8:] == iid, name
    assert iid[0] & 0x02 == 0, f"{name}: U/L bit must be clear in IID"


@pytest.mark.parametrize("name,vector", _error_cases())
def test_error_cases_rejected(name: str, vector: dict) -> None:
    with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
        yggdrasil_address(bytes.fromhex(vector["public_key"]))
    with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
        _pubkey_to_iid(bytes.fromhex(vector["public_key"]))
