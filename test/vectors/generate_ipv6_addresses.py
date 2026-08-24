#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate exact native IPv6 address vectors without importing LICHEN."""

from __future__ import annotations

import argparse
import hashlib
import sys
from ipaddress import IPv6Address
from pathlib import Path

VECTORS_DIR = Path(__file__).resolve().parent
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from atomic_json import (  # noqa: E402
    atomic_write_json_batch,
    json_bytes,
    read_bounded_exact,
)

OUTPUT = VECTORS_DIR / "ipv6-addresses.json"


def _key_vector(name: str, public_key: bytes) -> dict[str, object]:
    digest = hashlib.sha512(public_key).digest()
    iid = bytearray(digest[:8])
    iid[0] &= 0xFD
    native = bytes((0x02,)) + digest[:7] + bytes(iid)
    link_local = b"\xfe\x80" + bytes(6) + bytes(iid)
    return {
        "name": name,
        "profile": "key_derived_identity",
        "pubkey": public_key.hex(),
        "iid": bytes(iid).hex(),
        "link_local": str(IPv6Address(link_local)),
        "link_local_packed": link_local.hex(),
        "native": str(IPv6Address(native)),
        "native_packed": native.hex(),
        "iid_in_native": native[8:] == bytes(iid),
    }


def _eui_vector(name: str, eui64: bytes) -> dict[str, object]:
    iid = bytearray(eui64)
    iid[0] ^= 0x02
    link_local = b"\xfe\x80" + bytes(6) + bytes(iid)
    return {
        "name": name,
        "profile": "link_interoperability_only",
        "eui64": eui64.hex(),
        "iid": bytes(iid).hex(),
        "link_local": str(IPv6Address(link_local)),
        "link_local_packed": link_local.hex(),
    }


def _short_vector(name: str, address: int) -> dict[str, object]:
    iid = 0x0000_00FF_FE00_0000 | address
    return {
        "name": name,
        "profile": "link_interoperability_only",
        "short_addr": address,
        "short_hex": address.to_bytes(2, "big").hex(),
        "iid": iid.to_bytes(8, "big").hex(),
    }


def document() -> dict[str, object]:
    """Return the independently derived vector document."""
    vectors = [
        _key_vector("all_zero_pubkey", bytes(32)),
        _key_vector(
            "sha256_empty_as_pubkey",
            bytes.fromhex(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
        ),
        _key_vector(
            "rfc8032_test_public_key",
            bytes.fromhex(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            ),
        ),
        _key_vector("all_ab_pubkey", bytes((0xAB,)) * 32),
        _key_vector("all_ff_pubkey", bytes((0xFF,)) * 32),
        _eui_vector("eui64_spec_example", bytes.fromhex("103456789abcdef0")),
        _eui_vector("eui64_zero", bytes(8)),
        _eui_vector("eui64_all_ff", bytes((0xFF,)) * 8),
        _short_vector("short_0x0001", 0x0001),
        _short_vector("short_0xabcd", 0xABCD),
        _short_vector("short_0xffff", 0xFFFF),
    ]
    return {
        "$schema": "./schema.json",
        "format_version": 2,
        "description": (
            "Exact Ed25519 pubkey to SHA-512 IID, link-local, and primary "
            "0200::/8 native-address derivation. EUI-64 and short-address cases "
            "are explicitly link-interoperability helpers, not node identities."
        ),
        "oracle": {
            "basis": "spec/03-addressing.md and spec/06-security.md Section 8.5",
            "derivation": (
                "h=SHA-512(pubkey); iid=h[0:8] with U/L cleared; "
                "native=0x02||h[0:7]||iid"
            ),
            "implementation": "Python stdlib hashlib and ipaddress only",
            "generator_command": "python3 test/vectors/generate_ipv6_addresses.py",
        },
        "vectors": vectors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    generated = document()
    if arguments.check:
        try:
            current = read_bounded_exact(OUTPUT)
        except (FileNotFoundError, RuntimeError):
            current = None
        if current != json_bytes(generated):
            print(f"out-of-date vector file: {OUTPUT.name}", file=sys.stderr)
            return 1
        return 0
    atomic_write_json_batch([(OUTPUT, generated)])
    vectors = generated["vectors"]
    assert isinstance(vectors, list)
    print(f"Wrote {len(vectors)} vectors in {OUTPUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
