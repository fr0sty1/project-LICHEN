#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate signed, replay-checked SCHC Rule-Version DIO vectors."""

from __future__ import annotations

import argparse
import sys
import struct
from ipaddress import IPv6Address
from pathlib import Path

VECTORS_DIR = Path(__file__).resolve().parent
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from atomic_json import atomic_write_json, json_bytes, read_bounded_exact  # noqa: E402
from reference_schnorr48 import ReferenceIdentity, sign, signature_transcript  # noqa: E402

OUTPUT_PATH = VECTORS_DIR / "authenticated_schc_dio.json"
FORMAT_VERSION = 2

_RECEIVER_SEED = bytes(range(32))
_PEER_SEED = bytes(range(32, 64))
_ROOT_SEED = bytes(range(64, 96))
_ATTACKER_SEED = bytes(range(96, 128))
_VICTIM_SEED = bytes(range(128, 160))
_DESTINATION = IPv6Address("ff02::1a")
_PEER_DODAG = IPv6Address("0200::1")
_OTHER_DODAG = IPv6Address("0200::2")


def _internet_checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return int((~total) & 0xFFFF)


def _icmpv6(source: IPv6Address, destination: IPv6Address, body: bytes) -> bytes:
    without_checksum = bytes((155, 1, 0, 0)) + body
    pseudoheader = (
        source.packed
        + destination.packed
        + len(without_checksum).to_bytes(4, "big")
        + b"\x00\x00\x00\x3a"
    )
    checksum = _internet_checksum(pseudoheader + without_checksum)
    return bytes((155, 1)) + checksum.to_bytes(2, "big") + body


def _ipv6(source: IPv6Address, destination: IPv6Address, payload: bytes) -> bytes:
    return (
        b"\x60\x00\x00\x00"
        + len(payload).to_bytes(2, "big")
        + bytes((58, 255))
        + source.packed
        + destination.packed
        + payload
    )


def _raw_dio(
    *,
    dodag_id: IPv6Address,
    rank: int,
    options: bytes,
    rpl_instance_id: int = 0,
    mop: int = 1,
) -> bytes:
    """Encode a DIO base plus intentionally arbitrary option bytes."""
    return (
        bytes((rpl_instance_id, 1))
        + rank.to_bytes(2, "big")
        + bytes((mop << 3, 1, 0, 0))
        + dodag_id.packed
        + options
    )


def _signed_case(
    *,
    name: str,
    description: str,
    sender: ReferenceIdentity,
    source_identity: ReferenceIdentity | None = None,
    counter: int,
    rank: int,
    dodag_id: IPv6Address,
    options: bytes,
    trusted_role: str,
    expected_dodag_id: IPv6Address | None = None,
    admitted: bool,
    compatible: bool | None,
    error: str | None,
) -> dict[str, object]:
    rpl_instance_id = 0
    mop = 1
    dio = _raw_dio(
        dodag_id=dodag_id,
        rank=rank,
        options=options,
        rpl_instance_id=rpl_instance_id,
        mop=mop,
    )
    source_owner = sender if source_identity is None else source_identity
    source = IPv6Address(IPv6Address("fe80::").packed[:8] + source_owner.iid)
    icmp = _icmpv6(source, _DESTINATION, dio)
    ipv6 = _ipv6(source, _DESTINATION, icmp)
    link_payload = b"\x14\xff" + ipv6  # L2 SCHC dispatch + literal Rule 255
    epoch, seqnum = counter >> 16, counter & 0xFFFF
    body_length = 4 + 8 + len(link_payload) + 48
    wire_prefix = (
        bytes((body_length, 0xA0, epoch))
        + seqnum.to_bytes(2, "big")
        + sender.eui64
        + link_payload
    )
    signable = signature_transcript(wire_prefix, 0)
    signature = sign(sender, signable)
    wire = wire_prefix + signature
    receiver = ReferenceIdentity.from_seed(_RECEIVER_SEED)
    scope_dodag = dodag_id if expected_dodag_id is None else expected_dodag_id
    return {
        "name": name,
        "description": description,
        "sender_seed_hex": sender.seed.hex(),
        "sender_pubkey_hex": sender.pubkey.hex(),
        "receiver_seed_hex": receiver.seed.hex(),
        "receiver_pubkey_hex": receiver.pubkey.hex(),
        "wire_hex": wire.hex(),
        "epoch": epoch,
        "seqnum": seqnum,
        "rpl_instance_id": rpl_instance_id,
        "dodag_id_hex": dodag_id.packed.hex(),
        "mop": mop,
        "rank": rank,
        "trusted_role": trusted_role,
        "expected_rpl_instance_id": rpl_instance_id,
        "expected_dodag_id_hex": scope_dodag.packed.hex(),
        "expected_mop": mop,
        "expected_role": trusted_role,
        "source_ipv6": str(source),
        "source_iid_hex": source.packed[8:].hex(),
        "destination_ipv6": str(_DESTINATION),
        "option_bytes_hex": options.hex(),
        "dio_hex": dio.hex(),
        "ipv6_hex": ipv6.hex(),
        "link_payload_hex": link_payload.hex(),
        "expected": {
            "admitted": admitted,
            "compatible": compatible,
            "error": error,
        },
    }


def build_document() -> dict[str, object]:
    """Return the complete deterministic vector document."""
    peer = ReferenceIdentity.from_seed(_PEER_SEED)
    root = ReferenceIdentity.from_seed(_ROOT_SEED)
    attacker = ReferenceIdentity.from_seed(_ATTACKER_SEED)
    victim = ReferenceIdentity.from_seed(_VICTIM_SEED)
    root_dodag = IPv6Address(root.ygg_addr)
    victim_dodag = IPv6Address(victim.ygg_addr)
    version_3 = bytes.fromhex("130103")
    cases = [
        _signed_case(
            name="authenticated_peer_compatible_v3",
            description="Signed replay-accepted peer DIO advertises canonical Rule Set Version 3.",
            sender=peer,
            counter=1,
            rank=512,
            dodag_id=_PEER_DODAG,
            options=version_3,
            trusted_role="peer",
            admitted=True,
            compatible=True,
            error=None,
        ),
        _signed_case(
            name="authenticated_peer_rule_version_absent",
            description="Signed peer DIO without a Rule-Version option fails closed.",
            sender=peer,
            counter=2,
            rank=512,
            dodag_id=_PEER_DODAG,
            options=b"",
            trusted_role="peer",
            admitted=False,
            compatible=None,
            error="missing_rule_version",
        ),
        _signed_case(
            name="authenticated_peer_rule_version_length_0",
            description="Signed peer DIO with a zero-length Rule-Version option is malformed.",
            sender=peer,
            counter=3,
            rank=512,
            dodag_id=_PEER_DODAG,
            options=bytes.fromhex("1300"),
            trusted_role="peer",
            admitted=False,
            compatible=None,
            error="malformed_rule_version_length_0",
        ),
        _signed_case(
            name="authenticated_peer_rule_version_length_2",
            description="Signed peer DIO with a two-byte Rule-Version value is malformed.",
            sender=peer,
            counter=4,
            rank=512,
            dodag_id=_PEER_DODAG,
            options=bytes.fromhex("13020303"),
            trusted_role="peer",
            admitted=False,
            compatible=None,
            error="malformed_rule_version_length_2",
        ),
        _signed_case(
            name="authenticated_peer_rule_version_duplicate",
            description="Signed peer DIO with two canonical Rule-Version options fails closed.",
            sender=peer,
            counter=5,
            rank=512,
            dodag_id=_PEER_DODAG,
            options=version_3 + version_3,
            trusted_role="peer",
            admitted=False,
            compatible=None,
            error="duplicate_rule_version",
        ),
        _signed_case(
            name="authenticated_peer_incompatible_v2",
            description=(
                "Signed peer DIO establishes a v2 context that is valid but join-incompatible."
            ),
            sender=peer,
            counter=6,
            rank=512,
            dodag_id=_PEER_DODAG,
            options=bytes.fromhex("130102"),
            trusted_role="peer",
            admitted=True,
            compatible=False,
            error="incompatible_rule_version",
        ),
        _signed_case(
            name="authenticated_peer_wrong_dodag_scope",
            description=(
                "A valid signed DIO is rejected when it is presented to another DODAG scope."
            ),
            sender=peer,
            counter=7,
            rank=512,
            dodag_id=_PEER_DODAG,
            options=version_3,
            trusted_role="peer",
            expected_dodag_id=_OTHER_DODAG,
            admitted=False,
            compatible=None,
            error="dodag_scope_mismatch",
        ),
        _signed_case(
            name="authenticated_peer_wrong_role_scope",
            description=(
                "A non-root signed DIO is rejected when admitted under a trusted-root role."
            ),
            sender=peer,
            counter=8,
            rank=512,
            dodag_id=_PEER_DODAG,
            options=version_3,
            trusted_role="root",
            admitted=False,
            compatible=None,
            error="role_scope_mismatch",
        ),
        _signed_case(
            name="authenticated_peer_source_signer_mismatch",
            description=(
                "A signer-valid peer DIO cannot use a link-local source IID owned by another key."
            ),
            sender=peer,
            source_identity=victim,
            counter=9,
            rank=512,
            dodag_id=_PEER_DODAG,
            options=version_3,
            trusted_role="peer",
            admitted=False,
            compatible=None,
            error="source_signer_mismatch",
        ),
        _signed_case(
            name="authenticated_root_compatible_v3",
            description="A root signature, AddrForKey DODAGID, scope, and v3 option all agree.",
            sender=root,
            counter=10,
            rank=256,
            dodag_id=root_dodag,
            options=version_3,
            trusted_role="root",
            admitted=True,
            compatible=True,
            error=None,
        ),
        _signed_case(
            name="authenticated_root_key_dodag_mismatch",
            description=(
                "An attacker-valid signature cannot claim the victim root's AddrForKey DODAGID."
            ),
            sender=attacker,
            counter=11,
            rank=256,
            dodag_id=victim_dodag,
            options=version_3,
            trusted_role="root",
            admitted=False,
            compatible=None,
            error="root_key_dodag_mismatch",
        ),
    ]
    return {
        "format_version": FORMAT_VERSION,
        "description": (
            "Canonical signed Link/SCHC/RPL DIO admission vectors for the one-byte "
            "SCHC Rule Set Version option (type 0x13)."
        ),
        "provenance": {
            "security_oracle": (
                "Schnorr-48 keys and signatures are derived independently with PyNaCl "
                "group/scalar primitives in reference_schnorr48.py over fixed Link "
                "Signature Domain Version 1. Expected admission "
                "verdicts are fixed spec-derived literals, not production return values."
            ),
            "construction_helpers": (
                "A literal spec encoder constructs IPv6, ICMPv6 checksum, Rule 255, L2 dispatch, "
                "and link-frame bytes without importing production codecs; multicast ff02::1a "
                "selects Rule 255, and independent "
                "consumer tests revalidate the exact domain-separated signature "
                "transcript, checksums, source/signer binding, and root AddrForKey binding."
            ),
        },
        "semantics": {
            "admitted": (
                "The signed frame passes replay, signer/source-IID binding, DIO scope, required "
                "root AddrForKey binding, and Rule-Version structural admission."
            ),
            "compatible": (
                "The admitted peer context permits joining the local Rule Set Version 3 DODAG; "
                "null means no context was admitted."
            ),
            "incompatible_context": (
                "A structurally valid authenticated non-v3 option is admitted as policy evidence "
                "but denies DODAG join."
            ),
        },
        "vectors": cases,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare canonical output byte-for-byte without writing",
    )
    arguments = parser.parse_args(argv)
    document = build_document()
    if arguments.check:
        try:
            current = read_bounded_exact(OUTPUT_PATH)
        except (FileNotFoundError, RuntimeError):
            current = None
        expected = json_bytes(document)
        if current != expected:
            print(f"out-of-date vector file: {OUTPUT_PATH.name}", file=sys.stderr)
            return 1
    else:
        atomic_write_json(OUTPUT_PATH, document)
    vectors = document["vectors"]
    assert isinstance(vectors, list)
    action = "Checked" if arguments.check else "Wrote"
    print(f"{action} {len(vectors)} vectors in {OUTPUT_PATH.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
