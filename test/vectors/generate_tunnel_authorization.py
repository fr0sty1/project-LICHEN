#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate independent tunnel-authorization vectors for spec section 8.11."""

from __future__ import annotations

import argparse
import hashlib
import sys
from ipaddress import IPv6Network
from pathlib import Path

import cbor2

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from atomic_json import atomic_write_json_batch, json_bytes, read_bounded_exact  # noqa: E402
from reference_schnorr48 import ReferenceIdentity, sign  # noqa: E402

OUTPUT = HERE / "tunnel_authorization.json"
FORMAT_VERSION = 1
ALG = -65537
NOW = 1_900_000_000
ROOT = ReferenceIdentity.from_seed(bytes(range(32)))
OTHER_ROOT = ReferenceIdentity.from_seed(bytes(range(1, 33)))
EGRESS = ReferenceIdentity.from_seed(bytes(range(32, 64)))
OTHER_EGRESS = ReferenceIdentity.from_seed(bytes(range(64, 96)))
HOP = bytes.fromhex("0102030405060708")
ROUTE = (HOP, EGRESS.iid)
TARGET = IPv6Network("0200:1234:5600::/40")


def _route_hash(route: tuple[bytes, ...]) -> bytes:
    if not 1 <= len(route) <= 8 or any(len(hop) != 8 for hop in route):
        raise ValueError("route must contain 1-8 eight-byte IIDs")
    return hashlib.sha256(b"".join(route)).digest()[:16]


def _target_bytes(network: IPv6Network) -> bytes:
    return network.network_address.packed[: (network.prefixlen + 7) // 8]


def _identity(name: str, identity: ReferenceIdentity) -> dict[str, str]:
    return {
        "name": name,
        "seed_hex": identity.seed.hex(),
        "public_key_hex": identity.pubkey.hex(),
        "iid_hex": identity.iid.hex(),
        "address_hex": identity.ygg_addr.hex(),
    }


def _duplicate_payload(
    target: bytes, prefix_len: int, route_hash: bytes, path_seq: int, expiry: int, egress_iid: bytes
) -> bytes:
    # Seven pairs with key 1 repeated. This is syntactically valid CBOR but not
    # a deterministic map and MUST be rejected before publication.
    pairs = [
        (1, target),
        (1, target),
        (2, prefix_len),
        (3, route_hash),
        (4, path_seq),
        (5, expiry),
        (6, egress_iid),
    ]
    return b"\xa7" + b"".join(cbor2.dumps(k) + cbor2.dumps(v) for k, v in pairs)


def _message(
    name: str,
    description: str,
    *,
    network: IPv6Network = TARGET,
    route: tuple[bytes, ...] = ROUTE,
    path_seq: int = 7,
    expiry: int = NOW + 300,
    egress: ReferenceIdentity = EGRESS,
    signer: ReferenceIdentity = ROOT,
    kid: bytes | None = None,
    algorithm: int = ALG,
    mutation: str = "none",
) -> dict[str, object]:
    kid = signer.iid if kid is None else kid
    route_digest = _route_hash(route)
    target = _target_bytes(network)
    prefix_len = network.prefixlen
    protected = cbor2.dumps({1: algorithm}, canonical=True)
    payload = cbor2.dumps(
        {1: target, 2: prefix_len, 3: route_digest, 4: path_seq, 5: expiry, 6: egress.iid},
        canonical=True,
    )
    if mutation == "duplicate_protected":
        protected = bytes.fromhex("a2013a00010000013a00010000")
    elif mutation == "duplicate_payload":
        payload = _duplicate_payload(target, prefix_len, route_digest, path_seq, expiry, egress.iid)
    elif mutation == "nonzero_prefix_tail":
        target = target[:-1] + bytes((target[-1] | 0x01,))
        payload = cbor2.dumps(
            {1: target, 2: prefix_len, 3: route_digest, 4: path_seq, 5: expiry, 6: egress.iid},
            canonical=True,
        )
    elif mutation == "missing_claim":
        payload = cbor2.dumps(
            {1: target, 2: prefix_len, 3: route_digest, 4: path_seq, 5: expiry},
            canonical=True,
        )
    elif mutation == "unknown_claim":
        payload = cbor2.dumps(
            {
                1: target,
                2: prefix_len,
                3: route_digest,
                4: path_seq,
                5: expiry,
                6: egress.iid,
                99: 0,
            },
            canonical=True,
        )
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
    digest = hashlib.sha256(sig_structure).digest()
    signature = sign(signer, digest)
    cose = cbor2.dumps([protected, {4: kid}, payload, signature], canonical=True)
    if mutation == "signature_bit":
        decoded = cbor2.loads(cose)
        damaged = bytearray(decoded[3])
        damaged[-1] ^= 1
        decoded[3] = bytes(damaged)
        cose = cbor2.dumps(decoded, canonical=True)
    elif mutation == "noncanonical_outer":
        cose = b"\x98\x04" + cose[1:]
    elif mutation == "trailing_data":
        cose += b"\x00"
    elif mutation == "malformed_break":
        cose = b"\xff"
    return {
        "name": name,
        "description": description,
        "mutation": mutation,
        "root_seed_hex": signer.seed.hex(),
        "root_public_key_hex": signer.pubkey.hex(),
        "root_iid_hex": signer.iid.hex(),
        "kid_iid_hex": kid.hex(),
        "prefix_hex": network.network_address.packed.hex(),
        "target_bytes_hex": target.hex(),
        "prefix_len": prefix_len,
        "route_hops_hex": [hop.hex() for hop in route],
        "route_hash_hex": route_digest.hex(),
        "path_seq": path_seq,
        "expiry": expiry,
        "egress_iid_hex": egress.iid.hex(),
        "protected_hex": protected.hex(),
        "payload_hex": payload.hex(),
        "sig_structure_hex": sig_structure.hex(),
        "digest_hex": digest.hex(),
        "signature_hex": signature.hex(),
        "cose_sign1_hex": cose.hex(),
    }


def _setup_receive(message: str, now: int = NOW, sender: str = "root") -> dict[str, object]:
    return {"action": "receive", "message": message, "now": now, "sender": sender}


def _expect(allowed: bool, denial: str) -> dict[str, object]:
    return {"allowed": allowed, "denial": denial, "response_code": 204 if allowed else 403}


def document() -> dict[str, object]:
    prefix73 = IPv6Network("0200:1234:5678:9a80::/73")
    messages = [
        _message("valid", "Canonical root-to-egress authorization."),
        _message("seq_8", "Fresh sequence after the baseline grant.", path_seq=8),
        _message("seq_9", "Sequence at a revocation floor.", path_seq=9),
        _message("seq_10", "Sequence newer than a revocation floor.", path_seq=10),
        _message("expired", "Authorization expiring exactly at evaluation time.", expiry=NOW),
        _message(
            "wrong_kid", "Signed by root but carrying a different root kid.", kid=OTHER_ROOT.iid
        ),
        _message(
            "wrong_signer",
            "Header claims root but signature uses another key.",
            signer=OTHER_ROOT,
            kid=ROOT.iid,
        ),
        _message(
            "wrong_egress",
            "Valid signature bound to another egress.",
            egress=OTHER_EGRESS,
            route=(HOP, OTHER_EGRESS.iid),
        ),
        _message(
            "other_root", "Valid authorization issued after root rotation.", signer=OTHER_ROOT
        ),
        _message(
            "wrong_algorithm", "Valid signature over an unsupported algorithm.", algorithm=-65536
        ),
        _message("signature_bit", "One signature bit is changed.", mutation="signature_bit"),
        _message(
            "noncanonical_outer",
            "Non-shortest outer array encoding.",
            mutation="noncanonical_outer",
        ),
        _message(
            "trailing_data", "Canonical object followed by trailing CBOR.", mutation="trailing_data"
        ),
        _message(
            "duplicate_protected",
            "Protected map repeats the alg label.",
            mutation="duplicate_protected",
        ),
        _message(
            "duplicate_payload", "Payload map repeats target claim 1.", mutation="duplicate_payload"
        ),
        _message("missing_claim", "Payload omits egress claim 6.", mutation="missing_claim"),
        _message(
            "unknown_claim", "Payload contains unassigned claim 99.", mutation="unknown_claim"
        ),
        _message("malformed_break", "A lone CBOR break byte.", mutation="malformed_break"),
        _message("prefix_0", "Canonical zero-length prefix boundary.", network=IPv6Network("::/0")),
        _message("prefix_73", "Canonical non-octet prefix boundary.", network=prefix73),
        _message(
            "prefix_73_bad_tail",
            "Non-zero unused bits in a /73 target.",
            network=prefix73,
            mutation="nonzero_prefix_tail",
        ),
        _message(
            "prefix_128",
            "Canonical host prefix boundary.",
            network=IPv6Network("0200:1234:5678:9abc:def0:1234:5678:9abc/128"),
        ),
        _message("short_expiry", "Grant used to test exact data-plane expiry.", expiry=NOW + 1),
    ]
    post_cases = [
        {
            "name": "valid_root_egress",
            "message": "valid",
            "active_root": "root",
            "oscore_authenticated": True,
            "oscore_sender": "root",
            "now": NOW,
            "setup": [],
            "expected": _expect(True, "none"),
        },
        {
            "name": "oscore_required",
            "message": "valid",
            "active_root": "root",
            "oscore_authenticated": False,
            "oscore_sender": "root",
            "now": NOW,
            "setup": [],
            "expected": _expect(False, "oscore-required"),
        },
        {
            "name": "wrong_oscore_root",
            "message": "valid",
            "active_root": "root",
            "oscore_authenticated": True,
            "oscore_sender": "other_root",
            "now": NOW,
            "setup": [],
            "expected": _expect(False, "wrong-root"),
        },
        {
            "name": "wrong_kid",
            "message": "wrong_kid",
            "active_root": "root",
            "oscore_authenticated": True,
            "oscore_sender": "root",
            "now": NOW,
            "setup": [],
            "expected": _expect(False, "wrong-root"),
        },
        {
            "name": "wrong_signing_key",
            "message": "wrong_signer",
            "active_root": "root",
            "oscore_authenticated": True,
            "oscore_sender": "root",
            "now": NOW,
            "setup": [],
            "expected": _expect(False, "signature"),
        },
        {
            "name": "wrong_egress",
            "message": "wrong_egress",
            "active_root": "root",
            "oscore_authenticated": True,
            "oscore_sender": "root",
            "now": NOW,
            "setup": [],
            "expected": _expect(False, "wrong-egress"),
        },
        {
            "name": "expired",
            "message": "expired",
            "active_root": "root",
            "oscore_authenticated": True,
            "oscore_sender": "root",
            "now": NOW,
            "setup": [],
            "expected": _expect(False, "expired"),
        },
        {
            "name": "replay_equal",
            "message": "valid",
            "active_root": "root",
            "oscore_authenticated": True,
            "oscore_sender": "root",
            "now": NOW,
            "setup": [_setup_receive("valid")],
            "expected": _expect(False, "replay"),
        },
        {
            "name": "revoked_floor",
            "message": "seq_9",
            "active_root": "root",
            "oscore_authenticated": True,
            "oscore_sender": "root",
            "now": NOW,
            "setup": [
                _setup_receive("valid"),
                {"action": "revoke", "message": "valid", "through_path_seq": 9},
            ],
            "expected": _expect(False, "revoked"),
        },
        {
            "name": "fresh_after_revoke",
            "message": "seq_10",
            "active_root": "root",
            "oscore_authenticated": True,
            "oscore_sender": "root",
            "now": NOW,
            "setup": [
                _setup_receive("valid"),
                {"action": "revoke", "message": "valid", "through_path_seq": 9},
            ],
            "expected": _expect(True, "none"),
        },
        {
            "name": "clock_rollback",
            "message": "seq_8",
            "active_root": "root",
            "oscore_authenticated": True,
            "oscore_sender": "root",
            "now": NOW,
            "setup": [_setup_receive("valid", NOW + 100)],
            "expected": _expect(False, "clock-regression"),
        },
        {
            "name": "old_root_after_rotation",
            "message": "valid",
            "active_root": "root",
            "oscore_authenticated": True,
            "oscore_sender": "root",
            "now": NOW,
            "setup": [{"action": "change_root", "identity": "other_root"}],
            "expected": _expect(False, "wrong-root"),
        },
        {
            "name": "new_root_after_rotation",
            "message": "other_root",
            "active_root": "root",
            "oscore_authenticated": True,
            "oscore_sender": "other_root",
            "now": NOW,
            "setup": [{"action": "change_root", "identity": "other_root"}],
            "expected": _expect(True, "none"),
        },
    ]
    for message, denial in (
        ("wrong_algorithm", "algorithm"),
        ("signature_bit", "signature"),
        ("noncanonical_outer", "malformed"),
        ("trailing_data", "malformed"),
        ("duplicate_protected", "malformed"),
        ("duplicate_payload", "malformed"),
        ("missing_claim", "malformed"),
        ("unknown_claim", "malformed"),
        ("malformed_break", "malformed"),
        ("prefix_73_bad_tail", "malformed"),
    ):
        post_cases.append(
            {
                "name": message,
                "message": message,
                "active_root": "root",
                "oscore_authenticated": True,
                "oscore_sender": "root",
                "now": NOW,
                "setup": [],
                "expected": _expect(False, denial),
            }
        )
    for message in ("prefix_0", "prefix_73", "prefix_128"):
        post_cases.append(
            {
                "name": f"accept_{message}",
                "message": message,
                "active_root": "root",
                "oscore_authenticated": True,
                "oscore_sender": "root",
                "now": NOW,
                "setup": [],
                "expected": _expect(True, "none"),
            }
        )

    def decap(
        name: str,
        message: str | None,
        source: str,
        destination: str,
        route: tuple[bytes, ...] = ROUTE,
        direction: str = "mesh-to-external",
        now: int = NOW,
        extra_setup: list[dict[str, object]] | None = None,
        allowed: bool = True,
        denial: str = "none",
    ) -> dict[str, object]:
        setup = [] if message is None else [_setup_receive(message)]
        setup.extend(extra_setup or [])
        return {
            "name": name,
            "active_root": "root",
            "setup": setup,
            "route_hops_hex": [hop.hex() for hop in route],
            "inner_source": source,
            "inner_destination": destination,
            "direction": direction,
            "now": now,
            "expected": _expect(allowed, denial),
        }

    first = "0200:1234:5600::"
    last = "0200:1234:56ff:ffff:ffff:ffff:ffff:ffff"
    decapsulation_cases = [
        decap("valid_first_address", "valid", first, "2001:db8::1"),
        decap("valid_last_address", "valid", last, "2001:db8::1"),
        decap(
            "source_outside_prefix",
            "valid",
            "0200:1234:5700::",
            "2001:db8::1",
            allowed=False,
            denial="no-authorization",
        ),
        decap(
            "wrong_route_hash",
            "valid",
            first,
            "2001:db8::1",
            route=(bytes.fromhex("1112131415161718"), EGRESS.iid),
            allowed=False,
            denial="no-authorization",
        ),
        decap(
            "wrong_direction",
            "valid",
            first,
            "2001:db8::1",
            direction="external-to-mesh",
            allowed=False,
            denial="wrong-direction",
        ),
        decap(
            "mesh_destination",
            "valid",
            first,
            "0200:ffff::1",
            allowed=False,
            denial="destination-scope",
        ),
        decap(
            "multicast_destination",
            "valid",
            first,
            "ff02::1",
            allowed=False,
            denial="destination-scope",
        ),
        decap(
            "missing_authorization",
            None,
            first,
            "2001:db8::1",
            allowed=False,
            denial="no-authorization",
        ),
        decap(
            "expired_at_boundary",
            "short_expiry",
            first,
            "2001:db8::1",
            now=NOW + 1,
            allowed=False,
            denial="expired",
        ),
        decap(
            "revoked_authorization",
            "valid",
            first,
            "2001:db8::1",
            extra_setup=[{"action": "revoke", "message": "valid", "through_path_seq": 7}],
            allowed=False,
            denial="no-authorization",
        ),
        decap(
            "root_rotation_clears_table",
            "valid",
            first,
            "2001:db8::1",
            extra_setup=[{"action": "change_root", "identity": "other_root"}],
            allowed=False,
            denial="no-authorization",
        ),
        decap(
            "link_local_source_rejected",
            "prefix_0",
            "fe80::1",
            "2001:db8::1",
            allowed=False,
            denial="source-scope",
        ),
        decap(
            "looped_route",
            "valid",
            first,
            "2001:db8::1",
            route=(HOP, HOP),
            allowed=False,
            denial="invalid-route",
        ),
    ]
    return {
        "$schema": "./tunnel_authorization.schema.json",
        "vector_type": "tunnel_authorization",
        "format_version": FORMAT_VERSION,
        "description": (
            "Canonical and fail-closed tunnel authorization corpus for spec/06-security.md 8.11."
        ),
        "oracle": {
            "basis": "RFC 9052 Sig_structure plus LICHEN security spec 8.11",
            "implementation": (
                "independent PyNaCl reference_schnorr48.py; no lichen package imports"
            ),
            "generator_command": "python3 test/vectors/generate_tunnel_authorization.py",
            "freshness_command": "python3 test/vectors/generate_tunnel_authorization.py --check",
        },
        "constants": {
            "algorithm": ALG,
            "protected_hex": "a1013a00010000",
            "maximum_route_hops": 8,
            "maximum_authorizations": 256,
            "evaluation_time": NOW,
        },
        "identities": [
            _identity("root", ROOT),
            _identity("other_root", OTHER_ROOT),
            _identity("egress", EGRESS),
            _identity("other_egress", OTHER_EGRESS),
        ],
        "authorizations": messages,
        "post_cases": post_cases,
        "decapsulation_cases": decapsulation_cases,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    generated = document()
    if args.check:
        try:
            current = read_bounded_exact(OUTPUT)
        except (FileNotFoundError, RuntimeError):
            current = None
        if current != json_bytes(generated):
            print(f"out-of-date vector file: {OUTPUT.name}", file=sys.stderr)
            return 1
        return 0
    atomic_write_json_batch([(OUTPUT, generated)])
    print(
        f"Wrote {len(generated['authorizations'])} messages, "
        f"{len(generated['post_cases'])} POST cases, and "
        f"{len(generated['decapsulation_cases'])} data-plane cases"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
