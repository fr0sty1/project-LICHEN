# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Executable consumer for signed SCHC Rule-Version DIO vectors."""

from __future__ import annotations

import asyncio
import importlib.util
import json
from collections.abc import Callable
from ipaddress import IPv6Address
from pathlib import Path
from types import ModuleType
from typing import Any, cast

from lichen.crypto.identity import Identity, PeerIdentity
from lichen.ipv6.packet import IPv6Header
from lichen.link.link_layer import LinkLayer, RxFrame
from lichen.rpl.authenticated_dio import AuthenticatedDio
from lichen.rpl.root_signature import verify_dodagid_binding

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"
VECTOR_PATH = VECTORS_DIR / "authenticated_schc_dio.json"
GENERATOR_PATH = VECTORS_DIR / "generate_authenticated_schc_dio.py"


class _VectorRadio:
    def __init__(self, wire: bytes) -> None:
        self._wire = wire

    async def receive(self, _timeout_ms: int, channel: int = 0) -> tuple[bytes, int, int] | None:
        del channel
        wire, self._wire = self._wire, b""
        return (wire, -80, 2) if wire else None

    async def transmit(self, _payload: bytes, channel: int = 0) -> bool:
        del channel
        return True

    def configure(self, freq_hz: int, tx_power_dbm: int) -> None:
        del freq_hz, tx_power_dbm

    async def cad(self, _timeout_ms: int, channel: int = 0) -> bool:
        del channel
        return False


def _load_document() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(VECTOR_PATH.read_text()))


def _load_generator() -> Callable[[], dict[str, object]]:
    spec = importlib.util.spec_from_file_location(
        "authenticated_schc_dio_generator", GENERATOR_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    assert isinstance(module, ModuleType)
    spec.loader.exec_module(module)
    return cast(Callable[[], dict[str, object]], module.build_document)


def _classify_admission_error(exc: ValueError, authenticated: AuthenticatedDio | None) -> str:
    message = str(exc)
    if "DODAGID mismatch" in message:
        return "dodag_scope_mismatch"
    if "role mismatch" in message:
        return "role_scope_mismatch"
    if "source IID does not match signer" in message:
        return "source_signer_mismatch"
    if "root DODAGID does not match signer key" in message:
        return "root_key_dodag_mismatch"
    if authenticated is None:
        raise AssertionError(f"unclassified DIO scope error: {message}") from exc
    version_options = [option for option in authenticated.options if option.type == 0x13]
    if "exactly one" in message:
        if not version_options:
            return "missing_rule_version"
        if len(version_options) > 1:
            return "duplicate_rule_version"
    if len(version_options) == 1 and len(version_options[0].data) != 1:
        return f"malformed_rule_version_length_{len(version_options[0].data)}"
    raise AssertionError(f"unclassified SCHC admission error: {message}") from exc


def _option_bytes(authenticated: AuthenticatedDio) -> bytes:
    return b"".join(
        b"\x00" if option.type == 0 else bytes((option.type, len(option.data))) + option.data
        for option in authenticated.options
    )


async def _execute_vector(vector: dict[str, Any]) -> dict[str, object]:
    receiver = Identity.from_seed(bytes.fromhex(vector["receiver_seed_hex"]))
    assert receiver.pubkey.hex() == vector["receiver_pubkey_hex"]
    sender_identity = Identity.from_seed(bytes.fromhex(vector["sender_seed_hex"]))
    assert sender_identity.pubkey.hex() == vector["sender_pubkey_hex"]
    sender = PeerIdentity.from_pubkey(bytes.fromhex(vector["sender_pubkey_hex"]))
    radio = _VectorRadio(bytes.fromhex(vector["wire_hex"]))
    link = LinkLayer(
        radio=radio,
        identity=receiver,
        peer_lookup=lambda _iid: sender,
        peer_lookup_all=lambda: [sender],
    )
    received = await link.receive(10)
    assert isinstance(received, RxFrame), vector["name"]
    assert received.sender_pubkey == sender.pubkey
    assert received.epoch == vector["epoch"]
    assert received.seqnum == vector["seqnum"]
    assert received.payload.hex() == vector["link_payload_hex"]

    authenticated: AuthenticatedDio | None = None
    try:
        authenticated = link.accept_authenticated_dio(
            received,
            expected_rpl_instance_id=vector["expected_rpl_instance_id"],
            expected_dodag_id=IPv6Address(bytes.fromhex(vector["expected_dodag_id_hex"])),
            expected_mop=vector["expected_mop"],
            expected_role=vector["trusted_role"],
        )
        assert authenticated.ipv6.hex() == vector["ipv6_hex"]
        assert authenticated.dio.dodag_id.packed.hex() == vector["dodag_id_hex"]
        assert authenticated.dio.rank == vector["rank"]
        assert _option_bytes(authenticated).hex() == vector["option_bytes_hex"]
        source = IPv6Header.from_bytes(authenticated.ipv6).src_addr.packed
        assert source[8:].hex() == vector["source_iid_hex"]
        if source[:8] != IPv6Address("fe80::").packed[:8] or source[8:] != authenticated.sender_iid:
            return {
                "admitted": False,
                "compatible": None,
                "error": "source_signer_mismatch",
            }
        if vector["trusted_role"] == "root" and not verify_dodagid_binding(
            authenticated.sender_pubkey, authenticated.dio.dodag_id
        ):
            return {
                "admitted": False,
                "compatible": None,
                "error": "root_key_dodag_mismatch",
            }
        _, peer = link.accept_authenticated_schc_dio(authenticated)
    except ValueError as exc:
        return {
            "admitted": False,
            "compatible": None,
            "error": _classify_admission_error(exc, authenticated),
        }

    compatible = peer.allows_dodag_join
    return {
        "admitted": True,
        "compatible": compatible,
        "error": None if compatible else "incompatible_rule_version",
    }


def test_authenticated_schc_dio_vectors_are_deterministic() -> None:
    assert _load_document() == _load_generator()()


def test_authenticated_schc_dio_vectors() -> None:
    document = _load_document()
    assert document["format_version"] == 2
    vectors = document["vectors"]
    assert isinstance(vectors, list)
    assert len(vectors) == 11
    assert len({vector["name"] for vector in vectors}) == len(vectors)
    assert len({vector["wire_hex"] for vector in vectors}) == len(vectors)
    for vector in vectors:
        assert asyncio.run(_execute_vector(vector)) == vector["expected"], vector["name"]
