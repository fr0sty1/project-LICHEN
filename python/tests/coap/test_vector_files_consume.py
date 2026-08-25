# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume the orphaned CoAP vector files by driving the real implementation.

Files consumed (previously had zero machine consumers):

- ``test/vectors/coap_messages.json``          -> aiocoap wire codec + ``lichen.coap.params``
                                                  + ``parse_uri_authority``
- ``test/vectors/coap_option_malformed.json``  -> ``SecureDatagramChannel._has_oscore_option``
                                                  (the strict RFC 7252 §3.1 wire gate) and
                                                  the aiocoap option serializer/parser that
                                                  LICHEN's transport delegates to
- ``test/vectors/coap_token_validation.json``  -> the same wire gate plus request/response token
                                                  correlation in ``SecureDatagramChannel``
- ``test/vectors/coap_observe_sequence.json``  -> ``AiocoapResourceSubscription._should_accept``
- ``test/vectors/coap_rd.json``                -> ``ResourceDirectoryResource`` over a full
                                                  InMemoryNetwork client/server stack

Known vector-vs-implementation conflicts are asserted *exactly* as pinned and
marked ``xfail(strict=True)`` with evidence, so a future fix flips them to
XPASS and forces this marker to be revisited:

- ``observe_seq_large_jump_accept``: diff == 2**23 exactly; ``_should_accept``
  requires ``0 < diff < 2**23`` (bead project-LICHEN-worker6-l1qw.7.11.4).
- ``rd_register_sensor42`` / ``rd_lookup_all``: link descriptors are restricted
  to ``{href, rt}`` since the mutation-resource hardening (commit aca39ad044),
  but these vectors pin an ``if: core.s`` attribute, which now yields 4.00.
"""

from __future__ import annotations

import asyncio
import json
import struct
from pathlib import Path
from typing import Any

import aiocoap
import cbor2
import pytest
from aiocoap import Message
from aiocoap import error as aiocoap_error
from aiocoap.optiontypes import OpaqueOption

from lichen.client.ip_coap import AiocoapResourceSubscription
from lichen.coap.params import CONTENT_FORMATS
from lichen.coap.resources import StaticNodeInfo, build_site
from lichen.coap.secure.channel import SecureDatagramChannel
from lichen.coap.secure.types import PeerContext, _RequestCorrelation
from lichen.coap.transport import (
    DatagramChannel,
    InMemoryNetwork,
    LichenRemote,
    create_lichen_context,
    parse_uri_authority,
)
from lichen.crypto.identity import Identity
from lichen.crypto.oscore import MemorySecurityContext

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


def _load(name: str) -> dict[str, Any]:
    return json.loads((VECTORS_DIR / name).read_text())


COAP_MESSAGES = _load("coap_messages.json")
COAP_OPTION_MALFORMED = _load("coap_option_malformed.json")
COAP_TOKEN_VALIDATION = _load("coap_token_validation.json")
COAP_OBSERVE_SEQUENCE = _load("coap_observe_sequence.json")
COAP_RD = _load("coap_rd.json")


def _vec(doc: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [v for v in doc["vectors"] if v["name"] == name]
    assert len(matches) == 1, f"vector {name!r} not unique in {doc['name']}"
    return matches[0]


# ---------------------------------------------------------------------------
# Shared test doubles / helpers
# ---------------------------------------------------------------------------


class NullChannel(DatagramChannel):
    """Minimal DatagramChannel standing in under SecureDatagramChannel."""

    def __init__(self) -> None:
        self.sent: list[tuple[bytes, str]] = []
        self.receiver: Any = None

    def send_datagram(self, data: bytes, dest: str, **kwargs: object) -> None:
        self.sent.append((data, dest))

    def set_receiver(self, receiver: Any) -> None:
        self.receiver = receiver

    def clear_receiver(self, receiver: Any) -> None:
        if self.receiver == receiver:
            self.receiver = None

    def close(self) -> None:
        pass

    async def shutdown(self) -> None:
        pass

    def request_started(self, peer: str, token: bytes, *, locally_originated: bool) -> object:
        return object()

    def request_interest_ended(
        self, peer: str, token: bytes, lifecycle_id: object | None, *, locally_originated: bool
    ) -> None:
        pass

    def exchange_ended(self, peer: str, mid: int, *, reset: bool) -> None:
        pass


_SCANNER_HEADER = b"\x50\x01\x00\x01"  # Ver=1 T=NON TKL=0 GET MID=0x0001
_OSCORE_REACH_9 = b"\x91\x00"  # delta=9 len=1 value=0x00 -> cumulative delta hits OSCORE


def _scanner_probe(options_bytes: bytes) -> bool:
    """True iff the strict wire gate parses *options_bytes* far enough to find OSCORE."""
    return SecureDatagramChannel._has_oscore_option(_SCANNER_HEADER + options_bytes)


def _decode_wire(hex_or_bytes: str | bytes, remote: str = "srv") -> Message:
    wire = bytes.fromhex(hex_or_bytes) if isinstance(hex_or_bytes, str) else hex_or_bytes
    return Message.decode(wire, LichenRemote(remote))


def _make_subscription() -> AiocoapResourceSubscription:
    subscription = object.__new__(AiocoapResourceSubscription)
    subscription._handle = None
    subscription._method = "GET"
    subscription._path = "/x"
    subscription._timeout_s = 1.0
    subscription._closed = False
    subscription._closed_event = asyncio.Event()
    subscription._last_seq = None
    return subscription


def _observe_feed(last_seq: int, new_seq: int) -> bool:
    subscription = _make_subscription()
    subscription._last_seq = last_seq
    message = Message(code=aiocoap.CONTENT)
    message.opt.observe = new_seq
    accepted = subscription._should_accept(message)
    if accepted:
        assert subscription._last_seq == new_seq, "accepted notification must advance state"
    else:
        assert subscription._last_seq == last_seq, "rejected notification must not advance state"
    return accepted


async def _rd_setup() -> tuple[Any, Any]:
    net = InMemoryNetwork()
    site = build_site(StaticNodeInfo(), resource_directory=True)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server


async def _rd_teardown(client: Any, server: Any) -> None:
    await client.shutdown()
    await server.shutdown()


async def _rd_request(client: Any, method: Any, uri: str, payload: bytes | None = None) -> Message:
    message = Message(code=method, uri=f"coap://srv{uri}")
    if payload is not None:
        message.payload = payload
        message.opt.content_format = 60
    return await client.request(message).response


def _secure_channel_with_peer() -> tuple[SecureDatagramChannel, PeerContext]:
    channel = SecureDatagramChannel(NullChannel(), Identity.generate())
    context = PeerContext(
        MemorySecurityContext(
            master_secret=b"s" * 16,
            master_salt=b"t" * 8,
            sender_id=b"\x01",
            recipient_id=b"\x02",
        ),
        b"peer-key",
    )
    channel._active_peer_contexts["peer"] = context
    return channel, context


def _con_message(token_hex: str, mid: int = 1) -> Message:
    return Message(
        code=aiocoap.GET, _mtype=aiocoap.CON, _mid=mid, _token=bytes.fromhex(token_hex)
    )


# ---------------------------------------------------------------------------
# coap_messages.json — RFC 7252 wire codec (aiocoap engine used by LICHEN)
# ---------------------------------------------------------------------------


class TestCoapMessagesVectors:
    def test_con_get_status(self) -> None:
        vec = _vec(COAP_MESSAGES, "con_get_status")
        # Encode side: building the pinned fields reproduces the committed bytes.
        built = Message(code=aiocoap.GET, _mtype=aiocoap.CON, _mid=vec["mid"], _token=b"\x01\x02")
        built.opt.uri_path = tuple(vec["uri_path"])
        assert built.encode().hex() == vec["encoded"]
        assert built.encode().hex() == "420112340102b6737461747573"
        # Decode side: every decoded_* pin.
        decoded = _decode_wire(vec["encoded"])
        assert int(decoded.code) == vec["decoded_code"]
        assert int(decoded.mtype) == vec["decoded_mtype"]
        assert decoded.mid == vec["decoded_mid"]
        assert decoded.token.hex() == vec["decoded_token"]
        assert decoded.code.dotted == "0.01"
        assert decoded.opt.uri_path == tuple(vec["uri_path"])
        assert decoded.payload == b""

    def test_non_post_sensors_cbor(self) -> None:
        vec = _vec(COAP_MESSAGES, "non_post_sensors_cbor")
        payload = bytes.fromhex(vec["payload_hex"])
        assert cbor2.loads(payload) == vec["payload_cbor"]
        built = Message(code=aiocoap.POST, _mtype=aiocoap.NON, _mid=vec["mid"], _token=b"\xab")
        built.opt.uri_path = tuple(vec["uri_path"])
        built.opt.content_format = vec["content_format"]
        built.payload = payload
        assert built.encode().hex() == vec["encoded"]
        decoded = _decode_wire(vec["encoded"])
        assert int(decoded.code) == vec["decoded_code"]
        assert int(decoded.mtype) == vec["decoded_mtype"]
        assert decoded.payload.hex() == vec["decoded_payload_hex"]
        assert int(decoded.opt.content_format) == vec["decoded_content_format"]

    def test_ack_205_content(self) -> None:
        vec = _vec(COAP_MESSAGES, "ack_205_content")
        # Note: the committed `encoded` bytes carry code nibble 0x02, so its own
        # decoded_code pin (2) is what the wire really says; the descriptive
        # code/code_name metadata ("69", "2.05 Content") disagrees with those
        # bytes. The machine-checkable pins below all hold against the wire.
        decoded = _decode_wire(vec["encoded"])
        assert int(decoded.mtype) == vec["mtype"]  # ACK
        assert decoded.mid == vec["mid"]
        assert decoded.payload.hex() == vec["payload"]
        assert decoded.payload.decode() == vec["payload_text"]
        assert int(decoded.code) == vec["decoded_code"]
        assert decoded.payload.decode() == vec["decoded_payload_text"]

    def test_rst_empty(self) -> None:
        vec = _vec(COAP_MESSAGES, "rst_empty")
        built = Message(code=aiocoap.EMPTY, _mtype=aiocoap.RST, _mid=vec["mid"], _token=b"")
        assert built.encode().hex() == vec["encoded"]
        decoded = _decode_wire(vec["encoded"])
        assert int(decoded.mtype) == vec["decoded_mtype"]
        assert int(decoded.code) == vec["code"]
        assert decoded.mid == vec["mid"]

    def test_content_format_table(self) -> None:
        vec = _vec(COAP_MESSAGES, "content_format_table")
        assert {f["value"]: f["media_type"] for f in vec["formats"]} == CONTENT_FORMATS
        assert CONTENT_FORMATS[112] == "application/senml+cbor"

    def test_uri_authority_ipv6(self) -> None:
        vec = _vec(COAP_MESSAGES, "uri_authority_ipv6")
        endpoint = parse_uri_authority(vec["authority"])
        assert endpoint.host == vec["expected_host"]
        assert endpoint.port == vec["expected_port"]
        assert endpoint.host == vec["parsed_host"]
        assert endpoint.port == vec["parsed_port"]


# ---------------------------------------------------------------------------
# coap_option_malformed.json — RFC 7252 §3.1 delta/length edge cases
# ---------------------------------------------------------------------------


class TestCoapOptionMalformedVectors:
    @pytest.mark.parametrize(
        "name,option_number",
        [
            ("option_delta_13_extended_1byte", 13),
            ("option_delta_14_extended_2byte", 269),
        ],
    )
    def test_extended_delta_valid_encodes_exactly(self, name: str, option_number: int) -> None:
        vec = _vec(COAP_OPTION_MALFORMED, name)
        assert vec["expected"]["valid"] is True
        assert vec["expected"]["delta"] == option_number
        built = Message(code=aiocoap.GET, _mtype=aiocoap.NON, _mid=1, _token=b"")
        built.opt.add_option(OpaqueOption(option_number, b""))
        options_bytes = built.encode()[4:]
        assert options_bytes.hex() == vec["option_byte"] + vec["extended_delta"]
        # The parser accepts the well-formed extended delta without error.
        decoded = _decode_wire(_SCANNER_HEADER + options_bytes)
        assert decoded is not None

    @pytest.mark.parametrize(
        "name,length",
        [
            ("option_length_13_extended_1byte", 13),
            ("option_length_14_extended_2byte", 269),
        ],
    )
    def test_extended_length_valid_parses_value(self, name: str, length: int) -> None:
        vec = _vec(COAP_OPTION_MALFORMED, name)
        assert vec["expected"]["valid"] is True
        assert vec["expected"]["length"] == length
        # delta nibble 0 (kept small), length nibble 13/14 with extension bytes.
        wire_options = bytes.fromhex(vec["option_byte"] + vec["extended_length"]) + bytes(length)
        decoded = _decode_wire(_SCANNER_HEADER + wire_options)
        values = [
            bytes(o.value) if isinstance(o.value, (bytes, bytearray)) else o.value
            for o in decoded.opt.option_list()
        ]
        assert any(len(v) == length for v in values)
        # The strict wire gate also parses it cleanly (positive OSCORE detection
        # proves the whole scan advanced past the long value; delta 0 + delta 9
        # follower reaches the OSCORE cumulative delta).
        assert _scanner_probe(wire_options + b"\x91\x00") is True

    @pytest.mark.parametrize(
        "name",
        ["option_delta_15_reserved_reject", "option_length_15_reserved_reject"],
    )
    def test_reserved_nibble_15_rejected_by_wire_gate(self, name: str) -> None:
        vec = _vec(COAP_OPTION_MALFORMED, name)
        assert vec["expected"]["valid"] is False
        option_byte = bytes.fromhex(vec["option_byte"])
        assert _scanner_probe(option_byte) is False
        assert _scanner_probe(option_byte + _OSCORE_REACH_9) is False
        if name == "option_length_15_reserved_reject":
            with pytest.raises(aiocoap_error.UnparsableMessage):
                _decode_wire(_SCANNER_HEADER + option_byte + b"\x11")

    def test_option_0_if_match_zero_length(self) -> None:
        vec = _vec(COAP_OPTION_MALFORMED, "option_0_if_match_zero_length")
        assert vec["expected"]["valid"] is True
        assert vec["cumulative_number"] == 0
        assert vec["length"] == 0
        # Option number 0, zero-length value, then delta 9 reaching OSCORE.
        assert _scanner_probe(b"\x00" + _OSCORE_REACH_9) is True
        decoded = _decode_wire(_SCANNER_HEADER + b"\x00" + b"\x91\x00")
        numbers = [int(o.number) for o in decoded.opt.option_list()]
        assert numbers[0] == 0

    def test_option_truncated_extended_delta(self) -> None:
        vec = _vec(COAP_OPTION_MALFORMED, "option_truncated_extended_delta")
        assert vec["expected"]["valid"] is False
        assert _scanner_probe(bytes.fromhex(vec["wire_hex"])) is False

    def test_option_truncated_extended_length(self) -> None:
        vec = _vec(COAP_OPTION_MALFORMED, "option_truncated_extended_length")
        assert vec["expected"]["valid"] is False
        assert _scanner_probe(bytes.fromhex(vec["wire_hex"])) is False

    def test_option_value_truncated(self) -> None:
        vec = _vec(COAP_OPTION_MALFORMED, "option_value_truncated")
        assert vec["expected"]["valid"] is False
        wire = bytes.fromhex(vec["wire_hex"])
        assert _scanner_probe(wire) is False
        with pytest.raises(aiocoap.error.UnparsableMessage):
            _decode_wire(_SCANNER_HEADER + wire)

    def test_option_delta_overflow_reject(self) -> None:
        vec = _vec(COAP_OPTION_MALFORMED, "option_delta_overflow_reject")
        assert vec["expected"]["valid"] is False
        # First option: delta nibble 14 with extension 65530-269 = 0xFEDD.
        # Second option: delta nibble 14 with extension 0xFFFF (per vector),
        # pushing the cumulative option number to 65530+269+65535 = 131334.
        cumulative = struct.pack(">H", vec["cumulative_number"] - 269)
        overflow = bytes.fromhex(vec["extended_delta"])
        wire = _SCANNER_HEADER + b"\xe0" + cumulative + b"\xe0" + overflow
        # Strict wire gate drops the datagram before it can be processed.
        assert SecureDatagramChannel._has_oscore_option(wire) is False
        # The CoAP codec refuses to *emit* an option number beyond 16 bits.
        built = Message(code=aiocoap.GET, _mtype=aiocoap.NON, _mid=1, _token=b"")
        built.opt.add_option(OpaqueOption(vec["cumulative_number"] + 269 + 65535, b""))
        with pytest.raises(ValueError):
            built.encode()
        # Divergence note: the aiocoap decoder itself tolerates the overflow
        # (returns wrapped option numbers), so inbound strictness lives in the
        # LICHEN wire gate asserted above.

    def test_payload_marker_without_payload(self) -> None:
        """UNDRIVABLE today: no LICHEN component rejects a trailing 0xFF marker.

        The strict wire gate stops scanning at the marker (indistinguishable
        from any non-OSCORE datagram) and the aiocoap decoder used by the
        transport accepts the empty payload. Pinned expectation (reject) has no
        enforcing code path yet; kept visible as a skip rather than a fake pass.
        """
        vec = _vec(COAP_OPTION_MALFORMED, "payload_marker_without_payload")
        decoded = _decode_wire(vec["wire_hex"])  # tolerated by the codec today
        assert decoded.payload == b""
        pytest.skip(
            "UNDRIVABLE: empty_payload_after_marker is not rejected by any "
            "LICHEN code path; aiocoap tolerates it and the strict gate cannot "
            "distinguish it from a marker-free datagram"
        )


# ---------------------------------------------------------------------------
# coap_token_validation.json — RFC 7252 §3 TKL bounds and token semantics
# ---------------------------------------------------------------------------


class TestCoapTokenValidationVectors:
    @pytest.mark.parametrize(
        "name,tkl,token_hex",
        [
            ("tkl_0_empty_token_valid", 0, ""),
            ("tkl_1_single_byte_token", 1, "ab"),
            ("tkl_8_max_valid_token", 8, "0102030405060708"),
        ],
    )
    def test_valid_tkl_decodes_exact_token(self, name: str, tkl: int, token_hex: str) -> None:
        vec = _vec(COAP_TOKEN_VALIDATION, name)
        assert vec["tkl"] == tkl
        expected = vec["expected"]
        assert expected["valid"] is True
        wire = bytes.fromhex(vec["header_byte"]) + b"\x01\x00\x01"
        wire += bytes.fromhex(token_hex)
        decoded = _decode_wire(wire)
        assert len(decoded.token) == tkl
        if tkl == 0:
            assert decoded.token.hex() == expected["token"]
        elif "token_length" in expected:
            assert len(decoded.token) == expected["token_length"]
            assert decoded.token.hex() == token_hex
        # Positive control: with the token present, the strict gate scans past
        # it and finds a following OSCORE option.
        assert SecureDatagramChannel._has_oscore_option(wire + _OSCORE_REACH_9) is True

    @pytest.mark.parametrize(
        "name,tkl",
        [
            ("tkl_9_reject", 9),
            ("tkl_10_reject", 10),
            ("tkl_15_reject", 15),
        ],
    )
    def test_reserved_tkl_rejected_by_wire_gate(self, name: str, tkl: int) -> None:
        vec = _vec(COAP_TOKEN_VALIDATION, name)
        assert vec["tkl"] == tkl
        assert vec["expected"]["valid"] is False
        wire = bytes.fromhex(vec["header_byte"]) + b"\x01\x00\x01"
        # Strict gate: TKL > 8 never passes the reserved-range check.
        assert SecureDatagramChannel._has_oscore_option(wire) is False
        assert SecureDatagramChannel._has_oscore_option(wire + _OSCORE_REACH_9) is False

    def test_tkl_mismatch_truncated(self) -> None:
        vec = _vec(COAP_TOKEN_VALIDATION, "tkl_mismatch_truncated")
        assert vec["expected"]["valid"] is False
        truncated = bytes.fromhex(vec["header_byte"]) + b"\x01\x00\x01"
        truncated += bytes.fromhex(vec["token_hex"])  # 2 bytes, TKL claims 4
        assert SecureDatagramChannel._has_oscore_option(truncated) is False
        # Contrast: the same prefix with all 4 token bytes scans through fine,
        # proving the rejection above is specific to the truncation.
        complete = truncated + b"\x03\x04"
        assert SecureDatagramChannel._has_oscore_option(complete + _OSCORE_REACH_9) is True

    def test_token_zero_bytes_vs_empty(self) -> None:
        vec = _vec(COAP_TOKEN_VALIDATION, "token_zero_bytes_vs_empty")
        case_empty, case_zero = vec["cases"]
        empty = _decode_wire(bytes([0x40 | case_empty["tkl"]]) + b"\x01\x00\x01")
        zero = _decode_wire(bytes([0x40 | case_zero["tkl"]]) + b"\x01\x00\x01" + b"\x00\x00")
        assert len(empty.token) == 0
        assert zero.token == b"\x00\x00"
        assert (empty.token != zero.token) is vec["expected"]["tokens_distinct"]

    def test_con_request_should_have_token(self) -> None:
        vec = _vec(COAP_TOKEN_VALIDATION, "con_request_should_have_token")
        assert vec["expected"]["valid"] is True
        # Syntactically valid CON GET without token decodes cleanly. The
        # SHOULD-level warning is advisory prose, not enforced machinery.
        decoded = _decode_wire(bytes([0x40 | vec["tkl"]]) + bytes([vec["code"]]) + b"\x00\x01")
        assert int(decoded.mtype) == vec["mtype"]
        assert int(decoded.code) == vec["code"]
        assert decoded.token == b""

    def test_response_token_must_match_request(self) -> None:
        vec = _vec(COAP_TOKEN_VALIDATION, "response_token_must_match_request")
        assert vec["request_token"] == vec["response_token"]
        assert vec["expected"]["match"] is True
        channel, context = _secure_channel_with_peer()
        request = _con_message(vec["request_token"])
        operation = channel._prepare_send_operation(request.encode(), "peer", "peer")
        assert operation is not None
        assert operation.token == bytes.fromhex(vec["request_token"])
        # Server-side inbound correlation keyed by the exact request token.
        correlation = _RequestCorrelation(None, observe=False)
        context.inbound_requests[operation.token] = correlation
        matched = Message(
            code=aiocoap.CONTENT,
            _mtype=aiocoap.ACK,
            _mid=2,
            _token=bytes.fromhex(vec["response_token"]),
        )
        result = channel._prepare_send_operation(matched.encode(), "peer", "peer")
        assert result is not None
        assert result.correlation is correlation
        assert result.token == bytes.fromhex(vec["response_token"])

    def test_response_token_mismatch_reject(self) -> None:
        vec = _vec(COAP_TOKEN_VALIDATION, "response_token_mismatch_reject")
        assert vec["request_token"] != vec["response_token"]
        assert vec["expected"]["match"] is False
        channel, context = _secure_channel_with_peer()
        correlation = _RequestCorrelation(None, observe=False)
        context.inbound_requests[bytes.fromhex(vec["request_token"])] = correlation
        mismatched = Message(
            code=aiocoap.CONTENT,
            _mtype=aiocoap.ACK,
            _mid=3,
            _token=vec["response_token"].encode(),
        )
        result = channel._prepare_send_operation(mismatched.encode(), "peer", "peer")
        assert result is None


# ---------------------------------------------------------------------------
# coap_observe_sequence.json — RFC 7641 §4.4 24-bit sequence semantics
# ---------------------------------------------------------------------------

_OBSERVE_CONFLICT = (
    "Vector expects accept at exactly half 24-bit range (diff == 2**23); "
    "_should_accept requires 0 < diff < 2**23 (serial-arithmetic ambiguity, "
    "see bead project-LICHEN-worker6-l1qw.7.11.4 which flags the vector's "
    "off-by-one)"
)


class TestCoapObserveSequenceVectors:
    @pytest.mark.parametrize(
        "name",
        [
            "observe_seq_increasing_accept",
            "observe_seq_equal_reject",
            "observe_seq_lower_reject",
            "observe_seq_rollover_24bit",
            "observe_seq_rollover_small_gap",
            "observe_seq_rollover_backward_reject",
            "observe_max_seq_boundary",
            "observe_seq_exceeds_24bit_reject",
            "observe_seq_beyond_half_range_reject",
        ],
    )
    def test_sequence_window_semantics(self, name: str) -> None:
        vec = _vec(COAP_OBSERVE_SEQUENCE, name)
        accepted = _observe_feed(vec["last_seq"], vec["new_seq"])
        assert accepted is vec["expected"]["accept"]

    @pytest.mark.xfail(strict=True, reason=_OBSERVE_CONFLICT)
    def test_observe_seq_large_jump_accept(self) -> None:
        vec = _vec(COAP_OBSERVE_SEQUENCE, "observe_seq_large_jump_accept")
        accepted = _observe_feed(vec["last_seq"], vec["new_seq"])
        assert accepted is vec["expected"]["accept"] is True


# ---------------------------------------------------------------------------
# coap_rd.json — Resource Directory over the full client/server stack
# ---------------------------------------------------------------------------


class TestResourceDirectoryVectors:
    @pytest.mark.xfail(
        strict=True,
        reason=(
            "Vector registers link attribute 'if' ('core.s'); RD hardening "
            "(aca39ad044) restricts descriptors to {href, rt}, so the exact "
            "pinned payload now yields 4.00 instead of 2.01"
        ),
    )
    async def test_rd_register_sensor42_exact(self) -> None:
        vec = _vec(COAP_RD, "rd_register_sensor42")
        # Vector self-consistency (generator oracle): CBOR re-dump matches pin.
        assert cbor2.dumps(vec["payload_cbor"]).hex() == vec["payload_hex"]
        client, server = await _rd_setup()
        try:
            response = await _rd_request(
                client, aiocoap.POST, vec["uri"], bytes.fromhex(vec["payload_hex"])
            )
            assert response.code == vec["expected_code"]  # 65 Created
            assert response.opt.location_path[0] == vec["location_path_prefix"]
            assert response.opt.location_path[1]
        finally:
            await _rd_teardown(client, server)

    async def test_rd_register_sensor42_supported_attributes(self) -> None:
        """Drivable subset of rd_register_sensor42 without the 'if' attribute."""
        vec = _vec(COAP_RD, "rd_register_sensor42")
        links = [{"href": "/temperature", "rt": "sensor"}]
        client, server = await _rd_setup()
        try:
            response = await _rd_request(
                client, aiocoap.POST, vec["uri"], cbor2.dumps(links)
            )
            assert response.code == vec["expected_code"]
            location = response.opt.location_path
            assert location is not None
            assert location[0] == vec["location_path_prefix"]
            listing = cbor2.loads((await _rd_request(client, aiocoap.GET, "/rd")).payload)
            assert listing[0]["ep"] == "sensor-42"
            assert listing[0]["lt"] == 3600
            assert listing[0]["links"] == links
        finally:
            await _rd_teardown(client, server)

    async def test_rd_register_default_lifetime(self) -> None:
        vec = _vec(COAP_RD, "rd_register_default_lifetime")
        client, server = await _rd_setup()
        try:
            response = await _rd_request(client, aiocoap.POST, vec["uri"])
            assert response.code == vec["expected_code"]
            listing = cbor2.loads((await _rd_request(client, aiocoap.GET, "/rd")).payload)
            assert [entry["lt"] for entry in listing] == [vec["expected_lt"]]
        finally:
            await _rd_teardown(client, server)

    async def test_rd_register_missing_ep(self) -> None:
        vec = _vec(COAP_RD, "rd_register_missing_ep")
        client, server = await _rd_setup()
        try:
            response = await _rd_request(client, aiocoap.POST, vec["uri"], cbor2.dumps([]))
            assert response.code == vec["expected_code"] == aiocoap.BAD_REQUEST
            assert response.code.dotted == "4.00"
        finally:
            await _rd_teardown(client, server)

    @pytest.mark.parametrize(
        "name",
        [
            "rd_register_bad_lt_0",
            "rd_register_bad_lt_-1",
            "rd_register_bad_lt_true",
            "rd_register_bad_lt_empty",
        ],
    )
    async def test_rd_register_bad_lt(self, name: str) -> None:
        vec = _vec(COAP_RD, name)
        client, server = await _rd_setup()
        try:
            response = await _rd_request(client, aiocoap.POST, vec["uri"])
            assert response.code == vec["expected_code"] == aiocoap.BAD_REQUEST
            # No mutation on rejection.
            listing = cbor2.loads((await _rd_request(client, aiocoap.GET, "/rd")).payload)
            assert listing == []
        finally:
            await _rd_teardown(client, server)

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "Exact reproduction needs 'if' link attributes (now rejected, see "
            "aca39ad044) and absolute reg ids 1/2; the global id counter makes "
            "ids session-dependent"
        ),
    )
    async def test_rd_lookup_all_exact(self) -> None:
        vec = _vec(COAP_RD, "rd_lookup_all")
        client, server = await _rd_setup()
        try:
            for entry in vec["response_entries"]:
                response = await _rd_request(
                    client, aiocoap.POST, f"/rd?ep={entry['ep']}&lt={entry['lt']}",
                    cbor2.dumps(entry["links"]),
                )
                assert response.code == 65  # every pinned registration must succeed
            listed = await _rd_request(client, aiocoap.GET, vec["uri"])
            assert listed.code == vec["expected_code"]
            assert int(listed.opt.content_format) == vec["expected_content_format"]
            assert cbor2.loads(listed.payload) == vec["response_entries"]
            assert listed.payload.hex() == vec["response_payload_hex"]
        finally:
            await _rd_teardown(client, server)

    async def test_rd_lookup_all_structure(self) -> None:
        """Drivable subset of rd_lookup_all: shape, order, filtering fields."""
        vec = _vec(COAP_RD, "rd_lookup_all")
        links_42 = [{"href": "/temperature", "rt": "sensor"}]  # vector pins 'if' too
        links_43 = [{"href": "/humidity", "rt": "sensor"}]
        client, server = await _rd_setup()
        try:
            created = [
                await _rd_request(
                    client, aiocoap.POST, "/rd?ep=sensor-42&lt=3600", cbor2.dumps(links_42)
                ),
                await _rd_request(
                    client, aiocoap.POST, "/rd?ep=sensor-43&lt=86400", cbor2.dumps(links_43)
                ),
            ]
            assert [r.code for r in created] == [aiocoap.CREATED, aiocoap.CREATED]
            listed = await _rd_request(client, aiocoap.GET, vec["uri"])
            assert listed.code == vec["expected_code"]
            assert int(listed.opt.content_format) == vec["expected_content_format"]
            entries = cbor2.loads(listed.payload)
            assert [entry["ep"] for entry in entries] == ["sensor-42", "sensor-43"]
            assert [entry["lt"] for entry in entries] == [3600, 86400]
            assert all(entry["base"] is None for entry in entries)
            assert entries[0]["links"] == links_42
            assert entries[1]["links"] == links_43
            # ids echo the Location-Path of each registration
            assert entries[0]["id"] == created[0].opt.location_path[1]
            assert entries[1]["id"] == created[1].opt.location_path[1]
        finally:
            await _rd_teardown(client, server)

    async def test_rd_lookup_filter_ep(self) -> None:
        vec = _vec(COAP_RD, "rd_lookup_filter_ep")
        client, server = await _rd_setup()
        try:
            await _rd_request(client, aiocoap.POST, "/rd?ep=sensor-42&lt=3600")
            await _rd_request(client, aiocoap.POST, "/rd?ep=sensor-43&lt=86400")
            response = await _rd_request(client, aiocoap.GET, vec["uri"])
            assert response.code == vec["expected_code"]
            entries = cbor2.loads(response.payload)
            assert [entry["ep"] for entry in entries] == vec["expected_filtered_eps"]
        finally:
            await _rd_teardown(client, server)

    async def test_rd_lookup_res_by_rt(self) -> None:
        """UNDRIVABLE today: no /rd-lookup resource is mounted anywhere.

        The vector itself notes the alias is future work; driven here to show
        the live behavior before skipping.
        """
        vec = _vec(COAP_RD, "rd_lookup_res_by_rt")
        client, server = await _rd_setup()
        try:
            await _rd_request(client, aiocoap.POST, "/rd?ep=sensor-42&lt=3600")
            response = await _rd_request(client, aiocoap.GET, vec["uri"])
            assert response.code != vec["expected_code"]  # NOT_FOUND today
            pytest.skip(
                "UNDRIVABLE: /rd-lookup/res is not implemented (vector note "
                "says alias is future work); returns NOT_FOUND instead of 69"
            )
        finally:
            await _rd_teardown(client, server)

    async def test_rd_delete_success(self) -> None:
        vec = _vec(COAP_RD, "rd_delete_success")
        client, server = await _rd_setup()
        try:
            registered = await _rd_request(client, aiocoap.POST, "/rd?ep=node-01&lt=3600")
            assert registered.code == aiocoap.CREATED
            reg_id = registered.opt.location_path[1]
            deleted = await _rd_request(client, aiocoap.DELETE, f"/rd/{reg_id}")
            assert deleted.code == vec["expected_code_success"]
            repeat = await _rd_request(client, aiocoap.DELETE, f"/rd/{reg_id}")
            assert repeat.code == vec["expected_code_not_found"]
        finally:
            await _rd_teardown(client, server)

    @pytest.mark.parametrize(
        "name",
        [
            "rd_register_bad_href_temperature",
            "rd_register_bad_href__a_.._b",
            "rd_register_bad_href__",
        ],
    )
    async def test_rd_register_bad_href(self, name: str) -> None:
        vec = _vec(COAP_RD, name)
        client, server = await _rd_setup()
        try:
            response = await _rd_request(
                client, aiocoap.POST, vec["uri"], cbor2.dumps([vec["bad_link"]])
            )
            assert response.code == vec["expected_code"] == aiocoap.BAD_REQUEST
            listing = cbor2.loads((await _rd_request(client, aiocoap.GET, "/rd")).payload)
            assert listing == []  # rejected links must not mutate the directory
        finally:
            await _rd_teardown(client, server)


# ---------------------------------------------------------------------------
# Guard: every vector in each file is accounted for by this module
# ---------------------------------------------------------------------------


class TestAllVectorsAccountedFor:
    EXPECTED_COUNTS = {
        "coap_messages": 6,
        "coap_option_malformed": 12,
        "coap_token_validation": 11,
        "coap_observe_sequence": 10,
        "coap_rd": 14,
    }

    @pytest.mark.parametrize("doc", [COAP_MESSAGES, COAP_OPTION_MALFORMED,
                                     COAP_TOKEN_VALIDATION, COAP_OBSERVE_SEQUENCE, COAP_RD])
    def test_vector_count_matches_expectation(self, doc: dict[str, Any]) -> None:
        assert len(doc["vectors"]) == self.EXPECTED_COUNTS[doc["name"]]
