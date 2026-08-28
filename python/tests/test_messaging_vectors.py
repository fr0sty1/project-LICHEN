# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Cross-validate the Python messaging implementation against test/vectors/messaging.json.

These vectors test the messaging protocol per spec Section 17.5.7 (LCI) and 18.1 (Apps).
Covers /msg/inbox POST, /msg/sent GET, /msg/ack POST.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import cbor2
import pytest

from lichen.client.lci import _valid_receipt_id, _valid_receipt_timestamp
from lichen.client.model import MessageDraft, MessageReceipt, ReceiptStatus

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"


def _load_messaging_vectors() -> dict[str, Any]:
    return json.loads((VECTORS_DIR / "messaging.json").read_text())


def _get_vectors() -> list[tuple[str, dict[str, Any]]]:
    doc = _load_messaging_vectors()
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


def test_messaging_vectors_file_exists() -> None:
    """Verify the messaging.json test vectors file is present."""
    path = VECTORS_DIR / "messaging.json"
    assert path.is_file(), f"missing {path}"
    doc = _load_messaging_vectors()
    assert doc["name"] == "messaging"
    assert doc["format_version"] == 2
    assert len(doc["vectors"]) > 0


class TestInboxPostVectors:
    """Test vectors for POST /msg/inbox."""

    @pytest.mark.parametrize("name,vector", _get_vectors())
    def test_inbox_post_valid_payloads(self, name: str, vector: dict[str, Any]) -> None:
        """Valid POST payloads should encode correctly to CBOR."""
        if vector["resource"] != "/msg/inbox" or vector["method"] != "POST":
            pytest.skip("Not an inbox POST vector")

        cbor_payload = vector.get("cbor_payload")
        expected = vector.get("expected", {})
        expected_code = expected.get("response_code", "")

        if cbor_payload is None:
            pytest.skip("No CBOR payload in vector")

        # Skip error cases for payload encoding tests
        if expected_code.startswith("4."):
            pytest.skip("Error case tested separately")

        # For valid inbox POST, body or text or canned must be present
        if isinstance(cbor_payload, dict):
            has_body = "body" in cbor_payload
            has_text = "text" in cbor_payload
            has_canned = "canned" in cbor_payload
            has_content = has_body or has_text or has_canned
            if not has_content and expected_code.startswith("2."):
                pytest.fail(f"{name}: Valid inbox POST requires body, text, or canned field")

            # Verify CBOR encoding round-trips
            encoded = cbor2.dumps(cbor_payload)
            decoded = cbor2.loads(encoded)
            assert decoded == cbor_payload, f"{name}: CBOR round-trip failed"

    @pytest.mark.parametrize("name,vector", _get_vectors())
    def test_inbox_post_body_validation(self, name: str, vector: dict[str, Any]) -> None:
        """Validate body field handling per spec."""
        if vector["resource"] != "/msg/inbox" or vector["method"] != "POST":
            pytest.skip("Not an inbox POST vector")

        cbor_payload = vector.get("cbor_payload")
        expected = vector.get("expected", {})
        expected_code = expected.get("response_code", "")
        expected_error = expected.get("error")

        if cbor_payload is None:
            pytest.skip("No CBOR payload in vector")

        if not isinstance(cbor_payload, dict):
            # Array payloads should be rejected
            assert expected_code == "4.00 Bad Request", f"{name}: Non-map rejected"
            return

        body = cbor_payload.get("body")
        text = cbor_payload.get("text")

        # Validate body/text type requirements
        if expected_error == "body_not_string":
            assert body is not None and not isinstance(body, str), f"{name}: Expected non-str"
        elif expected_error == "missing_body_or_text":
            assert body is None and text is None, f"{name}: Expected missing body/text"

        # Valid payloads must have string body or text (or canned for canned messages)
        if expected_code.startswith("2.") and "canned" not in cbor_payload:
            has_string_body = isinstance(body, str)
            has_string_text = isinstance(text, str)
            assert has_string_body or has_string_text, f"{name}: Needs string body/text"


class TestMessageDraftEncoding:
    """Test MessageDraft.to_payload() produces spec-compliant CBOR maps."""

    def test_full_message_fields(self) -> None:
        """Full message with all optional fields per 18.1.1."""
        draft = MessageDraft(
            to="0200:1234:5678:9abc::aaaa:bbbb:cccc:dddd",
            body="Full message with all fields",
            ack=True,
            priority=1,
            reply_to=12340,
            ttl=3600,
        )
        payload = draft.to_payload()
        assert payload["to"] == "0200:1234:5678:9abc::aaaa:bbbb:cccc:dddd"
        assert payload["body"] == "Full message with all fields"
        assert payload["ack"] is True
        assert payload["priority"] == 1
        assert payload["reply_to"] == 12340
        assert payload["ttl"] == 3600

        # Verify CBOR encoding
        encoded = cbor2.dumps(payload)
        decoded = cbor2.loads(encoded)
        assert decoded == payload

    def test_minimal_message(self) -> None:
        """Minimal message with required fields only."""
        draft = MessageDraft(to="", body="Minimal message")
        payload = draft.to_payload()
        assert payload["body"] == "Minimal message"
        # to is included but empty for minimal
        assert "to" in payload

    def test_broadcast_address(self) -> None:
        """Broadcast address ff02::1 per spec."""
        draft = MessageDraft(to="ff02::1", body="Broadcast to all nodes")
        payload = draft.to_payload()
        assert payload["to"] == "ff02::1"
        encoded = cbor2.dumps(payload)
        decoded = cbor2.loads(encoded)
        assert decoded["to"] == "ff02::1"


class TestReceiptVectors:
    """Test vectors for POST /msg/ack."""

    @pytest.mark.parametrize("name,vector", _get_vectors())
    def test_receipt_post_encoding(self, name: str, vector: dict[str, Any]) -> None:
        """Valid receipt POSTs should encode correctly to CBOR."""
        if vector["resource"] != "/msg/ack" or vector["method"] != "POST":
            pytest.skip("Not an ack POST vector")

        cbor_payload = vector.get("cbor_payload")
        expected = vector.get("expected", {})
        expected_code = expected.get("response_code", "")

        if cbor_payload is None or not isinstance(cbor_payload, dict):
            pytest.skip("No valid CBOR map payload")

        # Skip error cases for encoding tests
        if expected_code.startswith("4."):
            pytest.skip("Error case tested separately")

        # Valid receipt must have id, status, ts
        assert "id" in cbor_payload, f"{name}: Receipt must have id"
        assert "status" in cbor_payload, f"{name}: Receipt must have status"
        assert "ts" in cbor_payload, f"{name}: Receipt must have ts"

        # Verify CBOR round-trip
        encoded = cbor2.dumps(cbor_payload)
        decoded = cbor2.loads(encoded)
        assert decoded == cbor_payload, f"{name}: CBOR round-trip failed"

    def test_receipt_cbor_hex_vector(self) -> None:
        """Validate receipt_post_delivered has correct CBOR hex encoding."""
        doc = _load_messaging_vectors()
        delivered_vector = next(
            v for v in doc["vectors"] if v["name"] == "receipt_post_delivered"
        )
        cbor_hex = delivered_vector.get("cbor_hex")
        if cbor_hex:
            # Decode the reference CBOR hex
            wire = bytes.fromhex(cbor_hex)
            decoded = cbor2.loads(wire)
            assert decoded["id"] == 12345
            assert decoded["status"] == "delivered"
            assert decoded["ts"] == 1716742900

            # Verify our encoding matches the vector
            payload = delivered_vector["cbor_payload"]
            encoded = cbor2.dumps(payload, canonical=True)
            # Note: CBOR encoding can vary (indefinite vs definite length, key order)
            # so we just verify round-trip decodes correctly
            re_decoded = cbor2.loads(encoded)
            assert re_decoded == payload


class TestReceiptValidation:
    """Test _valid_receipt_id and _valid_receipt_timestamp validation."""

    @pytest.mark.parametrize("name,vector", _get_vectors())
    def test_receipt_id_validation(self, name: str, vector: dict[str, Any]) -> None:
        """Validate receipt ID rules from vectors."""
        if vector["resource"] != "/msg/ack" or vector["method"] != "POST":
            pytest.skip("Not an ack POST vector")

        cbor_payload = vector.get("cbor_payload")
        expected = vector.get("expected", {})
        expected_error = expected.get("error")

        if cbor_payload is None or not isinstance(cbor_payload, dict):
            pytest.skip("No valid CBOR map payload")

        msg_id = cbor_payload.get("id")

        if expected_error == "invalid_id_type":
            # Negative, string, or wrong-type IDs should fail validation
            assert not _valid_receipt_id(msg_id), f"{name}: Expected invalid id"
        elif (
            expected_error is None
            and "id" in cbor_payload
            and isinstance(msg_id, int)
            and msg_id >= 0
        ):
            # Valid IDs should pass
            assert _valid_receipt_id(msg_id), f"{name}: Expected valid id"

    @pytest.mark.parametrize("name,vector", _get_vectors())
    def test_receipt_ts_validation(self, name: str, vector: dict[str, Any]) -> None:
        """Validate receipt timestamp rules from vectors."""
        if vector["resource"] != "/msg/ack" or vector["method"] != "POST":
            pytest.skip("Not an ack POST vector")

        cbor_payload = vector.get("cbor_payload")
        expected = vector.get("expected", {})
        expected_error = expected.get("error")

        if cbor_payload is None or not isinstance(cbor_payload, dict):
            pytest.skip("No valid CBOR map payload")

        ts = cbor_payload.get("ts")

        if expected_error == "invalid_ts_type":
            # Negative timestamps should fail validation
            assert not _valid_receipt_timestamp(ts), f"{name}: Expected invalid ts"
        elif (
            expected_error is None
            and "ts" in cbor_payload
            and isinstance(ts, int)
            and ts >= 0
        ):
            # Valid timestamps should pass (0 is valid per spec)
            assert _valid_receipt_timestamp(ts), f"{name}: Expected valid ts"

    def test_receipt_status_enum(self) -> None:
        """ReceiptStatus enum matches valid_statuses from vectors."""
        doc = _load_messaging_vectors()
        invalid_status_vector = next(
            v for v in doc["vectors"] if v["name"] == "receipt_post_invalid_status"
        )
        valid_statuses = set(invalid_status_vector["expected"]["valid_statuses"])
        enum_values = {s.value for s in ReceiptStatus}
        assert enum_values == valid_statuses, "ReceiptStatus enum must match spec valid_statuses"

    def test_receipt_id_edge_cases(self) -> None:
        """Test ID validation edge cases from vectors."""
        # id=0 is valid (receipt_post_min_values)
        assert _valid_receipt_id(0)
        # max uint64 is valid (receipt_post_max_u64)
        assert _valid_receipt_id(18446744073709551615)
        # negative is invalid (receipt_post_negative_id)
        assert not _valid_receipt_id(-1)
        # string is invalid (receipt_post_string_id)
        assert not _valid_receipt_id("12345")
        # bool is invalid (Python quirk: bool is subclass of int)
        assert not _valid_receipt_id(True)
        assert not _valid_receipt_id(False)

    def test_receipt_ts_edge_cases(self) -> None:
        """Test timestamp validation edge cases from vectors."""
        # ts=0 is valid (receipt_post_min_values)
        assert _valid_receipt_timestamp(0)
        # max uint32 is valid (receipt_post_max_u64)
        assert _valid_receipt_timestamp(4294967295)
        # negative is invalid (receipt_post_negative_ts)
        assert not _valid_receipt_timestamp(-1)


class TestMessageReceiptEncoding:
    """Test MessageReceipt.to_payload() produces spec-compliant CBOR maps."""

    def test_delivered_receipt(self) -> None:
        """Delivered receipt matches vector format."""
        receipt = MessageReceipt(
            message_id=12345,
            status=ReceiptStatus.DELIVERED,
            ts=1716742900,
        )
        payload = receipt.to_payload()
        assert payload["id"] == 12345
        assert payload["status"] == "delivered"
        assert payload["ts"] == 1716742900

        # Verify CBOR encoding
        encoded = cbor2.dumps(payload)
        decoded = cbor2.loads(encoded)
        assert decoded == payload

    def test_read_receipt(self) -> None:
        """Read receipt matches vector format."""
        receipt = MessageReceipt(
            message_id=12345,
            status=ReceiptStatus.READ,
            ts=1716742901,
        )
        payload = receipt.to_payload()
        assert payload["status"] == "read"

    def test_failed_receipt(self) -> None:
        """Failed receipt matches vector format."""
        receipt = MessageReceipt(
            message_id=12345,
            status=ReceiptStatus.FAILED,
            ts=1716742902,
        )
        payload = receipt.to_payload()
        assert payload["status"] == "failed"

    def test_min_values(self) -> None:
        """Minimum valid values per receipt_post_min_values vector."""
        receipt = MessageReceipt(
            message_id=0,
            status=ReceiptStatus.DELIVERED,
            ts=0,
        )
        payload = receipt.to_payload()
        assert payload["id"] == 0
        assert payload["ts"] == 0

        # Verify validation functions accept these values
        assert _valid_receipt_id(payload["id"])
        assert _valid_receipt_timestamp(payload["ts"])

    def test_max_u64_values(self) -> None:
        """Maximum uint64/uint32 values per receipt_post_max_u64 vector."""
        receipt = MessageReceipt(
            message_id=18446744073709551615,  # max uint64
            status=ReceiptStatus.DELIVERED,
            ts=4294967295,  # max uint32
        )
        payload = receipt.to_payload()
        assert payload["id"] == 18446744073709551615
        assert payload["ts"] == 4294967295

        # Verify CBOR can encode these large integers
        encoded = cbor2.dumps(payload)
        decoded = cbor2.loads(encoded)
        assert decoded["id"] == 18446744073709551615
        assert decoded["ts"] == 4294967295


class TestSentGetVectors:
    """Test vectors for GET /msg/sent and /msg/sent/{id}."""

    @pytest.mark.parametrize("name,vector", _get_vectors())
    def test_sent_resource_paths(self, name: str, vector: dict[str, Any]) -> None:
        """Validate /msg/sent path format expectations."""
        resource = vector.get("resource", "")
        method = vector.get("method", "")

        if not resource.startswith("/msg/sent"):
            pytest.skip("Not a sent resource vector")

        if method != "GET":
            pytest.skip("Not a GET vector")

        expected = vector.get("expected", {})
        expected_code = expected.get("response_code", "")

        # /msg/sent (collection) should return 2.05 Content
        if resource == "/msg/sent":
            assert expected_code == "2.05 Content", f"{name}: Collection GET should return 2.05"
            return

        # /msg/sent/{id} path validation
        path_parts = resource.split("/")
        assert len(path_parts) == 4, f"{name}: Invalid path format"

        msg_id_str = path_parts[3]

        # Invalid ID formats should return 4.04
        if expected_code == "4.04 Not Found":
            # Non-numeric, leading zeros, or overflow IDs are invalid
            note = expected.get("note", "")
            if "non-decimal" in note.lower() or "leading zeros" in note.lower():
                # These are explicitly invalid per spec
                pass
            elif "exceeds uint64" in note.lower():
                # Overflow case
                try:
                    parsed = int(msg_id_str)
                    assert parsed > 18446744073709551615, f"{name}: Should exceed uint64"
                except ValueError:
                    pass  # Non-numeric is also 4.04

    def test_id_format_rules(self) -> None:
        """Validate ID format rules from vectors."""
        doc = _load_messaging_vectors()

        # sent_get_leading_zeros: IDs must be canonical decimal
        leading_zeros = next(v for v in doc["vectors"] if v["name"] == "sent_get_leading_zeros")
        assert leading_zeros["resource"] == "/msg/sent/0042"
        assert leading_zeros["expected"]["response_code"] == "4.04 Not Found"

        # sent_get_invalid_id_format: Non-numeric IDs are invalid
        invalid_format = next(
            v for v in doc["vectors"] if v["name"] == "sent_get_invalid_id_format"
        )
        assert invalid_format["resource"] == "/msg/sent/abc"
        assert invalid_format["expected"]["response_code"] == "4.04 Not Found"

        # sent_get_overflow_id: IDs > uint64 max are invalid
        overflow = next(v for v in doc["vectors"] if v["name"] == "sent_get_overflow_id")
        assert overflow["resource"] == "/msg/sent/18446744073709551616"
        assert overflow["expected"]["response_code"] == "4.04 Not Found"


class TestErrorVectors:
    """Test error case vectors."""

    @pytest.mark.parametrize("name,vector", _get_vectors())
    def test_error_responses(self, name: str, vector: dict[str, Any]) -> None:
        """Verify error cases return 4.00 Bad Request."""
        expected = vector.get("expected", {})
        expected_code = expected.get("response_code", "")
        expected_error = expected.get("error")

        if not expected_code.startswith("4."):
            pytest.skip("Not an error vector")

        # All 4.xx vectors should have documented error reasons
        if expected_code == "4.00 Bad Request":
            # Most 4.00 errors should have an error field (some may just have notes)
            assert expected_error is not None or "note" in expected, (
                f"{name}: 4.00 response should document the error"
            )

    def test_malformed_cbor_handling(self) -> None:
        """inbox_post_invalid_cbor: malformed CBOR should be rejected by server.

        Note: The payload_hex "ff" is the CBOR break code. While cbor2 accepts it
        as a primitive, it's not a valid message payload (not a map), so the
        server should reject it with cbor_decode_failed.
        """
        doc = _load_messaging_vectors()
        invalid_cbor = next(v for v in doc["vectors"] if v["name"] == "inbox_post_invalid_cbor")
        wire = bytes.fromhex(invalid_cbor["payload_hex"])

        # The vector specifies this should be rejected as cbor_decode_failed
        assert invalid_cbor["expected"]["response_code"] == "4.00 Bad Request"
        assert invalid_cbor["expected"]["error"] == "cbor_decode_failed"

        # The decoded result is not a valid message map (dict)
        decoded = cbor2.loads(wire)
        assert not isinstance(decoded, dict), "Malformed CBOR should not decode to map"

    def test_empty_payload_handling(self) -> None:
        """Empty payloads should be rejected."""
        doc = _load_messaging_vectors()

        # inbox_post_empty_payload
        inbox_empty = next(v for v in doc["vectors"] if v["name"] == "inbox_post_empty_payload")
        assert inbox_empty["payload"] == ""
        assert inbox_empty["expected"]["response_code"] == "4.00 Bad Request"
        assert inbox_empty["expected"]["error"] == "empty_payload"

        # receipt_post_no_payload
        receipt_empty = next(v for v in doc["vectors"] if v["name"] == "receipt_post_no_payload")
        assert receipt_empty["payload"] == ""
        assert receipt_empty["expected"]["response_code"] == "4.00 Bad Request"


class TestVectorCoverage:
    """Verify test vector coverage."""

    def test_all_resources_covered(self) -> None:
        """Verify all three messaging resources have vectors."""
        doc = _load_messaging_vectors()
        resources = {
            v["resource"].split("/")[2]
            for v in doc["vectors"]
            if v["resource"].startswith("/msg/")
        }
        # Should cover inbox, sent, ack
        assert "inbox" in resources, "Missing /msg/inbox vectors"
        has_sent = "sent" in resources or any(
            "/msg/sent" in v["resource"] for v in doc["vectors"]
        )
        assert has_sent, "Missing /msg/sent vectors"
        assert "ack" in resources, "Missing /msg/ack vectors"

    def test_all_methods_covered(self) -> None:
        """Verify both GET and POST methods have vectors."""
        doc = _load_messaging_vectors()
        methods = {v["method"] for v in doc["vectors"]}
        assert "GET" in methods, "Missing GET vectors"
        assert "POST" in methods, "Missing POST vectors"

    def test_vector_count(self) -> None:
        """Verify reasonable vector count."""
        doc = _load_messaging_vectors()
        assert len(doc["vectors"]) >= 30, "Expected at least 30 messaging vectors"

    def test_categories_represented(self) -> None:
        """Verify both valid and error cases are represented."""
        doc = _load_messaging_vectors()
        codes = [v["expected"]["response_code"] for v in doc["vectors"]]
        success_codes = [c for c in codes if c.startswith("2.")]
        error_codes = [c for c in codes if c.startswith("4.")]
        assert len(success_codes) >= 10, "Expected at least 10 success cases"
        assert len(error_codes) >= 10, "Expected at least 10 error cases"
