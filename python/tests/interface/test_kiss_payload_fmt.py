"""Tests for payload formatter."""

import json

import pytest

from lichen.interface.kiss.payload_fmt import (
    HAS_CBOR,
    _compact_repr,
    _format_hex,
    format_payload,
    is_printable_text,
)


class TestFormatPayloadText:
    def test_simple_text(self):
        result = format_payload(b"Hello world")
        assert result == "Hello world"

    def test_text_with_newlines(self):
        result = format_payload(b"Line 1\nLine 2")
        assert "Line 1" in result
        assert "Line 2" in result

    def test_unicode_text(self):
        result = format_payload("Hello 世界".encode())
        assert "Hello" in result
        assert "世界" in result

    def test_mixed_with_control(self):
        # Strict 100% printable required (was 90%); control chars now force non-text
        data = b"Hello world!" + bytes([0x01])  # One control char
        assert not is_printable_text(data)
        result = format_payload(data)
        assert "<" in result or "B:" in result  # CBOR or hex


class TestFormatPayloadJson:
    def test_json_object(self):
        data = b'{"temp": 23.5, "humidity": 65}'
        result = format_payload(data)
        assert "temp" in result
        assert "23.5" in result

    def test_json_array(self):
        data = b'[1, 2, 3]'
        result = format_payload(data)
        # Valid UTF-8 text is returned as-is, or parsed as JSON
        assert "1" in result and "2" in result and "3" in result

    def test_nested_json(self):
        data = json.dumps({"sensor": {"temp": 22, "unit": "C"}}).encode()
        result = format_payload(data)
        assert "sensor" in result
        assert "temp" in result


@pytest.mark.skipif(not HAS_CBOR, reason="cbor2 not installed")
class TestFormatPayloadCbor:
    def test_cbor_map(self):
        import cbor2
        data = cbor2.dumps({"temp": 25, "name": "sensor1"})
        result = format_payload(data)
        assert "temp" in result
        assert "25" in result

    def test_cbor_array(self):
        import cbor2
        data = cbor2.dumps([1, 2, 3, 4, 5])
        result = format_payload(data)
        assert "1" in result
        assert "5" in result


class TestFormatPayloadBinary:
    def test_binary_shows_hex(self):
        data = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        result = format_payload(data)
        assert "dead" in result.lower()
        assert "beef" in result.lower()

    def test_binary_shows_length(self):
        # Use 0xFE prefix - invalid CBOR initial byte, so falls through to hex
        data = bytes([0xFE] + list(range(15)))
        result = format_payload(data)
        assert "16B" in result

    def test_coap_detection(self):
        # CoAP header: Ver=1, Type=CON, TKL=0
        # Use 0x7E prefix so CBOR rejects it (0x7E is reserved)
        # but CoAP detection still fires (0x7E & 0xC0 == 0x40)
        data = bytes([0x7E, 0x01, 0x00, 0x01]) + b"payload"
        result = format_payload(data)
        assert "[CoAP]" in result

    @pytest.mark.skipif(HAS_CBOR, reason="SCHC bytes are valid CBOR, decoded first")
    def test_schc_detection(self):
        # SCHC rule ID 0x00 - only shown when CBOR not installed
        # (SCHC rule IDs 0x00, 0x01 are valid CBOR integers)
        data = bytes([0x00, 0x12, 0x34])
        result = format_payload(data)
        assert "[SCHC]" in result


class TestFormatPayloadEmpty:
    def test_empty_payload(self):
        result = format_payload(b"")
        assert result == "[empty]"


class TestFormatPayloadTruncation:
    def test_long_text_truncated(self):
        data = b"x" * 500
        result = format_payload(data, max_len=50)
        assert len(result) <= 50
        assert result.endswith("...")

    def test_long_hex_truncated(self):
        data = bytes(range(256))
        result = format_payload(data, max_len=100)
        assert len(result) <= 100


class TestCompactRepr:
    def test_null(self):
        assert _compact_repr(None) == "null"

    def test_bool(self):
        assert _compact_repr(True) == "true"
        assert _compact_repr(False) == "false"

    def test_int(self):
        assert _compact_repr(42) == "42"

    def test_float_whole(self):
        assert _compact_repr(3.0) == "3"

    def test_float_decimal(self):
        result = _compact_repr(3.14159)
        assert "3.14" in result

    def test_short_string_no_quotes(self):
        assert _compact_repr("hello") == "hello"

    def test_string_with_spaces_quoted(self):
        assert _compact_repr("hello world") == '"hello world"'

    def test_empty_list(self):
        assert _compact_repr([]) == "[]"

    def test_list(self):
        assert _compact_repr([1, 2, 3]) == "[1,2,3]"

    def test_long_list_truncated(self):
        result = _compact_repr(list(range(20)))
        assert "...+10" in result

    def test_empty_dict(self):
        assert _compact_repr({}) == "{}"

    def test_dict(self):
        result = _compact_repr({"a": 1, "b": 2})
        assert "a:1" in result
        assert "b:2" in result

    def test_nested_depth_limit(self):
        # Deeply nested structure
        obj = {"a": {"b": {"c": {"d": {"e": {"f": {"g": 1}}}}}}}
        result = _compact_repr(obj)
        assert "..." in result

    def test_bytes_shows_size(self):
        assert _compact_repr(b"hello") == "<5B>"


class TestFormatHex:
    def test_basic_hex(self):
        result = _format_hex(bytes([0xAB, 0xCD, 0xEF]), 100)
        assert "abcd" in result.lower()
        assert "ef" in result.lower()

    def test_hex_spacing(self):
        result = _format_hex(bytes([0x01, 0x02, 0x03, 0x04, 0x05]), 100)
        # Should have spaces every 4 hex chars
        assert " " in result

    def test_l2_dispatch_labels(self):
        assert "[L2/SCHC]" in _format_hex(bytes([0x14, 0x01, 0x02]), 100)
        assert "[L2/Routing]" in _format_hex(bytes([0x15, 0x01, 0x02]), 100)


class TestIsPrintableText:
    def test_printable(self):
        assert is_printable_text(b"Hello world") is True

    def test_binary(self):
        assert is_printable_text(bytes(range(32))) is False

    def test_mixed(self):
        # Mostly binary
        assert is_printable_text(bytes(range(100))) is False


class TestRealWorldPayloads:
    """Test with realistic payloads."""

    def test_senml_json(self):
        # SenML-style sensor reading
        data = b'[{"n":"temp","v":22.5},{"n":"rh","v":65}]'
        result = format_payload(data)
        assert "temp" in result
        assert "22.5" in result

    def test_coap_with_payload(self):
        # Simplified CoAP-like structure
        # Use 0x7E prefix (invalid CBOR but triggers CoAP detection)
        header = bytes([0x7E, 0x01, 0x00, 0x01])  # CoAP-like
        token = bytes([0xAB, 0xCD, 0xEF, 0x12])
        data = header + token + b"\xff" + b"sensor data"
        result = format_payload(data)
        # Should detect CoAP and show hex
        assert "[CoAP]" in result or "sensor" in result.lower()

    def test_gps_coordinates(self):
        # Text-based GPS
        data = b"37.7749,-122.4194,15.2"
        result = format_payload(data)
        assert "37.7749" in result
