"""Tests for APRS synthesis from LICHEN payloads."""

import json

import pytest

from lichen.interface.kiss.aprs_synth import (
    HAS_CBOR,
    AprsDataType,
    _format_position,
    _format_telemetry,
    _format_weather,
    synthesize_aprs,
)


class TestSynthesizePosition:
    def test_json_lat_lon(self):
        data = json.dumps({"lat": 37.7749, "lon": -122.4194}).encode()
        result = synthesize_aprs(data)
        assert result is not None
        assert result.data_type == AprsDataType.POSITION
        assert b"3746" in result.aprs_payload  # 37 deg 46 min
        assert b"N" in result.aprs_payload
        assert b"12225" in result.aprs_payload  # 122 deg 25 min
        assert b"W" in result.aprs_payload

    def test_json_latitude_longitude(self):
        data = json.dumps({"latitude": 40.0, "longitude": -74.0}).encode()
        result = synthesize_aprs(data)
        assert result is not None
        assert result.data_type == AprsDataType.POSITION

    def test_with_altitude(self):
        data = json.dumps({"lat": 37.0, "lon": -122.0, "alt": 100}).encode()
        result = synthesize_aprs(data)
        assert result is not None
        assert b"/A=" in result.aprs_payload  # Altitude extension
        assert b"000328" in result.aprs_payload  # ~328 feet

    def test_southern_hemisphere(self):
        data = json.dumps({"lat": -33.8688, "lon": 151.2093}).encode()
        result = synthesize_aprs(data)
        assert result is not None
        assert b"S" in result.aprs_payload
        assert b"E" in result.aprs_payload

    @pytest.mark.skipif(not HAS_CBOR, reason="cbor2 not installed")
    def test_cbor_position(self):
        import cbor2
        data = cbor2.dumps({"lat": 37.7749, "lon": -122.4194})
        result = synthesize_aprs(data)
        assert result is not None
        assert result.data_type == AprsDataType.POSITION


class TestSynthesizeWeather:
    def test_temp_only(self):
        data = json.dumps({"temp": 22.5}).encode()
        result = synthesize_aprs(data)
        assert result is not None
        assert result.data_type == AprsDataType.WEATHER
        # 22.5C = 72.5F, truncates to 72
        assert b"t072" in result.aprs_payload

    def test_full_weather(self):
        data = json.dumps({
            "temp": 20,
            "humidity": 65,
            "pressure": 1013.25,
        }).encode()
        result = synthesize_aprs(data)
        assert result is not None
        assert result.data_type == AprsDataType.WEATHER
        assert b"t068" in result.aprs_payload  # 20C = 68F
        assert b"h65" in result.aprs_payload
        assert b"b10132" in result.aprs_payload  # 1013.2 * 10

    def test_humidity_100(self):
        data = json.dumps({"temp": 15, "humidity": 100}).encode()
        result = synthesize_aprs(data)
        assert result is not None
        assert b"h00" in result.aprs_payload  # 100% encoded as 00

    def test_with_wind(self):
        data = json.dumps({
            "temp": 18,
            "wind_speed": 5.0,  # m/s
            "wind_dir": 270,
        }).encode()
        result = synthesize_aprs(data)
        assert result is not None
        assert b"270/" in result.aprs_payload  # wind direction
        assert b"/011" in result.aprs_payload  # ~11 mph

    def test_weather_with_position(self):
        data = json.dumps({
            "lat": 37.0,
            "lon": -122.0,
            "temp": 20,
        }).encode()
        result = synthesize_aprs(data)
        assert result is not None
        assert result.data_type == AprsDataType.WEATHER
        # Should have position prefix
        assert b"3700" in result.aprs_payload
        assert b"N/" in result.aprs_payload

    def test_pressure_only(self):
        data = json.dumps({"pressure": 1020.5}).encode()
        result = synthesize_aprs(data)
        assert result is not None
        assert result.data_type == AprsDataType.WEATHER
        assert b"b10205" in result.aprs_payload

    @pytest.mark.skipif(not HAS_CBOR, reason="cbor2 not installed")
    def test_cbor_weather(self):
        import cbor2
        data = cbor2.dumps({"temp": 25, "rh": 50})
        result = synthesize_aprs(data)
        assert result is not None
        assert result.data_type == AprsDataType.WEATHER


class TestSynthesizeTelemetry:
    def test_array_of_numbers(self):
        data = json.dumps([100, 150, 200, 50, 75]).encode()
        result = synthesize_aprs(data)
        assert result is not None
        assert result.data_type == AprsDataType.TELEMETRY
        assert b"T#" in result.aprs_payload
        assert b"100,150,200,050,075" in result.aprs_payload

    def test_partial_array(self):
        data = json.dumps([10, 20]).encode()
        result = synthesize_aprs(data)
        assert result is not None
        # Should pad to 5 channels
        assert b"010,020,000,000,000" in result.aprs_payload

    def test_channel_keys(self):
        data = json.dumps({"ch0": 100, "ch1": 200, "ch2": 50}).encode()
        result = synthesize_aprs(data)
        assert result is not None
        assert result.data_type == AprsDataType.TELEMETRY

    def test_with_sequence(self):
        data = json.dumps({"seq": 42, "ch0": 100, "ch1": 200}).encode()
        result = synthesize_aprs(data)
        assert result is not None
        assert b"T#042" in result.aprs_payload

    def test_with_digital_bits(self):
        data = json.dumps({"ch0": 100, "digital": 0b10101010}).encode()
        result = synthesize_aprs(data)
        assert result is not None
        assert b"10101010" in result.aprs_payload

    def test_clamp_values(self):
        data = json.dumps([300, -50, 100]).encode()  # Out of range
        result = synthesize_aprs(data)
        assert result is not None
        assert b"255" in result.aprs_payload  # Clamped to 255
        assert b"000" in result.aprs_payload  # Clamped to 0

    @pytest.mark.skipif(not HAS_CBOR, reason="cbor2 not installed")
    def test_cbor_telemetry(self):
        import cbor2
        data = cbor2.dumps([10, 20, 30, 40, 50])
        result = synthesize_aprs(data)
        assert result is not None
        assert result.data_type == AprsDataType.TELEMETRY


class TestSynthesizeNoMatch:
    def test_plain_text(self):
        result = synthesize_aprs(b"Hello world")
        assert result is None

    def test_invalid_json(self):
        result = synthesize_aprs(b"not json")
        assert result is None

    def test_empty_object(self):
        result = synthesize_aprs(b"{}")
        assert result is None

    def test_unrecognized_keys(self):
        data = json.dumps({"foo": "bar", "baz": 123}).encode()
        result = synthesize_aprs(data)
        assert result is None


class TestFormatPosition:
    def test_san_francisco(self):
        result = _format_position(37.7749, -122.4194)
        assert result.startswith("!")
        assert "N/" in result
        assert "W" in result

    def test_zero_zero(self):
        result = _format_position(0.0, 0.0)
        assert "0000.00N" in result
        assert "00000.00E" in result

    def test_with_altitude(self):
        result = _format_position(37.0, -122.0, alt=1000)
        assert "/A=" in result


class TestFormatWeather:
    def test_minimal(self):
        result = _format_weather(temp_c=20)
        assert result.startswith("_")
        assert "t068" in result  # 20C = 68F

    def test_negative_temp(self):
        result = _format_weather(temp_c=-10)
        assert "t014" in result  # -10C = 14F

    def test_freezing(self):
        result = _format_weather(temp_c=0)
        assert "t032" in result  # 0C = 32F

    def test_negative_fahrenheit(self):
        # -30C = -22F, should produce exactly 3 chars after 't'
        result = _format_weather(temp_c=-30)
        assert "t-22" in result
        # Verify field is exactly 3 chars
        import re
        match = re.search(r"t(...)", result)
        assert match is not None
        assert len(match.group(1)) == 3

    def test_extreme_cold_uses_no_data(self):
        # -74C = -101F, below -99F representable range
        result = _format_weather(temp_c=-74)
        assert "t..." in result  # Should use no-data marker


class TestFormatTelemetry:
    def test_basic(self):
        result = _format_telemetry(0, [100, 200, 150, 50, 25])
        assert result == "T#000,100,200,150,050,025,00000000"

    def test_with_seq(self):
        result = _format_telemetry(123, [0, 0, 0, 0, 0])
        assert result.startswith("T#123")

    def test_with_bits(self):
        result = _format_telemetry(0, [0, 0, 0, 0, 0], bits=0xFF)
        assert result.endswith("11111111")


class TestPriorityOrder:
    """Weather detection should take priority over position."""

    def test_weather_with_position_is_weather(self):
        # Has both weather and position keys
        data = json.dumps({
            "lat": 37.0,
            "lon": -122.0,
            "temp": 20,
            "humidity": 65,
        }).encode()
        result = synthesize_aprs(data)
        assert result is not None
        # Should be detected as weather, not position
        assert result.data_type == AprsDataType.WEATHER
