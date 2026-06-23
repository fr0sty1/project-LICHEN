"""Tests for app_data encodings (spec 9.7, 11.4)."""

import pytest

from lichen.announce.coords import (
    APP_DATA_TYPE_CONGESTION,
    APP_DATA_TYPE_COORDS,
    APP_DATA_TYPE_DTN_EXPIRY,
    APP_DATA_TYPE_DTN_PENDING,
    HEADER_TYPE_OPPORTUNISTIC,
    OPPORTUNISTIC_SLOT_TIME_MS,
    decode_congestion,
    decode_coords,
    decode_dtn_expiry,
    decode_dtn_pending,
    decode_opportunistic_forwarders,
    encode_congestion,
    encode_coords,
    encode_dtn_expiry,
    encode_dtn_pending,
    encode_opportunistic_forwarders,
    opportunistic_wait_time_ms,
)


class TestCoordsEncoding:
    """Tests for encode_coords()."""

    def test_encode_zero(self):
        """Zero coords encode to type byte + 6 zero bytes."""
        result = encode_coords(0.0, 0.0)
        assert len(result) == 7
        assert result[0] == APP_DATA_TYPE_COORDS
        assert result[1:] == b"\x00\x00\x00\x00\x00\x00"

    def test_encode_positive(self):
        """Positive coords encode correctly."""
        # 47.6062 lat, -122.3321 lon (Seattle)
        # But lon is out of range at -122, so use a smaller example
        result = encode_coords(47.6062, 12.3321)
        assert len(result) == 7
        assert result[0] == APP_DATA_TYPE_COORDS

    def test_encode_negative(self):
        """Negative coords encode correctly."""
        result = encode_coords(-33.8688, -70.0)
        assert len(result) == 7
        assert result[0] == APP_DATA_TYPE_COORDS

    def test_encode_max_range(self):
        """Coords at edge of range encode without error."""
        result = encode_coords(83.88, 83.88)
        assert len(result) == 7
        result = encode_coords(-83.88, -83.88)
        assert len(result) == 7

    def test_encode_out_of_range_lat(self):
        """Latitude > 83.88 raises ValueError."""
        with pytest.raises(ValueError, match="latitude"):
            encode_coords(84.0, 0.0)

    def test_encode_out_of_range_lon(self):
        """Longitude > 83.88 raises ValueError."""
        with pytest.raises(ValueError, match="longitude"):
            encode_coords(0.0, 84.0)


class TestCoordsDecoding:
    """Tests for decode_coords()."""

    def test_decode_empty(self):
        """Empty app_data returns None."""
        assert decode_coords(b"") is None

    def test_decode_too_short(self):
        """App_data < 7 bytes returns None."""
        assert decode_coords(b"\x01\x00\x00") is None

    def test_decode_wrong_type(self):
        """App_data with wrong type byte returns None."""
        assert decode_coords(b"\x02\x00\x00\x00\x00\x00\x00") is None

    def test_decode_zero(self):
        """Zero coords decode correctly."""
        app_data = bytes([APP_DATA_TYPE_COORDS]) + b"\x00\x00\x00\x00\x00\x00"
        result = decode_coords(app_data)
        assert result == (0.0, 0.0)


class TestCoordsRoundTrip:
    """Round-trip tests for encode/decode."""

    @pytest.mark.parametrize(
        "lat,lon",
        [
            (0.0, 0.0),
            (47.6062, 12.3321),
            (-33.8688, 18.4241),
            (51.5074, -0.1278),  # London (lon in range)
            (83.0, 83.0),
            (-83.0, -83.0),
            (0.00001, 0.00001),  # minimum resolution
        ],
    )
    def test_round_trip(self, lat: float, lon: float):
        """Encode then decode recovers original coords within resolution."""
        encoded = encode_coords(lat, lon)
        decoded = decode_coords(encoded)
        assert decoded is not None
        # Resolution is 1e-5 degrees, allow small rounding error
        assert abs(decoded[0] - lat) < 1e-4
        assert abs(decoded[1] - lon) < 1e-4

    def test_extra_data_ignored(self):
        """Extra bytes after coords are ignored."""
        app_data = encode_coords(10.0, 20.0) + b"extra data"
        result = decode_coords(app_data)
        assert result is not None
        assert abs(result[0] - 10.0) < 1e-4
        assert abs(result[1] - 20.0) < 1e-4


class TestCongestionEncoding:
    """Tests for congestion encoding (spec 11.4)."""

    def test_encode_zero(self):
        """Zero queue depth encodes correctly."""
        result = encode_congestion(0)
        assert result == bytes([APP_DATA_TYPE_CONGESTION, 0])

    def test_encode_max(self):
        """Max queue depth (255) encodes correctly."""
        result = encode_congestion(255)
        assert result == bytes([APP_DATA_TYPE_CONGESTION, 255])

    def test_encode_out_of_range(self):
        """Queue depth > 255 raises ValueError."""
        with pytest.raises(ValueError, match="queue_depth"):
            encode_congestion(256)

    def test_encode_negative(self):
        """Negative queue depth raises ValueError."""
        with pytest.raises(ValueError, match="queue_depth"):
            encode_congestion(-1)


class TestCongestionDecoding:
    """Tests for decode_congestion()."""

    def test_decode_empty(self):
        """Empty app_data returns None."""
        assert decode_congestion(b"") is None

    def test_decode_too_short(self):
        """App_data < 2 bytes returns None."""
        assert decode_congestion(b"\x02") is None

    def test_decode_wrong_type(self):
        """App_data with wrong type byte returns None."""
        assert decode_congestion(b"\x01\x00") is None

    def test_decode_zero(self):
        """Zero queue depth decodes correctly."""
        result = decode_congestion(bytes([APP_DATA_TYPE_CONGESTION, 0]))
        assert result == 0

    def test_decode_max(self):
        """Max queue depth decodes correctly."""
        result = decode_congestion(bytes([APP_DATA_TYPE_CONGESTION, 255]))
        assert result == 255

    @pytest.mark.parametrize("depth", [0, 1, 50, 100, 200, 255])
    def test_round_trip(self, depth: int):
        """Encode then decode recovers original value."""
        encoded = encode_congestion(depth)
        decoded = decode_congestion(encoded)
        assert decoded == depth


class TestDtnExpiryEncoding:
    """Tests for DTN expiry encoding (spec 9.8)."""

    def test_encode_zero(self):
        """Zero timestamp encodes correctly."""
        result = encode_dtn_expiry(0)
        assert len(result) == 5
        assert result[0] == APP_DATA_TYPE_DTN_EXPIRY

    def test_encode_max(self):
        """Max 32-bit timestamp encodes correctly."""
        result = encode_dtn_expiry(0xFFFFFFFF)
        assert len(result) == 5

    def test_encode_out_of_range(self):
        """Timestamp > 2^32-1 raises ValueError."""
        with pytest.raises(ValueError, match="expiry_unix"):
            encode_dtn_expiry(0x100000000)

    def test_decode_empty(self):
        """Empty app_data returns None."""
        assert decode_dtn_expiry(b"") is None

    def test_decode_too_short(self):
        """App_data < 5 bytes returns None."""
        assert decode_dtn_expiry(b"\x03\x00\x00") is None

    def test_decode_wrong_type(self):
        """App_data with wrong type byte returns None."""
        assert decode_dtn_expiry(b"\x01\x00\x00\x00\x00") is None

    @pytest.mark.parametrize("ts", [0, 1, 1000000, 1719100800, 0xFFFFFFFF])
    def test_round_trip(self, ts: int):
        """Encode then decode recovers original timestamp."""
        encoded = encode_dtn_expiry(ts)
        decoded = decode_dtn_expiry(encoded)
        assert decoded == ts


class TestDtnPendingEncoding:
    """Tests for DTN pending IIDs encoding (spec 9.8)."""

    def test_encode_empty(self):
        """Empty list encodes to 2 bytes."""
        result = encode_dtn_pending([])
        assert result == bytes([APP_DATA_TYPE_DTN_PENDING, 0])

    def test_encode_one_iid(self):
        """Single IID encodes correctly."""
        iid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        result = encode_dtn_pending([iid])
        assert len(result) == 10  # type + count + 8
        assert result[0] == APP_DATA_TYPE_DTN_PENDING
        assert result[1] == 1
        assert result[2:] == iid

    def test_encode_multiple_iids(self):
        """Multiple IIDs encode correctly."""
        iids = [bytes([i] * 8) for i in range(3)]
        result = encode_dtn_pending(iids)
        assert len(result) == 2 + 3 * 8
        assert result[1] == 3

    def test_encode_wrong_iid_length(self):
        """IID not 8 bytes raises ValueError."""
        with pytest.raises(ValueError, match="length"):
            encode_dtn_pending([b"\x01\x02\x03"])

    def test_decode_empty_list(self):
        """Empty pending list decodes correctly."""
        result = decode_dtn_pending(bytes([APP_DATA_TYPE_DTN_PENDING, 0]))
        assert result == []

    def test_decode_one_iid(self):
        """Single IID decodes correctly."""
        iid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        encoded = encode_dtn_pending([iid])
        decoded = decode_dtn_pending(encoded)
        assert decoded == [iid]

    def test_decode_truncated(self):
        """Truncated data returns None."""
        # Says 1 IID but only has 4 bytes
        assert decode_dtn_pending(bytes([APP_DATA_TYPE_DTN_PENDING, 1, 0, 0, 0, 0])) is None

    def test_round_trip(self):
        """Encode then decode recovers original IIDs."""
        iids = [bytes([i] * 8) for i in range(5)]
        encoded = encode_dtn_pending(iids)
        decoded = decode_dtn_pending(encoded)
        assert decoded == iids


class TestOpportunisticEncoding:
    """Tests for opportunistic forwarding encoding (spec 9.9)."""

    def test_encode_empty(self):
        """Empty forwarder list encodes to 2 bytes."""
        result = encode_opportunistic_forwarders([])
        assert result == bytes([HEADER_TYPE_OPPORTUNISTIC, 0])

    def test_encode_one_forwarder(self):
        """Single forwarder encodes correctly."""
        iid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        result = encode_opportunistic_forwarders([iid])
        assert len(result) == 10
        assert result[0] == HEADER_TYPE_OPPORTUNISTIC
        assert result[1] == 1
        assert result[2:] == iid

    def test_encode_max_forwarders(self):
        """Maximum forwarders (4) encode correctly."""
        iids = [bytes([i] * 8) for i in range(4)]
        result = encode_opportunistic_forwarders(iids)
        assert len(result) == 2 + 4 * 8
        assert result[1] == 4

    def test_encode_too_many_forwarders(self):
        """More than 4 forwarders raises ValueError."""
        iids = [bytes([i] * 8) for i in range(5)]
        with pytest.raises(ValueError, match="too many"):
            encode_opportunistic_forwarders(iids)

    def test_encode_wrong_iid_length(self):
        """IID not 8 bytes raises ValueError."""
        with pytest.raises(ValueError, match="length"):
            encode_opportunistic_forwarders([b"\x01\x02\x03"])

    def test_decode_empty(self):
        """Empty data returns None."""
        assert decode_opportunistic_forwarders(b"") is None

    def test_decode_wrong_type(self):
        """Wrong type byte returns None."""
        assert decode_opportunistic_forwarders(b"\x01\x00") is None

    def test_decode_truncated(self):
        """Truncated data returns None."""
        # Says 1 forwarder but only 4 bytes of IID
        assert (
            decode_opportunistic_forwarders(bytes([HEADER_TYPE_OPPORTUNISTIC, 1, 0, 0, 0, 0]))
            is None
        )

    def test_round_trip(self):
        """Encode then decode recovers original forwarders."""
        iids = [bytes([i] * 8) for i in range(3)]
        encoded = encode_opportunistic_forwarders(iids)
        decoded = decode_opportunistic_forwarders(encoded)
        assert decoded == iids


class TestOpportunisticTiming:
    """Tests for opportunistic forwarding timing (spec 9.9)."""

    def test_rank_0_immediate(self):
        """Rank 0 (best) forwards immediately."""
        assert opportunistic_wait_time_ms(0) == 0

    def test_rank_1_waits_slot(self):
        """Rank 1 waits one slot time."""
        assert opportunistic_wait_time_ms(1) == OPPORTUNISTIC_SLOT_TIME_MS

    def test_rank_increases_linearly(self):
        """Wait time increases linearly with rank."""
        assert opportunistic_wait_time_ms(3) == 3 * OPPORTUNISTIC_SLOT_TIME_MS
