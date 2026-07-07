"""Tests for IID ↔ callsign mapping."""

import pytest

from lichen.interface.kiss.callsign import (
    LICHEN_PREFIX,
    SimplePeerLookup,
    broadcast_iid,
    callsign_to_iid,
    callsign_to_suffix,
    iid_to_callsign,
    is_broadcast_callsign,
)


class TestIidToCallsign:
    def test_basic_conversion(self):
        iid = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03])
        call = iid_to_callsign(iid)
        assert call.startswith(LICHEN_PREFIX)
        assert len(call) <= 6  # Max callsign length

    def test_with_ssid(self):
        iid = bytes([0x00] * 8)
        call = iid_to_callsign(iid, ssid=5)
        assert call.endswith("-5")

    def test_ssid_zero_omitted(self):
        iid = bytes([0x00] * 8)
        call = iid_to_callsign(iid, ssid=0)
        assert "-" not in call

    def test_different_iids_different_calls(self):
        iid1 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03])
        iid2 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x05, 0x06])
        assert iid_to_callsign(iid1) != iid_to_callsign(iid2)

    def test_max_suffix(self):
        # Max 24-bit value: 0xFFFFFF
        iid = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF])
        call = iid_to_callsign(iid)
        # Should still fit in 6 chars
        assert len(call) <= 6

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError, match="8 bytes"):
            iid_to_callsign(b"short")


class TestCallsignToSuffix:
    def test_basic_decode(self):
        # Encode then decode suffix
        iid = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0xAB, 0xCD, 0xEF])
        call = iid_to_callsign(iid)
        suffix = callsign_to_suffix(call)
        expected = (0xAB << 16) | (0xCD << 8) | 0xEF
        assert suffix == expected

    def test_with_ssid(self):
        iid = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33])
        call = iid_to_callsign(iid, ssid=7)
        suffix = callsign_to_suffix(call)
        expected = (0x11 << 16) | (0x22 << 8) | 0x33
        assert suffix == expected

    def test_non_lichen_returns_none(self):
        assert callsign_to_suffix("W1AW") is None
        assert callsign_to_suffix("CQ") is None
        assert callsign_to_suffix("BEACON") is None

    def test_case_insensitive(self):
        iid = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03])
        call = iid_to_callsign(iid)
        lower_call = call.lower()
        assert callsign_to_suffix(call) == callsign_to_suffix(lower_call)

    def test_invalid_chars_returns_none(self):
        assert callsign_to_suffix("LI!!??") is None


class TestCallsignToIid:
    def test_lookup_found(self):
        iid = bytes([0xFE, 0x80, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC])
        peers = SimplePeerLookup()
        peers.add(iid)

        call = iid_to_callsign(iid)
        result = callsign_to_iid(call, peers)
        assert result == iid

    def test_lookup_not_found(self):
        peers = SimplePeerLookup()
        result = callsign_to_iid("LI1234", peers)
        assert result is None

    def test_non_lichen_returns_none(self):
        peers = SimplePeerLookup()
        result = callsign_to_iid("W1AW", peers)
        assert result is None


class TestBroadcast:
    def test_cq_is_broadcast(self):
        assert is_broadcast_callsign("CQ") is True
        assert is_broadcast_callsign("cq") is True
        assert is_broadcast_callsign("CQ-0") is True

    def test_beacon_is_broadcast(self):
        assert is_broadcast_callsign("BEACON") is True
        assert is_broadcast_callsign("BEACON-5") is True

    def test_all_is_broadcast(self):
        assert is_broadcast_callsign("ALL") is True

    def test_regular_callsign_not_broadcast(self):
        assert is_broadcast_callsign("W1AW") is False
        assert is_broadcast_callsign("LI1234") is False

    def test_broadcast_iid(self):
        iid = broadcast_iid()
        assert len(iid) == 8


class TestSimplePeerLookup:
    def test_add_and_lookup(self):
        peers = SimplePeerLookup()
        iid = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56])
        peers.add(iid)

        suffix = (0x12 << 16) | (0x34 << 8) | 0x56
        assert peers.lookup_by_suffix(suffix) == iid

    def test_all_iids(self):
        peers = SimplePeerLookup()
        iid1 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03])
        iid2 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x05, 0x06])
        peers.add(iid1)
        peers.add(iid2)

        all_iids = peers.all_iids()
        assert len(all_iids) == 2
        assert iid1 in all_iids
        assert iid2 in all_iids

    def test_wrong_length_raises(self):
        peers = SimplePeerLookup()
        with pytest.raises(ValueError):
            peers.add(b"short")


class TestRoundtrip:
    def test_iid_roundtrip(self):
        """IID → callsign → suffix matches original IID suffix."""
        test_iids = [
            bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            bytes([0xFE, 0x80, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78]),
            bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
        ]

        for iid in test_iids:
            call = iid_to_callsign(iid)
            suffix = callsign_to_suffix(call)
            expected = (iid[5] << 16) | (iid[6] << 8) | iid[7]
            assert suffix == expected, f"Failed for IID {iid.hex()}"

    def test_full_roundtrip_with_lookup(self):
        """IID → callsign → lookup → original IID."""
        peers = SimplePeerLookup()
        iid = bytes([0xFE, 0x80, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF])
        peers.add(iid)

        call = iid_to_callsign(iid)
        result = callsign_to_iid(call, peers)
        assert result == iid
