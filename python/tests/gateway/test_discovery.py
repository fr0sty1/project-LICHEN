# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for gateway discovery protocol (GCP-4)."""

from ipaddress import IPv6Address

import cbor2
import pytest

from lichen.gateway.discovery import (
    GATEWAY_FLAG,
    AllocationMode,
    DiscoveryError,
    FederationMode,
    GatewayCapabilities,
    GatewayInfo,
    LoRaGatewayAnnounce,
    SlotMap,
    elect_time_master,
    iid_compare,
)


class TestGatewayCapabilities:
    """Tests for GatewayCapabilities."""

    def test_defaults(self) -> None:
        caps = GatewayCapabilities()
        assert caps.max_slots == 60
        assert caps.gps_sync is False
        assert caps.backbone_ipv6 is True
        assert caps.lr_fhss is False
        assert caps.channels == 8
        assert caps.max_nodes == 256

    def test_custom_values(self) -> None:
        caps = GatewayCapabilities(
            max_slots=120,
            gps_sync=True,
            backbone_ipv6=True,
            lr_fhss=True,
            channels=16,
            max_nodes=1000,
        )
        assert caps.max_slots == 120
        assert caps.gps_sync is True
        assert caps.lr_fhss is True

    def test_invalid_max_slots(self) -> None:
        with pytest.raises(DiscoveryError, match="max_slots out of range"):
            GatewayCapabilities(max_slots=0)
        with pytest.raises(DiscoveryError, match="max_slots out of range"):
            GatewayCapabilities(max_slots=1001)

    def test_invalid_channels(self) -> None:
        with pytest.raises(DiscoveryError, match="channels out of range"):
            GatewayCapabilities(channels=17)

    def test_cbor_roundtrip(self) -> None:
        caps = GatewayCapabilities(
            max_slots=100,
            gps_sync=True,
            backbone_ipv6=True,
            lr_fhss=False,
            channels=4,
            max_nodes=500,
        )
        cbor_map = caps.to_cbor_map()
        decoded = GatewayCapabilities.from_cbor_map(cbor_map)
        assert decoded == caps


class TestSlotMap:
    """Tests for SlotMap."""

    def test_interleaved_default(self) -> None:
        slot_map = SlotMap()
        assert slot_map.mode == AllocationMode.INTERLEAVED
        assert slot_map.gateway_count == 1
        assert slot_map.ordinal == 0
        # Single gateway owns all slots
        assert slot_map.owned_slots(60) == list(range(60))

    def test_interleaved_three_gateways(self) -> None:
        slot_map = SlotMap(
            mode=AllocationMode.INTERLEAVED,
            gateway_count=3,
            ordinal=1,
        )
        # Gateway 1 owns slots 1, 4, 7, 10, ...
        expected = [1, 4, 7, 10, 13, 16, 19, 22, 25, 28, 31, 34, 37, 40, 43, 46, 49, 52, 55, 58]
        assert slot_map.owned_slots(60) == expected

    def test_contiguous_mode(self) -> None:
        slot_map = SlotMap(
            mode=AllocationMode.CONTIGUOUS,
            gateway_count=3,
            ordinal=1,
            start_slot=20,
            slot_count=20,
        )
        expected = list(range(20, 40))
        assert slot_map.owned_slots(60) == expected

    def test_contiguous_missing_params(self) -> None:
        with pytest.raises(DiscoveryError, match="contiguous mode requires"):
            SlotMap(mode=AllocationMode.CONTIGUOUS, gateway_count=2, ordinal=0)

    def test_invalid_ordinal(self) -> None:
        with pytest.raises(DiscoveryError, match="ordinal.*out of range"):
            SlotMap(gateway_count=3, ordinal=5)

    def test_cbor_roundtrip_interleaved(self) -> None:
        slot_map = SlotMap(
            mode=AllocationMode.INTERLEAVED,
            gateway_count=3,
            ordinal=0,
        )
        cbor_map = slot_map.to_cbor_map(60)
        decoded = SlotMap.from_cbor_map(cbor_map)
        assert decoded.mode == slot_map.mode
        assert decoded.gateway_count == slot_map.gateway_count
        assert decoded.ordinal == slot_map.ordinal

    def test_cbor_roundtrip_contiguous(self) -> None:
        slot_map = SlotMap(
            mode=AllocationMode.CONTIGUOUS,
            gateway_count=3,
            ordinal=1,
            start_slot=20,
            slot_count=20,
        )
        cbor_map = slot_map.to_cbor_map(60)
        decoded = SlotMap.from_cbor_map(cbor_map)
        assert decoded.mode == slot_map.mode
        assert decoded.start_slot == slot_map.start_slot
        assert decoded.slot_count == slot_map.slot_count


class TestGatewayInfo:
    """Tests for GatewayInfo."""

    def test_basic_gateway_info(self) -> None:
        iid = IPv6Address("fe80::1234:5678:9abc:def0")
        info = GatewayInfo(iid=iid)
        assert info.iid == iid
        assert info.superframe_duration_s == 60
        assert FederationMode.PSK in info.federation_modes
        assert FederationMode.ED25519 in info.federation_modes

    def test_full_gateway_info(self) -> None:
        iid = IPv6Address("fe80::1234:5678:9abc:def0")
        caps = GatewayCapabilities(max_slots=60, gps_sync=True)
        slot_map = SlotMap(gateway_count=3, ordinal=0)
        info = GatewayInfo(
            iid=iid,
            capabilities=caps,
            slot_map=slot_map,
            superframe_duration_s=60,
            federation_modes=(FederationMode.PSK, FederationMode.ED25519),
            superframe_epoch=1720000000,
            time_source="gps",
        )
        assert info.time_source == "gps"
        assert info.superframe_epoch == 1720000000

    def test_invalid_superframe_duration(self) -> None:
        iid = IPv6Address("fe80::1")
        with pytest.raises(DiscoveryError, match="superframe_duration"):
            GatewayInfo(iid=iid, superframe_duration_s=0)

    def test_invalid_time_source(self) -> None:
        iid = IPv6Address("fe80::1")
        with pytest.raises(DiscoveryError, match="invalid time_source"):
            GatewayInfo(iid=iid, time_source="unknown")

    def test_empty_federation_modes(self) -> None:
        iid = IPv6Address("fe80::1")
        with pytest.raises(DiscoveryError, match="at least one federation mode"):
            GatewayInfo(iid=iid, federation_modes=())

    def test_cbor_roundtrip(self) -> None:
        iid = IPv6Address("fe80::1234:5678:9abc:def0")
        caps = GatewayCapabilities(max_slots=60, gps_sync=True, backbone_ipv6=True)
        slot_map = SlotMap(gateway_count=3, ordinal=0)
        info = GatewayInfo(
            iid=iid,
            capabilities=caps,
            slot_map=slot_map,
            superframe_duration_s=60,
            federation_modes=(FederationMode.PSK, FederationMode.ED25519),
            superframe_epoch=1720000000,
            time_source="gps",
        )
        encoded = info.encode()
        decoded = GatewayInfo.decode(encoded)

        assert decoded.iid == info.iid
        assert decoded.superframe_duration_s == info.superframe_duration_s
        assert decoded.federation_modes == info.federation_modes
        assert decoded.superframe_epoch == info.superframe_epoch
        assert decoded.time_source == info.time_source
        assert decoded.capabilities.max_slots == caps.max_slots
        assert decoded.capabilities.gps_sync == caps.gps_sync

    def test_decode_invalid_cbor(self) -> None:
        # Truncated CBOR (starts a map but incomplete)
        with pytest.raises(DiscoveryError, match="invalid CBOR"):
            GatewayInfo.decode(b"\xbf\x01")  # Indefinite map, one byte, truncated

    def test_decode_missing_iid(self) -> None:
        payload = cbor2.dumps({2: {}})  # capabilities but no IID
        with pytest.raises(DiscoveryError, match="missing or invalid gateway IID"):
            GatewayInfo.decode(payload)


class TestLoRaGatewayAnnounce:
    """Tests for LoRaGatewayAnnounce (GCP-4.2 fallback)."""

    def test_basic_announce(self) -> None:
        announce = LoRaGatewayAnnounce(
            iid_short=bytes.fromhex("1234def0"),
            superframe_epoch=1720000000,
            channel_id=7,
        )
        assert announce.iid_short == bytes.fromhex("1234def0")
        assert announce.superframe_epoch == 1720000000
        assert announce.channel_id == 7

    def test_from_gateway_iid(self) -> None:
        iid = IPv6Address("fe80::1234:5678:9abc:def0")
        announce = LoRaGatewayAnnounce.from_gateway_iid(iid, 1720000000, 7)
        # Last 4 bytes of fe80::1234:5678:9abc:def0 are 9abc:def0
        assert announce.iid_short == bytes.fromhex("9abcdef0")

    def test_invalid_iid_short_length(self) -> None:
        with pytest.raises(DiscoveryError, match="iid_short must be 4 bytes"):
            LoRaGatewayAnnounce(
                iid_short=bytes.fromhex("1234"),  # Only 2 bytes
                superframe_epoch=1720000000,
                channel_id=7,
            )

    def test_invalid_channel_id(self) -> None:
        with pytest.raises(DiscoveryError, match="channel_id out of range"):
            LoRaGatewayAnnounce(
                iid_short=bytes.fromhex("1234def0"),
                superframe_epoch=1720000000,
                channel_id=16,
            )

    def test_encode_wire_format(self) -> None:
        announce = LoRaGatewayAnnounce(
            iid_short=bytes.fromhex("1234def0"),
            superframe_epoch=1720000000,
            channel_id=7,
        )
        encoded = announce.encode()
        # Expected: 0x81 (announce | GATEWAY) + 4B IID + 4B epoch + 1B channel = 10 bytes
        assert len(encoded) == 10
        assert encoded[0] == 0x81  # 0x01 | 0x80
        assert encoded[1:5] == bytes.fromhex("1234def0")
        assert encoded[5:9] == (1720000000).to_bytes(4, "big")
        assert encoded[9] == 7

    def test_encode_decode_roundtrip(self) -> None:
        original = LoRaGatewayAnnounce(
            iid_short=bytes.fromhex("aabbccdd"),
            superframe_epoch=1720001234,
            channel_id=3,
        )
        encoded = original.encode()
        decoded = LoRaGatewayAnnounce.decode(encoded)
        assert decoded.iid_short == original.iid_short
        assert decoded.superframe_epoch == original.superframe_epoch
        assert decoded.channel_id == original.channel_id

    def test_decode_without_gateway_flag(self) -> None:
        # Regular announce without GATEWAY flag (10 bytes: type + 4B IID + 4B epoch + 1B channel)
        iid_short = bytes.fromhex("1234def0")
        epoch_bytes = (1720000000).to_bytes(4, "big")
        payload = bytes([0x01]) + iid_short + epoch_bytes + bytes([7])
        with pytest.raises(DiscoveryError, match="GATEWAY flag not set"):
            LoRaGatewayAnnounce.decode(payload)

    def test_is_gateway_announce(self) -> None:
        # With GATEWAY flag
        assert LoRaGatewayAnnounce.is_gateway_announce(bytes([0x81]))
        # Without GATEWAY flag
        assert not LoRaGatewayAnnounce.is_gateway_announce(bytes([0x01]))
        # Empty
        assert not LoRaGatewayAnnounce.is_gateway_announce(b"")


class TestIidCompare:
    """Tests for IID comparison (slot conflict resolution)."""

    def test_lower_wins(self) -> None:
        a = IPv6Address("fe80::0001:0001:0001:0001")
        b = IPv6Address("fe80::ffff:ffff:ffff:ffff")
        assert iid_compare(a, b) == -1  # a wins

    def test_higher_loses(self) -> None:
        a = IPv6Address("fe80::ffff:ffff:ffff:ffff")
        b = IPv6Address("fe80::0001:0001:0001:0001")
        assert iid_compare(a, b) == 1  # b wins

    def test_equal(self) -> None:
        a = IPv6Address("fe80::1234:5678:9abc:def0")
        b = IPv6Address("fe80::1234:5678:9abc:def0")
        assert iid_compare(a, b) == 0


class TestElectTimeMaster:
    """Tests for time master election (GCP-6.1)."""

    def test_empty_candidates(self) -> None:
        assert elect_time_master([]) is None

    def test_single_candidate(self) -> None:
        iid = IPv6Address("fe80::1")
        assert elect_time_master([(iid, False)]) == iid

    def test_gps_preferred(self) -> None:
        gps_iid = IPv6Address("fe80::ffff")  # Higher IID but has GPS
        no_gps_iid = IPv6Address("fe80::0001")  # Lower IID, no GPS
        # GPS gateway wins even with higher IID
        assert elect_time_master([(no_gps_iid, False), (gps_iid, True)]) == gps_iid

    def test_lowest_iid_among_gps(self) -> None:
        gps_high = IPv6Address("fe80::ffff")
        gps_low = IPv6Address("fe80::0001")
        # Both have GPS, lower IID wins
        result = elect_time_master([(gps_high, True), (gps_low, True)])
        assert result == gps_low

    def test_lowest_iid_among_no_gps(self) -> None:
        no_gps_high = IPv6Address("fe80::ffff")
        no_gps_low = IPv6Address("fe80::0001")
        # Neither has GPS, lower IID wins
        result = elect_time_master([(no_gps_high, False), (no_gps_low, False)])
        assert result == no_gps_low


class TestGatewayFlag:
    """Tests for GATEWAY_FLAG constant."""

    def test_gateway_flag_value(self) -> None:
        assert GATEWAY_FLAG == 0x80

    def test_gateway_flag_preserves_type(self) -> None:
        # GATEWAY flag should be usable with announce type 0x01
        combined = 0x01 | GATEWAY_FLAG
        assert combined == 0x81
        # Extract type byte
        base_type = combined & ~GATEWAY_FLAG
        assert base_type == 0x01
