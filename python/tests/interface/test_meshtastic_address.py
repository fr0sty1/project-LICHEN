# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for Meshtastic address mapping."""

import pytest

from lichen.interface.meshtastic.address import (
    BROADCAST_NODE_NUM,
    AddressMapper,
    extract_synthetic_node_num,
    iid_to_node_num,
    iid_to_user_id,
    is_synthetic_iid,
    node_num_to_iid,
    synthetic_iid,
)


class TestIidToNodeNum:
    """Tests for iid_to_node_num."""

    def test_extracts_low_32_bits(self) -> None:
        iid = bytes([0x01, 0x02, 0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF])
        assert iid_to_node_num(iid) == 0xDEADBEEF

    def test_all_zeros(self) -> None:
        iid = bytes(8)
        assert iid_to_node_num(iid) == 0

    def test_all_ones(self) -> None:
        iid = bytes([0xFF] * 8)
        assert iid_to_node_num(iid) == 0xFFFFFFFF

    def test_rejects_wrong_length(self) -> None:
        with pytest.raises(ValueError, match="must be 8 bytes"):
            iid_to_node_num(bytes(7))


class TestIidToUserId:
    """Tests for iid_to_user_id."""

    def test_format(self) -> None:
        iid = bytes([0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF])
        assert iid_to_user_id(iid) == "!deadbeef"

    def test_zero_padded(self) -> None:
        iid = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x23])
        assert iid_to_user_id(iid) == "!00000123"


class TestNodeNumToIid:
    """Tests for node_num_to_iid."""

    def test_broadcast_returns_all_ones(self) -> None:
        result = node_num_to_iid(BROADCAST_NODE_NUM)
        assert result == bytes([0xFF] * 8)

    def test_unknown_returns_none(self) -> None:
        result = node_num_to_iid(0x12345678, peers={})
        assert result is None

    def test_finds_matching_peer(self) -> None:
        iid = bytes([0x01, 0x02, 0x03, 0x04, 0x12, 0x34, 0x56, 0x78])
        peers = {iid: b"pubkey" * 4}  # 32-byte dummy pubkey
        result = node_num_to_iid(0x12345678, peers)
        assert result == iid

    def test_no_peers_returns_none(self) -> None:
        result = node_num_to_iid(0x12345678, peers=None)
        assert result is None


class TestSyntheticIid:
    """Tests for synthetic IID functions."""

    def test_synthetic_iid_format(self) -> None:
        iid = synthetic_iid(0x12345678)
        assert iid[:4] == b"MESH"
        assert iid[4:] == bytes([0x12, 0x34, 0x56, 0x78])

    def test_is_synthetic_detects_marker(self) -> None:
        iid = synthetic_iid(0xDEADBEEF)
        assert is_synthetic_iid(iid)

    def test_is_synthetic_rejects_normal_iid(self) -> None:
        iid = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        assert not is_synthetic_iid(iid)

    def test_extract_roundtrip(self) -> None:
        node_num = 0xCAFEBABE
        iid = synthetic_iid(node_num)
        assert extract_synthetic_node_num(iid) == node_num

    def test_extract_from_normal_iid_returns_none(self) -> None:
        iid = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        assert extract_synthetic_node_num(iid) is None


class TestAddressMapper:
    """Tests for AddressMapper."""

    def test_empty_mapper(self) -> None:
        mapper = AddressMapper()
        assert len(mapper) == 0

    def test_learn_and_lookup(self) -> None:
        mapper = AddressMapper()
        iid = bytes([0x01, 0x02, 0x03, 0x04, 0x12, 0x34, 0x56, 0x78])
        pubkey = bytes(32)
        assert mapper.learn(iid, pubkey) is True

        assert len(mapper) == 1
        assert mapper.is_known(0x12345678)
        assert mapper.node_num_to_iid(0x12345678) == iid
        assert mapper.get_pubkey(iid) == pubkey

    def test_unknown_node_returns_synthetic(self) -> None:
        mapper = AddressMapper()
        iid = mapper.node_num_to_iid(0xDEADBEEF)
        assert is_synthetic_iid(iid)
        assert extract_synthetic_node_num(iid) == 0xDEADBEEF

    def test_broadcast_returns_all_ones(self) -> None:
        mapper = AddressMapper()
        iid = mapper.node_num_to_iid(BROADCAST_NODE_NUM)
        assert iid == bytes([0xFF] * 8)

    def test_iid_to_node_num(self) -> None:
        mapper = AddressMapper()
        iid = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44])
        assert mapper.iid_to_node_num(iid) == 0x11223344

    def test_rejects_invalid_iid_length(self) -> None:
        mapper = AddressMapper()
        with pytest.raises(ValueError, match="must be 8 bytes"):
            mapper.learn(bytes(7), bytes(32))

    def test_rejects_invalid_pubkey_length(self) -> None:
        mapper = AddressMapper()
        with pytest.raises(ValueError, match="must be 32 bytes"):
            mapper.learn(bytes(8), bytes(31))

    def test_tofu_violation_returns_false(self) -> None:
        """TOFU violation logs warning and returns False instead of raising."""
        mapper = AddressMapper()
        iid = bytes([0x01, 0x02, 0x03, 0x04, 0x12, 0x34, 0x56, 0x78])
        pubkey1 = bytes(32)
        pubkey2 = bytes([0xFF] * 32)  # Different key

        # First contact succeeds
        assert mapper.learn(iid, pubkey1) is True
        assert mapper.get_pubkey(iid) == pubkey1

        # Second contact with different key fails gracefully
        assert mapper.learn(iid, pubkey2) is False

        # Original key is still pinned
        assert mapper.get_pubkey(iid) == pubkey1

    def test_same_pubkey_succeeds(self) -> None:
        """Relearning with same pubkey succeeds."""
        mapper = AddressMapper()
        iid = bytes([0x01, 0x02, 0x03, 0x04, 0x12, 0x34, 0x56, 0x78])
        pubkey = bytes(32)

        assert mapper.learn(iid, pubkey) is True
        assert mapper.learn(iid, pubkey) is True  # Same key, should succeed
