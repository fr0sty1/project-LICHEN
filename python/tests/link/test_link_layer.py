# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for core link layer functionality.

Why these tests: The link layer's core behavior must be correct. Bugs here mean:
- Unpredictable epochs not working (replay vulnerability on reboot)
- Sequence management broken (counter reuse)
- Invalid construction allowed (missing identity/radio)

Test categories:
1. Epoch: Entropy-based initialization on construction
2. Sequence: get/set/wrap behavior
3. Construction: Parameter validation
"""

import pytest

from lichen.crypto.identity import Identity
from lichen.link.link_layer import LinkLayer

from .conftest import MockRadio


class TestLinkLayerEpoch:
    """Tests for unpredictable reboot epoch initialization."""

    def test_epoch_uses_system_entropy(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_radio: MockRadio,
        node_identity: Identity,
    ) -> None:
        calls: list[int] = []

        def randbelow(limit: int) -> int:
            calls.append(limit)
            return 127

        monkeypatch.setattr("lichen.link.link_layer.secrets.randbelow", randbelow)
        ll = LinkLayer(radio=mock_radio, identity=node_identity, peer_lookup=lambda _: None)

        assert calls == [128]
        assert ll.get_sequence() == (255, 0)

    def test_entropy_failure_propagates(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_radio: MockRadio,
        node_identity: Identity,
    ) -> None:
        def fail(_: int) -> int:
            raise RuntimeError("entropy unavailable")

        monkeypatch.setattr("lichen.link.link_layer.secrets.randbelow", fail)
        with pytest.raises(RuntimeError, match="entropy unavailable"):
            LinkLayer(radio=mock_radio, identity=node_identity, peer_lookup=lambda _: None)


class TestSequenceManagement:
    """Tests for sequence number management."""

    def test_get_set_sequence(self, link_layer: LinkLayer):
        """set_sequence and get_sequence work correctly."""
        link_layer.set_sequence(5, 1000)
        epoch, seqnum = link_layer.get_sequence()

        assert epoch == 5
        assert seqnum == 1000

    def test_set_sequence_validates_epoch(self, link_layer: LinkLayer):
        """set_sequence rejects invalid epoch values."""
        with pytest.raises(ValueError, match="epoch out of range"):
            link_layer.set_sequence(256, 0)

        with pytest.raises(ValueError, match="epoch out of range"):
            link_layer.set_sequence(-1, 0)

    def test_set_sequence_validates_seqnum(self, link_layer: LinkLayer):
        """set_sequence rejects invalid seqnum values."""
        with pytest.raises(ValueError, match="seqnum out of range"):
            link_layer.set_sequence(0, 0x10000)

        with pytest.raises(ValueError, match="seqnum out of range"):
            link_layer.set_sequence(0, -1)

    def test_restored_terminal_tuple_fails_closed(self, link_layer: LinkLayer):
        with pytest.raises(OverflowError, match="sequence exhausted"):
            link_layer.set_sequence(0xFF, 0xFFFF)

        with pytest.raises(OverflowError, match="sequence exhausted"):
            link_layer.get_sequence()
        with pytest.raises(OverflowError, match="sequence exhausted"):
            link_layer.set_sequence(0, 0)

    @pytest.mark.asyncio
    async def test_set_sequence_rejects_counter_used_by_terminal_cad_failure(
        self, link_layer: LinkLayer, mock_radio: MockRadio
    ) -> None:
        mock_radio.cad_returns = True
        assert await link_layer.send(b"queued") is False

        with pytest.raises(RuntimeError, match="cannot be reset"):
            link_layer.set_sequence(0, 0)

        assert link_layer.get_sequence() == (0, 1)
        assert len(link_layer.tx_queue) == 0

    @pytest.mark.asyncio
    async def test_set_sequence_rejects_used_counter(self, link_layer: LinkLayer) -> None:
        assert await link_layer.send(b"sent") is True
        assert len(link_layer.tx_queue) == 0

        with pytest.raises(RuntimeError, match="cannot be reset"):
            link_layer.set_sequence(0, 0)

        assert link_layer.get_sequence() == (0, 1)


class TestLinkLayerConstruction:
    """Tests for LinkLayer construction and validation."""

    def test_requires_identity(self, mock_radio: MockRadio):
        """LinkLayer requires an identity."""
        with pytest.raises(ValueError, match="identity is required"):
            LinkLayer(
                radio=mock_radio,
                identity=None,
                peer_lookup=lambda x: None,
            )

    def test_requires_radio(self, node_identity: Identity):
        """LinkLayer requires a radio."""
        with pytest.raises(ValueError, match="radio is required"):
            LinkLayer(
                radio=None,
                identity=node_identity,
                peer_lookup=lambda x: None,
            )

    def test_requires_peer_lookup(self, mock_radio: MockRadio, node_identity: Identity):
        """LinkLayer requires a peer_lookup callback."""
        with pytest.raises(ValueError, match="peer_lookup callback is required"):
            LinkLayer(
                radio=mock_radio,
                identity=node_identity,
                peer_lookup=None,
            )
