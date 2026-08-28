# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Independent literals for lichen.sim.protocol.hop_channel (CCP-16 SelectChannel).

Expected channels were derived by hand from the SelectChannel pseudocode in
spec/02a-coordinated-capacity.md:190-196 and spec/appendix-ccp12-hopping.md:81-86
using an independent FNV-1a32 oracle (test/vectors/generate.py
``_oracle_hash_32``), never the code under test. The ``spec_example_eui_sfn1``
vector additionally matches the worked example in
spec/appendix-ccp12-hopping.md section 3.2: hash 926423932 (0x373854FC),
channel 1. ``ccp15_freq_agility_epoch42`` comes from the committed shared
vector file test/vectors/ccp15.json. The same literals are asserted by the
Rust twin ``lichen_core::rf_health::select_channel`` in
rust/lichen-core/src/rf_health.rs (cross-implementation oracle).
"""

import pytest

from lichen.sim.protocol import hop_channel

EUI_ZERO = bytes(8)
EUI_FF = b"\xff" * 8
EUI_SPEC = bytes.fromhex("0011223344556677")
SFN_MAX = 0xFFFFFFFF

# (name, sfn, eui64, num_channels, epoch, expected_channel, expected_hash)
HOP_VECTORS = [
    ("zero_sfn_zero_eui_8ch", 0, EUI_ZERO, 8, 0, 3, 3795608245),
    ("sfn_wrap_ff_eui_8ch", SFN_MAX, EUI_FF, 8, 0, 4, 4020062665),
    ("spec_example_eui_sfn1", 1, EUI_SPEC, 8, 0, 1, 926423932),
    ("sfn_wrap_epoch1_spec_eui", SFN_MAX, EUI_SPEC, 8, 1, 4, 2271500941),
    ("sfn42_epoch7_16ch", 42, EUI_ZERO, 16, 7, 13, 2404135572),
    ("sfn_max_zero_eui_16ch", SFN_MAX, EUI_ZERO, 16, 0, 15, 588931409),
    ("ccp15_freq_agility_epoch42", 42, EUI_SPEC, 8, 0, 1, 2697127431),
]


def test_hop_channel_literals() -> None:
    """hop_channel matches the hand-derived SelectChannel literals."""
    for name, sfn, eui64, num_channels, epoch, expected, _expected_hash in HOP_VECTORS:
        assert hop_channel(sfn, eui64, num_channels, epoch) == expected, name


@pytest.mark.parametrize(
    "name,sfn,eui64,num_channels,epoch,expected,_expected_hash", HOP_VECTORS
)
def test_hop_channel_literal_parametrized(
    name: str,
    sfn: int,
    eui64: bytes,
    num_channels: int,
    epoch: int,
    expected: int,
    _expected_hash: int,
) -> None:
    """Each vector asserted individually for precise failure reporting."""
    assert hop_channel(sfn, eui64, num_channels, epoch) == expected, name


def test_hop_channel_epoch_offset_identity() -> None:
    """(sfn + epoch) mod 2^32: SFN 8 epoch 0 equals SFN 5 epoch 3."""
    assert hop_channel(8, EUI_ZERO, 8, 0) == hop_channel(5, EUI_ZERO, 8, 3) == 1


def test_hop_channel_sfn_wraparound() -> None:
    """SFN MAX + 1 wraps to 0 per spec Now() unsigned 32-bit arithmetic."""
    assert hop_channel(SFN_MAX, EUI_SPEC, 8, 1) == hop_channel(0, EUI_SPEC, 8, 0) == 4


def test_hop_channel_degenerate_channel_plans() -> None:
    """No data channel fails closed; one data channel always selects CH1."""
    assert hop_channel(5, EUI_ZERO, 0) == 0
    assert hop_channel(5, EUI_ZERO, 1) == 0
    assert hop_channel(5, EUI_ZERO, 2) == 1


def test_hop_channel_result_bounds() -> None:
    """Every selected data channel is strictly below the plan count."""
    for sfn in (0, 1, 42, 0x7FFFFFFF, SFN_MAX):
        for num_channels in (2, 3, 4, 8, 16, 64, 255):
            channel = hop_channel(sfn, EUI_SPEC, num_channels)
            assert 1 <= channel < num_channels


def test_hop_channel_rejects_wrong_eui_length() -> None:
    """EUI-64 must be exactly 8 bytes."""
    with pytest.raises(ValueError, match="8 bytes"):
        hop_channel(0, b"\x00" * 7)
    with pytest.raises(ValueError, match="8 bytes"):
        hop_channel(0, b"\x00" * 9)
    with pytest.raises(ValueError, match="8 bytes"):
        hop_channel(0, b"")
