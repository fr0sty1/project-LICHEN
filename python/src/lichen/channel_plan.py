# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CCP-4 Regional Channel Plans for the LICHEN protocol.

Defines regional channel plan data structures, lookup tables, and the
``select_channel`` algorithm from spec/02a-coordinated-capacity.md:129-135.

Every implementation MUST produce identical output to the test vectors in
``test/vectors/ccp16.json`` and ``test/vectors/ccp9.json``.
"""

from __future__ import annotations

from dataclasses import dataclass


def hash_32(data: bytes) -> int:
    h = 0x811c9dc5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xffffffff
    return h


@dataclass(frozen=True)
class ChannelEntry:
    frequency_hz: int
    bandwidth_hz: int = 125_000
    spreading_factor: int = 10
    coding_rate: int = 5
    max_power_dbm: int = 14
    regulatory_group: int = 0


@dataclass(frozen=True)
class ChannelPlan:
    plan_id: int
    version: int
    name: str
    channels: tuple[ChannelEntry, ...]

    @property
    def num_channels(self) -> int:
        return len(self.channels)

    def frequency(self, channel_index: int) -> int:
        if channel_index < 0 or channel_index >= len(self.channels):
            raise ValueError(
                f"channel index {channel_index} out of range "
                f"[0, {len(self.channels)})"
            )
        return self.channels[channel_index].frequency_hz

    def select_channel(self, eui64: bytes, epoch: int, density: int) -> int:
        if density > 8:
            return 0
        data = eui64 + epoch.to_bytes(4, "little")
        h = hash_32(data)
        n = max(self.num_channels, 3)
        return 1 + (h % n)


EU868: ChannelPlan = ChannelPlan(
    plan_id=0x01,
    version=1,
    name="EU868",
    channels=(
        ChannelEntry(frequency_hz=868_100_000, max_power_dbm=14, regulatory_group=1),
        ChannelEntry(frequency_hz=868_300_000, max_power_dbm=14, regulatory_group=1),
        ChannelEntry(frequency_hz=868_500_000, max_power_dbm=14, regulatory_group=1),
        ChannelEntry(frequency_hz=867_100_000, max_power_dbm=14, regulatory_group=1),
        ChannelEntry(frequency_hz=867_300_000, max_power_dbm=14, regulatory_group=1),
        ChannelEntry(frequency_hz=867_500_000, max_power_dbm=14, regulatory_group=1),
        ChannelEntry(frequency_hz=867_700_000, max_power_dbm=14, regulatory_group=1),
        ChannelEntry(frequency_hz=867_900_000, max_power_dbm=14, regulatory_group=1),
    ),
)

US915: ChannelPlan = ChannelPlan(
    plan_id=0x02,
    version=1,
    name="US915",
    channels=(
        ChannelEntry(frequency_hz=915_000_000, max_power_dbm=22, regulatory_group=2),
        ChannelEntry(frequency_hz=915_200_000, max_power_dbm=22, regulatory_group=2),
        ChannelEntry(frequency_hz=915_400_000, max_power_dbm=22, regulatory_group=2),
        ChannelEntry(frequency_hz=915_600_000, max_power_dbm=22, regulatory_group=2),
        ChannelEntry(frequency_hz=915_800_000, max_power_dbm=22, regulatory_group=2),
        ChannelEntry(frequency_hz=916_000_000, max_power_dbm=22, regulatory_group=2),
        ChannelEntry(frequency_hz=916_200_000, max_power_dbm=22, regulatory_group=2),
        ChannelEntry(frequency_hz=916_400_000, max_power_dbm=22, regulatory_group=2),
    ),
)

AU915: ChannelPlan = ChannelPlan(
    plan_id=0x03,
    version=1,
    name="AU915",
    channels=(
        ChannelEntry(frequency_hz=915_000_000, max_power_dbm=30, regulatory_group=3),
        ChannelEntry(frequency_hz=915_200_000, max_power_dbm=30, regulatory_group=3),
        ChannelEntry(frequency_hz=915_400_000, max_power_dbm=30, regulatory_group=3),
        ChannelEntry(frequency_hz=915_600_000, max_power_dbm=30, regulatory_group=3),
        ChannelEntry(frequency_hz=915_800_000, max_power_dbm=30, regulatory_group=3),
        ChannelEntry(frequency_hz=916_000_000, max_power_dbm=30, regulatory_group=3),
        ChannelEntry(frequency_hz=916_200_000, max_power_dbm=30, regulatory_group=3),
        ChannelEntry(frequency_hz=916_400_000, max_power_dbm=30, regulatory_group=3),
    ),
)

CN470: ChannelPlan = ChannelPlan(
    plan_id=0x04,
    version=1,
    name="CN470",
    channels=(
        ChannelEntry(frequency_hz=470_300_000, max_power_dbm=19, regulatory_group=4),
        ChannelEntry(frequency_hz=470_500_000, max_power_dbm=19, regulatory_group=4),
        ChannelEntry(frequency_hz=470_700_000, max_power_dbm=19, regulatory_group=4),
        ChannelEntry(frequency_hz=470_900_000, max_power_dbm=19, regulatory_group=4),
        ChannelEntry(frequency_hz=471_100_000, max_power_dbm=19, regulatory_group=4),
        ChannelEntry(frequency_hz=471_300_000, max_power_dbm=19, regulatory_group=4),
        ChannelEntry(frequency_hz=471_500_000, max_power_dbm=19, regulatory_group=4),
        ChannelEntry(frequency_hz=471_700_000, max_power_dbm=19, regulatory_group=4),
    ),
)

AS923: ChannelPlan = ChannelPlan(
    plan_id=0x05,
    version=1,
    name="AS923",
    channels=(
        ChannelEntry(frequency_hz=920_125_000, max_power_dbm=16, regulatory_group=5),
        ChannelEntry(frequency_hz=920_325_000, max_power_dbm=16, regulatory_group=5),
        ChannelEntry(frequency_hz=920_525_000, max_power_dbm=16, regulatory_group=5),
        ChannelEntry(frequency_hz=920_725_000, max_power_dbm=16, regulatory_group=5),
        ChannelEntry(frequency_hz=920_925_000, max_power_dbm=16, regulatory_group=5),
        ChannelEntry(frequency_hz=921_125_000, max_power_dbm=16, regulatory_group=5),
        ChannelEntry(frequency_hz=921_325_000, max_power_dbm=16, regulatory_group=5),
        ChannelEntry(frequency_hz=921_525_000, max_power_dbm=16, regulatory_group=5),
    ),
)

IN865: ChannelPlan = ChannelPlan(
    plan_id=0x06,
    version=1,
    name="IN865",
    channels=(
        ChannelEntry(frequency_hz=865_062_500, max_power_dbm=30, regulatory_group=6),
        ChannelEntry(frequency_hz=865_262_500, max_power_dbm=30, regulatory_group=6),
        ChannelEntry(frequency_hz=865_462_500, max_power_dbm=30, regulatory_group=6),
        ChannelEntry(frequency_hz=865_662_500, max_power_dbm=30, regulatory_group=6),
        ChannelEntry(frequency_hz=865_862_500, max_power_dbm=30, regulatory_group=6),
        ChannelEntry(frequency_hz=866_062_500, max_power_dbm=30, regulatory_group=6),
        ChannelEntry(frequency_hz=866_262_500, max_power_dbm=30, regulatory_group=6),
        ChannelEntry(frequency_hz=866_462_500, max_power_dbm=30, regulatory_group=6),
    ),
)

KR920: ChannelPlan = ChannelPlan(
    plan_id=0x07,
    version=1,
    name="KR920",
    channels=(
        ChannelEntry(frequency_hz=920_900_000, max_power_dbm=14, regulatory_group=7),
        ChannelEntry(frequency_hz=921_100_000, max_power_dbm=14, regulatory_group=7),
        ChannelEntry(frequency_hz=921_300_000, max_power_dbm=14, regulatory_group=7),
        ChannelEntry(frequency_hz=921_500_000, max_power_dbm=14, regulatory_group=7),
        ChannelEntry(frequency_hz=921_700_000, max_power_dbm=14, regulatory_group=7),
        ChannelEntry(frequency_hz=921_900_000, max_power_dbm=14, regulatory_group=7),
        ChannelEntry(frequency_hz=922_100_000, max_power_dbm=14, regulatory_group=7),
        ChannelEntry(frequency_hz=922_300_000, max_power_dbm=14, regulatory_group=7),
    ),
)

REGIONAL_PLANS: dict[int, ChannelPlan] = {
    p.plan_id: p
    for p in (EU868, US915, AU915, CN470, AS923, IN865, KR920)
}

REGIONAL_PLANS_BY_NAME: dict[str, ChannelPlan] = {
    p.name: p for p in REGIONAL_PLANS.values()
}


def get_plan(plan_id: int) -> ChannelPlan:
    plan = REGIONAL_PLANS.get(plan_id)
    if plan is None:
        return EU868
    return plan


def get_plan_by_name(name: str) -> ChannelPlan:
    plan = REGIONAL_PLANS_BY_NAME.get(name)
    if plan is None:
        return EU868
    return plan


def channel_frequency(plan: ChannelPlan, channel_index: int) -> int:
    return plan.frequency(channel_index)


def select_channel(
    eui64: bytes,
    epoch: int,
    density: int,
    plan: ChannelPlan = US915,
) -> int:
    if density > 8:
        return 0
    data = eui64 + epoch.to_bytes(4, "little")
    h = hash_32(data)
    n = max(plan.num_channels, 3)
    return 1 + (h % n)
