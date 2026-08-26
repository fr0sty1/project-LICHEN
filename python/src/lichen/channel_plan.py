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
from enum import Enum, auto


class UnknownPlanError(LookupError):
    """Raised when a channel plan id or name is not recognized.

    Plan resolution is fail-closed: an unknown plan never silently
    substitutes another region's regulatory rules, because applying
    e.g. EU868 duty-cycle/power limits in an LBT/dwell-time region is
    a regulatory compliance hazard. Spec 02a-coordinated-capacity.md:182
    requires CH0 fallback for unknown plans; callers detect that case
    with :func:`ch0_fallback_required` and operate conservatively.
    """


class RegulatoryMode(Enum):
    """Regulatory modes for regional channel plans."""

    DUTY_CYCLE = auto()
    DWELL_TIME = auto()
    LBT = auto()


@dataclass(frozen=True)
class RegulatoryRules:
    """Regulatory rules for a channel plan."""

    mode: RegulatoryMode
    duty_cycle_percent: float | None = None
    dwell_time_ms: int | None = None
    lbt_threshold_dbm: int | None = None


def hash_32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
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
    regulatory_rules: RegulatoryRules = RegulatoryRules(mode=RegulatoryMode.DUTY_CYCLE)

    @property
    def num_channels(self) -> int:
        return len(self.channels)

    def frequency(self, channel_index: int) -> int:
        if channel_index < 0 or channel_index >= len(self.channels):
            raise ValueError(
                f"channel index {channel_index} out of range [0, {len(self.channels)})"
            )
        return self.channels[channel_index].frequency_hz

    def validate_channel_mask(self, mask: int) -> int:
        """Return mask with bits cleared for channels beyond num_channels."""
        valid_mask = (1 << self.num_channels) - 1
        return mask & valid_mask

    def is_valid_power(self, channel_index: int, power_dbm: int) -> bool:
        """Check if power level is valid for the given channel."""
        if channel_index < 0 or channel_index >= self.num_channels:
            return False
        return power_dbm <= self.channels[channel_index].max_power_dbm

    def select_channel(self, eui64: bytes, epoch: int, density: int) -> int:
        """Select a valid channel index per the CCP-12 priority chain.

        Density above eight forces control channel CH0. Degenerate plans are
        explicit: a one-channel plan has only CH0, while a two-channel plan
        has only CH1 for data. Plans with three or more entries retain the
        normative 1-based hash domain ``[1, num_channels]``.

        ``epoch`` is truncated to u32 (``& 0xFFFFFFFF``) before the
        little-endian hash input, matching the C/Rust truncate
        semantics so every implementation agrees for epochs >= 2^32.
        """
        return _select_channel_index(eui64, epoch, density, self.num_channels)


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
    regulatory_rules=RegulatoryRules(mode=RegulatoryMode.DUTY_CYCLE, duty_cycle_percent=1.0),
)

US915: ChannelPlan = ChannelPlan(
    plan_id=0x02,
    version=1,
    name="US915",
    # 64 channels for FCC Part 15.247 FHSS compliance (requires 50+)
    # 902.3-914.9 MHz, 200kHz spacing (same as LoRaWAN uplink channels)
    channels=tuple(
        ChannelEntry(frequency_hz=902_300_000 + i * 200_000, max_power_dbm=22, regulatory_group=2)
        for i in range(64)
    ),
    regulatory_rules=RegulatoryRules(mode=RegulatoryMode.DWELL_TIME, dwell_time_ms=400),
)

AU915: ChannelPlan = ChannelPlan(
    plan_id=0x03,
    version=1,
    name="AU915",
    # 64 channels, 915-928 MHz, 200kHz spacing (ACMA allows up to 30 dBm EIRP)
    channels=tuple(
        ChannelEntry(frequency_hz=915_200_000 + i * 200_000, max_power_dbm=30, regulatory_group=3)
        for i in range(64)
    ),
    regulatory_rules=RegulatoryRules(mode=RegulatoryMode.DWELL_TIME, dwell_time_ms=400),
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
    regulatory_rules=RegulatoryRules(mode=RegulatoryMode.DUTY_CYCLE, duty_cycle_percent=1.0),
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
    regulatory_rules=RegulatoryRules(mode=RegulatoryMode.LBT, lbt_threshold_dbm=-80),
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
    regulatory_rules=RegulatoryRules(mode=RegulatoryMode.DUTY_CYCLE, duty_cycle_percent=1.0),
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
    regulatory_rules=RegulatoryRules(mode=RegulatoryMode.LBT, lbt_threshold_dbm=-80),
)

REGIONAL_PLANS: dict[int, ChannelPlan] = {
    p.plan_id: p for p in (EU868, US915, AU915, CN470, AS923, IN865, KR920)
}

REGIONAL_PLANS_BY_NAME: dict[str, ChannelPlan] = {p.name: p for p in REGIONAL_PLANS.values()}


def get_plan(plan_id: int) -> ChannelPlan:
    """Return the regional plan for ``plan_id``.

    Fail-closed: raises :class:`UnknownPlanError` for unrecognized ids
    rather than substituting a default region's regulatory rules.
    """
    plan = REGIONAL_PLANS.get(plan_id)
    if plan is None:
        raise UnknownPlanError(f"unknown channel plan_id: {plan_id}")
    return plan


def get_plan_by_name(name: str) -> ChannelPlan:
    """Return the regional plan for ``name`` (exact match).

    Fail-closed: raises :class:`UnknownPlanError` for unrecognized
    names rather than substituting a default region's regulatory rules.
    """
    plan = REGIONAL_PLANS_BY_NAME.get(name)
    if plan is None:
        raise UnknownPlanError(f"unknown channel plan name: {name!r}")
    return plan


def validate_plan_id(plan_id: int) -> bool:
    """Return True if plan_id is known."""
    return plan_id in REGIONAL_PLANS


def ch0_fallback_required(plan_id: int, version: int = 1) -> bool:
    """Return True if CH0 fallback is required for unknown plan/version."""
    plan = REGIONAL_PLANS.get(plan_id)
    if plan is None:
        return True
    return plan.version != version


def channel_frequency(plan: ChannelPlan, channel_number: int) -> int:
    if channel_number < 1 or channel_number > plan.num_channels:
        raise ValueError(f"channel number {channel_number} out of range [1, {plan.num_channels}]")
    return plan.frequency(channel_number - 1)


def _select_channel_index(eui64: bytes, epoch: int, density: int, n_channels: int) -> int:
    """Implement CCP-12 hash selection for an explicitly bounded plan.

    ``n_channels`` must be positive; callers cannot select from an empty or
    nonsensical negative-size plan. The one- and two-channel branches prevent
    the spec's minimum-three modulo domain from producing a nonexistent CH2.
    """
    if type(n_channels) is not int or n_channels <= 0:
        raise ValueError("n_channels must be a positive integer")
    if density > 8 or n_channels == 1:
        return 0
    if n_channels == 2:
        return 1
    data = eui64 + (epoch & 0xFFFFFFFF).to_bytes(4, "little")
    h = hash_32(data)
    return 1 + (h % n_channels)


def select_channel(
    eui64: bytes,
    epoch: int,
    density: int,
    plan: ChannelPlan = US915,
) -> int:
    """Select a channel per spec 02a §2a.3.1 (see
    :meth:`ChannelPlan.select_channel` for the contract, including the
    u32 epoch truncation)."""
    return _select_channel_index(eui64, epoch, density, plan.num_channels)
