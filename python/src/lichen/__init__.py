# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN: LoRa IPv6 CoAP Hybrid Extended Network.

A mesh networking protocol stack for LoRa radios using standard IPv6 and CoAP.
"""

from lichen.channel_plan import (
    AS923,
    AU915,
    CN470,
    EU868,
    IN865,
    KR920,
    US915,
    ChannelEntry,
    ChannelPlan,
    REGIONAL_PLANS,
    REGIONAL_PLANS_BY_NAME,
    channel_frequency,
    get_plan,
    get_plan_by_name,
    select_channel,
)

__version__ = "0.1.0"

__all__ = [
    "AS923",
    "AU915",
    "CN470",
    "ChannelEntry",
    "ChannelPlan",
    "EU868",
    "IN865",
    "KR920",
    "REGIONAL_PLANS",
    "REGIONAL_PLANS_BY_NAME",
    "US915",
    "channel_frequency",
    "get_plan",
    "get_plan_by_name",
    "select_channel",
    "__version__",
]
