# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN: LoRa IPv6 CoAP Hybrid Extended Network.

A mesh networking protocol stack for LoRa radios using standard IPv6 and CoAP.
"""

from lichen.address_collision import (
    ADDRESS_CLAIM_LIFETIME_SECONDS,
    MAX_COLLISION_ADDRESSES,
    MAX_KEYS_PER_ADDRESS,
    AddressBindingError,
    AddressCollisionCapacityError,
    AddressCollisionDetector,
    AddressCollisionError,
    AddressCollisionTimeError,
    AddressKind,
    CollisionObservation,
    ObservationStatus,
    verify_native_address_binding,
)
from lichen.channel_plan import (
    AS923,
    AU915,
    CN470,
    EU868,
    IN865,
    KR920,
    REGIONAL_PLANS,
    REGIONAL_PLANS_BY_NAME,
    US915,
    ChannelEntry,
    ChannelPlan,
    channel_frequency,
    get_plan,
    get_plan_by_name,
    select_channel,
)
from lichen.time_provider import (
    MonotonicTimeProvider,
    SimulatedTimeProvider,
    TimeProvider,
)

__version__ = "0.1.0"

__all__ = [
    "ADDRESS_CLAIM_LIFETIME_SECONDS",
    "AS923",
    "AU915",
    "AddressBindingError",
    "AddressCollisionCapacityError",
    "AddressCollisionDetector",
    "AddressCollisionError",
    "AddressCollisionTimeError",
    "AddressKind",
    "CN470",
    "ChannelEntry",
    "ChannelPlan",
    "EU868",
    "IN865",
    "KR920",
    "MonotonicTimeProvider",
    "MAX_COLLISION_ADDRESSES",
    "MAX_KEYS_PER_ADDRESS",
    "CollisionObservation",
    "ObservationStatus",
    "REGIONAL_PLANS",
    "REGIONAL_PLANS_BY_NAME",
    "SimulatedTimeProvider",
    "TimeProvider",
    "US915",
    "__version__",
    "channel_frequency",
    "get_plan",
    "get_plan_by_name",
    "select_channel",
    "verify_native_address_binding",
]
