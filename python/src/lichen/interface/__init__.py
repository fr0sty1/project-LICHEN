"""LICHEN interface adapters and protocol definitions.

Submodules:
- kiss: KISS TNC protocol for APRS/APRSDroid compatibility
- meshtastic: Meshtastic app compatibility adapter
- protocols: Protocol classes defining cross-implementation contracts
"""

from lichen.interface import kiss, meshtastic, protocols
from lichen.interface.protocols import (
    Clock,
    FrameParser,
    Identity,
    LinkLayerRx,
    LinkLayerTx,
    NonVolatile,
    PeerIdentity,
    RadioDriver,
    ReplayProtector,
    ReplayWindow,
    Rng,
    RxResult,
    Signer,
    Verifier,
)

__all__ = [
    "kiss",
    "meshtastic",
    "protocols",
    # Protocol classes
    "Clock",
    "FrameParser",
    "Identity",
    "LinkLayerRx",
    "LinkLayerTx",
    "NonVolatile",
    "PeerIdentity",
    "RadioDriver",
    "ReplayProtector",
    "ReplayWindow",
    "Rng",
    "RxResult",
    "Signer",
    "Verifier",
]
