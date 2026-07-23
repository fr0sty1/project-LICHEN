"""LICHEN protocol constants.

Canonical values shared across layers. The language-neutral source of truth
is ``constants.toml`` at the repository root; keep these in sync with it.
"""

# LoRa physical layer
LORA_SPREADING_FACTOR: int = 10
LORA_BANDWIDTH_HZ: int = 125_000
LORA_PREAMBLE_SYMBOLS: int = 8
LORA_SYNC_WORD: int = 0x34  # Distinct from Meshtastic (0x2B)
LORA_CAD_SYMBOLS: int = 2  # Symbols to detect in CAD mode (2-4 typical)
LORA_CAD_TIMEOUT_MS: int = 35  # Default CAD timeout (covers ~4 symbols + overhead)
CAD_SLOT_MS: int = 10  # Backoff slot duration for CAD-based CSMA
CAD_MAX_BACKOFF_EXPONENT: int = 5  # Max slots = 2^5 - 1 = 31
CAD_MAX_CYCLES: int = 3  # Full backoff cycles before TX failure

# Default channel 0 frequencies per region (spec §02-physical-link)
FREQ_US_CA_HZ: int = 903_900_000   # US/CA 915 MHz ISM band
FREQ_EU_HZ: int = 868_100_000      # EU 868 MHz band
FREQ_AU_NZ_HZ: int = 916_800_000   # AU/NZ 915 MHz ISM band

# Well-known port numbers
PORT_COAP: int = 5683
PORT_COAP_DTLS: int = 5684
PORT_MQTT_SN: int = 10883

# SCHC compression rule IDs (RFC 8724; spec appendix-schc.md)
SCHC_RULE_LINK_LOCAL_COAP: int = 0    # Link-local IPv6 + UDP + CoAP
SCHC_RULE_GLOBAL_COAP: int = 1        # Global IPv6 + UDP + CoAP
SCHC_RULE_ICMPV6_ECHO: int = 2        # ICMPv6 Echo Request/Reply
SCHC_RULE_RPL_DIO: int = 3            # RPL DIO over link-local ICMPv6
SCHC_RULE_RPL_DAO: int = 4            # RPL DAO with DODAGID over link-local ICMPv6
SCHC_RULE_UNCOMPRESSED: int = 255     # No compression; full headers follow

# Authenticated L2 inner-payload dispatch bytes
L2_DISPATCH_SCHC: int = 0x14
L2_DISPATCH_ROUTING: int = 0x15

# RPL configuration (spec/drafts/draft-lichen-rpl-lora-00.md, RFC 6550)
RPL_INSTANCE_ID: int = 0
RPL_MODE_OF_OPERATION: int = 1        # Non-Storing (MOP=1)
RPL_ICMPV6_TYPE: int = 155
RPL_MIN_HOP_RANK_INCREASE: int = 256
RPL_MAX_RANK_INCREASE: int = 2048
RPL_INFINITE_RANK: int = 0xFFFF
RPL_ROOT_RANK: int = RPL_MIN_HOP_RANK_INCREASE
RPL_DEFAULT_LIFETIME_S: int = 1800    # 30 minutes
RPL_LIFETIME_UNIT_S: int = 60

# RPL Trickle timer parameters (RFC 6206)
RPL_TRICKLE_IMIN_MS: int = 4000       # 4 seconds per spec (draft-lichen-rpl-lora-00.md)
RPL_TRICKLE_IMAX_DOUBLINGS: int = 8   # max = imin * 2^8 = 2^20 ms (~17 min)
RPL_TRICKLE_K: int = 10               # Redundancy constant

# LICHEN Announce message (spec §05-routing)
ANNOUNCE_TYPE: int = 0x01

SCHC_FRAGMENT_M: int = 1
SCHC_FRAGMENT_N: int = 6
SCHC_FRAGMENT_T: int = 0
SCHC_RCS_BYTES: int = 4
SCHC_RETRANSMISSION_TIMEOUT_S: int = 10
SCHC_MAX_ACK_REQUESTS: int = 3
SCHC_INACTIVITY_TIMEOUT_S: int = 60
