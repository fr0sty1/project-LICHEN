"""LICHEN protocol constants.

Canonical values shared across layers. The language-neutral source of truth
is ``constants.toml`` at the repository root; keep these in sync with it.
"""

# LoRa physical layer
LORA_SPREADING_FACTOR: int = 10
LORA_BANDWIDTH_HZ: int = 125_000
LORA_PREAMBLE_SYMBOLS: int = 8
LORA_SYNC_WORD: int = 0x34  # Distinct from Meshtastic (0x2B)

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

# RPL configuration (spec appendix-rpl.md, RFC 6550)
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
RPL_TRICKLE_IMIN_MS: int = 4096       # ~4 seconds
RPL_TRICKLE_IMAX_DOUBLINGS: int = 8   # max = imin * 2^8 = 2^20 ms (~17 min)
RPL_TRICKLE_K: int = 10               # Redundancy constant

# LICHEN Announce message (spec §05-routing)
ANNOUNCE_TYPE: int = 0x01
