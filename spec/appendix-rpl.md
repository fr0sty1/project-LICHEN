<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Appendix B: RPL Configuration

RPL is used for border router traffic only. See Section 8 for details.
For peer-to-peer traffic, see Appendix B2 (LOADng).

## B.1. Constants (from constants.toml [rpl], lichen-core::constants, lichen/rpl)

| Parameter | Value | Source |
|-----------|-------|--------|
| RPL_INSTANCE_ID | 0 | constants.toml:46 |
| MODE_OF_OPERATION | 1 (Non-Storing) | constants.toml:47, RFC 6550 MOP=1 |
| ICMPV6_TYPE | 155 | constants.toml:48 |
| MIN_HOP_RANK_INCREASE | 256 | constants.toml:49 |
| ROOT_RANK | 256 | constants.toml:52 |
| INFINITE_RANK | 0xFFFF | constants.toml:51 |
| DEFAULT_LIFETIME_S | 1800 (30min) | constants.toml:53 |
| LIFETIME_UNIT_S | 60 | constants.toml:54 |
| MAX_RANK_INCREASE | 2048 | constants.toml:50 |

Trickle: Imin=4096ms, Imax_doublings=8 (~17min), k=10 per constants.toml:56-60, lichen_rpl_dodag_init() and Trickle timer impl in lichen/subsys/lichen/rpl/.

See lichen/subsys/lichen/rpl_dodag.h: lichen_rpl_dodag_init(), rust/rpl/ for current impl.

## B.2. Objective Function

MRHOF per RFC 6719 tuned for LoRa ETX.

---


[← Previous: Appendix A](appendix-schc.md) | [Index](README.md) | [Next: Appendix B2 →](appendix-loadng.md)
