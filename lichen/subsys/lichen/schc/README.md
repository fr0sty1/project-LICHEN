<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# LICHEN SCHC Profile

The generic SCHC module lives in `lichen/subsys/schc` and provides rule-table
dispatch, uncompressed fallback handling, reusable MSB-first bitstream helpers
for SCHC residues, and the public fragmentation API surface. It does not know
the LICHEN IPv6, UDP, CoAP, ICMPv6, or RPL packet profiles.

This directory installs the LICHEN profile:

- `CONFIG_LICHEN_SCHC` selects `CONFIG_SCHC`.
- `schc.c` defines the static `lichen_schc_rules` table with wire rule IDs
  from `constants.toml` and `test/vectors/schc_compression.json`.
- `lichen_schc_compress()` preserves LICHEN's packet validation and then calls
  the generic `schc_compress()` dispatcher.
- `lichen_schc_decompress()` calls the generic `schc_decompress()` dispatcher.

The existing `lichen/schc.h` API remains the LICHEN-facing compatibility layer.
Other Zephyr applications can enable `CONFIG_SCHC` and include `schc/schc.h`
without enabling `CONFIG_LICHEN`.
