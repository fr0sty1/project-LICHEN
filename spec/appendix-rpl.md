<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Appendix: RPL Configuration

The canonical normative specification is `spec/drafts/draft-lichen-rpl-lora-00.md`
(RPL Non-Storing Mode, MRHOF with LoRa adaptations, Trickle parameters,
DAO Origin Signature Option with Schnorr48, CCP-16 extensions).

**Implementation notes (non-normative):**
- All constants from `constants.toml` `[rpl]` (lines 44-55) and `[rpl.trickle]` (lines 57-61: Imin=4000 ms, Imax=8 doublings, k=10).
- Rust: `rust/lichen-rpl/` (`no_std` core crate; full DAO origin signature,
  replay floor, test vectors in `dao_origin_vectors.rs`, `rpl_route_state_vectors.rs`).
- C/Zephyr: `lichen/subsys/lichen/rpl/` (`lichen_rpl_dodag_init()`, `rpl_dodag.h`,
  matching the Rust behavior for interop).
- All changes validated against `test/vectors/` oracles.

See the draft for wire formats, verification order, source routing, and security model.

[← Previous: Appendix A](appendix-schc.md) | [Index](README.md) | [Next: Appendix B2 →](appendix-loadng.md)

