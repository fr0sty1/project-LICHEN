<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Acknowledgments

## In Memoriam

**Dave Täht** (1963–2023)

Dave dedicated years to understanding and fixing bufferbloat — the network
latency crisis caused by oversized buffers throughout the internet. His work
on fq_codel, CAKE, and the make-wifi-fast project transformed how we think
about queue management. He proved that "more buffer" is not the answer; that
latency matters as much as throughput; and that good queue discipline makes
networks feel fast even when they're slow.

LICHEN's queue management design draws directly from Dave's insights:
- Small, bounded queues with backpressure
- Time-based packet expiry over byte-based limits
- Fair queuing to prevent single-flow starvation
- "It's not about the bandwidth, it's about the latency"

His Bufferbloat.net project remains essential reading for anyone building
networked systems: https://www.bufferbloat.net/

Dave showed that one determined engineer with the right ideas can fix
problems that entire industries ignored for decades. We honor his memory
by not repeating the mistakes he spent his life correcting.

---

[Index](README.md)
