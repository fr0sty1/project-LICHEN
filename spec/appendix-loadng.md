<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Appendix B2: LOADng Configuration

LOADng is used for mesh-internal peer-to-peer traffic only when recent
authenticated evidence indicates that the destination is local. It MUST NOT
probe an arbitrary `0200::/8` destination. See Section 9 for details.
For border router traffic, see Appendix B (RPL).

## B2.1. Protocol Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| RREQ_WAIT_TIME | 5000 ms | Wait for RREP before retry |
| RREQ_RETRIES | 3 | Maximum RREQ attempts |
| RREQ_RATELIMIT | 10/min | Max RREQs originated per minute |
| MAX_HOP_LIMIT | 15 | Maximum RREQ flood scope |
| INITIAL_HOP_LIMIT | 4 | Expanding ring start |

## B2.2. Route Cache Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| ROUTE_CACHE_SIZE | 32 | Maximum cached routes |
| ROUTE_TIMEOUT | 300 sec | Route validity (no traffic) |
| ROUTE_REFRESH | 60 sec | Refresh if used within |
| SEQNUM_LIFETIME | 600 sec | Sequence number validity |

## B2.3. Metric

LOADng uses **hop count** as the default metric.

Optional: ETX-weighted metric for quality-aware routing:

```
Metric = sum(ETX(link)) * 100
```

Lower metric preferred. Maximum metric value: 65535.

## B2.4. ICMPv6 Allocation

LOADng messages use ICMPv6 type 158 (experimental range):

| Code | Message |
|------|---------|
| 0 | RREQ (Route Request) |
| 1 | RREP (Route Reply) |
| 2 | RERR (Route Error) |
| 3 | RACK (Route Acknowledgment) |

## B2.5. Expanding Ring Search

After the local-evidence gate passes, minimize flood scope for nearby destinations:

| Attempt | Hop Limit |
|---------|-----------|
| 1 | 4 |
| 2 | 8 |
| 3 | 15 (MAX_HOP_LIMIT) |

Each attempt waits RREQ_WAIT_TIME before expanding.

## B2.6. RREQ Suppression

Nodes track recently-seen RREQs to suppress duplicates:

```
RREQ_ID = hash(originator || destination || seq_num)
```

Suppress if RREQ_ID seen within last 10 seconds.

## B2.7. Interaction with Broadcast Rate Limiting

RREQ flooding is subject to the same broadcast rate limits as other
mesh-wide traffic (see Section 6.3.3). This prevents RREQ storms from
consuming the network.

The RREQ_RATELIMIT parameter (10/min) is an additional per-node limit
on originated RREQs to prevent aggressive discovery.

---

[← Previous: Appendix B](appendix-rpl.md) | [Index](README.md) | [Next: Appendix C →](appendix-misc.md)
