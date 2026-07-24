<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Appendix F: SenML Sensor Profile

This appendix defines the standard SenML (RFC 8428) representation for common
sensor data in the mesh. Using SenML ensures interoperability and enables
generic data collection.

## F.1. Overview

All sensor data SHOULD be encoded as SenML over CoAP (see lichen-senml, rust/lichen-senml/src/):

- Content-Format: `application/senml+cbor` = 112 (lichen-coap/src/option.rs:33, constants.toml ports)
- Observable resources for streaming data
- Base name = `urn:dev:mac:<EUI-64>:` (from lichen link EUI-64)
- Timestamps relative to base time when possible (saves bytes, see lichen_core constants for time)

## F.2. Base Name Convention

```
urn:dev:mac:<EUI-64>:
```

Example: `urn:dev:mac:0011223344556677:`

This allows globally unique sensor identification across meshes.

## F.3. Location

Resource: `/sensors/location`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "lat", "u": "lat", "v": 37.774929},
  {"n": "lon", "u": "lon", "v": -122.419416},
  {"n": "alt", "u": "m", "v": 10.5},
  {"n": "hacc", "u": "m", "v": 5.0},
  {"n": "vacc", "u": "m", "v": 10.0},
  {"n": "speed", "u": "m/s", "v": 1.2},
  {"n": "heading", "u": "deg", "v": 45.0}
]
```

| Name | Unit | Description |
|------|------|-------------|
| lat | lat | Latitude (WGS84 degrees, + = N) |
| lon | lon | Longitude (WGS84 degrees, + = E) |
| alt | m | Altitude above sea level |
| hacc | m | Horizontal accuracy (CEP) |
| vacc | m | Vertical accuracy |
| speed | m/s | Ground speed |
| heading | deg | Heading (0 = N, 90 = E) |

Minimal location (lat/lon only): ~25 bytes CBOR.

## F.4. Battery

Resource: `/sensors/battery`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "pct", "u": "%", "v": 87},
  {"n": "mv", "u": "mV", "v": 3950},
  {"n": "charging", "vb": false}
]
```

| Name | Unit | Description |
|------|------|-------------|
| pct | % | State of charge (0-100) |
| mv | mV | Battery voltage |
| charging | (bool) | Currently charging |
| mah | mAh | Remaining capacity (optional) |

## F.5. Temperature

Resource: `/sensors/temp`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "temp", "u": "Cel", "v": 23.5}
]
```

| Name | Unit | Description |
|------|------|-------------|
| temp | Cel | Temperature in Celsius |

For Fahrenheit sources, convert to Celsius for wire format.

## F.6. Humidity

Resource: `/sensors/humidity`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "hum", "u": "%RH", "v": 65.2}
]
```

## F.7. Pressure

Resource: `/sensors/pressure`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "pressure", "u": "Pa", "v": 101325}
]
```

Use Pa (Pascals) as the base unit. 1 hPa = 100 Pa, 1 mbar = 100 Pa.

## F.8. Accelerometer / IMU

Resource: `/sensors/accel`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "ax", "u": "m/s2", "v": 0.05},
  {"n": "ay", "u": "m/s2", "v": -0.12},
  {"n": "az", "u": "m/s2", "v": 9.78}
]
```

Gyroscope (if present): `/sensors/gyro` with `gx`, `gy`, `gz` in `rad/s`.
Magnetometer: `/sensors/mag` with `mx`, `my`, `mz` in `T` (Tesla).

## F.9. Air Quality

Resource: `/sensors/air`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "co2", "u": "ppm", "v": 412},
  {"n": "pm25", "u": "ug/m3", "v": 12.5},
  {"n": "pm10", "u": "ug/m3", "v": 18.0},
  {"n": "voc", "u": "ppb", "v": 150}
]
```

| Name | Unit | Description |
|------|------|-------------|
| co2 | ppm | CO2 concentration |
| pm25 | ug/m3 | PM2.5 particulates |
| pm10 | ug/m3 | PM10 particulates |
| voc | ppb | Volatile organic compounds |
| aqi | (none) | Air quality index (0-500) |

## F.10. Radio Telemetry

Resource: `/sensors/radio`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "rssi", "u": "dBm", "v": -85},
  {"n": "snr", "u": "dB", "v": 7.5},
  {"n": "txpwr", "u": "dBm", "v": 20},
  {"n": "sf", "v": 9},
  {"n": "freq", "u": "MHz", "v": 906.875},
  {"n": "duty", "u": "%", "v": 2.3}
]
```

## F.11. Composite Sensor Pack

For devices with multiple sensors, a single resource MAY return all readings:

Resource: `/sensors`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "lat", "u": "lat", "v": 37.774929},
  {"n": "lon", "u": "lon", "v": -122.419416},
  {"n": "temp", "u": "Cel", "v": 23.5},
   {"n": "hum", "u": "%RH", "v": 65.2},
   {"n": "batt/pct", "u": "%", "v": 87}
]

```

Use hierarchical names (e.g., `batt/pct`) for namespacing.

## F.12. Timestamps

**Base time (bt):** Absolute Unix timestamp (seconds since 1970-01-01T00:00:00Z)
from the firmware time provider. Senders SHOULD include `bt` only when the time
provider reports `wall_clock_valid=true`. See `docs/firmware-time-provider.md`
for epoch floor validation and source class precedence.

**Relative time (t):** Offset from base time in seconds.

```cbor
[
  {"bn": "...", "bt": 1716742800},
  {"n": "temp", "u": "Cel", "v": 23.5, "t": 0},
  {"n": "temp", "u": "Cel", "v": 23.6, "t": 60},
  {"n": "temp", "u": "Cel", "v": 23.4, "t": 120}
]
```

This efficiently encodes time series (3 readings, shared base time).

## F.13. CoAP Integration

**Discovery:**

```
GET /.well-known/core?rt=senml

</sensors/location>;rt="senml";if="sensor";obs,
</sensors/battery>;rt="senml";if="sensor";obs,
</sensors/temp>;rt="senml";if="sensor";obs
```

**Observe for streaming:**

```
GET /sensors/location
Observe: 0

<-- 2.05 Content (initial)
<-- 2.05 Content (notification on move)
<-- 2.05 Content (notification on move)
```

**Batch retrieval:**

```
GET /sensors
Accept: application/senml+cbor

<-- 2.05 Content (all sensor readings)
```

## F.14. SCHC Compression for SenML

Common SenML fields compress well with SCHC:

| Field | Compression |
|-------|-------------|
| bn (base name) | Elide if same as L2 source |
| bt (base time) | Delta from previous |
| n (name) | Dictionary encoding |
| u (unit) | Dictionary encoding |
| v (value) | Value-sent |

A dedicated SCHC rule for SenML payloads can reduce typical sensor reports
from ~50 bytes to ~15-20 bytes.

## F.15. Resource Directory Registration

Nodes SHOULD register SenML resources with the Resource Directory:

```
POST coap://[6lbr]/rd?ep=node-0011223344556677&lt=86400
Content-Format: application/link-format

</sensors/location>;rt="senml";if="sensor";geo="*",
</sensors/temp>;rt="senml";if="sensor",
</sensors/battery>;rt="senml";if="sensor",
</metrics>;rt="senml";if="sensor";obs
```

The `geo="*"` attribute indicates location-providing resources.

## F.16. Metrics Telemetry + Battery Profile

Resource: `/metrics`

Combines network telemetry (RSSI, node count, packet rate, collision rate) and battery status in one SenML pack. Useful for dashboard and monitoring.

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "rssi", "u": "dBm", "v": -85},
  {"n": "nodecount", "v": 12},
  {"n": "pps", "u": "1/s", "v": 2.3},
   {"n": "battery", "u": "%", "v": 75},
   {"n": "collision-rate", "u": "%", "v": 0.1}
]
```

Independent test vector (CBOR hex, 72 bytes with bn):

`83a121781d75726e3a6465763a6d61633a303031313232333334343535363637373aa3006472737369016364426d023854a300676261747465727901612502fb4052c00000000000`

(Computed independently using cbor2; matches `pack([SenmlRecord(bn=...), *metrics(...)])`).

| Name | Unit | Description |
|------|------|-------------|
| rssi | dBm | Received signal strength |
| nodecount | - | Number of mesh nodes seen |
| pps | 1/s | Packets per second |
| battery | % | Battery state of charge |
| collision-rate | % | Packet collision rate |


Use with CoAP Observe for live telemetry streaming. SCHC compresses well.

---

*This document is a design sketch, not a finalized specification. Implementation
will require detailed engineering of timing, buffer management, and edge cases
not covered here.*

---

[← Previous: Appendix C-E](appendix-misc.md) | [Index](README.md)
