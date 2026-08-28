<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Appendix K: BLE GATT to IPSO/SenML Mapping

This appendix defines a mapping from Bluetooth SIG GATT Services and
Characteristics to OMA IPSO Smart Object IDs for gateway translation.
Enables BLE peripherals (health trackers, environmental sensors, fitness
devices) to relay data over LICHEN mesh as SenML or IPSO Direct payloads.

## K.1. Overview

```
BLE Peripheral          Gateway (nRF52/ESP32)              LICHEN Mesh
     |                         |                               |
     |-- GATT Notify --------->|                               |
     |   (Characteristic UUID) |                               |
     |                         |-- Lookup IPSO Object -------->|
     |                         |-- Pack as SenML/IPSO Direct ->|
     |                         |-- Transmit over LoRa -------->|
```

**References:**

- Bluetooth Assigned Numbers: https://www.bluetooth.com/specifications/assigned-numbers/
- OMA LwM2M Registry: https://technical.openmobilealliance.org/OMNA/LwM2M/LwM2MRegistry.html
- IEEE 11073-10101: Nomenclature codes (shared heritage)

## K.2. Service-Level Mapping

GATT Services map to IPSO Object classes. A device exposing a GATT Service
SHOULD be represented as one or more IPSO Object instances.

| GATT Service | UUID | IPSO Object | ID | Notes |
|--------------|------|-------------|-----|-------|
| Environmental Sensing | 0x181A | (multiple) | — | Container; map per-characteristic |
| Heart Rate | 0x180D | Rate | 3346 | bpm as SenML `{n: "hr", u: "/min"}` |
| Health Thermometer | 0x1809 | Temperature | 3303 | Body temp in Cel |
| Weight Scale | 0x181D | Load | 3322 | Mass in kg |
| Blood Pressure | 0x1810 | Pressure | 3323 | mmHg; convert to Pa (x133.322) |
| Glucose | 0x1808 | Concentration | 3325 | mg/dL or mmol/L |
| Body Composition | 0x181B | (extension) | 26250 | Body fat %, muscle mass |
| Running Speed & Cadence | 0x1814 | (multiple) | — | Speed: 3346; Cadence: 3346 |
| Cycling Speed & Cadence | 0x1816 | (multiple) | — | Speed: 3346; Cadence: 3346 |
| Cycling Power | 0x1818 | Power | 3328 | Watts |
| Location & Navigation | 0x1819 | Location | 3336 | Lat/lon/alt |
| Indoor Positioning | 0x1821 | Positioner | 3337 | Floor, zone |
| Battery Service | 0x180F | (extension) | 26251 | SoC %, voltage |
| Automation IO | 0x1815 | Digital Input | 3200 | Binary sensors/actuators |
| User Data | 0x181C | (extension) | 26252 | Height, weight, age |
| Device Information | 0x180A | Device | 3 | LwM2M Device object |
| Current Time | 0x1805 | — | — | Protocol-level, not sensor data |

## K.3. Characteristic-Level Mapping

### K.3.1. Environmental Sensing (0x181A)

| Characteristic | UUID | IPSO Object | ID | Resource | SenML Unit |
|----------------|------|-------------|-----|----------|------------|
| Temperature | 0x2A6E | Temperature | 3303 | 5700 | Cel |
| Humidity | 0x2A6F | Humidity | 3304 | 5700 | %RH |
| Pressure | 0x2A6D | Barometer | 3315 | 5700 | Pa |
| True Wind Speed | 0x2A70 | (extension) | 26253 | 5700 | m/s |
| True Wind Direction | 0x2A71 | (extension) | 26253 | 5701 | deg |
| Apparent Wind Speed | 0x2A72 | (extension) | 26253 | 5702 | m/s |
| Apparent Wind Direction | 0x2A73 | (extension) | 26253 | 5703 | deg |
| Gust Factor | 0x2A74 | (extension) | 26253 | 5704 | 1 |
| Pollen Concentration | 0x2A75 | Concentration | 3325 | 5700 | /m3 |
| UV Index | 0x2A76 | (extension) | 26254 | 5700 | 1 |
| Irradiance | 0x2A77 | Illuminance | 3301 | 5700 | W/m2 |
| Rainfall | 0x2A78 | (extension) | 26255 | 5700 | mm |
| Magnetic Declination | 0x2A2C | (extension) | 26256 | 5700 | deg |
| Magnetic Flux Density 2D | 0x2AA0 | Magnetometer | 3314 | 5702/5703 | T |
| Magnetic Flux Density 3D | 0x2AA1 | Magnetometer | 3314 | 5702-5704 | T |
| Elevation | 0x2A6C | Altitude | 3338 | 5700 | m |
| Dew Point | 0x2A7B | Temperature | 3303 | 5701 | Cel |
| Heat Index | 0x2A7A | Temperature | 3303 | 5702 | Cel |
| Wind Chill | 0x2A79 | Temperature | 3303 | 5703 | Cel |

### K.3.2. Motion & Activity

| Characteristic | UUID | IPSO Object | ID | Resource | SenML Unit |
|----------------|------|-------------|-----|----------|------------|
| Acceleration (aggregate) | 0x2713 | Accelerometer | 3313 | 5702-5704 | m/s2 |
| Gyroscope (aggregate) | — | Gyrometer | 3334 | 5702-5704 | rad/s |
| Step Counter | 0x2ACF | (extension) | 26257 | 5700 | count |
| Cadence (RSC) | 0x2A53 | Rate | 3346 | 5700 | /min |
| Speed (RSC) | 0x2A53 | Rate | 3346 | 5701 | m/s |
| Stride Length | 0x2A53 | Distance | 3330 | 5700 | m |
| Cadence (CSC) | 0x2A5B | Rate | 3346 | 5700 | /min |
| Wheel Revolutions | 0x2A5B | Counter | 3340 | 5700 | count |

### K.3.3. Health & Medical

| Characteristic | UUID | IPSO Object | ID | Resource | SenML Unit |
|----------------|------|-------------|-----|----------|------------|
| Heart Rate Measurement | 0x2A37 | Rate | 3346 | 5700 | /min |
| Body Sensor Location | 0x2A38 | — | — | — | enum (metadata) |
| Temperature Measurement | 0x2A1C | Temperature | 3303 | 5700 | Cel |
| Intermediate Temperature | 0x2A1E | Temperature | 3303 | 5700 | Cel |
| Weight Measurement | 0x2A9D | Load | 3322 | 5700 | kg |
| Body Fat Percentage | 0x2A9B | (extension) | 26250 | 5700 | % |
| Body Mass Index | 0x2A9C | (extension) | 26250 | 5701 | kg/m2 |
| Blood Pressure Measurement | 0x2A35 | Pressure | 3323 | 5700/5701 | Pa |
| Glucose Measurement | 0x2A18 | Concentration | 3325 | 5700 | kg/L |
| SpO2 (Pulse Oximetry) | 0x2A5F | Concentration | 3325 | 5701 | % |
| VO2 Max | 0x2A96 | (extension) | 26258 | 5700 | mL/kg/min |
| Resting Heart Rate | 0x2A92 | Rate | 3346 | 5701 | /min |
| Aerobic Threshold (HR) | 0x2A7F | Rate | 3346 | 5702 | /min |
| Anaerobic Threshold (HR) | 0x2A83 | Rate | 3346 | 5703 | /min |

### K.3.4. Location & Navigation

| Characteristic | UUID | IPSO Object | ID | Resource | SenML Unit |
|----------------|------|-------------|-----|----------|------------|
| Location & Speed | 0x2A67 | Location | 3336 | 6051-6053 | lat/lon/m |
| Latitude | 0x2AAE | Location | 3336 | 6051 | lat |
| Longitude | 0x2AAF | Location | 3336 | 6052 | lon |
| Altitude | 0x2AB3 | Location | 3336 | 6053 | m |
| Floor Number | 0x2AB2 | Positioner | 3337 | 5700 | 1 |
| Position Quality | 0x2A69 | Location | 3336 | 6054 | m |
| Heading | 0x2A68 | Compass | 3320 | 5700 | deg |
| Speed | 0x2A67 | (in location) | 3336 | 5700 | m/s |

### K.3.5. Lighting & Color

| Characteristic | UUID | IPSO Object | ID | Resource | SenML Unit |
|----------------|------|-------------|-----|----------|------------|
| Illuminance | 0x2AFB | Illuminance | 3301 | 5700 | lux |
| Chromaticity Coordinates | 0x2AE4 | Color | 3335 | 5701/5702 | 1 |
| Color Temperature | 0x2AE5 | Light Control | 3311 | 5706 | K |
| Luminous Intensity | 0x2AFF | Light Control | 3311 | 5700 | cd |
| Luminous Flux | 0x2AFE | Light Control | 3311 | 5701 | lm |
| Luminous Energy | 0x2AFD | Energy | 3331 | 5700 | lm*s |
| Luminous Exposure | 0x2AFC | (extension) | 26259 | 5700 | lx*s |
| Correlated Color Temperature | 0x2AE5 | Light Control | 3311 | 5706 | K |
| CIE xy Coordinates | 0x2AE3 | Color | 3335 | 5701/5702 | 1 |

### K.3.6. Power & Battery

| Characteristic | UUID | IPSO Object | ID | Resource | SenML Unit |
|----------------|------|-------------|-----|----------|------------|
| Battery Level | 0x2A19 | (extension) | 26251 | 5700 | % |
| Battery Power State | 0x2A1A | (extension) | 26251 | 5701 | enum |
| Battery Energy Status | 0x2BF0 | Energy | 3331 | 5700 | Wh |
| Voltage | 0x2B18 | Voltage | 3316 | 5700 | V |
| Current | 0x2AEE | Current | 3317 | 5700 | A |
| Power | 0x2B05 | Power | 3328 | 5700 | W |
| Energy | 0x2B06 | Energy | 3331 | 5700 | Wh |

### K.3.7. Automation & Digital IO

| Characteristic | UUID | IPSO Object | ID | Resource | SenML Unit |
|----------------|------|-------------|-----|----------|------------|
| Digital (Input/Output) | 0x2A56 | Digital Input | 3200 | 5500 | bool |
| Analog (Input/Output) | 0x2A58/59 | Analog Input | 3202 | 5600 | 1 |
| Aggregate Input | 0x2A5A | Digital Input | 3200 | 5500 | bitmap |

## K.4. Extension Objects

IPSO object IDs 26250-26299 are reserved for LICHEN BLE extensions not
covered by the OMA registry. These are LICHEN-specific; interop with other
LwM2M systems requires explicit mapping.

| ID | Name | Resources | Description |
|----|------|-----------|-------------|
| 26250 | Body Composition | 5700: fat%, 5701: BMI, 5702: muscle% | From BLE Body Composition |
| 26251 | Battery | 5700: SoC%, 5701: state, 5702: mV | From BLE Battery Service |
| 26252 | User Profile | 5700: height, 5701: weight, 5702: age | From BLE User Data |
| 26253 | Wind | 5700: speed, 5701: dir, 5702-5704: apparent | Environmental Sensing |
| 26254 | UV Index | 5700: index (0-11+) | Environmental Sensing |
| 26255 | Rainfall | 5700: mm | Environmental Sensing |
| 26256 | Magnetic Declination | 5700: deg | Environmental Sensing |
| 26257 | Step Counter | 5700: count, 5701: distance | Activity tracking |
| 26258 | VO2 Max | 5700: mL/kg/min | Fitness metric |
| 26259 | Luminous Exposure | 5700: lx*s | Lighting |

## K.5. Unit Conversions

Some GATT characteristics use non-SI units. Gateways MUST convert to SenML
canonical units before transmission.

| GATT Unit | SenML Unit | Conversion |
|-----------|------------|------------|
| mmHg (blood pressure) | Pa | x 133.322 |
| Fahrenheit | Cel | (F - 32) x 5/9 |
| mg/dL (glucose) | kg/L | x 1e-5 |
| lbs (weight) | kg | x 0.453592 |
| feet (altitude) | m | x 0.3048 |
| mph | m/s | x 0.44704 |
| rpm | /min | (same) |
| bpm | /min | (same) |
| centidegrees | deg | / 100 |
| 1/1024 degrees | deg | / 1024 |

## K.6. SenML Encoding Example

A heart rate monitor advertising Heart Rate Service (0x180D):

**GATT Notification:**
```
Characteristic: 0x2A37 (Heart Rate Measurement)
Flags: 0x00 (UINT8 value, no RR-interval)
Value: 72
```

**SenML Pack:**
```cbor
[
  {"bn": "urn:dev:mac:001122334455:", "bt": 1719100000},
  {"n": "3346/0/5700", "u": "/min", "v": 72}
]
```

**IPSO Direct Alternative:**
```
PUT /3346/0/5700
Content-Format: 60
Payload: 18 48   (CBOR: 72)
```

## K.7. Multi-Characteristic Devices

A weather station with Environmental Sensing Service (0x181A) exposing
temperature, humidity, and pressure:

**SenML Pack (preferred for batch):**
```cbor
[
  {"bn": "urn:dev:mac:aabbccddeeff:", "bt": 1719100000},
  {"n": "3303/0/5700", "u": "Cel", "v": 23.5},
  {"n": "3304/0/5700", "u": "%RH", "v": 65.2},
  {"n": "3315/0/5700", "u": "Pa", "v": 101325}
]
```

Single transmission over LoRa vs three separate GATT notifications.

## K.8. Characteristics Not Mapped

The following GATT characteristics are protocol-level and do not map to
IPSO sensor/actuator objects:

| Characteristic | UUID | Reason |
|----------------|------|--------|
| Device Name | 0x2A00 | Identity, not telemetry |
| Appearance | 0x2A01 | Device class, not telemetry |
| Peripheral Preferred Connection Parameters | 0x2A04 | BLE protocol |
| Service Changed | 0x2A05 | GATT protocol |
| Alert Level | 0x2A06 | Control, not measurement |
| Client Characteristic Configuration | 0x2902 | GATT descriptor |
| Server Characteristic Configuration | 0x2903 | GATT descriptor |
| Valid Range | 0x2906 | Metadata |
| External Report Reference | 0x2907 | HID protocol |
| Report Reference | 0x2908 | HID protocol |

Device metadata (manufacturer, model, serial, firmware version) maps to
LwM2M Device Object (ID 3), not IPSO sensor objects.

## K.9. Implementation Notes

1. **Instance Numbering:** When a BLE device exposes multiple instances of
   the same characteristic (e.g., two temperature sensors), assign
   sequential IPSO instance IDs (3303/0, 3303/1).

2. **Timestamps:** GATT notifications lack timestamps. Gateway MUST add
   `bt` (base time) at reception. If BLE device advertises Current Time
   Service (0x1805), prefer device time.

3. **Aggregation:** For high-frequency sensors (accelerometer, gyro),
   gateway MAY aggregate multiple GATT notifications into one SenML pack
   with relative timestamps (`t` field).

4. **Sleep Coordination:** BLE peripherals often sleep between connections.
   Gateway SHOULD cache last-known values and include staleness indicator
   in SenML (`ut` field for update time).

5. **Discovery:** Gateway advertises relayed BLE devices in CoRE Link Format
   with `anchor` pointing to BLE MAC:

   ```
   GET /.well-known/core?rt=ipso
   
   </3303/0>;rt="ipso";anchor="ble:aabbccddeeff"
   ```

---

*This mapping is informational. OMA and Bluetooth SIG may update their
registries independently. When in doubt, consult primary sources.*

---

[← Previous: Appendix F (SenML)](appendix-senml.md) | [Index](README.md)
