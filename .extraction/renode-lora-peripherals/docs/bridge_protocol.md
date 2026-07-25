# Bridge Protocol Specification

Binary protocol for connecting Renode LoRa peripherals to an external RF simulator.

## Transport

- TCP connection
- Little-endian byte order
- Length-prefixed messages: 4-byte LE length, then payload

## Message Format

```
+----------------+------------------+
| Length (4B LE) | Payload          |
+----------------+------------------+
```

The length field contains the size of the payload only (not including the 4-byte length itself).

## Message Types

### TX (0x10) - Transmit Request

Peripheral -> Simulator

Request to transmit a packet.

```
+------+------------+---------+
| 0x10 | len (2B)   | data    |
+------+------------+---------+
```

- `len`: Payload length (uint16, LE)
- `data`: Payload bytes

### TX_DONE (0x11) - Transmit Complete

Simulator -> Peripheral

Indicates transmission completed successfully.

```
+------+-----------------+
| 0x11 | airtime_us (4B) |
+------+-----------------+
```

- `airtime_us`: Transmission airtime in microseconds (uint32, LE)

### TX_FAIL (0x12) - Transmit Failed

Simulator -> Peripheral

Indicates transmission failed.

```
+------+
| 0x12 |
+------+
```

### RX_ENTER (0x24) - Enter Receive Mode

Peripheral -> Simulator

Indicates the radio has entered receive mode with a timeout.

```
+------+-----------------+
| 0x24 | timeout_us (4B) |
+------+-----------------+
```

- `timeout_us`: RX timeout in microseconds (uint32, LE). 0xFFFFFFFF = continuous RX.

### RX_EXIT (0x26) - Exit Receive Mode

Peripheral -> Simulator

Indicates the radio has exited receive mode (e.g., SetStandby called).

```
+------+
| 0x26 |
+------+
```

### RX_PACKET (0x27) - Packet Received

Simulator -> Peripheral (unsolicited)

Pushed by simulator when a packet arrives for this node.

```
+------+------------+---------+------------+----------+
| 0x27 | len (2B)   | data    | rssi (2B)  | snr (2B) |
+------+------------+---------+------------+----------+
```

- `len`: Payload length (uint16, LE)
- `data`: Payload bytes
- `rssi`: RSSI in dBm (int16, LE)
- `snr`: SNR in dB * 10 (int16, LE). E.g., -55 = -5.5 dB.

### RX_TIMEOUT (0x28) - Receive Timeout

Simulator -> Peripheral (unsolicited)

Pushed by simulator when RX timeout expires without receiving a packet.

```
+------+
| 0x28 |
+------+
```

## Sequence Diagrams

### Successful TX

```
Peripheral                    Simulator
    |                             |
    |-- TX (payload) ------------>|
    |                             | (simulate propagation)
    |<-------- TX_DONE (airtime) -|
    |                             |
```

### RX with Packet

```
Peripheral                    Simulator
    |                             |
    |-- RX_ENTER (timeout) ------>|
    |                             | (wait for packet)
    |<-------- RX_PACKET ---------|
    |                             |
```

### RX Timeout

```
Peripheral                    Simulator
    |                             |
    |-- RX_ENTER (timeout) ------>|
    |                             | (timeout expires)
    |<-------- RX_TIMEOUT --------|
    |                             |
```

### RX Cancelled

```
Peripheral                    Simulator
    |                             |
    |-- RX_ENTER (timeout) ------>|
    |                             |
    |-- RX_EXIT ----------------->| (firmware calls SetStandby)
    |                             |
```

## Implementation Notes

1. The simulator must track which nodes are in RX mode and deliver packets only to listening nodes.

2. The airtime in TX_DONE should reflect realistic LoRa transmission times based on the payload size and configured modulation parameters.

3. RSSI and SNR values should be computed based on the RF propagation model (distance, path loss, etc.).

4. The peripheral does NOT block on RX_ENTER. RX_PACKET and RX_TIMEOUT are pushed asynchronously via a background reader thread. The SPI Transmit() path never blocks on socket I/O, so the firmware can leave RX mode (via SetTx or SetStandby) without deadlocking.
