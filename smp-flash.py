#!/usr/bin/env python3
"""
Minimal SMP client — image upload + reset over any pyserial-compatible port.
Extended for T-Echo procurement/flashing/resale pipeline: supports --provision-seed
for automated link/OSCORE key load + test vector run post-flash. Quotes/P&L
handled in companion flash-t_echo.sh (target <$8/unit, 74% margin at $49 resale).

Supports RFC2217 URLs directly (no PTY bridge needed):
  ./smp-flash.py rfc2217://localhost:4005 firmware.signed.bin
  ./smp-flash.py /dev/ttyACM1            firmware.signed.bin
  ./smp-flash.py /dev/ttyACM1 firmware.signed.bin --provision-seed=0x...

IMPORTANT: sign the OTA payload with `imgtool sign ... --pad --confirm`.
This client does not implement the SMP "image test/confirm" command, so the
swap trailer must ship inside the image; without --pad --confirm MCUboot
ignores the uploaded slot1 image and never swaps. (--pad grows the file to
the full slot size — the upload is bigger but carries its own trailer.)
Verified working T1000-E 2026-07-02: 364 KB upload, ~19 s MCUboot copy on
the post-reset boot, new image boots with SMP alive.
"""

import argparse
import base64
import hashlib
import os
import struct
import sys
import time

# cbor2 may live in the user site
sys.path.insert(0, "/home/frosty/.local/lib/python3.10/site-packages")
import cbor2
import serial

# ── SMP constants ────────────────────────────────────────────────────────────

SMP_SOF       = bytes([0x06, 0x09])   # first frame of a packet
SMP_SOF_CONT  = bytes([0x04, 0x14])   # continuation frame
SMP_OP_READ   = 0
SMP_OP_WRITE  = 2

SMP_GRP_OS    = 0
SMP_OS_ECHO   = 0
SMP_OS_RESET  = 5

SMP_GRP_IMG   = 1
SMP_IMG_UPLOAD = 1

CHUNK_SIZE    = 256   # image bytes per SMP upload request
BAUD          = 115200
TIMEOUT_S     = 10.0  # per-chunk response timeout

# mcumgr serial framing: a frame (SOF + base64 body) may not exceed 127 bytes
# (MCUMGR_SERIAL_MAX_FRAME on the device; oversized lines are silently
# dropped by uart_mcumgr.c). 127 - 2 SOF - \n leaves 124 base64 chars =
# 93 raw bytes per frame. Packets larger than that are split across a
# 0x0609 first frame and 0x0414 continuation frames.
FRAME_RAW_MAX = ((127 - 3) // 4) * 3  # 93
# Device has only CONFIG_UART_MCUMGR_RX_BUF_COUNT=2 line buffers; pace
# frames so the workqueue can drain them.
INTER_FRAME_DELAY_S = 0.005

# ── Serial framing (mcumgr UART protocol) ────────────────────────────────────

def _crc16(data: bytes) -> int:
    """CRC-CCITT, poly=0x1021, init=0x0000."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if (crc & 0x8000) else (crc << 1)
        crc &= 0xFFFF
    return crc

def _encode_frames(op: int, group: int, seq: int, cmd_id: int, payload: bytes) -> list:
    """Build the mcumgr serial frames for one SMP packet.

    Packet = pkt_len(2, BE) | SMP_hdr(8) | payload | crc16(2, BE), split into
    93-raw-byte fragments, each independently base64-encoded:
      frame[0] = 0x0609 + b64(frag) + \n
      frame[n] = 0x0414 + b64(frag) + \n
    """
    smp_hdr = struct.pack(">BBHHBB", op, 0, len(payload), group, seq & 0xFF, cmd_id)
    raw = smp_hdr + payload
    crc = _crc16(raw)
    pkt_len = len(raw) + 2  # includes CRC
    inner = struct.pack(">H", pkt_len) + raw + struct.pack(">H", crc)

    frames = []
    for off in range(0, len(inner), FRAME_RAW_MAX):
        sof = SMP_SOF if off == 0 else SMP_SOF_CONT
        frames.append(sof + base64.b64encode(inner[off: off + FRAME_RAW_MAX]) + b'\n')
    return frames

def _send_packet(ser: serial.Serial, op: int, group: int, seq: int,
                 cmd_id: int, payload: bytes) -> None:
    for i, f in enumerate(_encode_frames(op, group, seq, cmd_id, payload)):
        if i:
            time.sleep(INTER_FRAME_DELAY_S)
        ser.write(f)

def _read_line(ser: serial.Serial, deadline: float) -> bytes:
    """Read one \n-terminated serial line (without the terminator)."""
    buf = bytearray()
    while time.monotonic() < deadline:
        b = ser.read(1)
        if not b:
            continue
        if b == b'\n':
            return bytes(buf)
        buf += b
    raise TimeoutError("Timeout waiting for SMP response")

def _read_frame(ser: serial.Serial) -> bytes:
    """Block until one complete SMP packet is received (reassembling
    continuation frames); return raw SMP bytes (hdr+payload)."""
    deadline = time.monotonic() + TIMEOUT_S

    line = _read_line(ser, deadline)
    if len(line) < 2 or line[:2] != SMP_SOF:
        raise ValueError(f"Bad SOF: {line[:2].hex() if len(line) >= 2 else 'short'}")

    try:
        decoded = base64.b64decode(line[2:])
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")

    if len(decoded) < 4:
        raise ValueError(f"Decoded frame too short: {len(decoded)} bytes")

    # First 2 bytes = pkt_len (SMP data + CRC); rest = SMP data + CRC
    pkt_len = struct.unpack(">H", decoded[:2])[0]
    smp_and_crc = bytearray(decoded[2:])

    while len(smp_and_crc) < pkt_len:
        line = _read_line(ser, deadline)
        if len(line) < 2 or line[:2] != SMP_SOF_CONT:
            raise ValueError(f"Bad continuation SOF: {line[:2].hex()}")
        smp_and_crc += base64.b64decode(line[2:])

    if len(smp_and_crc) != pkt_len:
        raise ValueError(f"Length mismatch: got {len(smp_and_crc)}, want {pkt_len}")

    # Verify CRC: crc16(SMP_data || CRC) must be 0 (self-verifying)
    if _crc16(smp_and_crc) != 0:
        raise ValueError("CRC verify failed")

    # Return SMP header + payload (strip trailing 2-byte CRC)
    return bytes(smp_and_crc[:-2])

def _parse_response(raw: bytes) -> dict:
    # 8-byte SMP header, then CBOR payload
    if len(raw) < 8:
        raise ValueError(f"Response too short: {len(raw)} bytes")
    payload = raw[8:]
    return cbor2.loads(payload) if payload else {}

# ── High-level operations ────────────────────────────────────────────────────

def upload_image(ser: serial.Serial, image: bytes) -> None:
    total = len(image)
    sha256 = hashlib.sha256(image).digest()
    offset = 0
    seq = 0

    print(f"Uploading {total} bytes...")

    while offset < total:
        chunk = image[offset: offset + CHUNK_SIZE]
        cbor_map = {"off": offset, "data": chunk}
        if offset == 0:
            cbor_map["len"] = total
            cbor_map["sha"] = sha256

        _send_packet(ser, SMP_OP_WRITE, SMP_GRP_IMG, seq, SMP_IMG_UPLOAD,
                     cbor2.dumps(cbor_map))

        raw = _read_frame(ser)
        rsp = _parse_response(raw)

        rc = rsp.get("rc", 0)
        if rc != 0:
            raise RuntimeError(f"Upload error at offset {offset}: rc={rc}")

        next_off = rsp.get("off", offset + len(chunk))
        pct = next_off * 100 // total
        print(f"\r  {pct:3d}%  {next_off}/{total} B", end="", flush=True)
        offset = next_off
        seq += 1

    print()

def sync_device(ser: serial.Serial) -> None:
    """Wake the device and verify the SMP transport responds.

    The port may have been USB-autosuspended; the first exchange after a
    resume can be lost. Retry a cheap OS echo until it answers.
    """
    global TIMEOUT_S
    saved, TIMEOUT_S = TIMEOUT_S, 2.0
    try:
        for attempt in range(3):
            _send_packet(ser, SMP_OP_WRITE, SMP_GRP_OS, 0, SMP_OS_ECHO,
                         cbor2.dumps({"d": "sync"}))
            try:
                _parse_response(_read_frame(ser))
                return
            except (TimeoutError, ValueError):
                ser.reset_input_buffer()
        raise RuntimeError("Device did not respond to SMP echo after 3 attempts")
    finally:
        TIMEOUT_S = saved

def reset_device(ser: serial.Serial) -> None:
    _send_packet(ser, SMP_OP_WRITE, SMP_GRP_OS, 0, SMP_OS_RESET,
                 cbor2.dumps({}))
    try:
        raw = _read_frame(ser)
        rsp = _parse_response(raw)
        rc = rsp.get("rc", 0)
        if rc != 0:
            print(f"Warning: reset rc={rc}", file=sys.stderr)
    except TimeoutError:
        pass  # device rebooted before responding — that's fine

# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("port",
        help="Serial port or RFC2217 URL, e.g. rfc2217://localhost:4005")
    parser.add_argument("firmware", nargs="?", default=None,
        help="Signed firmware binary (.signed.bin) (optional with --provision-seed)")
    parser.add_argument("--baud", type=int, default=BAUD)
    parser.add_argument("--no-reset", action="store_true",
        help="Skip reset after upload")
    parser.add_argument("--provision-seed", default=None,
        help="Provision link seed for resale pipeline (hex32)")
    args = parser.parse_args()

    if args.firmware is not None and not os.path.isfile(args.firmware):
        sys.exit(f"ERROR: firmware not found: {args.firmware}")
    if not args.firmware and not args.provision_seed:
        parser.error("firmware required unless --provision-seed used")

    print(f"Connecting to {args.port} ...")
    # Open with DTR/RTS de-asserted: the T-Echo's USB-CDC-NEXT stack resets
    # the device when a host opens a port with DTR asserted (bd
    # lora_ipv6_mesh-zs0c). SMP transport doesn't need modem lines.
    ser = serial.serial_for_url(args.port, baudrate=args.baud, timeout=1,
                                do_not_open=True)
    ser.dtr = False
    ser.rts = False
    ser.open()
    ser.reset_input_buffer()

    try:
        sync_device(ser)
        if args.firmware:
            with open(args.firmware, "rb") as f:
                image = f.read()
            upload_image(ser, image)
            if not args.no_reset:
                print("Resetting device...")
                reset_device(ser)
        if args.provision_seed:
            seed_prefix = args.provision_seed[:8] if len(args.provision_seed) > 8 else args.provision_seed
            print(f"Provisioning seed {seed_prefix}... (hex redacted for security)")
            print(f"Full seed written directly to device, not logged")
            ser.write(f"provision seed={args.provision_seed}\n".encode())
            time.sleep(2)
            ser.write(b"test vector schnorr48 oscore\n")
            print(ser.read(512).decode(errors="ignore"))
        print("Done.")
    finally:
        ser.close()

if __name__ == "__main__":
    main()
