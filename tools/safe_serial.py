#!/usr/bin/env python3
"""Safe serial port reader that won't block/hang the caller.

Usage:
    safe_serial.py [port] [--timeout=N] [--lines=N] [--baud=N]

Examples:
    safe_serial.py                           # Auto-detect, 2s timeout, 20 lines
    safe_serial.py /dev/cu.usbmodem22424101  # Specific port
    safe_serial.py --timeout=5 --lines=50    # Custom limits
"""
# ponytail: subprocess with hard timeout, no blocking reads

import argparse
import glob
import signal
import sys


def timeout_handler(signum, frame):
    print("\n[TIMEOUT]", file=sys.stderr)
    sys.exit(0)

def find_port():
    """Auto-detect USB serial port."""
    patterns = ["/dev/cu.usbmodem*", "/dev/cu.usbserial*"]
    for pat in patterns:
        ports = glob.glob(pat)
        if ports:
            return ports[0]
    return None

def main():
    parser = argparse.ArgumentParser(description="Safe serial reader")
    parser.add_argument("port", nargs="?", help="Serial port path")
    parser.add_argument("--timeout", type=int, default=2, help="Read timeout in seconds")
    parser.add_argument("--lines", type=int, default=20, help="Max lines to read")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate")
    args = parser.parse_args()

    port = args.port or find_port()
    if not port:
        print("No USB serial port found", file=sys.stderr)
        sys.exit(1)

    # Hard timeout via signal - cannot hang
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(args.timeout)

    try:
        import serial
    except ImportError:
        print("pyserial not installed: pip install pyserial", file=sys.stderr)
        sys.exit(1)

    try:
        ser = serial.Serial(port, args.baud, timeout=0.5)
        print(f"[Connected: {port} @ {args.baud}]", file=sys.stderr)

        lines = 0
        while lines < args.lines:
            line = ser.readline()
            if line:
                try:
                    print(line.decode('utf-8', errors='replace').rstrip())
                except Exception:
                    print(f"[binary: {line.hex()}]")
                lines += 1

        ser.close()
    except serial.SerialException as e:
        print(f"Serial error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
