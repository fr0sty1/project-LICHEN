#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""
GNSS NMEA sentence feeder for native_sim testing.

Feeds NMEA GGA/RMC sentences to a PTY endpoint for testing GNSS parsing
in native_sim builds. The PTY path is printed by the native_sim executable
at startup (look for "uart_1 connected to pseudotty: /dev/pts/N").

Usage:
    # Fixed position (default: 37.7749, -122.4194 — San Francisco)
    python tools/gnss_nmea_feeder.py /dev/pts/N

    # Custom position
    python tools/gnss_nmea_feeder.py /dev/pts/N --lat 51.5074 --lon -0.1278

    # No fix (simulates GPS searching)
    python tools/gnss_nmea_feeder.py /dev/pts/N --no-fix

    # One-shot mode (send once and exit)
    python tools/gnss_nmea_feeder.py /dev/pts/N --once
"""
from __future__ import annotations

import argparse
import datetime
import sys
import time


def nmea_checksum(sentence: str) -> str:
    """Compute NMEA checksum (XOR of all chars between $ and *)."""
    chk = 0
    for c in sentence:
        chk ^= ord(c)
    return f"{chk:02X}"


def make_gga(
    lat: float,
    lon: float,
    alt: float = 10.0,
    fix_quality: int = 1,
    num_sats: int = 8,
    hdop: float = 1.0,
    utc: datetime.datetime | None = None,
) -> str:
    """
    Generate an NMEA GGA sentence.

    fix_quality: 0=no fix, 1=GPS fix, 2=DGPS fix
    """
    if utc is None:
        utc = datetime.datetime.now(datetime.UTC)

    time_str = utc.strftime("%H%M%S.00")

    # Convert lat/lon to NMEA format (DDMM.MMMM)
    lat_dir = "N" if lat >= 0 else "S"
    lat = abs(lat)
    lat_deg = int(lat)
    lat_min = (lat - lat_deg) * 60
    lat_str = f"{lat_deg:02d}{lat_min:07.4f}"

    lon_dir = "E" if lon >= 0 else "W"
    lon = abs(lon)
    lon_deg = int(lon)
    lon_min = (lon - lon_deg) * 60
    lon_str = f"{lon_deg:03d}{lon_min:07.4f}"

    # GGA: Global Positioning System Fix Data
    # $GPGGA,time,lat,N/S,lon,E/W,quality,numSV,HDOP,alt,M,sep,M,diffAge,diffStation*cs
    body = (
        f"GPGGA,{time_str},{lat_str},{lat_dir},{lon_str},{lon_dir},"
        f"{fix_quality},{num_sats:02d},{hdop:.1f},{alt:.1f},M,0.0,M,,"
    )
    return f"${body}*{nmea_checksum(body)}\r\n"


def make_rmc(
    lat: float,
    lon: float,
    speed_knots: float = 0.0,
    course: float = 0.0,
    valid: bool = True,
    utc: datetime.datetime | None = None,
) -> str:
    """
    Generate an NMEA RMC sentence.

    valid: True for A (valid), False for V (void/invalid)
    """
    if utc is None:
        utc = datetime.datetime.now(datetime.UTC)

    time_str = utc.strftime("%H%M%S.00")
    date_str = utc.strftime("%d%m%y")
    status = "A" if valid else "V"

    # Convert lat/lon to NMEA format
    lat_dir = "N" if lat >= 0 else "S"
    lat = abs(lat)
    lat_deg = int(lat)
    lat_min = (lat - lat_deg) * 60
    lat_str = f"{lat_deg:02d}{lat_min:07.4f}"

    lon_dir = "E" if lon >= 0 else "W"
    lon = abs(lon)
    lon_deg = int(lon)
    lon_min = (lon - lon_deg) * 60
    lon_str = f"{lon_deg:03d}{lon_min:07.4f}"

    # RMC: Recommended Minimum Navigation Information
    # $GPRMC,time,status,lat,N/S,lon,E/W,speed,course,date,magVar,E/W,mode*cs
    body = (
        f"GPRMC,{time_str},{status},{lat_str},{lat_dir},{lon_str},{lon_dir},"
        f"{speed_knots:.1f},{course:.1f},{date_str},,,A"
    )
    return f"${body}*{nmea_checksum(body)}\r\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Feed NMEA sentences to a PTY for native_sim GNSS testing"
    )
    parser.add_argument("pty", help="PTY device path (e.g., /dev/pts/5)")
    parser.add_argument(
        "--lat",
        type=float,
        default=37.7749,
        help="Latitude in decimal degrees (default: 37.7749)",
    )
    parser.add_argument(
        "--lon",
        type=float,
        default=-122.4194,
        help="Longitude in decimal degrees (default: -122.4194)",
    )
    parser.add_argument(
        "--alt",
        type=float,
        default=10.0,
        help="Altitude in meters (default: 10.0)",
    )
    parser.add_argument(
        "--no-fix",
        action="store_true",
        help="Simulate no GPS fix (fix quality 0, status V)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Interval between sentences in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Send one set of sentences and exit",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print sentences to stderr",
    )
    args = parser.parse_args()

    fix_quality = 0 if args.no_fix else 1
    valid = not args.no_fix

    try:
        with open(args.pty, "wb", buffering=0) as pty:
            print(f"Feeding NMEA to {args.pty}", file=sys.stderr)
            if args.no_fix:
                print("Mode: NO FIX (simulating GPS searching)", file=sys.stderr)
            else:
                print(
                    f"Position: {args.lat:.6f}, {args.lon:.6f}, {args.alt:.1f}m",
                    file=sys.stderr,
                )

            while True:
                utc = datetime.datetime.now(datetime.UTC)

                gga = make_gga(
                    args.lat,
                    args.lon,
                    args.alt,
                    fix_quality=fix_quality,
                    utc=utc,
                )
                rmc = make_rmc(
                    args.lat,
                    args.lon,
                    valid=valid,
                    utc=utc,
                )

                pty.write(gga.encode("ascii"))
                pty.write(rmc.encode("ascii"))

                if args.verbose:
                    print(gga.strip(), file=sys.stderr)
                    print(rmc.strip(), file=sys.stderr)

                if args.once:
                    break

                time.sleep(args.interval)

    except FileNotFoundError:
        print(f"Error: PTY device not found: {args.pty}", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"Error: Permission denied: {args.pty}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
