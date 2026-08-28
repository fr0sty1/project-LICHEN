#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""
GNSS NMEA sentence feeder for native_sim testing.

Feeds NMEA GGA/RMC sentences to a PTY endpoint for testing GNSS parsing
in native_sim builds. The PTY path is printed by the native_sim executable
at startup (look for "uart_1 connected to pseudotty: /dev/pts/N").

Usage:
    # Fixed position (default: 37.7749, -122.4194 -- San Francisco)
    python tools/gnss_nmea_feeder.py /dev/pts/N

    # Custom position
    python tools/gnss_nmea_feeder.py /dev/pts/N --lat 51.5074 --lon -0.1278

    # No fix (simulates GPS searching)
    python tools/gnss_nmea_feeder.py /dev/pts/N --no-fix

    # One-shot mode (send once and exit)
    python tools/gnss_nmea_feeder.py /dev/pts/N --once

This is a thin CLI wrapper around lichen.sim.gnss. For programmatic use,
import the module directly::

    from lichen.sim.gnss import GnssStub, NmeaSentences, make_gga, make_rmc
"""
from __future__ import annotations

import argparse
import datetime
import sys
import time

# Import from the proper module location
from lichen.sim.gnss import make_gga, make_rmc


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
