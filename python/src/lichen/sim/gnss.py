# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""GNSS simulation stub for native_sim and simulator testing.

Provides NMEA sentence generation and a GnssStub class that can feed NMEA
data to simulated nodes via PTY, pipe, or programmatic injection.

Usage
-----
Programmatic (for simulation integration)::

    from lichen.sim.gnss import GnssStub, NmeaSentences

    # Generate NMEA sentences
    sentences = NmeaSentences.generate(lat=37.7749, lon=-122.4194)
    print(sentences.gga)  # $GPGGA,...
    print(sentences.rmc)  # $GPRMC,...

    # Create a stub that feeds a PTY
    stub = GnssStub(lat=37.7749, lon=-122.4194)
    await stub.start_pty("/dev/pts/5")  # Feeds NMEA at 1Hz

CLI (for manual testing)::

    python -m lichen.sim.gnss /dev/pts/5 --lat 37.7749 --lon -122.4194

Test scenarios
--------------
- Fixed position: Use default or specify --lat/--lon
- No fix: Use --no-fix flag (fix_quality=0, status=V)
- Moving: Call set_position() or use mobility patterns
"""
from __future__ import annotations

import asyncio
import contextlib
import datetime
import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


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

    Args:
        lat: Latitude in decimal degrees (positive=N, negative=S).
        lon: Longitude in decimal degrees (positive=E, negative=W).
        alt: Altitude in meters above MSL.
        fix_quality: GPS fix quality (0=no fix, 1=GPS fix, 2=DGPS fix).
        num_sats: Number of satellites in view.
        hdop: Horizontal dilution of precision.
        utc: UTC timestamp. Defaults to current time.

    Returns:
        Complete NMEA GGA sentence with checksum and CRLF terminator.
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

    Args:
        lat: Latitude in decimal degrees (positive=N, negative=S).
        lon: Longitude in decimal degrees (positive=E, negative=W).
        speed_knots: Speed over ground in knots.
        course: Course over ground in degrees.
        valid: True for A (valid fix), False for V (void/invalid).
        utc: UTC timestamp. Defaults to current time.

    Returns:
        Complete NMEA RMC sentence with checksum and CRLF terminator.
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


@dataclass(frozen=True, slots=True)
class NmeaSentences:
    """A pair of GGA and RMC NMEA sentences for a single position fix."""

    gga: str
    rmc: str
    utc: datetime.datetime

    @classmethod
    def generate(
        cls,
        lat: float,
        lon: float,
        alt: float = 10.0,
        fix_quality: int = 1,
        num_sats: int = 8,
        hdop: float = 1.0,
        speed_knots: float = 0.0,
        course: float = 0.0,
        utc: datetime.datetime | None = None,
    ) -> NmeaSentences:
        """Generate a consistent pair of GGA and RMC sentences.

        Args:
            lat: Latitude in decimal degrees.
            lon: Longitude in decimal degrees.
            alt: Altitude in meters.
            fix_quality: GPS fix quality (0=no fix, 1=GPS, 2=DGPS).
            num_sats: Number of satellites.
            hdop: Horizontal dilution of precision.
            speed_knots: Speed over ground in knots.
            course: Course over ground in degrees.
            utc: UTC timestamp (defaults to now).

        Returns:
            NmeaSentences with matching timestamps.
        """
        if utc is None:
            utc = datetime.datetime.now(datetime.UTC)

        valid = fix_quality > 0

        gga = make_gga(
            lat=lat,
            lon=lon,
            alt=alt,
            fix_quality=fix_quality,
            num_sats=num_sats,
            hdop=hdop,
            utc=utc,
        )
        rmc = make_rmc(
            lat=lat,
            lon=lon,
            speed_knots=speed_knots,
            course=course,
            valid=valid,
            utc=utc,
        )
        return cls(gga=gga, rmc=rmc, utc=utc)

    def as_bytes(self) -> bytes:
        """Return both sentences as ASCII bytes for UART transmission."""
        return (self.gga + self.rmc).encode("ascii")


class GnssStub:
    """GNSS simulation stub that feeds NMEA sentences to a target.

    Can output to:
    - PTY device (for native_sim UART)
    - Pipe or file descriptor
    - Callback function (for in-process simulation)

    Attributes:
        lat: Current latitude in decimal degrees.
        lon: Current longitude in decimal degrees.
        alt: Current altitude in meters.
        has_fix: Whether the GNSS has a valid fix.
        interval: Seconds between sentence outputs.
    """

    def __init__(
        self,
        lat: float = 37.7749,
        lon: float = -122.4194,
        alt: float = 10.0,
        has_fix: bool = True,
        interval: float = 1.0,
    ) -> None:
        """Initialize a GNSS stub.

        Args:
            lat: Initial latitude (default: San Francisco).
            lon: Initial longitude.
            alt: Initial altitude in meters.
            has_fix: Whether the simulated GNSS has a fix.
            interval: Seconds between NMEA outputs.
        """
        self.lat = lat
        self.lon = lon
        self.alt = alt
        self.has_fix = has_fix
        self.interval = interval
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._output: Callable[[bytes], None] | None = None
        self._fd: int | None = None

    def set_position(
        self,
        lat: float,
        lon: float,
        alt: float | None = None,
    ) -> None:
        """Update the simulated position.

        Args:
            lat: New latitude in decimal degrees.
            lon: New longitude in decimal degrees.
            alt: New altitude in meters (unchanged if None).
        """
        self.lat = lat
        self.lon = lon
        if alt is not None:
            self.alt = alt

    def set_fix(self, has_fix: bool) -> None:
        """Set whether the GNSS reports a valid fix."""
        self.has_fix = has_fix

    def generate_sentences(
        self,
        utc: datetime.datetime | None = None,
    ) -> NmeaSentences:
        """Generate NMEA sentences for the current position.

        Args:
            utc: UTC timestamp (defaults to now).

        Returns:
            NmeaSentences with current position data.
        """
        return NmeaSentences.generate(
            lat=self.lat,
            lon=self.lon,
            alt=self.alt,
            fix_quality=1 if self.has_fix else 0,
            utc=utc,
        )

    async def start_pty(self, pty_path: str) -> None:
        """Start feeding NMEA sentences to a PTY device.

        Args:
            pty_path: Path to PTY device (e.g., /dev/pts/5).

        Raises:
            FileNotFoundError: If the PTY does not exist.
            PermissionError: If access to the PTY is denied.
        """
        fd = os.open(pty_path, os.O_WRONLY | os.O_NONBLOCK)
        self._fd = fd
        self._output = lambda data: os.write(fd, data)
        await self._start_loop()
        logger.info("GnssStub: feeding NMEA to %s", pty_path)

    async def start_callback(
        self,
        callback: Callable[[bytes], None],
    ) -> None:
        """Start feeding NMEA sentences to a callback function.

        Args:
            callback: Function called with NMEA bytes at each interval.
        """
        self._output = callback
        await self._start_loop()
        logger.info("GnssStub: feeding NMEA to callback")

    async def _start_loop(self) -> None:
        """Start the NMEA output loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._feed_loop())

    async def _feed_loop(self) -> None:
        """Background loop that emits NMEA sentences at interval."""
        while self._running:
            try:
                sentences = self.generate_sentences()
                if self._output is not None:
                    self._output(sentences.as_bytes())
            except OSError as e:
                logger.warning("GnssStub: output error: %s", e)
            await asyncio.sleep(self.interval)

    async def stop(self) -> None:
        """Stop the NMEA output loop and close resources."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self._fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._fd)
            self._fd = None
        self._output = None
        logger.info("GnssStub: stopped")

    def feed_once(self, utc: datetime.datetime | None = None) -> bytes:
        """Generate and return one set of NMEA sentences (no output).

        Useful for tests that need to inject NMEA data directly.

        Args:
            utc: UTC timestamp (defaults to now).

        Returns:
            NMEA sentences as ASCII bytes.
        """
        return self.generate_sentences(utc).as_bytes()


# Convenience aliases for backward compatibility with tools/gnss_nmea_feeder.py
def nmea_gga(
    lat: float,
    lon: float,
    alt: float = 10.0,
    fix_quality: int = 1,
    num_sats: int = 8,
    hdop: float = 1.0,
    utc: datetime.datetime | None = None,
) -> str:
    """Alias for make_gga() - backward compatibility."""
    return make_gga(lat, lon, alt, fix_quality, num_sats, hdop, utc)


def nmea_rmc(
    lat: float,
    lon: float,
    speed_knots: float = 0.0,
    course: float = 0.0,
    valid: bool = True,
    utc: datetime.datetime | None = None,
) -> str:
    """Alias for make_rmc() - backward compatibility."""
    return make_rmc(lat, lon, speed_knots, course, valid, utc)
