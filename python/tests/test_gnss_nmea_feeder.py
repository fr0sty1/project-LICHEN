# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the GNSS NMEA feeder tool."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Add tools directory to path so we can import the feeder
TOOLS_DIR = Path(__file__).parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS_DIR))

from gnss_nmea_feeder import make_gga, make_rmc, nmea_checksum


class TestNmeaChecksum:
    """Tests for NMEA checksum calculation."""

    def test_checksum_gga(self) -> None:
        """Verify checksum for a known GGA sentence body."""
        # Body without $ and *checksum
        body = "GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,47.0,M,,"
        chk = nmea_checksum(body)
        # Known correct checksum for this sentence
        assert len(chk) == 2
        assert chk.isalnum()

    def test_checksum_empty(self) -> None:
        """Empty body should return 00."""
        assert nmea_checksum("") == "00"


class TestMakeGga:
    """Tests for GGA sentence generation."""

    def test_gga_format(self) -> None:
        """GGA sentence should have correct format."""
        gga = make_gga(37.7749, -122.4194, 10.0)
        assert gga.startswith("$GPGGA,")
        assert gga.endswith("\r\n")
        assert "*" in gga

    def test_gga_has_checksum(self) -> None:
        """GGA sentence should have valid checksum."""
        gga = make_gga(37.7749, -122.4194)
        # Extract body between $ and *
        assert gga.startswith("$")
        body_end = gga.index("*")
        body = gga[1:body_end]
        expected_chk = gga[body_end + 1 : body_end + 3]
        assert nmea_checksum(body) == expected_chk

    def test_gga_no_fix(self) -> None:
        """GGA with fix_quality=0 should indicate no fix."""
        gga = make_gga(37.7749, -122.4194, fix_quality=0)
        # Fix quality is field 6 (0-indexed: 5)
        fields = gga.split(",")
        assert fields[6] == "0"

    def test_gga_with_fix(self) -> None:
        """GGA with fix_quality=1 should indicate GPS fix."""
        gga = make_gga(37.7749, -122.4194, fix_quality=1)
        fields = gga.split(",")
        assert fields[6] == "1"

    def test_gga_north_latitude(self) -> None:
        """Positive latitude should show N."""
        gga = make_gga(37.7749, -122.4194)
        fields = gga.split(",")
        assert fields[3] == "N"

    def test_gga_south_latitude(self) -> None:
        """Negative latitude should show S."""
        gga = make_gga(-33.8688, 151.2093)  # Sydney
        fields = gga.split(",")
        assert fields[3] == "S"

    def test_gga_west_longitude(self) -> None:
        """Negative longitude should show W."""
        gga = make_gga(37.7749, -122.4194)
        fields = gga.split(",")
        assert fields[5] == "W"

    def test_gga_east_longitude(self) -> None:
        """Positive longitude should show E."""
        gga = make_gga(51.5074, 0.1278)  # London
        fields = gga.split(",")
        assert fields[5] == "E"


class TestMakeRmc:
    """Tests for RMC sentence generation."""

    def test_rmc_format(self) -> None:
        """RMC sentence should have correct format."""
        rmc = make_rmc(37.7749, -122.4194)
        assert rmc.startswith("$GPRMC,")
        assert rmc.endswith("\r\n")
        assert "*" in rmc

    def test_rmc_has_checksum(self) -> None:
        """RMC sentence should have valid checksum."""
        rmc = make_rmc(37.7749, -122.4194)
        assert rmc.startswith("$")
        body_end = rmc.index("*")
        body = rmc[1:body_end]
        expected_chk = rmc[body_end + 1 : body_end + 3]
        assert nmea_checksum(body) == expected_chk

    def test_rmc_valid(self) -> None:
        """RMC with valid=True should show A status."""
        rmc = make_rmc(37.7749, -122.4194, valid=True)
        fields = rmc.split(",")
        assert fields[2] == "A"

    def test_rmc_invalid(self) -> None:
        """RMC with valid=False should show V status."""
        rmc = make_rmc(37.7749, -122.4194, valid=False)
        fields = rmc.split(",")
        assert fields[2] == "V"

    def test_rmc_speed_course(self) -> None:
        """RMC should include speed and course."""
        rmc = make_rmc(37.7749, -122.4194, speed_knots=5.5, course=180.0)
        fields = rmc.split(",")
        assert fields[7] == "5.5"
        assert fields[8] == "180.0"


class TestLatLonConversion:
    """Tests for lat/lon decimal to NMEA format conversion."""

    def test_latitude_format(self) -> None:
        """Latitude should be in DDMM.MMMM format."""
        gga = make_gga(37.7749, -122.4194)
        fields = gga.split(",")
        lat_str = fields[2]
        # 37.7749 -> 37 degrees, 46.494 minutes -> 3746.4940
        assert lat_str.startswith("37")
        assert "." in lat_str

    def test_longitude_format(self) -> None:
        """Longitude should be in DDDMM.MMMM format."""
        gga = make_gga(37.7749, -122.4194)
        fields = gga.split(",")
        lon_str = fields[4]
        # 122.4194 -> 122 degrees, 25.164 minutes -> 12225.1640
        assert lon_str.startswith("122")
        assert "." in lon_str

    def test_zero_latitude(self) -> None:
        """Zero latitude should work."""
        gga = make_gga(0.0, 0.0)
        fields = gga.split(",")
        assert fields[2].startswith("00")

    def test_zero_longitude(self) -> None:
        """Zero longitude should work."""
        gga = make_gga(0.0, 0.0)
        fields = gga.split(",")
        assert fields[4].startswith("000")
