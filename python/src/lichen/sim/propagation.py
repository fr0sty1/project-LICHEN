# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LoRa radio propagation model for LICHEN simulator.

Implements the log-distance path loss model for simulating LoRa radio
propagation in mesh network scenarios.

Model: PL(d) = PL₀ + 10·n·log₁₀(d/d₀)

Where:
    PL(d) = path loss at distance d (dB)
    PL₀   = path loss at reference distance d₀ (dB)
    n     = path loss exponent (environment-dependent)
    d₀    = reference distance (typically 1m)

Sensitivity thresholds and capture effect parameters are based on:
    Bor, M., Roedig, U., Voigt, T., & Alonso, J. M. (2016).
    "Do LoRa Low-Power Wide-Area Networks Scale?"
    Proceedings of the 19th ACM International Conference on
    Modeling, Analysis and Simulation of Wireless and Mobile Systems.

LR-FHSS sensitivity from Semtech AN1200.64 and SX1262 datasheet (varies by CR/OCW;
-137.0 used for sim consistency with fragment FEC and 2x airtime).
See beads project-LICHEN-9o94/yd9a for independent test vectors.

SF sensitivity thresholds at 125kHz bandwidth:
    SF7: -123 dBm, SF8: -126 dBm, SF9: -129 dBm,
    SF10: -132 dBm, SF11: -134.5 dBm, SF12: -137 dBm
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# Sensitivity thresholds at 125kHz bandwidth (from LoRaSim)
SENSITIVITY_SF7 = -123.0
SENSITIVITY_SF8 = -126.0
SENSITIVITY_SF9 = -129.0
SENSITIVITY_SF10 = -132.0
SENSITIVITY_SF11 = -134.5
SENSITIVITY_SF12 = -137.0
SENSITIVITY_LR_FHSS = -135.0
SENSITIVITY_DEFAULT = SENSITIVITY_SF10

# Capture effect threshold: stronger signal wins if delta >= 6 dB
CAPTURE_THRESHOLD_DB = 6.0

# Path loss exponents for different environments
PATH_LOSS_FREE_SPACE = 2.0
PATH_LOSS_URBAN = 2.7
PATH_LOSS_INDOOR = 3.5


@dataclass
class PropagationModel:
    """Log-distance path loss model for LoRa radio propagation.

    Computes received signal strength based on transmit power and distance
    using the log-distance path loss model.

    The default parameters are calibrated for 915 MHz LoRa in urban
    environments with a reference path loss of 32.44 dB at 1m (free space)
    plus antenna/implementation losses.

    Attributes:
        pl0_dbm: Path loss at reference distance d₀ (dB). Default is 32.44 dB
            for 915 MHz free space at 1m plus typical implementation losses.
        d0_m: Reference distance in meters. Default is 1.0m.
        n: Path loss exponent. 2.0 for free space, 2.7 for urban, 3.5 for indoor.
        noise_floor_dbm: Receiver noise floor in dBm. Default is -120 dBm.

    Example:
        >>> model = PropagationModel()
        >>> model.received_power(tx_power_dbm=14.0, distance_m=100.0)
        -72.41  # approximate, depends on parameters
    """

    pl0_dbm: float = 32.44
    d0_m: float = 1.0
    n: float = 2.7
    noise_floor_dbm: float = -120.0

    def __post_init__(self) -> None:
        if self.n <= 0:
            raise ValueError(f"Path loss exponent n must be positive, got {self.n}")
        if self.d0_m <= 0:
            raise ValueError(f"Reference distance d0_m must be positive, got {self.d0_m}")

    def path_loss(self, distance_m: float) -> float:
        """Calculate path loss at a given distance.

        Args:
            distance_m: Distance from transmitter in meters. Must be > 0.
                For distances <= d₀, returns PL₀.

        Returns:
            Path loss in dB (positive value).

        Raises:
            ValueError: If distance_m <= 0.
        """
        if distance_m <= 0:
            raise ValueError(f"Distance must be positive, got {distance_m}")

        if distance_m <= self.d0_m:
            return self.pl0_dbm

        return self.pl0_dbm + 10.0 * self.n * math.log10(distance_m / self.d0_m)

    def received_power(self, tx_power_dbm: float, distance_m: float) -> float:
        """Calculate received signal power at a given distance.

        Args:
            tx_power_dbm: Transmit power in dBm.
            distance_m: Distance from transmitter in meters. Must be > 0.

        Returns:
            Received power in dBm.

        Raises:
            ValueError: If distance_m <= 0.
        """
        return tx_power_dbm - self.path_loss(distance_m)

    def snr(self, tx_power_dbm: float, distance_m: float) -> float:
        """Calculate signal-to-noise ratio at a given distance.

        Args:
            tx_power_dbm: Transmit power in dBm.
            distance_m: Distance from transmitter in meters. Must be > 0.

        Returns:
            SNR in dB (can be negative if signal is below noise floor).

        Raises:
            ValueError: If distance_m <= 0.
        """
        rx_power = self.received_power(tx_power_dbm, distance_m)
        return rx_power - self.noise_floor_dbm

    def can_decode(
        self,
        tx_power_dbm: float,
        distance_m: float,
        *,
        sensitivity_dbm: float = SENSITIVITY_SF10,
    ) -> bool:
        rx_power = self.received_power(tx_power_dbm, distance_m)
        return rx_power >= sensitivity_dbm

    def max_range(
        self,
        tx_power_dbm: float,
        *,
        sensitivity_dbm: float = SENSITIVITY_SF10,
    ) -> float:
        exponent = (tx_power_dbm - self.pl0_dbm - sensitivity_dbm) / (10.0 * self.n)
        return self.d0_m * math.pow(10.0, exponent)
