# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LoRa radio propagation model for LICHEN simulator.

Implements the log-distance path loss model with optional log-normal
shadowing and small-scale fading (Rayleigh / Rice) for higher-fidelity
LoRa simulation.

Deterministic model: PL(d) = PL₀ + 10·n·log₁₀(d/d₀)

Log-normal shadowing adds a zero-mean Gaussian term (dB) with configurable
standard deviation (sigma_sf_dB). Small-scale fading adds either Rayleigh
(no LOS) or Rice (LOS) amplitude variation.

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

Shadowing and fading parameters from:
    Rappaport, T. S. (2002). Wireless Communications: Principles and Practice (2nd ed.).
    ITU-R P.1411 for urban shadowing (sigma = 4-8 dB).
    Loriot, M. et al. (2017). "A survey of LoRaWAN simulation tools."
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

# Sensitivity thresholds at 125kHz bandwidth (LoRaSim for SFs; AN1200.64 for LR-FHSS)
SENSITIVITY_SF7 = -123.0
SENSITIVITY_SF8 = -126.0
SENSITIVITY_SF9 = -129.0
SENSITIVITY_SF10 = -132.0
SENSITIVITY_SF11 = -134.5
SENSITIVITY_SF12 = -137.0
SENSITIVITY_LR_FHSS = -137.0
SENSITIVITY_DEFAULT = SENSITIVITY_SF10

# Capture effect threshold: stronger signal wins if delta >= 6 dB
CAPTURE_THRESHOLD_DB = 6.0

# Path loss exponents for different environments
PATH_LOSS_FREE_SPACE = 2.0
PATH_LOSS_URBAN = 2.7
PATH_LOSS_INDOOR = 3.5

# Default shadowing standard deviation (dB) for urban environments (ITU-R P.1411)
SHADOWING_STD_URBAN = 6.0
SHADOWING_STD_SUBURBAN = 4.0
SHADOWING_STD_INDOOR = 8.0


class FadingType(Enum):
    """Small-scale fading distribution type.

    NONE:   No small-scale fading (deterministic path loss + shadowing only).
    RAYLEIGH: Rayleigh fading — no dominant LOS path (NLoS).
    RICE:     Rice fading — dominant LOS path present.
    """
    NONE = "none"
    RAYLEIGH = "rayleigh"
    RICE = "rice"


@dataclass
class ShadowingConfig:
    """Configuration for log-normal shadowing.

    Attributes:
        sigma_dB: Standard deviation of shadowing in dB.
            Urban: 6 dB, Suburban: 4 dB, Indoor: 8 dB typical.
        enable: Whether shadowing is active. Default True.
        rng: Optional seeded random generator for reproducible shadowing.
            If None, uses random.gauss (non-reproducible).
    """
    sigma_dB: float = SHADOWING_STD_URBAN
    enable: bool = True
    rng: random.Random | None = None

    def shadowing_loss(self) -> float:
        if not self.enable or self.sigma_dB <= 0:
            return 0.0
        if self.rng is not None:
            return self.rng.gauss(0.0, self.sigma_dB)
        return random.gauss(0.0, self.sigma_dB)


@dataclass
class FadingConfig:
    """Configuration for small-scale (multipath) fading.

    Attributes:
        fading_type: Type of fading distribution (NONE, RAYLEIGH, RICE).
        k_factor_dB: Rice K-factor in dB (only used for RICE). LOS power ratio.
            Typical range 6-12 dB for LoRa in suburban environments.
        enable: Whether fading is active. Default True.
        rng: Optional seeded random generator for reproducible fading.
            If None, uses random.random (non-reproducible).
    """
    fading_type: FadingType = FadingType.NONE
    k_factor_dB: float = 6.0
    enable: bool = True
    rng: random.Random | None = None

    def fading_gain(self) -> float:
        """Return a fading power gain factor (linear scale, mean = 1).

        Multiply the received linear-power by this factor, then convert
        back to dB to get the fading-affected RSSI.
        """
        if not self.enable or self.fading_type == FadingType.NONE:
            return 1.0

        rng = self.rng if self.rng is not None else random

        if self.fading_type == FadingType.RAYLEIGH:
            u1 = rng.random()
            u2 = rng.random()
            while u1 <= 0:
                u1 = rng.random()
            # Rayleigh power gain ~ Exp(1), but we need E[gain] = 1:
            # scale by -ln(u1) * PI/2 to keep mean = 1 in power
            power_gain = -math.log(u1) * (math.pi / 2)
            return power_gain * (2.0 / math.pi)

        if self.fading_type == FadingType.RICE:
            k_linear = 10.0 ** (self.k_factor_dB / 10.0)
            u1 = rng.random()
            u2 = rng.random()
            while u1 <= 0:
                u1 = rng.random()
            # Rice power gain normalized to mean = 1
            s = math.sqrt(k_linear / (k_linear + 1.0))
            sigma = 1.0 / math.sqrt(2.0 * (k_linear + 1.0))
            # Box-Muller for two independent Gaussian components
            z1 = math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
            z2 = math.sqrt(-2.0 * math.log(u1)) * math.sin(2.0 * math.pi * u2)
            amplitude = (s + sigma * z1) ** 2 + (sigma * z2) ** 2
            return amplitude

        return 1.0


@dataclass
class PropagationModel:
    """Log-distance path loss model with optional shadowing and fading.

    Computes received signal strength based on transmit power and distance
    using the log-distance path loss model. Optionally adds log-normal
    shadowing (slow fading) and small-scale fading (Rayleigh / Rice).

    The default parameters are calibrated for 915 MHz LoRa in urban
    environments with a reference path loss of 32.44 dB at 1m (free space)
    plus antenna/implementation losses.

    Attributes:
        pl0_dbm: Path loss at reference distance d₀ (dB). Default is 32.44 dB
            for 915 MHz free space at 1m plus typical implementation losses.
        d0_m: Reference distance in meters. Default is 1.0m.
        n: Path loss exponent. 2.0 for free space, 2.7 for urban, 3.5 for indoor.
        noise_floor_dbm: Receiver noise floor in dBm. Default is -120 dBm.
        shadowing: Configuration for log-normal shadowing. Default is urban (6 dB).
        fading: Configuration for small-scale multipath fading. Default is NONE.

    Example:
        >>> model = PropagationModel()
        >>> model.received_power(tx_power_dbm=14.0, distance_m=100.0)
        -72.41  # approximate, depends on parameters
    """

    pl0_dbm: float = 32.44
    d0_m: float = 1.0
    n: float = 2.7
    noise_floor_dbm: float = -120.0
    shadowing: ShadowingConfig = field(default_factory=lambda: ShadowingConfig())
    fading: FadingConfig = field(default_factory=lambda: FadingConfig())

    def __post_init__(self) -> None:
        if self.n <= 0:
            raise ValueError(f"Path loss exponent n must be positive, got {self.n}")
        if self.d0_m <= 0:
            raise ValueError(f"Reference distance d0_m must be positive, got {self.d0_m}")

    def path_loss(self, distance_m: float) -> float:
        """Calculate deterministic path loss at a given distance.

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

    def path_loss_with_shadowing(self, distance_m: float) -> float:
        """Calculate path loss including log-normal shadowing.

        Returns deterministic path loss plus a zero-mean Gaussian
        shadowing term (if enabled).
        """
        pl_det = self.path_loss(distance_m)
        return pl_det + self.shadowing.shadowing_loss()

    def received_power(
        self,
        tx_power_dbm: float,
        distance_m: float,
        *,
        with_shadowing: bool = False,
        with_fading: bool = False,
    ) -> float:
        """Calculate received signal power at a given distance.

        Args:
            tx_power_dbm: Transmit power in dBm.
            distance_m: Distance from transmitter in meters. Must be > 0.
            with_shadowing: Include log-normal shadowing term.
            with_fading: Include small-scale fading.

        Returns:
            Received power in dBm.

        Raises:
            ValueError: If distance_m <= 0.
        """
        if with_shadowing:
            rx_power_dbm = tx_power_dbm - self.path_loss_with_shadowing(distance_m)
        else:
            rx_power_dbm = tx_power_dbm - self.path_loss(distance_m)

        if with_fading and self.fading.enable and self.fading.fading_type != FadingType.NONE:
            rx_power_linear = 10.0 ** (rx_power_dbm / 10.0)
            fading_gain = self.fading.fading_gain()
            rx_power_linear *= fading_gain
            rx_power_dbm = 10.0 * math.log10(max(rx_power_linear, 1e-30))

        return rx_power_dbm

    def snr(
        self,
        tx_power_dbm: float,
        distance_m: float,
        *,
        with_shadowing: bool = False,
        with_fading: bool = False,
    ) -> float:
        """Calculate signal-to-noise ratio at a given distance.

        Args:
            tx_power_dbm: Transmit power in dBm.
            distance_m: Distance from transmitter in meters. Must be > 0.
            with_shadowing: Include log-normal shadowing term.
            with_fading: Include small-scale fading.

        Returns:
            SNR in dB (can be negative if signal is below noise floor).

        Raises:
            ValueError: If distance_m <= 0.
        """
        rx_power = self.received_power(
            tx_power_dbm, distance_m,
            with_shadowing=with_shadowing,
            with_fading=with_fading,
        )
        return rx_power - self.noise_floor_dbm

    def can_decode(
        self,
        tx_power_dbm: float,
        distance_m: float,
        *,
        sensitivity_dbm: float = SENSITIVITY_SF10,
        with_shadowing: bool = False,
        with_fading: bool = False,
    ) -> bool:
        rx_power = self.received_power(
            tx_power_dbm, distance_m,
            with_shadowing=with_shadowing,
            with_fading=with_fading,
        )
        return rx_power >= sensitivity_dbm

    def max_range(
        self,
        tx_power_dbm: float,
        *,
        sensitivity_dbm: float = SENSITIVITY_SF10,
    ) -> float:
        exponent = (tx_power_dbm - self.pl0_dbm - sensitivity_dbm) / (10.0 * self.n)
        return self.d0_m * math.pow(10.0, exponent)
