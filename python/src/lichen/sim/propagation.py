# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LoRa radio propagation model for LICHEN simulator.

Implements the log-distance path loss model with optional log-normal
shadowing and small-scale fading for simulating LoRa radio propagation
in mesh network scenarios.

Model: PL(d) = PL₀ + 10·n·log₁₀(d/d₀) + X_σ + F

Where:
    PL(d) = path loss at distance d (dB)
    PL₀   = path loss at reference distance d₀ (dB)
    n     = path loss exponent (environment-dependent)
    d₀    = reference distance (typically 1m)
    X_σ   = log-normal shadowing term (dB), N(0, σ_shadow)
    F     = small-scale fading term (dB), Rayleigh or Ricean

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
import secrets
from dataclasses import dataclass, field
from typing import Literal

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

# Shadowing standard deviation defaults (dB) based on ITU-R P.1238 / 3GPP TR 38.901
SHADOW_STD_URBAN = 4.0
SHADOW_STD_SUBURBAN = 6.0
SHADOW_STD_INDOOR = 8.0

# Default small-scale fading standard deviation (dB) for Rayleigh fading
FADING_STD_RAYLEIGH = 6.0
FADING_STD_RICEAN = 3.0


def _db_to_linear(dbm: float) -> float:
    return 10.0 ** (dbm / 10.0)


def _linear_to_db(linear: float) -> float:
    if linear <= 0:
        return -float("inf")
    return 10.0 * math.log10(linear)


def _box_muller() -> tuple[float, float]:
    """Marsaglia polar method for two independent N(0,1) samples."""
    while True:
        u = 2.0 * secrets.randbelow(2**31) / 2**31 - 1.0
        v = 2.0 * secrets.randbelow(2**31) / 2**31 - 1.0
        s = u * u + v * v
        if 0.0 < s < 1.0:
            factor = math.sqrt(-2.0 * math.log(s) / s)
            return u * factor, v * factor


def _gauss_sample() -> float:
    """Single N(0,1) sample via Box-Muller (discard second)."""
    return _box_muller()[0]


@dataclass
class PropagationModel:
    """Log-distance path loss model with optional shadowing and small-scale fading.

    Computes received signal strength based on transmit power and distance
    using the log-distance path loss model with optional log-normal shadowing
    and small-scale (Rayleigh/Ricean) fading.

    Shadowing models large-scale signal variation due to obstacles in the
    propagation path. Fading models multipath interference at small spatial
    scales. Both are stochastic and use independent random draws per call.

    The default parameters are calibrated for 915 MHz LoRa in urban
    environments with a reference path loss of 32.44 dB at 1m (free space)
    plus antenna/implementation losses.

    Attributes:
        pl0_dbm: Path loss at reference distance d₀ (dB). Default is 32.44 dB
            for 915 MHz free space at 1m plus typical implementation losses.
        d0_m: Reference distance in meters. Default is 1.0m.
        n: Path loss exponent. 2.0 for free space, 2.7 for urban, 3.5 for indoor.
        noise_floor_dbm: Receiver noise floor in dBm. Default is -120 dBm.
        shadow_std_db: Log-normal shadowing standard deviation (dB). 0 = disabled.
            Default 0 (disabled for deterministic tests).
        fading_std_db: Small-scale fading standard deviation (dB). 0 = disabled.
            Default 0 (disabled for deterministic tests).
        fading_type: 'rayleigh' or 'ricean'. Ignored when fading_std_db == 0.

    Example:
        >>> model = PropagationModel()
        >>> model.received_power(tx_power_dbm=14.0, distance_m=100.0)
        -72.41  # approximate, depends on parameters
    """

    pl0_dbm: float = 32.44
    d0_m: float = 1.0
    n: float = 2.7
    noise_floor_dbm: float = -120.0
    shadow_std_db: float = 0.0
    fading_std_db: float = 0.0
    fading_type: Literal["rayleigh", "ricean"] = "rayleigh"

    # Deterministic seed override for reproducibility. When set to a float >= 0,
    # _gauss_sample returns shadow_std_db * seed_hack and fading_std_db * seed_hack
    # instead of random draws. Used only by tests.
    _seed: float = field(default=-1.0, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.n <= 0:
            raise ValueError(f"Path loss exponent n must be positive, got {self.n}")
        if self.d0_m <= 0:
            raise ValueError(f"Reference distance d0_m must be positive, got {self.d0_m}")
        if self.shadow_std_db < 0:
            raise ValueError(
                f"Shadow standard deviation must be >= 0, got {self.shadow_std_db}"
            )
        if self.fading_std_db < 0:
            raise ValueError(
                f"Fading standard deviation must be >= 0, got {self.fading_std_db}"
            )
        if self.fading_type not in ("rayleigh", "ricean"):
            raise ValueError(
                f"fading_type must be 'rayleigh' or 'ricean', got {self.fading_type}"
            )

    def _shadow_loss(self) -> float:
        if self._seed >= 0.0:
            return self.shadow_std_db * self._seed
        if self.shadow_std_db <= 0.0:
            return 0.0
        return self.shadow_std_db * _gauss_sample()

    def _fading_loss(self) -> float:
        if self._seed >= 0.0:
            return self.fading_std_db * self._seed
        if self.fading_std_db <= 0.0:
            return 0.0
        gauss = _gauss_sample()
        if self.fading_type == "ricean":
            return self.fading_std_db * abs(gauss)
        return self.fading_std_db * gauss

    def path_loss(self, distance_m: float) -> float:
        if distance_m <= 0:
            raise ValueError(f"Distance must be positive, got {distance_m}")
        if distance_m <= self.d0_m:
            pl = self.pl0_dbm
        else:
            pl = self.pl0_dbm + 10.0 * self.n * math.log10(distance_m / self.d0_m)
        return pl + self._shadow_loss() + self._fading_loss()

    def received_power(self, tx_power_dbm: float, distance_m: float) -> float:
        return tx_power_dbm - self.path_loss(distance_m)

    def snr(self, tx_power_dbm: float, distance_m: float) -> float:
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

    def sinr(
        self,
        tx_power_dbm: float,
        distance_m: float,
        interfering_powers_linear: list[float],
    ) -> float:
        """Signal-to-interference-plus-noise ratio in dB.

        SINR(dB) = 10 * log10(S / (N + sum(I)))

        Where S = signal power (linear), N = noise floor (linear),
        and I = interfering signal powers (linear).

        Args:
            tx_power_dbm: Transmit power of desired signal in dBm.
            distance_m: Distance from desired transmitter in meters.
            interfering_powers_linear: List of interfering signal powers
                in linear scale (mW).

        Returns:
            SINR in dB.
        """
        signal_linear = _db_to_linear(self.received_power(tx_power_dbm, distance_m))
        noise_linear = _db_to_linear(self.noise_floor_dbm)
        interference_linear = sum(interfering_powers_linear)
        total_noise = noise_linear + interference_linear
        if total_noise <= 0:
            return float("inf")
        return _linear_to_db(signal_linear / total_noise)


def link_budget(
    tx_power_dbm: float,
    tx_antenna_gain_dbi: float,
    rx_antenna_gain_dbi: float,
    cable_loss_db: float,
    distance_m: float,
    *,
    n: float = PATH_LOSS_URBAN,
    pl0_dbm: float = 32.44,
    d0_m: float = 1.0,
) -> dict[str, float]:
    """Compute a point-to-point LoRa link budget.

    Link budget = TX_power + TX_antenna_gain - cable_loss - path_loss
                  + RX_antenna_gain

    Returns a dict with intermediate values for diagnostic display.

    Args:
        tx_power_dbm: Transmitter output power in dBm.
        tx_antenna_gain_dbi: Transmitter antenna gain in dBi.
        rx_antenna_gain_dbi: Receiver antenna gain in dBi.
        cable_loss_db: Combined cable/connector loss in dB (positive value).
        distance_m: Link distance in meters.
        n: Path loss exponent.
        pl0_dbm: Path loss at reference distance.
        d0_m: Reference distance in meters.

    Returns:
        dict with keys: tx_power_dbm, tx_antenna_gain_dbi, cable_loss_db,
        path_loss_db, rx_antenna_gain_dbi, rx_power_dbm, noise_floor_dbm,
        snr_db, link_margin_db, sensitivity_dbm
    """
    pl = PropagationModel(pl0_dbm=pl0_dbm, d0_m=d0_m, n=n)
    pl_db = pl.path_loss(distance_m) - pl._shadow_loss() - pl._fading_loss()
    rx_power = (
        tx_power_dbm + tx_antenna_gain_dbi - cable_loss_db - pl_db + rx_antenna_gain_dbi
    )
    margin = rx_power - SENSITIVITY_SF10
    snr_val = rx_power - pl.noise_floor_dbm
    return {
        "tx_power_dbm": tx_power_dbm,
        "tx_antenna_gain_dbi": tx_antenna_gain_dbi,
        "cable_loss_db": cable_loss_db,
        "path_loss_db": pl_db,
        "rx_antenna_gain_dbi": rx_antenna_gain_dbi,
        "rx_power_dbm": rx_power,
        "noise_floor_dbm": pl.noise_floor_dbm,
        "snr_db": snr_val,
        "link_margin_db": margin,
        "sensitivity_dbm": SENSITIVITY_SF10,
    }
