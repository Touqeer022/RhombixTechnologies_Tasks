"""
signal_model.py
A simplified RF power-budget model for a passive (unpowered) RFID/NFC tag.

WHY THIS MATTERS FOR "RFID BLOCKING":
Passive RFID tags (the kind in contactless cards and passports) have no
battery. They are powered entirely by the electromagnetic field radiated by
a reader. If the received power at the tag falls below the tag's minimum
operating threshold, the tag's chip never powers up and CANNOT respond -
not "refuses to", but is physically incapable of it. This is the real
mechanism behind "RFID-blocking" wallets/sleeves: a conductive (Faraday)
layer attenuates the reader's field enough that the tag never receives
enough energy to wake up, regardless of how sophisticated the reader is.

This module is a deliberately simplified illustrative model (log-distance
path loss), not a certified RF engineering tool - it's accurate enough to
demonstrate the *shape* of the problem (why proximity and shielding matter)
for a security-education project, not for real antenna/EMC design.
"""

import math
from dataclasses import dataclass

# Typical contactless smart-card / NFC operating assumptions (illustrative):
DEFAULT_READER_TX_DBM = 20.0        # a generous/"boosted" reader, e.g. a skimmer
TAG_MIN_POWER_DBM = -20.0           # minimum received power for the tag IC to power up
REFERENCE_DISTANCE_M = 0.01         # 1 cm reference point
PATH_LOSS_EXPONENT = 3.0            # near-field RFID attenuates faster than free-space (n=2)


@dataclass
class SignalResult:
    distance_m: float
    shielding_db: float
    received_power_dbm: float
    tag_powered: bool


def path_loss_db(distance_m: float) -> float:
    """
    Log-distance path loss relative to REFERENCE_DISTANCE_M.
    Returns 0 dB loss at the reference distance, increasing with distance.
    """
    distance_m = max(distance_m, REFERENCE_DISTANCE_M)
    return 10 * PATH_LOSS_EXPONENT * math.log10(distance_m / REFERENCE_DISTANCE_M)


def received_power_dbm(
    distance_m: float,
    shielding_db: float = 0.0,
    tx_power_dbm: float = DEFAULT_READER_TX_DBM,
) -> float:
    """
    Power actually reaching the tag's antenna, after free-space-ish
    attenuation over distance and any additional shielding attenuation
    (e.g. a Faraday-cage wallet/sleeve).
    """
    return tx_power_dbm - path_loss_db(distance_m) - shielding_db


def evaluate(
    distance_m: float,
    shielding_db: float = 0.0,
    tx_power_dbm: float = DEFAULT_READER_TX_DBM,
    min_power_dbm: float = TAG_MIN_POWER_DBM,
) -> SignalResult:
    power = received_power_dbm(distance_m, shielding_db, tx_power_dbm)
    return SignalResult(
        distance_m=distance_m,
        shielding_db=shielding_db,
        received_power_dbm=power,
        tag_powered=power >= min_power_dbm,
    )


# Illustrative shielding levels for common real-world products, used by the
# simulation/demo layer. These are representative orders of magnitude for
# teaching purposes, not measured values for any specific product.
SHIELDING_NONE_DB = 0.0
SHIELDING_THIN_SLEEVE_DB = 40.0     # a basic RFID-blocking sleeve
SHIELDING_WALLET_DB = 70.0          # a well-built shielded wallet
SHIELDING_FARADAY_BAG_DB = 100.0    # a dedicated Faraday bag
