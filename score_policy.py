"""OMG 0–100 uncalibrated policy SAFETY index.

Bands use continuous ranges: 0 <= s < 75 RESTRICTED,
75 <= s < 86 WARNING, 86 <= s <= 100 SAFE.
Security findings determine the verdict BEFORE scoring. A null score indicates
that a mandatory scanner failed; it MUST NOT authorize sending.
"""
from __future__ import annotations
from math import isfinite

BANDS = {"RESTRICTED": (0.0, 74.99), "WARNING": (75.0, 85.99), "SAFE": (86.0, 100.0)}


def score_band(score: float | int | None) -> str | None:
    if score is None:
        return None
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not isfinite(score) or not 0 <= score <= 100:
        raise ValueError("Policy safety score must be a finite number from 0 to 100, or null")
    if score < 75:
        return "RESTRICTED"
    if score < 86:
        return "WARNING"
    return "SAFE"


def clamp_to_status(status: str, score: float | int) -> float:
    if status not in BANDS:
        raise ValueError(f"Unsupported verdict: {status}")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not isfinite(score):
        raise ValueError("Invalid policy safety score")
    low, high = BANDS[status]
    return round(max(low, min(high, float(score))), 2)
