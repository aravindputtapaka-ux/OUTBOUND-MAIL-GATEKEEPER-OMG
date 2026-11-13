
"""Central policy configuration for OMG."""

from enum import Enum
from math import isfinite
from numbers import Real

MODULE_WEIGHTS = {
    "content": 0.40,
    "url": 0.30,
    "attachments": 0.30,
}

SAFE_THRESHOLD = 85.0
WARNING_THRESHOLD = 75.0

INVESTIGATION_THRESHOLD = 85.0
DEEP_INVESTIGATION_THRESHOLD = 75.0

MIN_SCORE = 0.0
MAX_SCORE = 100.0

# Highest score a module may have while still carrying an actionable finding.
# Scores are reported to one decimal place, so a WARNING must stay below 85.0
# even after rounding.
WARNING_CEILING = round(SAFE_THRESHOLD - 0.1, 2)

# Deterministic score assigned to a module whose validator returned RESTRICTED
# without any itemized finding to derive a score from.
RESTRICTED_MODULE_SCORE = 29.99

# Risk points per finding. Confirmed findings use the full value; unconfirmed
# findings are scaled by detector confidence. The values are deliberately
# spread so the reported score moves with severity instead of snapping to a
# fixed value per verdict.
RISK_POINTS = {
    "INFO": 0,
    "LOW": 12,
    "MEDIUM": 22,
    "HIGH": 45,
    "CRITICAL": 60,
}

# Each verdict owns a score range. The risk index is projected into that range,
# so the reported number always agrees with the policy verdict while remaining
# a continuous function of severity, confidence and finding count.
SCORE_PROJECTION = {
    "RESTRICTED": (0.0, round(WARNING_THRESHOLD - 0.1, 2)),
    "WARNING": (WARNING_THRESHOLD, WARNING_CEILING),
    "SAFE": (SAFE_THRESHOLD, 100.0),
}

# Risk needed to reach the bottom of each projected range.
RESTRICTED_RISK_SCALE = 150.0
WARNING_RISK_SCALE = 30.0

# Risk assumed for an upstream validator that reports RESTRICTED/WARNING with
# no itemized findings (for example an attachment policy block).
POLICY_RESTRICTED_RISK = 90.0
POLICY_WARNING_RISK = 12.0

# Maximum benign-context deduction applied to a clean module score.
MAX_CONTEXT_PENALTY = 15.0

# Overall-score aggregation. The worst module anchors the overall risk; the
# remaining modules contribute at reduced weight, and every extra module below
# the SAFE threshold adds corroborating risk. Module scores are unaffected.
OVERALL_CORROBORATION_FACTOR = 0.25
OVERALL_EXTRA_MODULE_RISK = 2.5

# Overall warnings combine corroborating module evidence, so their risk index
# is larger than any single module's. A scale anchored to one HIGH finding
# keeps the overall score spread across 75-84.9 instead of every multi-finding
# warning saturating at the 75.0 floor. Module scores continue to use
# WARNING_RISK_SCALE.
OVERALL_WARNING_RISK_SCALE = 45.0


def _project_risk(risk_points, verdict, warning_scale=None):
    if isinstance(risk_points, bool) or not isinstance(risk_points, Real):
        raise ValueError("Risk points must be a finite number.")
    risk = float(risk_points)
    if not isfinite(risk):
        raise ValueError("Risk points must be a finite number.")
    risk = max(0.0, risk)

    verdict = str(verdict).upper()
    if verdict not in SCORE_PROJECTION:
        raise ValueError(f"Unknown score verdict: {verdict}")

    if verdict == "RESTRICTED":
        span = RESTRICTED_RISK_SCALE
    elif verdict == "WARNING":
        span = warning_scale or WARNING_RISK_SCALE
    else:
        return round(100.0 - min(MAX_CONTEXT_PENALTY, risk), 2)

    low, high = SCORE_PROJECTION[verdict]
    return round(high - (high - low) * min(1.0, risk / span), 2)


def project_safety_score(risk_points, verdict):
    """Map accumulated risk points onto the score range for a verdict.

    The mapping is monotonic: more or stronger findings always produce a lower
    score, and the result can never contradict the verdict band.
    """
    return _project_risk(risk_points, verdict)


def project_overall_score(risk_points, verdict):
    """Project aggregated module evidence into the verdict's overall band.

    Warnings use a wider risk scale than individual modules because the
    aggregate includes corroborating evidence from every module.
    """
    return _project_risk(
        risk_points,
        verdict,
        OVERALL_WARNING_RISK_SCALE if str(verdict).upper() == "WARNING" else None,
    )


# Score bands for display. Each verdict owns a disjoint half-open range:
# [0,75) RESTRICTED, [75,85) WARNING, [85,100] SAFE.
BANDS = {
    "RESTRICTED": (0.0, WARNING_THRESHOLD),
    "WARNING": (WARNING_THRESHOLD, SAFE_THRESHOLD),
    "SAFE": (SAFE_THRESHOLD, 100.0),
}


class Verdict(str, Enum):
    SAFE = "SAFE"
    WARNING = "WARNING"
    RESTRICTED = "RESTRICTED"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class InvestigationStatus(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    CLEARED = "CLEARED"
    UNRESOLVED = "UNRESOLVED"


BLOCKING_SEVERITIES = {
    Severity.HIGH.value,
    Severity.CRITICAL.value,
}

VALID_SEVERITIES = {item.value for item in Severity}


def validate_score(score):
    if isinstance(score, bool):
        raise ValueError("Boolean is not a valid score.")

    score = float(score)

    if not MIN_SCORE <= score <= MAX_SCORE:
        raise ValueError("Score must be between 0 and 100.")

    return round(score, 2)


def score_band(score):
    if (isinstance(score, bool) or not isinstance(score, Real)
            or not isfinite(float(score)) or not MIN_SCORE <= float(score) <= MAX_SCORE):
        raise ValueError("Score must be a finite number between 0 and 100.")

    if score < BANDS["WARNING"][0]:
        return "RESTRICTED"
    if score < BANDS["SAFE"][0]:
        return "WARNING"
    return "SAFE"


def clamp_to_status(status, score):
    status = str(status).upper()
    if status not in BANDS:
        raise ValueError(f"Unknown score status: {status}")
    if isinstance(score, bool) or not isinstance(score, Real) or not isfinite(float(score)):
        raise ValueError("Score must be a finite number.")

    lower, upper = BANDS[status]
    # Reported scores use one decimal place; keep a non-SAFE score strictly
    # inside its own band so it can never display as the next verdict's floor.
    upper_inclusive = upper if status == "SAFE" else round(upper - 0.1, 2)
    return round(min(max(float(score), lower), upper_inclusive), 2)


def validate_weights():
    if round(sum(MODULE_WEIGHTS.values()), 6) != 1.0:
        raise ValueError("Module weights must total 1.0.")


validate_weights()
