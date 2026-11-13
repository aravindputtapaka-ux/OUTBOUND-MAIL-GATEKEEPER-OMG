
"""Common finding and module scoring utilities."""

from dataclasses import dataclass, field
from math import isfinite
from typing import List

from score_policy import Severity, RISK_POINTS, validate_score


@dataclass
class Finding:
    name: str
    description: str
    severity: str = Severity.LOW.value
    confidence: float = 0.5
    confirmed: bool = False
    evidence: str = ""

    def __post_init__(self):
        self.name = str(self.name or "").strip() or "UNNAMED_FINDING"
        self.description = str(self.description or "")
        self.evidence = str(self.evidence or "")
        self.severity = str(self.severity).upper()

        allowed = {item.value for item in Severity}
        if self.severity not in allowed:
            raise ValueError(f"Invalid severity: {self.severity}")

        try:
            self.confidence = float(self.confidence)
        except (TypeError, ValueError) as exc:
            raise ValueError("Confidence must be a number between 0 and 1.") from exc
        if self.confidence != self.confidence:  # NaN guard
            raise ValueError("Confidence must be a number between 0 and 1.")
        if not 0 <= self.confidence <= 1:
            raise ValueError("Confidence must be between 0 and 1.")

        if not isinstance(self.confirmed, bool):
            raise ValueError("Confirmed must be a boolean.")


@dataclass
class ModuleResult:
    module: str
    safety_score: float
    inspection_complete: bool
    findings: List[Finding] = field(default_factory=list)
    message: str = ""
    # Pre-projection risk used to derive safety_score. Internal only; lets the
    # overall score aggregate raw evidence without projecting twice.
    projection_risk: float = 0.0

    def __post_init__(self):
        self.module = str(self.module or "").strip().lower()
        if not self.module:
            raise ValueError("Module name is required.")
        if not isinstance(self.inspection_complete, bool):
            raise ValueError("inspection_complete must be a boolean.")
        self.safety_score = validate_score(self.safety_score)
        try:
            self.projection_risk = float(self.projection_risk)
        except (TypeError, ValueError) as exc:
            raise ValueError("projection_risk must be a finite non-negative number.") from exc
        if not isfinite(self.projection_risk) or self.projection_risk < 0:
            raise ValueError("projection_risk must be a finite non-negative number.")
        if not self.findings:
            self.findings = []
        for finding in self.findings:
            if not isinstance(finding, Finding):
                raise TypeError("ModuleResult.findings must contain Finding objects.")


# Penalties are configurable. Tune them against labelled data.
SEVERITY_PENALTIES = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 5,
    Severity.MEDIUM.value: 15,
    Severity.HIGH.value: 35,
    Severity.CRITICAL.value: 60,
}


def calculate_risk_points(findings):
    """Accumulate confidence-adjusted risk, counting each finding name once.

    Detectors overlap on purpose (a text rule and a contextual rule can both
    describe the same fraud pattern), so identical finding names are collapsed
    to their strongest instance instead of double-counting the same evidence.
    """
    strongest = {}
    for finding in findings:
        points = RISK_POINTS[finding.severity]
        if not finding.confirmed:
            points *= finding.confidence
        strongest[finding.name] = max(strongest.get(finding.name, 0.0), points)
    return round(sum(strongest.values()), 2)


def calculate_safety_score(findings):
    """
    Calculate a module safety score.

    Penalties are confidence-adjusted and capped at 100.
    Confirmed findings receive their full severity penalty.
    """

    total_penalty = 0.0

    for finding in findings:
        penalty = SEVERITY_PENALTIES[finding.severity]

        if finding.confirmed:
            total_penalty += penalty
        else:
            total_penalty += penalty * finding.confidence

    return round(max(0.0, 100.0 - min(100.0, total_penalty)), 2)


def build_module_result(
    module,
    findings=None,
    inspection_complete=True,
    message=""
):
    findings = findings or []

    return ModuleResult(
        module=module,
        safety_score=calculate_safety_score(findings),
        inspection_complete=inspection_complete,
        findings=findings,
        message=message,
    )


def finding_to_dict(finding):
    return {
        "name": finding.name,
        "description": finding.description,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "confirmed": finding.confirmed,
        "evidence": finding.evidence,
    }


def module_to_dict(result):
    return {
        "module": result.module,
        "safety_score": result.safety_score,
        "inspection_complete": result.inspection_complete,
        "message": result.message,
        "findings": [
            finding_to_dict(item) for item in result.findings
        ],
    }
