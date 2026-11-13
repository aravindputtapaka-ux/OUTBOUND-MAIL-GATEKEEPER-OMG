
"""Deprecated compatibility layer over :mod:`decision_making`.

The legacy classes and response keys are preserved for existing integrations,
but every verdict is produced by the single authoritative engine. New code
should import from :mod:`decision_making` and :mod:`score_policy`.
"""

from dataclasses import dataclass, field
from typing import Dict, List

from decision_making import evaluate_email as _evaluate_email
from pattern_scoring import Finding as _EngineFinding
from pattern_scoring import ModuleResult as _EngineModuleResult
from score_policy import (
    BLOCKING_SEVERITIES,
    INVESTIGATION_THRESHOLD,
    MODULE_WEIGHTS,
    SAFE_THRESHOLD,
    WARNING_THRESHOLD,
    InvestigationStatus,
    Verdict,
    validate_score,
)


WEIGHTS = MODULE_WEIGHTS


@dataclass
class Finding:
    name: str
    severity: str
    confidence: float = 1.0
    confirmed: bool = False


@dataclass
class ModuleResult:
    module: str
    safety_score: float
    inspection_complete: bool = True
    findings: List[Finding] = field(default_factory=list)

    def validate(self):
        self.module = str(self.module or "").strip().lower()
        if self.module not in WEIGHTS:
            raise ValueError(f"Unknown module: {self.module}")

        self.safety_score = validate_score(self.safety_score)

        for finding in self.findings:
            if not 0 <= finding.confidence <= 1:
                raise ValueError("Finding confidence must be between 0 and 1")


def _normalize_severity(value):
    severity = str(value or "").upper()
    return "LOW" if severity == "MINOR" else severity


def _adapt(module, result: ModuleResult) -> _EngineModuleResult:
    result.validate()
    findings = [
        _EngineFinding(
            name=getattr(finding, "name", module),
            description=getattr(finding, "description", "") or getattr(finding, "name", ""),
            severity=_normalize_severity(getattr(finding, "severity", "LOW")),
            confidence=getattr(finding, "confidence", 1.0),
            confirmed=bool(getattr(finding, "confirmed", False)),
            evidence=getattr(finding, "evidence", ""),
        )
        for finding in result.findings
    ]
    return _EngineModuleResult(
        module=module,
        safety_score=result.safety_score,
        inspection_complete=bool(result.inspection_complete),
        findings=findings,
    )


def calculate_weighted_score(modules: Dict[str, ModuleResult]) -> float:
    expected = set(WEIGHTS)
    received = set(modules)

    if received != expected:
        raise ValueError(f"Expected modules {expected}, received {received}")

    return round(
        sum(modules[name].safety_score * WEIGHTS[name] for name in WEIGHTS),
        2,
    )


def get_lowest_module(modules: Dict[str, ModuleResult]) -> ModuleResult:
    return min(
        modules.values(),
        key=lambda module: module.safety_score,
    )


def has_hard_block(modules: Dict[str, ModuleResult]) -> bool:
    for module in modules.values():
        for finding in module.findings:
            if (
                str(finding.severity).upper() in BLOCKING_SEVERITIES
                and finding.confirmed
            ):
                return True

    return False


def evaluate_email(
    modules: Dict[str, ModuleResult],
    investigation_status: str = "NOT_REQUIRED",
) -> dict:
    expected = set(WEIGHTS)
    if set(modules) != expected:
        raise ValueError(f"Expected modules {expected}, received {set(modules)}")

    adapted = {
        name: _adapt(name, result)
        for name, result in modules.items()
    }

    decision = _evaluate_email(adapted.values(), investigation_status)

    individual_scores = {}
    for name, result in adapted.items():
        safety = round(result.safety_score, 2)
        individual_scores[name] = {
            "safety_score": safety,
            "risk_score": round(100 - safety, 2),
            "weight": WEIGHTS[name],
            "inspection_complete": result.inspection_complete,
        }

    return {
        "verdict": decision["verdict"],
        "overall_safety_score": decision["overall_safety_score"],
        "overall_risk_score": round(100 - decision["overall_safety_score"], 2),
        "individual_scores": individual_scores,
        "lowest_module": decision["lowest_scoring_module"],
        "lowest_module_score": decision["lowest_module_score"],
        "investigation_required": decision["investigation"]["required"],
        "deeper_investigation": decision["investigation"]["deep_investigation_required"],
        "investigation_status": decision["investigation"]["status"],
        "incomplete_modules": sorted(
            name for name, result in adapted.items()
            if not result.inspection_complete
        ),
        "reason": "; ".join(decision["reasons"]),
        "sending_allowed": decision["sending_allowed"],
    }
