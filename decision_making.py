"""Hybrid decision engine for Outbound Mail Gatekeeper.

Exactly one verdict implementation lives here. Validator reports are adapted
into the common :class:`pattern_scoring.ModuleResult` shape, then evaluated by
a fixed precedence:

1. any mandatory inspection incomplete  -> RESTRICTED
2. any confirmed HIGH/CRITICAL finding  -> RESTRICTED
3. investigation UNRESOLVED             -> RESTRICTED
4. lowest module below 75 (not CLEARED) -> RESTRICTED
5. investigation PENDING                -> WARNING
6. lowest module below 85               -> WARNING (investigation required)
7. otherwise                            -> weighted policy score
"""

from math import isfinite

from score_policy import (
    MODULE_WEIGHTS,
    SAFE_THRESHOLD,
    WARNING_THRESHOLD,
    INVESTIGATION_THRESHOLD,
    DEEP_INVESTIGATION_THRESHOLD,
    POLICY_RESTRICTED_RISK,
    POLICY_WARNING_RISK,
    MAX_CONTEXT_PENALTY,
    OVERALL_CORROBORATION_FACTOR,
    OVERALL_EXTRA_MODULE_RISK,
    BLOCKING_SEVERITIES,
    VALID_SEVERITIES,
    Verdict,
    InvestigationStatus,
    clamp_to_status,
    project_overall_score,
    project_safety_score,
)
from pattern_scoring import (
    Finding as ScoringFinding,
    ModuleResult,
    calculate_risk_points,
    module_to_dict,
)
HARD_BLOCK_CODES = {
    "DEATH_THREAT",
    "THREATENING_EXTORTION",
    "VIOLENT_THREAT",
    "PHYSICAL_HARM_THREAT",
    "PHYSICAL_HARM_INTIMIDATION",
}

REQUIRED_MODULES = {"content", "url", "attachments"}
MODULE_ORDER = {name: index for index, name in enumerate(MODULE_WEIGHTS)}
MODULE_LABEL = {
    "content": "CONTENT",
    "url": "URL",
    "attachments": "ATTACHMENTS",
}

_FAILURE_CODE_SUFFIXES = (
    "_FAILED", "_UNAVAILABLE", "_ERROR", "_INCOMPLETE", "_FAILURE", "_SCAN_INCOMPLETE",
)
_INCOMPLETE_COVERAGE_STATES = {
    "failed", "incomplete", "required_unavailable", "unavailable",
    "partial", "timeout", "error", "skipped",
}


def _is_inspection_failure(item):
    category = str(item.get("category", "")).upper()
    code = str(item.get("code", "")).upper()
    return category == "INSPECTION_FAILURE" or code.endswith(_FAILURE_CODE_SUFFIXES)


def _report_findings(report):
    """Return finding dictionaries from one validator report."""
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        return []

    normalized = [item for item in findings if isinstance(item, dict)]

    attachments = report.get("attachments", [])
    if isinstance(attachments, list):
        for attachment in attachments:
            if not isinstance(attachment, dict):
                continue
            for key in ("findings", "advisories"):
                items = attachment.get(key, [])
                if isinstance(items, list):
                    normalized.extend(
                        {**item, "filename": attachment.get("filename")}
                        for item in items
                        if isinstance(item, dict)
                    )
    return normalized


def _coerce_confidence(value):
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.5
    if not isfinite(confidence) or not 0 <= confidence <= 1:
        return 0.5
    return confidence


def _normalize_severity(value):
    severity = str(value or "").upper()
    if severity == "MINOR":
        severity = "LOW"
    return severity if severity in VALID_SEVERITIES else "LOW"

def _is_hard_block_finding(item):
    code = str(
        item.get("code") or item.get("name") or ""
    ).strip().upper()

    return code in HARD_BLOCK_CODES

def _scoring_findings(report, *, module):
    findings = []
    for item in _report_findings(report):
        findings.append(ScoringFinding(
            name=str(item.get("code") or item.get("name") or f"{module}_finding"),
            description=str(item.get("message") or item.get("reason") or ""),
            severity=_normalize_severity(item.get("severity")),
            confidence=_coerce_confidence(item.get("confidence", 0.5)),
            confirmed=(
    item.get("confirmed") is True
    or _is_hard_block_finding(item)
),
            evidence=str(item.get("evidence") or item.get("filename") or ""),
        ))
    return findings


def _report_is_complete(report):
    flag = report.get("inspection_complete", True)
    if not isinstance(flag, bool):
        # A non-boolean completeness flag cannot be trusted.
        return False
    if flag is False:
        return False

    if "coverage" in report:
        coverage = report.get("coverage")
        if not isinstance(coverage, dict):
            return False
        for value in coverage.values():
            if value is False or value is None:
                return False
            if isinstance(value, str) and value.strip().lower() in _INCOMPLETE_COVERAGE_STATES:
                return False

    return not any(_is_inspection_failure(item) for item in _report_findings(report))


def _coerce_score(value):
    """Return a validated 0-100 score, or None when the value is unusable."""
    if value is None or isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not isfinite(score) or not 0 <= score <= 100:
        return None
    return round(score, 2)


def _coerce_risk(value):
    """Return a non-negative context-risk value, or 0 when unusable."""
    if value is None or isinstance(value, bool):
        return 0.0
    try:
        risk = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not isfinite(risk) or risk < 0:
        return 0.0
    return risk


def _module_result_from_report(module, report):
    findings = _scoring_findings(report, module=module)
    status = str(report.get("status") or "").strip().upper()

    explicit_score = _coerce_score(report.get("safety_score"))
    if explicit_score is None:
        explicit_score = _coerce_score(report.get("confidence_score"))
    context_penalty = _coerce_risk(report.get("context_penalty"))

    inspection_complete = _report_is_complete(report)
    if status not in {"", "SAFE", "WARNING", "RESTRICTED"}:
        # Unknown status from an upstream validator: fail closed.
        inspection_complete = False
        findings.append(ScoringFinding(
            name=f"{MODULE_LABEL[module]}_STATUS_UNKNOWN",
            description=f"The {module} validator returned an unrecognized status.",
            severity="HIGH",
            confidence=1.0,
            confirmed=False,
        ))

    actionable = [item for item in findings if item.severity != "INFO"]
    blocking = any(
        (
            item.confirmed
            and item.severity in BLOCKING_SEVERITIES
        )
        or item.name.strip().upper() in HARD_BLOCK_CODES
        for item in actionable
    )
    risk = calculate_risk_points(findings)

    # A validator-provided confidence/safety score is the module's final score.
    # The compatibility interface in hybrid_scoring.py uses that score directly
    # and derives module risk as (100 - score). Keep the same contract in the
    # portal path instead of re-projecting an already-scored module from its
    # findings a second time. Findings and inspection state still control the
    # verdict, so a score can never override a hard block or incomplete scan.
    if explicit_score is not None:
        if status == "RESTRICTED" or blocking or not inspection_complete or explicit_score < WARNING_THRESHOLD:
            band = "RESTRICTED"
            score = min(explicit_score, WARNING_THRESHOLD - 0.1)
        elif status == "WARNING" or actionable or explicit_score < SAFE_THRESHOLD:
            band = "WARNING"
            score = min(max(explicit_score, WARNING_THRESHOLD), SAFE_THRESHOLD - 0.1)
        else:
            band = "SAFE"
            score = explicit_score
        projection_risk = max(0.0, 100.0 - score)
    elif status == "RESTRICTED" or blocking or not inspection_complete:
        band = "RESTRICTED"
        if explicit_score is not None and explicit_score < WARNING_THRESHOLD:
            risk += (100.0 - explicit_score) * 0.5
        if risk <= 0:
            risk = POLICY_RESTRICTED_RISK
        projection_risk = risk + context_penalty * 0.5
        score = project_safety_score(projection_risk, band)
    elif (
        explicit_score is not None
        and explicit_score < WARNING_THRESHOLD
    ):
        # An upstream validator that scored the module below the warning floor
        # is treated as a restriction even when it did not set a status.
        band = "RESTRICTED"
        risk = max(risk + (100.0 - explicit_score) * 0.5, POLICY_RESTRICTED_RISK)
        projection_risk = risk + context_penalty * 0.5
        score = project_safety_score(projection_risk, band)
    elif status == "WARNING" or actionable:
        band = "WARNING"
        # Findings drive the score. When an upstream validator only signals a
        # warning (no itemized findings), its own score deficit becomes risk.
        gap = 0.0 if explicit_score is None else max(0.0, 100.0 - explicit_score)
        projection_risk = risk + gap + context_penalty * 0.5
        score = project_safety_score(projection_risk, band)
    else:
        base = 100.0 if explicit_score is None else explicit_score
        score = max(85.0, min(100.0, base - context_penalty))
        projection_risk = 100.0 - score

    # Match hybrid_scoring._adapt(): overall aggregation consumes each module's
    # final safety score as risk = 100 - safety_score. Do not aggregate the
    # pre-projection finding risk here, otherwise the portal and compatibility
    # interface can report different overall scores for the same module scores.
    projection_risk = max(0.0, 100.0 - score)

    if status == "RESTRICTED":
        findings.append(ScoringFinding(
            name=f"{module.upper()}_POLICY_RESTRICTED",
            description=f"The {module} validator returned RESTRICTED.",
            severity="HIGH",
            confidence=1.0,
            confirmed=True,
        ))

    return ModuleResult(
        module=module,
        safety_score=score,
        inspection_complete=inspection_complete,
        findings=findings,
        projection_risk=projection_risk,
    )


def _score_status(score, inspection_complete, findings=()):
    if not inspection_complete:
        return Verdict.RESTRICTED.value
    if score is None or not 0 <= score <= 100:
        return Verdict.RESTRICTED.value
    if any(
        finding.confirmed and finding.severity in BLOCKING_SEVERITIES
        for finding in findings
    ):
        return Verdict.RESTRICTED.value
    if score < WARNING_THRESHOLD:
        return Verdict.RESTRICTED.value
    if score < SAFE_THRESHOLD:
        return Verdict.WARNING.value
    return Verdict.SAFE.value


def _public_finding(item, source):
    return {
        **item,
        "code": str(item.get("code") or item.get("name") or "SECURITY_FINDING"),
        "severity": _normalize_severity(item.get("severity")),
        "message": str(item.get("message") or item.get("reason") or "Security finding requires review."),
        "source": source,
    }


def _report_for_module(data, *, module):
    """Never let a malformed detector result disappear into a SAFE verdict."""
    if isinstance(data, dict):
        findings = data.get("findings", [])
        if isinstance(findings, list) and all(isinstance(item, dict) for item in findings):
            return data

    name = MODULE_LABEL[module]
    return {
        "status": "RESTRICTED",
        "inspection_complete": False,
        "findings": [{
            "code": f"{name}_SCAN_INCOMPLETE",
            "category": "INSPECTION_FAILURE",
            "severity": "HIGH",
            "message": f"The {module} scanner did not return a valid inspection report.",
        }],
        "coverage": {"url_syntax_inspection" if module == "url" else "runtime_text_rules": "failed"},
        "attachments": [],
    }


def decide_email(content, urls, attachment_report=None):
    """Adapt the existing validator reports to the hybrid decision engine.

    The validator report schemas and the endpoint response shape remain intact.
    Explicit safety/confidence scores are honored; otherwise raw findings use
    the existing confidence-adjusted severity penalty policy.
    """
    reports = {
        "content": _report_for_module(content, module="content"),
        "url": _report_for_module(urls, module="url"),
        "attachments": (
            {"status": "SAFE", "findings": [], "attachments": []}
            if attachment_report is None
            else _report_for_module(attachment_report, module="attachments")
        ),
    }

    results = [
        _module_result_from_report(name, report)
        for name, report in reports.items()
    ]
    decision = evaluate_email(results)
    result_by_module = {item.module: item for item in results}

    validation_results = {}
    for name in ("content", "url"):
        report = reports[name]
        result = result_by_module[name]
        public_report = {
            **report,
            "findings": [
                _public_finding(item, "urls" if name == "url" else name)
                for item in report.get("findings", [])
                if isinstance(item, dict)
            ],
            "status": _score_status(
                result.safety_score,
                result.inspection_complete,
                result.findings,
            ),
            "confidence_score": result.safety_score,
            "safety_score": result.safety_score,
        }
        if name == "url" and not report.get("url_count") and not public_report["findings"]:
            validation_results["urls"] = "empty"
        else:
            validation_results[name if name != "url" else "urls"] = public_report

    attachment_result = result_by_module["attachments"]
    validation_results["attachments"] = {
        **reports["attachments"],
        "status": _score_status(
            attachment_result.safety_score,
            attachment_result.inspection_complete,
            attachment_result.findings,
        ),
        "confidence_score": attachment_result.safety_score,
        "safety_score": attachment_result.safety_score,
        "files": reports["attachments"].get("attachments", []),
    }

    raw_findings = []
    for name, report in reports.items():
        source = "urls" if name == "url" else name
        raw_findings.extend(
            _public_finding(item, source)
            for item in _report_findings(report)
        )

    return {
        "status": decision["verdict"],
        "can_send": decision["sending_allowed"],
        "confidence_score": decision["overall_safety_score"],
        "requires_acknowledgement": decision["verdict"] == Verdict.WARNING.value,
        "confidence_source": "hybrid_weighted_policy_score",
        "validation_results": validation_results,
        "findings": raw_findings,
        "warning_challenge": reports["attachments"].get("warning_challenge"),
        "decision": decision,
    }


def calculate_weighted_score(results):
    missing = REQUIRED_MODULES - set(results)
    if missing:
        raise ValueError(f"Missing module results: {', '.join(sorted(missing))}")

    score = 0.0

    for module, weight in MODULE_WEIGHTS.items():
        score += results[module].safety_score * weight

    return round(score, 2)


def get_lowest_module(results):
    return min(
        results.values(),
        key=lambda result: (
            result.safety_score,
            MODULE_ORDER.get(result.module, len(MODULE_ORDER)),
        ),
    )


def get_confirmed_blocking_findings(results):
    blocking = []

    for result in results.values():
        for finding in result.findings:
            if (
                (
                    finding.confirmed
                    and finding.severity in BLOCKING_SEVERITIES
                )
                or finding.name.strip().upper() in HARD_BLOCK_CODES
            ):
                blocking.append({
                    "module": result.module,
                    "name": finding.name,
                    "severity": finding.severity,
                    "description": finding.description,
                })

    return blocking


def _overall_projection_risk(results, verdict, lowest):
    """Aggregate raw module risk for the overall score.

    The weakest module anchors the risk; other modules contribute their own
    evidence at reduced weight, and each additional module below the SAFE
    threshold adds corroborating risk. Module scores themselves are unchanged.
    """
    risks = {}
    for name, result in results.items():
        risk = max(0.0, float(getattr(result, "projection_risk", 0.0) or 0.0))
        if risk == 0.0 and result.safety_score < 100.0:
            # Results built outside the report adapter carry no raw risk.
            risk = 100.0 - result.safety_score
        risks[name] = risk

    ordered = sorted(risks.values(), reverse=True)
    risk_total = ordered[0] + OVERALL_CORROBORATION_FACTOR * sum(ordered[1:])
    if verdict == Verdict.SAFE:
        return min(MAX_CONTEXT_PENALTY, risk_total)

    flagged = sum(
        1 for result in results.values()
        if result.safety_score < SAFE_THRESHOLD
    )
    risk_total += OVERALL_EXTRA_MODULE_RISK * max(0, flagged - 1)
    if verdict == Verdict.RESTRICTED and lowest.safety_score >= WARNING_THRESHOLD:
        # The restriction came from policy or an unresolved investigation
        # rather than a low module score; keep the overall risk proportionate.
        risk_total = max(risk_total, POLICY_RESTRICTED_RISK)
    return risk_total


def make_response(
    verdict,
    results,
    lowest,
    investigation_status,
    investigation_required,
    deep_investigation_required,
    reasons,
    blocking_findings,
):
    # The reported index aggregates all modules but is projected into the band
    # owned by the verdict, so it can never contradict the weakest module.
    risk_total = _overall_projection_risk(results, verdict, lowest)
    overall_score = project_overall_score(risk_total, verdict.value)
    overall_score = clamp_to_status(verdict.value, overall_score)

    return {
        "verdict": verdict.value,
        "overall_safety_score": overall_score,
        "module_scores": {
            name: result.safety_score
            for name, result in results.items()
        },
        "lowest_scoring_module": lowest.module,
        "lowest_module_score": lowest.safety_score,
        "investigation": {
            "required": investigation_required,
            "deep_investigation_required": deep_investigation_required,
            "status": investigation_status.value,
        },
        "blocking_findings": blocking_findings,
        "reasons": reasons,
        "sending_allowed": verdict == Verdict.SAFE,
        "modules": {
            name: module_to_dict(result)
            for name, result in results.items()
        },
    }


def evaluate_email(
    module_results,
    investigation_status=InvestigationStatus.NOT_REQUIRED,
):
    """
    Evaluate all mandatory OMG modules.

    investigation_status can be:
      NOT_REQUIRED
      PENDING
      CLEARED
      UNRESOLVED

    An investigation status of CLEARED means follow-up checks
    have actually been completed and cleared the concern.
    """
    if isinstance(investigation_status, str):
        try:
            investigation_status = InvestigationStatus(
                investigation_status.strip().upper()
            )
        except ValueError as exc:
            raise ValueError("Invalid investigation status") from exc
    if not isinstance(investigation_status, InvestigationStatus):
        raise ValueError("Invalid investigation status")

    results = {}
    for result in module_results:
        if not isinstance(result, ModuleResult):
            raise TypeError("evaluate_email expects ModuleResult objects.")
        if result.module in results:
            raise ValueError(f"Duplicate module result: {result.module}")
        results[result.module] = result

    if set(results) != REQUIRED_MODULES:
        raise ValueError(
            "All three modules are mandatory: "
            "content, url, attachments."
        )

    weighted_score = calculate_weighted_score(results)
    lowest = get_lowest_module(results)

    blocking_findings = get_confirmed_blocking_findings(results)

    incomplete_modules = sorted(
        name for name, result in results.items()
        if not result.inspection_complete
    )

    investigation_required = (
        lowest.safety_score < INVESTIGATION_THRESHOLD
    )

    deep_investigation_required = (
        lowest.safety_score < DEEP_INVESTIGATION_THRESHOLD
    )

    reasons = []

    if incomplete_modules:
        verdict = Verdict.RESTRICTED
        reasons.append(
            "Mandatory inspection incomplete: " + ", ".join(incomplete_modules)
        )

    elif blocking_findings:
        verdict = Verdict.RESTRICTED
        reasons.append("Confirmed high or critical security finding.")

    elif investigation_status is InvestigationStatus.UNRESOLVED:
        verdict = Verdict.RESTRICTED
        reasons.append("Risk remains unresolved after investigation.")

    elif (
        deep_investigation_required
        and investigation_status is not InvestigationStatus.CLEARED
    ):
        verdict = Verdict.RESTRICTED
        reasons.append("Lowest module score is below the permitted warning threshold.")

    elif investigation_status is InvestigationStatus.PENDING:
        verdict = Verdict.WARNING
        reasons.append("Additional investigation is pending.")

    elif (
        investigation_status is InvestigationStatus.NOT_REQUIRED
        and investigation_required
    ):
        verdict = Verdict.WARNING
        reasons.append("Lowest module score requires additional investigation.")

    elif weighted_score >= SAFE_THRESHOLD:
        verdict = Verdict.SAFE
        reasons.append("All scans complete and safety score is acceptable.")

    elif weighted_score >= WARNING_THRESHOLD:
        verdict = Verdict.WARNING
        reasons.append("Overall safety score is in the warning range.")

    else:
        verdict = Verdict.RESTRICTED
        reasons.append(
            "Overall safety score is below the permitted warning threshold."
        )

    return make_response(
        verdict,
        results,
        lowest,
        investigation_status,
        investigation_required,
        deep_investigation_required,
        reasons,
        blocking_findings,
    )
