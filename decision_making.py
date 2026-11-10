"""Unified deterministic policy decision and three-contribution safety score.

Each module starts with an EXACT 100/3 policy-credit contribution. Risk evidence
subtracts deterministic points in that module. Status comes from findings and
mandatory inspection results, never from an average that can hide a CRITICAL
issue. A documented enforcement deduction, applied to the risk-bearing module,
keeps the numeric score inside the final policy band. This is NOT a calibrated
probability of safety, and does not certify any URL or attachment malware-free.
"""
from __future__ import annotations
from typing import Any

from score_policy import score_band

MODULE_CAP = 100.0 / 3.0
INSPECTION_FAILURE_SUFFIXES = ("_FAILED", "_UNAVAILABLE", "_ERROR", "_INCOMPLETE", "_FAILURE")
WARNING_ELIGIBLE_CODES = frozenset({
    "SHORTENED_URL", "POTENTIAL_PAYMENT_REDIRECTION", "POTENTIAL_ACCOUNT_VERIFICATION_LURE",
    "INSECURE_LOGIN_URL", "SENSITIVE_FINANCIAL_CHANGE", "ACCOUNT_UPDATE_LINK_REVIEW",
    "PAYMENT_UPDATE_LINK_REVIEW", "PAYMENT_CHANGE_LINK_REVIEW", "VENDOR_PAYMENT_CHANGE_REVIEW",
    "LOOKALIKE_TRUSTED_DOMAIN",
})
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MINOR": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
BASE_PENALTIES = {"INFO": 1.5, "LOW": 14.25, "MINOR": 15.5, "MEDIUM": 20.0,
                  "HIGH": 26.0, "CRITICAL": 30.0}
EXTRA_PENALTIES = {
    "VENDOR_PAYMENT_DIVERSION": 1.4,
    "CREDENTIAL_COLLECTION_REQUEST": 1.2,
    "CREDENTIAL_PHISHING": 1.0,
    "PAYMENT_APPROVAL_BYPASS_LINK": 1.1,
    "SHORTENED_URL": 0.8,
    "PAYMENT_CHANGE_LINK_REVIEW": 1.2,
    "INSECURE_LOGIN_URL": 1.5,
    "SENSITIVE_FINANCIAL_CHANGE": -0.9,
}


def _finding(item: dict, source: str, filename: str | None = None, warning: bool = False) -> dict:
    code = str(item.get("code") or "UNKNOWN_FINDING")
    category = str(item.get("category") or ("ATTACHMENT" if source == "attachments" else source.upper()))
    explicit = str(item.get("severity") or "").upper()
    if category == "INSPECTION_FAILURE" or code.endswith(INSPECTION_FAILURE_SUFFIXES):
        severity = "CRITICAL"
    elif explicit in SEVERITY_ORDER:
        severity = explicit
    elif warning or code in WARNING_ELIGIBLE_CODES:
        severity = "MINOR"
    else:
        severity = "HIGH"  # conservative for unclassified existing detector findings
    finding = {"code": code, "category": category, "severity": severity,
               "message": str(item.get("message") or item.get("reason") or "Security review required"),
               "source": source}
    if filename is not None:
        finding["filename"] = filename
    return finding


def _dedupe(findings: list[dict]) -> list[dict]:
    deduped = {}
    for f in findings:
        k = (f.get("source"), f.get("filename"), f["code"], f["message"])
        if k not in deduped:
            deduped[k] = f
    return list(deduped.values())


def _module_status(findings: list[dict]) -> str:
    if any(f["severity"] in {"CRITICAL", "HIGH"} for f in findings):
        return "RESTRICTED"
    if any(f["severity"] in {"LOW", "MINOR", "MEDIUM"} for f in findings):
        return "WARNING"
    return "SAFE"


def _failed_inspection(findings: list[dict]) -> bool:
    return any(f["category"] == "INSPECTION_FAILURE" or f["code"].endswith(INSPECTION_FAILURE_SUFFIXES)
               for f in findings)


def _module_contribution(findings: list[dict], *, inspection_failed: bool = False) -> float:
    """Risk score uses most severe signal plus bounded independent corroboration.

    Repetitions of the same detection code don't amplify the risk; distinct
    signals do, without double-counting a long message as multiple incidents.
    """
    if inspection_failed:
        return 0.0  # No policy safety credit without mandatory inspection.
    by_code: dict[str, float] = {}
    for finding in findings:
        # if finding["severity"] == "INFO":
        #     continue
        code = finding["code"]
        impact = BASE_PENALTIES[finding["severity"]] + EXTRA_PENALTIES.get(code, 0.0)
        by_code[code] = max(by_code.get(code, 0), impact)
    if not by_code:
        return MODULE_CAP
    ranking = sorted(by_code.values(), reverse=True)
    # A dominant threat carries the majority of the loss. Supporting distinct
    # findings add incremental penalty at diminishing rates.
    penalty = ranking[0] + sum(value * (0.12 / i) for i, value in enumerate(ranking[1:], 1))
    return max(0.0, MODULE_CAP - min(MODULE_CAP, penalty))


def _combined_scores(
    c: list[dict], u: list[dict], a: list[dict], status: str,
    *, attachment_failure: bool = False,
) -> tuple[float, dict[str, float]]:
    raw = [
        _module_contribution(c, inspection_failed=_failed_inspection(c)),
        _module_contribution(u, inspection_failed=_failed_inspection(u)),
        _module_contribution(a, inspection_failed=attachment_failure or _failed_inspection(a)),
    ]
    raw_total = sum(raw)
    # Status always wins. In uncommon cases (e.g. one HIGH rule with little
    # corroboration), apply a transparent policy-enforcement deduction to the
    # implicated module so score and status cannot contradict each other.
    if status == "RESTRICTED" and raw_total >= 75:
        excess = raw_total - 74.5
    elif status == "WARNING" and raw_total >= 86:
        excess = raw_total - 85.5
    elif status == "SAFE" and raw_total < 86:
        raise ValueError("SAFE verdict cannot have a low policy safety score")
    else:
        excess = 0.0
    if status == "WARNING" and raw_total < 75:
        # Multiple independent review-only signals are still WARNING, not
        # proven high-risk enforcement findings. The policy review band
        # saturates rather than accidentally labelling them RESTRICTED.
        deficit = 75.25 - raw_total
        buckets = (c, u, a)
        for index in range(3):
            if _module_status(buckets[index]) == "SAFE":
                continue
            credit = min(MODULE_CAP - raw[index], deficit)
            raw[index] += credit
            deficit -= credit
            if deficit <= 1e-9:
                break
    if excess:
        buckets = (c, u, a)
        offending = [i for i, bucket in enumerate(buckets) if _module_status(bucket) != "SAFE"]
        # Attachment-only reported restriction may have no per-file details.
        if not offending:
            offending = [2]
        for index in offending:
            deduction = min(raw[index], excess)
            raw[index] -= deduction
            excess -= deduction
            if excess <= 1e-9:
                break
    # Four-decimal JSON must reconcile to the exact total. Assign residual
    # only to a module that actually earned positive credit. The all-clean
    # 33.3333/33.3333/33.3334 display is a 0.0001 rounding artifact.
    total = round(sum(raw), 4)
    rounded = [round(x, 4) for x in raw]
    residual = round(total - sum(rounded), 4)
    if abs(residual) > 0:
        positive = [i for i, value in enumerate(raw) if value > 0]
        if positive:
            index = max(positive, key=lambda i: (raw[i], i))
            rounded[index] = round(rounded[index] + residual, 4)
    contributions = dict(zip(("text", "URL", "attachments"), rounded))
    if score_band(total) != status:
        raise AssertionError(f"Policy-score mismatch: {status} / {total}")
    return total, contributions


def decide_email(content: dict, urls: dict, attachments: dict | None = None) -> dict[str, Any]:
    """Merge independent module findings without weakening the scanner decisions."""
    c = [_finding(x, "content") for x in content.get("findings", [])]
    u = [_finding(x, "urls") for x in urls.get("findings", [])]
    for source, report, bucket in (("CONTENT", content, c), ("URL", urls, u)):
        declared = report.get("status")
        if declared in {"WARNING", "RESTRICTED"} and not bucket:
            bucket.append(_finding({
                "code": source + ("_REVIEW_REQUIRED" if declared == "WARNING" else "_INSPECTION_INCOMPLETE"),
                "category": "REVIEW" if declared == "WARNING" else "INSPECTION_FAILURE",
                "severity": "MINOR" if declared == "WARNING" else "CRITICAL",
                "message": f"{source} validator declared {declared} without details.",
            }, "content" if source == "CONTENT" else "urls"))
    a: list[dict] = []
    report = attachments
    if report is not None:
        a.extend(_finding(f, "attachments") for f in report.get("findings", []))
        for item in report.get("attachments", []):
            name = str(item.get("filename") or "(unnamed)")
            a.extend(_finding(f, "attachments", name) for f in item.get("findings", []))
            a.extend(_finding(f, "attachments", name, warning=True) for f in item.get("advisories", []))
        if report.get("status") in {"RESTRICTED", "WARNING"} and not a:
            reasons = (report.get("popup") or {}).get("reasons") or []
            for reason in reasons:
                if isinstance(reason, dict):
                    a.append(_finding(reason, "attachments", reason.get("filename")))
                else:
                    a.append(_finding({"code": "ATTACHMENT_RESTRICTED", "message": str(reason)}, "attachments"))
            if not a:
                restricted = report["status"] == "RESTRICTED"
                a.append(_finding({"code": "ATTACHMENT_INSPECTION_INCOMPLETE" if restricted else "ATTACHMENT_REVIEW_REQUIRED",
                                   "category": "INSPECTION_FAILURE" if restricted else "REVIEW",
                                   "severity": "CRITICAL" if restricted else "MINOR",
                                   "message": "Attachment inspection was incomplete." if restricted else "Attachment requires review."},
                                  "attachments"))
    c, u, a = map(_dedupe, (c, u, a))
    c_status, u_status = _module_status(c), _module_status(u)
    a_status = _module_status(a)
    priority = {"SAFE": 0, "WARNING": 1, "RESTRICTED": 2}
    if report is not None:
        declared_a = report.get("status", "RESTRICTED")
        a_status = max((a_status, declared_a), key=lambda st: priority.get(st, 2))
    status = max((c_status, u_status, a_status), key=priority.get)
    incomplete_a = bool(report is not None and report.get("confidence_score") is None and a_status == "RESTRICTED")
    score, contributions = _combined_scores(c, u, a, status, attachment_failure=incomplete_a)
    findings = _dedupe(c + u + a)
    result = {
        "status": status,
        "can_send": status == "SAFE",
        "confidence_score": score,
        "score_contributions": contributions,
        "requires_acknowledgement": status == "WARNING",
        "confidence_source": "policy_safety_score_uncalibrated",
        "validation_results": {
            "content": {"status": c_status, "findings": c},
            "urls": "empty" if urls.get("url_count") == 0 and not u else {"status": u_status, "findings": u},
            "attachments": "empty" if report is None else {
                "status": a_status, "files": report.get("attachments", []),
                "warnings": report.get("warnings", []),
            },
        },
        "findings": findings,
        "patterns_detected": sorted({f["code"] for f in findings}),
        "inspection_coverage": {**content.get("coverage", {}), **urls.get("coverage", {})},
        "popup": None,
    }
    if status == "WARNING":
        result["popup"] = {"show": True, "type": "WARNING", "title": "Email Security Warning",
                           "message": "Review the detected security findings and acknowledge before sending.",
                           "actions": ["EDIT_MAIL", "CLOSE"]}
    elif status == "RESTRICTED":
        result["popup"] = {"show": True, "type": "RESTRICTED", "title": "Email Restricted",
                           "message": "Sending is blocked until the findings are corrected and revalidated.",
                           "actions": ["CLOSE"]}
    if report and report.get("warning_challenge") and status == "WARNING":
        result["warning_challenge"] = report["warning_challenge"]
    return result


def decide_content_and_urls(content: dict, urls: dict) -> dict[str, Any]:
    return decide_email(content, urls, attachments=None)


def decide_attachment_report(report: dict) -> dict[str, Any]:
    """Attachment-only policy: other module scores are neutral, not inspections."""
    return decide_email({"findings": [], "coverage": {}},
                        {"findings": [], "url_count": 0, "coverage": {}}, attachments=report)
