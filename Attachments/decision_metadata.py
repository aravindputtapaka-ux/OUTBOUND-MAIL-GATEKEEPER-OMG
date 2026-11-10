"""OMG explainable, dynamic POLICY SAFETY scores (not calibrated ML probabilities).

Higher = safer. Client scoring bands: [0,75) RESTRICTED, [75,86)
WARNING, [86,100] SAFE. Actual security policy verdicts take precedence:
never use a score to downgrade a block, approve an incomplete scan, or bypass
warning acknowledgment. An unchanged set of identical findings should yield
an unchanged score (deterministic, auditable behavior).
"""
from __future__ import annotations

from math import isfinite
from numbers import Real
from typing import Any
from score_policy import BANDS, clamp_to_status, score_band as shared_score_band

SCORE_BANDS = BANDS
SAFE_BASELINE_SCORE = 97.5  # demo policy baseline, NOT 97.5% probability of safety
WARNING_BASELINE_SCORE = 81.2
RESTRICTED_BASELINE_SCORE = 6.5

# Initial safety anchors. Severity/rule context AND corroborating evidence
# adjust these anchors; none is a learned/calibrated probability.
RULE_SAFETY_SCORES = {
    'DIRECT_THREAT': 8.0,
    'TARGETED_ABUSE': 14.0,
    'CREDENTIAL_REQUEST': 6.5,
    'CREDENTIAL_HARVESTING': 6.5,
    'SEXUAL_SOLICITATION': 11.0,
    'PHISHING_ACCOUNT_URGENCY': 12.0,
    'SPAM_PRIZE_LURE': 16.0,
    'SOFT_REPLY_URGENCY': 81.2,
    'FILENAME_EXCESSIVE_PUNCTUATION': 81.5,
    'PROMOTIONAL_LANGUAGE_WARNING': 81.2,
    'SUBJECT_EXCESSIVE_PUNCTUATION': 83.0,
    'HASH_DENYLIST': 0.0,
    'MALWARE_DETECTED': 0.0,
    'TYPE_MISMATCH': 0.0,
    'FILE_TOO_LARGE': 0.0,
    'TOTAL_SIZE_EXCEEDED': 0.0,
    'TOO_MANY_ATTACHMENTS': 0.0,
    'UNSUPPORTED_EXTENSION': 0.0,
    'PDF_ACTIVE_CONTENT': 5.0,
    'ENCRYPTED_PDF': 0.0,
    'ZIP_TRAVERSAL': 0.0,
    'ZIP_BOMB': 0.0,
    'ZIP_ENCRYPTED': 0.0,
    'BLOCKED_EXTENSION': 0.0,
}

UNKNOWN_SAFETY_CODES = {
    'OCR_UNAVAILABLE', 'OCR_FAILED', 'OCR_DISABLED', 'SCANNER_FAILURE',
    'CLAMAV_UNAVAILABLE', 'CLAMAV_ERROR', 'ANTIVIRUS_UNAVAILABLE',
    'ML_UNAVAILABLE', 'CONTENT_UNINSPECTABLE', 'CONTENT_SCAN_FAILED',
    'CONTENT_SCANNER_FAILURE', 'PARSER_FAILURE', 'SCAN_INCOMPLETE',
}

# More urgent phrasing is a somewhat stronger *warning* signal, not evidence
# of malware. These weights are reviewable organization policy settings.
URGENCY_CUE_DEDUCTION = {'soon': 0.0, 'today': 1.0, 'asap': 2.5}
EXTRA_MATCH_DEDUCTION = 2.0
EXTRA_INDEPENDENT_FINDING_DEDUCTION = 1.5
EXTRA_FLAGGED_ATTACHMENT_DEDUCTION = 1.0

NOTE = (
    'Illustrative, uncalibrated policy safety score (0–100, higher is safer); '
    'not a model probability, accuracy estimate, or malware-free guarantee. '
    'Score varies with detected policy categories, corroborating distinct '
    'findings, supported occurrence counts, and urgency cues. '
    'Unverifiable mandatory inspection returns RESTRICTED with null score.'
)


def score_band(score: float | int | None) -> str | None:
    if score is None:
        return None
    if (isinstance(score, bool) or not isinstance(score, Real)
            or not isfinite(float(score)) or not 0 <= float(score) <= 100):
        raise ValueError('confidence_score must be a finite number between 0 and 100 or null')
    return shared_score_band(score)


def _bounded_occurrences(issue: dict[str, Any]) -> int:
    value = issue.get('occurrences', 1)
    return max(1, min(5, value)) if type(value) is int else 1


def _issue_score(issue: dict[str, Any], status: str) -> float | None:
    code = str(issue.get('code', '')).upper()
    if (code in UNKNOWN_SAFETY_CODES or 'UNAVAILABLE' in code
            or 'SCAN_FAILED' in code or code.endswith('_SCAN_FAILURE')):
        return None
    anchor = RULE_SAFETY_SCORES.get(
        code, WARNING_BASELINE_SCORE if status == 'WARNING' else RESTRICTED_BASELINE_SCORE
    )
    # Repeated independently matched instances are stronger evidence than one.
    anchor -= EXTRA_MATCH_DEDUCTION * (_bounded_occurrences(issue) - 1)
    if code == 'SOFT_REPLY_URGENCY':
        anchor -= URGENCY_CUE_DEDUCTION.get(str(issue.get('urgency_cue', '')).lower(), 0.0)
    return clamp_to_status(status, anchor)


def _status_score(status: str, issues: list[dict[str, Any]]) -> float | None:
    if status == 'SAFE':
        return SAFE_BASELINE_SCORE
    if status not in ('WARNING', 'RESTRICTED'):
        raise ValueError(f'Unknown attachment decision status: {status}')
    if not issues:
        return WARNING_BASELINE_SCORE if status == 'WARNING' else RESTRICTED_BASELINE_SCORE
    scores = [_issue_score(x, status) for x in issues]
    if any(x is None for x in scores):
        return None
    # Different codes and/or different source documents add corroborating
    # evidence; do not increase risk for repeated copies of the same finding.
    evidence_groups = {(str(x.get('code', '')).upper(), str(x.get('source', ''))) for x in issues}
    extra = max(0, len(evidence_groups) - 1)
    score = min(scores) - EXTRA_INDEPENDENT_FINDING_DEDUCTION * extra
    return clamp_to_status(status, score)


def _source_for_score(score: float | None) -> str:
    return 'policy_safety_score_uncalibrated' if score is not None else 'safety_unknown_scan_failed'


def with_decision_metadata(result: dict[str, Any]) -> dict[str, Any]:
    """Annotate an already-determined security verdict, NEVER relax it.

    The scanner's severity decisions come first. This score summarises that
    evidence inside the corresponding client band; it cannot authorize Send.
    """
    result['type'] = {'text': False, 'urls': False, 'attachments': True}
    status = str(result['status']).upper()
    file_scores: list[float | None] = []
    flagged_files = 0
    for item in result.get('attachments', []):
        file_status = str(item.get('status', 'SAFE')).upper()
        issues = list(item.get('findings', [])) + list(item.get('advisories', []))
        score = _status_score(file_status, issues)
        file_scores.append(score)
        if issues:
            flagged_files += 1
        item['confidence_score'] = score
        item['confidence_source'] = _source_for_score(score)
        item['confidence_calibrated'] = False
        item['score_factors'] = {
            'finding_codes': list(dict.fromkeys(str(x.get('code', '')) for x in issues)),
            'finding_count': len(issues),
            'detected_occurrences': sum(_bounded_occurrences(x) for x in issues),
        }

    overall_issues = list(result.get('findings', []))
    if not result.get('attachments'):
        overall_issues.extend((result.get('popup') or {}).get('reasons', []))
    score = _status_score(status, overall_issues)
    if any(x is None for x in file_scores):
        score = None
    elif file_scores:
        # Worst attachment wins, and additional flagged files lower the overall
        # score slightly. SAFE siblings don't change a restricted verdict.
        score = min(file_scores + ([score] if overall_issues else []))
        if score is not None and status != 'SAFE':
            score -= EXTRA_FLAGGED_ATTACHMENT_DEDUCTION * max(0, flagged_files - 1)
            score = clamp_to_status(status, score)

    result['confidence_score'] = score
    result['risk_score'] = round(100.0 - score, 2) if score is not None else None
    result['confidence_source'] = _source_for_score(score)
    result['confidence_calibrated'] = False
    result['confidence_note'] = NOTE
    result['warning_required'] = status == 'WARNING'
    result['score_factors'] = {
        'files_scanned': len(result.get('attachments', [])),
        'flagged_files': flagged_files,
        'global_finding_count': len(overall_issues),
        'decision_priority': 'RESTRICTED > WARNING > SAFE',
    }

    flagged = status in ('WARNING', 'RESTRICTED') and (
        bool(result.get('findings')) or bool(result.get('advisories')) or
        any(item.get('findings') or item.get('advisories') for item in result.get('attachments', [])) or
        bool((result.get('popup') or {}).get('reasons'))
    )
    result['Error'] = {'content': False, 'URLS': False, 'Attachments': bool(flagged)}
    return result
