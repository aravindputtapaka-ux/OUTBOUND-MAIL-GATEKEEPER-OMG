"""Independent email text + HTML + optional source ML validation."""
from __future__ import annotations
import logging
import re
from bs4 import BeautifulSoup
from .rule_checks import inspect_patterns
from .contextual_risk import inspect_contextual_risks
from .html_inspection import inspect_html_content
from .classifier import classify_email
from .config import settings

logger = logging.getLogger(__name__)

# Weak context signals that never change a verdict on their own. They keep the
# reported score informative for clean mail instead of returning a constant 100
# for every message. The total is capped at MAX_CONTEXT_PENALTY by the caller.
_CONTEXT_SIGNALS = (
    (re.compile(r"\b(?:urgent(?:ly)?|immediately|asap|right\s+away)\b", re.I), 2.0),
    (re.compile(r"\b(?:deadline|overdue|expir(?:e|es|ed|ing|y)|final\s+warning)\b", re.I), 2.0),
    (re.compile(r"\b(?:payment|invoice|bank(?:ing)?|wire|transfer|salary|payroll|refund)\b", re.I), 2.0),
    (re.compile(r"\b(?:password|passcode|otp|one[ -]?time|login|credentials?)\b", re.I), 2.0),
    (re.compile(r"\b(?:verify|confirm|validate|review|update|submit)\b", re.I), 1.0),
    (re.compile(r"\b(?:https?://|www\.)", re.I), 1.0),
    (re.compile(r"\b(?:attached|attachment|enclosed)\b", re.I), 1.0),
    (re.compile(r"!{2,}"), 1.0),
)


def contextual_penalty(subject: str, body: str = "", html: str = "") -> float:
    """Return a small, explainable deduction for weak contextual signals."""
    text = " ".join(
        part for part in (subject or "", BeautifulSoup(body or "", "html.parser").get_text(" ", strip=True),
                          BeautifulSoup(html or "", "html.parser").get_text(" ", strip=True))
        if part
    )
    penalty = sum(weight for pattern, weight in _CONTEXT_SIGNALS if pattern.search(text))
    if re.search(r"\b[A-Z]{4,}\b", subject or ""):
        penalty += 1.0
    return round(min(12.0, penalty), 2)

def validate_content(subject: str, body: str = "", html: str = "") -> dict:
    """Preserve original OMG text/HTML checks. Optional ML is explicitly opt-in.

    The original sklearn artifact is retained but MUST be trusted before enabling
    deserialization. ML confidence is NOT a calibrated security safety score.
    """
    combined = "\n\n".join(x.strip() for x in (body,html) if x and x.strip())
    findings = []
    coverage = {"runtime_text_rules": "complete", "html_inspection": "complete", "ml_classifier": "disabled_optional"}
    for name, fn in (("runtime_text_rules",lambda: inspect_patterns(subject,combined)),
                     ("html_inspection",lambda: inspect_html_content(subject,html or body))):
        try:
            result = fn()
            if not isinstance(result,list):raise TypeError("Invalid inspection response")
            findings.extend(result)
        except Exception as exc:
            logger.exception("Content inspection failed: %s",name)
            coverage[name] = "failed"
            findings.append({"code": name.upper()+"_FAILED", "category":"INSPECTION_FAILURE",
                             "severity":"HIGH", "confidence":1.0,
                             "message":f"{name} failed ({type(exc).__name__})"})
    try:
        findings.extend(inspect_contextual_risks(subject, body, html))
        coverage["contextual_text_rules"] = "complete"
    except Exception as exc:
        logger.exception("Contextual content inspection failed")
        coverage["contextual_text_rules"] = "failed"
        findings.append({"code": "CONTEXTUAL_TEXT_RULES_FAILED", "category": "INSPECTION_FAILURE",
                         "severity": "CRITICAL", "message": f"Contextual inspection failed ({type(exc).__name__})"})
    if settings.ENABLE_EXPERIMENTAL_TFIDF:
        # Small synthetic catalogue: review-only evidence, never automatic block.
        try:
            from .experimental_tfidf import inspect_patterns as inspect_legacy_patterns
            legacy = inspect_legacy_patterns(subject, combined)
            if legacy:
                risk = float(legacy[0].get("risk_score", 0.0) or 0.0)
                findings.append({
                    "code": "EXPERIMENTAL_TFIDF_REVIEW",
                    "category": "EXPERIMENTAL_REVIEW",
                    "severity": "MEDIUM" if risk >= 65.0 else "LOW",
                    "confidence": 0.5,
                    "message": "Experimental synthetic TF-IDF catalogue matched. Manual review recommended; not a validated model.",
                })
                coverage["experimental_tfidf"] = "matched_review_only"
            else:
                coverage["experimental_tfidf"] = "no_match"
        except Exception as exc:
            logger.exception("Optional experimental TF-IDF inspection failed")
            coverage["experimental_tfidf"] = "optional_unavailable"
    else:
        coverage["experimental_tfidf"] = "disabled_optional"
    model_version="rules-baseline-v1"
    if settings.ENABLE_ML or settings.REQUIRE_ML:
        try:
            ml = classify_email(subject,combined)
        except Exception as exc:
            logger.exception("ML inspection failed")
            ml={"completed":False,"reason":type(exc).__name__}
        if ml.get("completed") is True:
            coverage["ml_classifier"]="complete"
            model_version=ml.get("model_version",model_version)
            if ml.get("finding"):
                findings.append(ml["finding"])
        else:
            coverage["ml_classifier"]="required_unavailable" if settings.REQUIRE_ML else "optional_unavailable"
            if settings.REQUIRE_ML:
                findings.append({"code":"ML_INSPECTION_INCOMPLETE","category":"INSPECTION_FAILURE",
                                 "severity":"HIGH", "confidence":1.0,
                                 "message":"Required email ML inspection unavailable."})
    elif settings.REQUIRE_ML:
        coverage["ml_classifier"]="required_unavailable"
        findings.append({"code":"ML_INSPECTION_INCOMPLETE","category":"INSPECTION_FAILURE",
                         "severity":"HIGH", "confidence":1.0,
                         "message":"Required email ML inspection disabled."})
    try:
        penalty = contextual_penalty(subject, body, html)
        coverage["contextual_signals"] = "complete"
    except Exception as exc:
        logger.exception("Contextual signal scoring failed")
        penalty = 0.0
        coverage["contextual_signals"] = "optional_unavailable"
    return {"findings":findings,"coverage":coverage,"model_version":model_version,
            "context_penalty":penalty}
