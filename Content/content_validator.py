"""Independent email text + HTML + optional source ML validation."""
from __future__ import annotations
import logging
from bs4 import BeautifulSoup
from .rule_checks import inspect_patterns
from .contextual_risk import inspect_contextual_risks
from .html_inspection import inspect_html_content
from .classifier import classify_email
from .config import settings

logger = logging.getLogger(__name__)

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
                findings.append({
                    "code": "EXPERIMENTAL_TFIDF_REVIEW",
                    "category": "EXPERIMENTAL_REVIEW",
                    "severity": "MINOR",
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
                                 "message":"Required email ML inspection unavailable."})
    elif settings.REQUIRE_ML:
        coverage["ml_classifier"]="required_unavailable"
        findings.append({"code":"ML_INSPECTION_INCOMPLETE","category":"INSPECTION_FAILURE",
                         "message":"Required email ML inspection disabled."})
    return {"findings":findings,"coverage":coverage,"model_version":model_version}
