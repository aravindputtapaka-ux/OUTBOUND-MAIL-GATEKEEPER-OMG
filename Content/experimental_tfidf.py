"""Runtime inspection using the offline-generated TF-IDF pattern catalogue."""
from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class PatternCatalogueUnavailable(RuntimeError):
    """Raised when the generated pattern catalogue is missing or invalid."""


@lru_cache(maxsize=2)
def _load_catalogue(path_string: str, modified_ns: int):
    path = Path(path_string)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("catalogue_version") != 1 or not isinstance(data.get("patterns"), list):
            raise ValueError("Unsupported or malformed catalogue.")
        return data
    except Exception as exc:
        raise PatternCatalogueUnavailable(
            f"Could not load pattern catalogue ({type(exc).__name__})."
        ) from exc


def clear_catalogue_cache() -> None:
    _load_catalogue.cache_clear()


def extract_email_text(subject: str, content: str) -> str:
    visible = BeautifulSoup(content or "", "html.parser").get_text(" ", strip=True)
    return re.sub(r"\s+", " ", f"{subject or ''} {visible}").strip().lower()


def inspect_patterns(subject: str, content: str) -> list[dict]:
    """Match learned SAFE/RESTRICTED n-gram patterns and estimate rule risk."""
    path = Path(__file__).resolve().parent / "legacy_tfidf_catalog.json"
    if not path.is_file():
        raise PatternCatalogueUnavailable(f"Pattern catalogue not found: {path}")
    catalogue = _load_catalogue(str(path), path.stat().st_mtime_ns)
    text = extract_email_text(subject, content)
    if not text:
        return []

    restricted_score = 0.0
    safe_score = 0.0
    matched_restricted: list[str] = []

    for item in catalogue["patterns"]:
        phrase = str(item.get("pattern") or "").strip().lower()
        if not phrase:
            continue
        phrase_pattern = r"(?<!\w)" + re.escape(phrase) + r"(?!\w)"
        if not re.search(phrase_pattern, text):
            continue
        weight = float(item.get("weight", 0.0))
        if item.get("class") == "RESTRICTED":
            restricted_score += weight
            matched_restricted.append(phrase)
        elif item.get("class") == "SAFE":
            safe_score += weight

    if not matched_restricted:
        return []

    # This is a deterministic pattern-evidence ratio, not a probability.
    risk_score = 100.0 * restricted_score / (
        restricted_score + safe_score + 1.0
    )

    if risk_score >= 65.0:
        code = "LEARNED_PATTERN_RESTRICTED"
        category = "SPAM"
        message = (
            f"Multiple learned restricted-content patterns matched "
            f"({len(matched_restricted)} indicators; rule risk score {risk_score:.1f})."
        )
    elif risk_score >= 35.0:
        code = "LEARNED_PATTERN_WARNING"
        category = "SUSPICIOUS_CONTENT"
        message = (
            f"Learned suspicious-content patterns matched; manual review is "
            f"recommended (rule risk score {risk_score:.1f})."
        )
    else:
        return []

    return [{
        "code": code,
        "category": category,
        "message": message,
        "risk_score": round(risk_score, 2),
        "matched_pattern_count": len(matched_restricted),
    }]
