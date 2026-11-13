"""Runtime-editable text rules for outgoing email inspection."""
import json
import logging
import re
import threading
from pathlib import Path
from typing import Any
from bs4 import BeautifulSoup
from score_policy import VALID_SEVERITIES
from Content.config import settings
from Content.exceptions import RuleConfigurationError
from Content.pattern_catalog import get_catalog_summary

logger = logging.getLogger(__name__)

# Rules that omit severity/confidence keep review-level defaults instead of
# silently inheriting a blocking weight.
DEFAULT_RULE_SEVERITY = "MEDIUM"
DEFAULT_RULE_CONFIDENCE = 0.5

_RULES_LOCK = threading.Lock()
_RULES_CACHE: dict[str, Any] = {"key": None, "rules": None}

DEFAULT_RULES = [
    {"code": "LOTTERY_SCAM", "category": "FRAUD", "patterns": [r"\bclaim your lottery prize\b", r"\byou have won\b.*\bprize\b", r"\bclaim your winnings\b"]},
    {"code": "CREDENTIAL_PHISHING", "category": "PHISHING", "patterns": [r"\bverify your password\b", r"\bconfirm your login credentials\b", r"\baccount will be suspended\b"]},
    {"code": "UNSOLICITED_SPAM", "category": "SPAM", "patterns": [r"\bearn money fast\b", r"\bguaranteed income\b", r"\bact now\b.*\blimited offer\b"]},
]


def extract_email_text(subject: str, html: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    return f"{subject or ''}\n{soup.get_text(' ', strip=True)}"


def _rule_severity(value) -> str:
    severity = str(value or DEFAULT_RULE_SEVERITY).strip().upper()
    if severity == "MINOR":
        severity = "LOW"
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Invalid rule severity: {value}")
    return severity


def _rule_confidence(value) -> float:
    try:
        confidence = float(value if value is not None else DEFAULT_RULE_CONFIDENCE)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid rule confidence: {value}") from exc
    if confidence != confidence or not 0 <= confidence <= 1:
        raise ValueError(f"Invalid rule confidence: {value}")
    return confidence


def _load_runtime_rules() -> list[dict[str, Any]]:
    path = settings.resolve_path(settings.RULES_PATH)
    if not path.is_file():
        raise RuleConfigurationError(f"Required runtime rule configuration is missing: {path}")
    try:
        stat = path.stat()
        cache_key = (str(path), stat.st_mtime_ns, stat.st_size)
    except OSError as exc:
        raise RuleConfigurationError(f"Cannot stat runtime rule configuration at {path}: {exc}") from exc

    with _RULES_LOCK:
        if _RULES_CACHE["key"] == cache_key:
            return _RULES_CACHE["rules"]

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            rules = data.get("rules") if isinstance(data, dict) else None
            if not isinstance(rules, list):
                raise ValueError("'rules' must be a list")
            for index, rule in enumerate(rules):
                if not isinstance(rule, dict) or not all(isinstance(rule.get(k), str) and rule[k] for k in ("code", "category")):
                    raise ValueError(f"Rule {index} needs non-empty code and category")
                if not isinstance(rule.get("patterns"), list) or not rule["patterns"]:
                    raise ValueError(f"Rule {index} needs a non-empty patterns list")
                compiled = []
                for pattern in rule["patterns"]:
                    if not isinstance(pattern, str):
                        raise ValueError(f"Rule {index} patterns must be strings")
                    compiled.append(re.compile(pattern, flags=re.IGNORECASE | re.DOTALL))
                rule["severity"] = _rule_severity(rule.get("severity"))
                rule["confidence"] = _rule_confidence(rule.get("confidence"))
                rule["_compiled"] = compiled
        except (OSError, json.JSONDecodeError, ValueError, re.error) as exc:
            raise RuleConfigurationError(f"Invalid runtime rule configuration at {path}: {exc}") from exc

        _RULES_CACHE["key"] = cache_key
        _RULES_CACHE["rules"] = rules
        return rules


def inspect_patterns(subject: str, html: str) -> list[dict]:
    text = extract_email_text(subject, html)
    findings, seen = [], set()
    for rule in _load_runtime_rules():
        for pattern, compiled in zip(rule["patterns"], rule["_compiled"]):
            matches = list(compiled.finditer(text))
            if not matches:
                continue
            # Do not report security-awareness prohibitions ("never share your
            # OTP") as requests to disclose credentials. This only applies to
            # direct secret-request phrase rules, not independent phishing cues.
            if rule["code"] in {"OTP_OR_AUTH_CODE_REQUEST", "MFA_CODE_REQUEST",
                                "HTML_FORM_CREDENTIAL_CAPTURE", "CREDENTIAL_PHISHING"}:
                matches = [m for m in matches if not re.search(
                    r"\b(?:do\s+not|don.t|never|must\s+not|should\s+not|avoid)\s*$",
                    text[max(0, m.start() - 28):m.start()], flags=re.IGNORECASE)]
            # Suppress broad 'send ... OTP' rule matches when the requested
            # object is clearly a training guide or password-policy document,
            # rather than someone's actual OTP or password.
            if rule["code"] in {"OTP_OR_AUTH_CODE_REQUEST", "MFA_CODE_REQUEST"}:
                matches = [m for m in matches if not (
                    re.search(r"\b(?:training|awareness|guide|policy|documentation|"
                              r"notes|slides|manual|brochure|tutorial)\b",
                              text[m.start():m.end() + 70], flags=re.IGNORECASE)
                    and not re.search(r"\b(?:your|their|my|the)\s+"
                                      r"(?:otp|one[ -]?time\s+(?:password|code)|"
                                      r"verification\s+code|mfa\s+code|2fa\s+code)\b",
                                      text[m.start():m.end()], flags=re.IGNORECASE)
                )]
            if matches:
                key = (rule["code"], pattern)
                if key not in seen:
                    seen.add(key)
                    findings.append({"code": rule["code"], "category": rule["category"],
                                     "severity": rule["severity"],
                                     "confidence": rule["confidence"],
                                     "confirmed": False,
                                     "message": f"Matched configured suspicious-content rule: {rule['code']}."})
                break
    return findings


def _inspect_builtin_threats(text: str) -> list[dict]:
    """Detect explicit violent threats and threats used to demand money."""

    threat_patterns = [
        r"\bi\s+will\s+(?:kill|murder|shoot|stab|attack|hurt)\s+you\b",
        r"\bi(?:'ll|\s+am\s+going\s+to)\s+(?:kill|murder|shoot|stab|attack|hurt)\s+you\b",
        r"\byou\s+will\s+die\b",
        r"\byou\s+are\s+going\s+to\s+die\b",
        r"\bi\s+will\s+make\s+you\s+pay\s+with\s+your\s+life\b",
        r"\bi\s+will\s+physically\s+harm\s+you\b",
    ]

    if not any(re.search(pattern, text, re.IGNORECASE) for pattern in threat_patterns):
        return []

    # Avoid treating educational or prevention messages as actual threats.
    awareness_patterns = [
        r"\b(?:security awareness|threat awareness|anti-violence training)\b",
        r"\b(?:do not|don't|never)\s+(?:threaten|kill|murder|hurt)\s+anyone\b",
        r"\bexample of a (?:death threat|violent threat)\b",
    ]

    if any(re.search(pattern, text, re.IGNORECASE) for pattern in awareness_patterns):
        return []

    findings = [{
        "code": "DEATH_THREAT",
        "category": "THREAT_AND_EXTORTION",
        "severity": "CRITICAL",
        "confidence": 1.0,
        "confirmed": True,
        "message": "Explicit threat of death or serious physical violence detected.",
    }]

    money_demand = re.search(
        r"\b(?:give|pay|send|transfer|hand\s+over)\b"
        r".{0,80}\b(?:me|money|cash|funds|payment|ransom)\b"
        r"|\b(?:money|cash|funds|payment)\b"
        r".{0,60}\b(?:or|otherwise)\b",
        text,
        re.IGNORECASE,
    )

    conditional_demand = re.search(
        r"\bif\s+you\s+(?:do\s+not|don't|dont|refuse|fail\s+to)\b"
        r".{0,120}\b(?:give|pay|send|transfer)\b",
        text,
        re.IGNORECASE,
    )

    if money_demand or conditional_demand:
        findings.append({
            "code": "THREATENING_EXTORTION",
            "category": "THREAT_AND_EXTORTION",
            "severity": "CRITICAL",
            "confidence": 1.0,
            "confirmed": True,
            "message": "A demand for money or payment is combined with a violent threat.",
        })

    return findings

def get_rule_catalog_status() -> dict[str, int]:
    return get_catalog_summary()
