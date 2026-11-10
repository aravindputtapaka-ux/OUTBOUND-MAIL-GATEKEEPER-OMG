"""Runtime-editable text rules for outgoing email inspection."""
import json
import logging
import re
from pathlib import Path
from typing import Any
from bs4 import BeautifulSoup
from Content.config import settings
from Content.exceptions import RuleConfigurationError
from Content.pattern_catalog import get_catalog_summary

logger = logging.getLogger(__name__)
DEFAULT_RULES = [
    {"code": "LOTTERY_SCAM", "category": "FRAUD", "patterns": [r"\bclaim your lottery prize\b", r"\byou have won\b.*\bprize\b", r"\bclaim your winnings\b"]},
    {"code": "CREDENTIAL_PHISHING", "category": "PHISHING", "patterns": [r"\bverify your password\b", r"\bconfirm your login credentials\b", r"\baccount will be suspended\b"]},
    {"code": "UNSOLICITED_SPAM", "category": "SPAM", "patterns": [r"\bearn money fast\b", r"\bguaranteed income\b", r"\bact now\b.*\blimited offer\b"]},
]


def extract_email_text(subject: str, html: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    return f"{subject or ''}\n{soup.get_text(' ', strip=True)}"


def _load_runtime_rules() -> list[dict[str, Any]]:
    path = settings.resolve_path(settings.RULES_PATH)
    if not path.is_file():
        raise RuleConfigurationError(f"Required runtime rule configuration is missing: {path}")
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
            for pattern in rule["patterns"]:
                if not isinstance(pattern, str):
                    raise ValueError(f"Rule {index} patterns must be strings")
                re.compile(pattern)
        return rules
    except (OSError, json.JSONDecodeError, ValueError, re.error) as exc:
        raise RuleConfigurationError(f"Invalid runtime rule configuration at {path}: {exc}") from exc


def inspect_patterns(subject: str, html: str) -> list[dict]:
    text = extract_email_text(subject, html)
    findings, seen = [], set()
    for rule in _load_runtime_rules():
        for pattern in rule["patterns"]:
            matches = list(re.finditer(pattern, text, flags=re.IGNORECASE | re.DOTALL))
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
                                     "message": f"Matched configured suspicious-content rule: {rule['code']}."})
                break
    return findings


def get_rule_catalog_status() -> dict[str, int]:
    return get_catalog_summary()
