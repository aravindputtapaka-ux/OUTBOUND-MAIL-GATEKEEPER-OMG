"""Low-severity *advisory* patterns for the attachment content gate.

These demonstrate a reviewed minor issue. They NEVER downgrade threats, phishing,
malware, scanner outages, or other blocking findings. Final policy review and
validation are required before using such advisory rules in production.
"""
from __future__ import annotations
import re

# Require an explicit request for a fast reply, not just a single word "urgent".
SOFT_DEADLINE = re.compile(r"\b(?:please|kindly)\s+(?:respond|reply)\s+(?:asap|soon|today)\b", re.I)


def detect_minor_advisories(text: str) -> list[dict[str, str | int]]:
    matches = list(SOFT_DEADLINE.finditer(re.sub(r"\s+", " ", text)))
    if not matches:
        return []
    # The matched *request*, not arbitrary document length or file name,
    # determines signal intensity. Keep evidence bounded and privacy-safe.
    cues = [m.group(0).split()[-1].lower() for m in matches]
    cue = "asap" if "asap" in cues else "today" if "today" in cues else "soon"
    return [{
        'code': 'SOFT_REPLY_URGENCY',
        'reason': 'Attachment requests a rapid reply; verify the urgency and recipient before sending',
        'severity': 'MINOR',
        'urgency_cue': cue,
        'occurrences': min(len(matches), 5),
    }]
