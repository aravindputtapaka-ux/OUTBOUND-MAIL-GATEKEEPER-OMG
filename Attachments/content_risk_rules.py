"""Contextual, transparent attachment-text policy rules.

These are organizational policy heuristics, NOT a malware detector, a calibrated
probability estimate, or a replacement for an evaluated supervised classifier.
Use the same reviewed rules with every supported document type and ZIP member.
"""
from __future__ import annotations
import re

# Require at least two *independent* contextual signals. Never use file names,
# TEST LABEL markers, or single words such as "urgent" as the sole basis.
MAILBOX_PRESSURE = re.compile(
    r"\b(?:mailbox|email\s+account|account|mail\s+access)\b.{0,110}"
    r"\b(?:disabled|suspend(?:ed|sion)?|expir(?:e|es|ing)|locked|deactivat(?:ed|ion))\b"
    r"|\b(?:disabled|suspend(?:ed|sion)?|expir(?:e|es|ing)|locked|deactivat(?:ed|ion))\b.{0,110}"
    r"\b(?:mailbox|email\s+account|account|mail\s+access)\b", re.I | re.S,
)
ACCOUNT_ACTION = re.compile(r"\b(?:verify|confirm|reactivate|unlock|validate|update)\b.{0,50}\b(?:account|identity|mailbox|credentials)\b", re.I | re.S)
URGENCY = re.compile(r"\b(?:immediately|urgently|within\s+(?:24|48)\s+hours|today|right\s+now|avoid\s+(?:interruption|suspension)|action\s+required)\b", re.I)
PRIZE = re.compile(r"\b(?:cash\s+reward|cash\s+prize|lottery\s+winnings|prize|reward\s+payment)\b", re.I)
CLAIM = re.compile(r"\b(?:claim|redeem|collect)\b.{0,80}\b(?:prize|reward|cash|winnings)\b", re.I | re.S)
SCARCITY = re.compile(r"\b(?:immediately|limited.time|exclusive\s+opportunity|before\s+it\s+expires|avoid\s+losing|act\s+now)\b", re.I | re.S)


def detect_lure_patterns(text: str) -> list[dict[str, str]]:
    """Signal suspicious *messages*, not isolated keywords or filenames.

    Educational examples containing an actual simulated lure are still flagged
    by a strict demonstration policy; a flag does NOT imply actual fraud.
    """
    # Collapse whitespace so DOCX XML runs, slides and PDF lines are comparable.
    norm = re.sub(r'\s+', ' ', text)
    findings = []
    if MAILBOX_PRESSURE.search(norm) and ACCOUNT_ACTION.search(norm) and URGENCY.search(norm):
        findings.append({
            'code': 'PHISHING_ACCOUNT_URGENCY',
            'reason': 'Attachment text combines threatened account/mailbox access with an urgent account-verification request',
        })
    if PRIZE.search(norm) and CLAIM.search(norm) and SCARCITY.search(norm):
        findings.append({
            'code': 'SPAM_PRIZE_LURE',
            'reason': 'Attachment text contains a prize or cash-reward claim with pressure to act immediately',
        })
    return findings
