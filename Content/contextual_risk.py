"""Conservative, explainable outbound-email social-engineering checks.

These checks identify explicit requests and risky combinations of instructions.
They are not a trained classifier, proof of sender identity, or URL reputation.
Avoid rule-per-sample matching: evidence must occur in the submitted text.
"""
from __future__ import annotations

import re
from bs4 import BeautifulSoup

# These policy findings are shared by the email and attachment content inspectors.
# Rules do not establish sender identity or maliciousness of URL destinations.

# Limit text passed to multi-signal heuristics; schema limits also apply upstream.
_MAX = 100_000


def _has(pattern: str, text: str) -> bool:
    return bool(re.search(pattern, text, re.IGNORECASE))


def _normalize(subject: str, body: str, html: str) -> str:
    readable = BeautifulSoup("\n".join((body or "", html or "")), "html.parser").get_text(" ", strip=True)
    return re.sub(r"\s+", " ", f"{subject or ''} {readable}")[:_MAX]


def inspect_contextual_risks(subject: str, body: str, html: str = "") -> list[dict[str, str]]:
    """Find credential requests, fraudulent-payment instructions and softer financial-change cues."""
    text = _normalize(subject, body, html)
    findings: list[dict[str, str]] = []

    def flag(code: str, severity: str, reason: str) -> None:
        findings.append({"code": code, "category": "SOCIAL_ENGINEERING", "severity": severity, "message": reason})

    # Critical rule 1: explicit credentials or OTP collection. Limit the
    # request-to-secret span to one clause; unrelated messages mentioning
    # password policy or providing security advice must not be restricted.
    # A login link + a password/OTP collection instruction is still critical;
    # the URL inspector independently checks link structure and review cues.
    request_phrase = re.compile(
        r"\b(?:reply(?:\s+to\s+(?:this\s+)?email)?\s+with|send|share|provide|forward|"
        r"submit|enter|type|give|disclose|upload)\b"
        r"(?:(?![.!?]).){0,120}?"
        r"\b(?:passwords?|passcodes?|otps?|one[ -]?time\s+(?:password|code|passcode)|"
        r"verification\s+codes?|2fa|mfa)\b",
        re.IGNORECASE,
    )
    credential_collection = False
    for match in request_phrase.finditer(text):
        before = text[max(0, match.start() - 65):match.start()].lower()
        clause = match.group(0).lower()
        # Negated imperatives are *advice not to disclose*. Exclude common
        # 'do not reply', 'never share', 'not allowed to send' variants.
        if re.search(
            r"\b(?:do\s+not|don't|never|avoid|must\s+not|should\s+not|"
            r"not\s+allowed\s+to|not\s+permitted\s+to|do\s+not\s+ever)\s*$",
            before,
        ):
            continue
        if re.search(
            r"\b(?:not|never)\s+(?:to\s+)?(?:send|share|provide|enter|submit|"
            r"forward|reply|upload|disclose)\b", clause,
        ):
            continue
        # Requests for *documents about passwords* are not requests for the
        # passwords themselves (e.g. "send the password security training PDF").
        # Actual credentials + authentication code remain actionable.
        context_after = text[match.end():match.end() + 75]
        if _has(r"\b(?:training|awareness|policy|guide|documentation|manual|"
                r"slides|brochure|article|example|tutorial|notes)\b", clause + " " + context_after) and not _has(
            r"\b(?:your|their|my|corporate|company|login|account)\b.{0,30}"
            r"\b(?:password|passcode|otp|verification\s+code)\b", clause
        ):
            continue
        # 'Enter your password' in an ordinary login announcement does not
        # alone prove phishing. Require OTP/urgency/secrecy in such cases.
        if re.match(r"^(?:enter|type)\b", clause) and not (
            _has(r"\b(?:otp|one[ -]?time\s+(?:code|passcode|password)|"
                 r"verification\s+code)\b", clause)
            or _has(r"\b(?:within\s+\d+\s+minutes?|disabled|suspended|"
                    r"deactivated|do\s+not\s+contact|bypass|permanently)\b", text)
        ):
            continue
        credential_collection = True
        break
    if credential_collection:
        flag("CREDENTIAL_COLLECTION_REQUEST", "CRITICAL",
             "Message asks a recipient to disclose passwords or authentication codes; independently verify the request.")

    # Critical rule 2: an actual payment/transfer direction *combined* with
    # avoiding approval/verification. Neither 'transfer' nor 'urgent' alone
    # is enough for automatic RESTRICTED.
    money_context = _has(
        r"\b(?:payment|invoice|vendor|finance|bank|funds|money|wire|transfer|remittance)\b|₹\s*\d", text
    )
    payment_action = _has(
        r"\b(?:transfer|wire|send|process|make|complete|arrange|initiate|release)\b"
        r".{0,100}(?:₹\s*[\d,]+|(?:rs\.?|inr)\s*[\d,]+|payment|funds|money|invoice)\b",
        text,
    )
    bypass_patterns = (
        # Bypass normal approval, skip the usual checks, ignore policy, etc.
        r"\b(?:bypass|skip|ignore|circumvent|override|avoid)\b.{0,60}"
        r"\b(?:approval|authorization|verification|review|checks?|process|procedure|policy)\b",
        # 'Do not verify with the vendor', 'don't check with finance'.
        r"\b(?:do\s+not|don't)\s+(?:verify|confirm|check|contact|consult|"
        r"discuss|notify|ask)\b.{0,100}"
        r"\b(?:vendor|bank|finance|manager|transfer|transaction|payment|account|anyone)\b",
        # 'Without manager approval', 'without consulting the finance team'.
        r"\bwithout\b.{0,70}\b(?:approval|authorization|verification|"
        r"consulting|informing)\b",
    )
    approval_bypass = False
    for expression in bypass_patterns:
        for match in re.finditer(expression, text, re.IGNORECASE):
            before = text[max(0, match.start() - 35):match.start()].lower()
            # A security reminder 'Never bypass the approval process' or
            # 'Do not skip checks' must not be interpreted as an instruction.
            if re.search(r"\b(?:never|do\s+not|don't|must\s+not|should\s+not)\s*$", before):
                continue
            approval_bypass = True
            break
        if approval_bypass:
            break
    if money_context and payment_action and approval_bypass:
        flag("PAYMENT_APPROVAL_BYPASS", "CRITICAL",
             "Payment or transfer instructions explicitly bypass approval or independent verification.")

    # Unverified changes are *review* signals, not proof of fraud. The sender
    # identity and authorization are unknown to this endpoint.
    financial_context = _has(r"\b(?:salary|payroll|direct\s+deposit|vendor|payment|invoice|remittance|finance|bank)\b", text)
    bank_change = (
        _has(r"\b(?:new|updated|changed|revised|recently\s+changed)\b.{0,80}"
             r"\b(?:bank\s+account|bank\s+details|account\s+details|payment\s+details|"
             r"payment\s+instructions|account\s+information)\b", text)
        or _has(r"\b(?:bank\s+account|bank\s+details|account\s+details|payment\s+details|"
                r"payment\s+instructions|salary\s+account|direct\s+deposit|vendor.s\s+bank\s+account)\b"
                r".{0,60}\b(?:changed|updated|revised|replaced|new)\b", text)
    )
    # Vendor payment diversion is an evidence-combination rule, not a keyword
    # blacklist. Mere notice of an authorized account change stays review-only.
    vendor_context = _has(r"\b(?:vendor|supplier|beneficiary|accounts\s+payable)\b", text)
    urgent_transfer = _has(
        r"\b(?:immediately|urgent(?:ly)?|right\s+away|today|asap|without\s+delay)\b", text
    )
    payment_redirection = _has(
        r"\b(?:revised|new|updated|changed|different|replacement)\b.{0,90}"
        r"\b(?:bank\s+account|payment\s+instructions|bank\s+details|account\s+details)\b"
        r"|\b(?:bank\s+account|payment\s+instructions|bank\s+details)\b"
        r".{0,90}\b(?:revised|changed|updated|new|different|replacement)\b", text
    )
    if (vendor_context and bank_change and payment_redirection and
            money_context and payment_action and approval_bypass):
        flag("VENDOR_PAYMENT_DIVERSION", "CRITICAL",
             "Vendor bank details changed alongside a payment direction and instructions to bypass independent approval or verification.")
    elif (vendor_context and bank_change and payment_action and urgent_transfer and
          not approval_bypass):
        flag("VENDOR_PAYMENT_CHANGE_REVIEW", "MEDIUM",
             "An urgent vendor-payment request uses changed bank details; verify through an approved independent channel.")

    if financial_context and bank_change and not approval_bypass:
        flag("SENSITIVE_FINANCIAL_CHANGE", "MINOR",
             "A change to financial or payroll account information needs out-of-band verification.")

    # Prize/lottery social engineering is often phrased without the exact
    # words "claim your lottery prize". Require *multiple* independent signals
    # instead of blocking every mention of a lottery or the word "winner".
    # Do not infer that the prize is legitimate or that a domain is malicious.
    prize_context = _has(
        r"\b(?:lottery|lucky\s+draw|sweepstakes|jackpot|raffle|prize|winnings|reward)\b", text
    )
    winner_claim = _has(
        r"\b(?:congratulations|winner|winning|selected|chosen|you\s+(?:have\s+)?won|"
        r"claim\s+(?:your|the)\s+(?:prize|reward|winnings))\b", text
    )
    fee_request = _has(
        r"\b(?:processing|release|administrative|handling|verification|transfer)\s+fee\b"
        r"|(?:₹|\brs\.?|\binr\b)\s*[\d,]+(?:\.\d+)?\s+(?:processing\s+)?fee\b"
        r"|\b(?:pay|submit|deposit|transfer)\b.{0,90}\b(?:fee|charge)\b", text
    )
    fee_to_claim = _has(
        r"\b(?:fee|charge)\b.{0,90}\b(?:release|unlock|receive|claim|collect)\b"
        r".{0,70}\b(?:prize|winnings|reward)\b", text
    )
    requests_personal_data = _has(
        r"\b(?:provide|send|share|submit|enter|reply\s+with|upload)\b.{0,240}"
        r"\b(?:bank\s+account\s+details|bank\s+details|aadhaar|aadhar|pan\s+(?:card|details)|"
        r"passport\s+(?:details|number)|identity\s+documents?|credit\s+card\s+(?:details|number))\b",
        text,
    )
    # Avoid treating straightforward anti-fraud education as a request for fees
    # or personal data. This is a narrow, explainable heuristic, not a perfect
    # negation/intent classifier.
    awareness = _has(
        r"\b(?:scam\s+alert|security\s+awareness|warning\s+about\s+lottery\s+scams|"
        r"beware\s+of\s+lottery\s+scams|example\s+of\s+a\s+lottery\s+scam|"
        r"never\s+pay\s+(?:a\s+)?(?:processing\s+)?fee|"
        r"do\s+not\s+pay\s+(?:a\s+)?(?:processing\s+)?fee|"
        r"no\s+(?:processing\s+)?fee\s+is\s+required)\b", text
    )
    if prize_context and winner_claim and not awareness:
        if fee_request and (fee_to_claim or requests_personal_data):
            flag("LOTTERY_SCAM", "CRITICAL",
                 "Lottery/prize claim combined with an advance-fee demand; possible prize fraud.")
            flag("ADVANCE_FEE_FRAUD", "CRITICAL",
                 "Payment is requested to release an alleged prize or winnings.")
        elif requests_personal_data:
            flag("PRIZE_SENSITIVE_DATA_REQUEST", "HIGH",
                 "Prize notification requests banking or identity information; verify independently.")

    return findings
