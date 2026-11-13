
"""Conservative, explainable outbound-email social-engineering checks.

These checks identify explicit requests and risky combinations of instructions.
They are not a trained classifier, proof of sender identity, or URL reputation.
Avoid rule-per-sample matching: evidence must occur in the submitted text.
"""
from __future__ import annotations

import re
from bs4 import BeautifulSoup

_MAX = 100_000


def _has(pattern: str, text: str) -> bool:
    return bool(re.search(pattern, text, re.IGNORECASE | re.DOTALL))


def _normalize(subject: str, body: str, html: str) -> str:
    readable = BeautifulSoup(
        "\n".join((body or "", html or "")),
        "html.parser"
    ).get_text(" ", strip=True)

    return re.sub(
        r"\s+",
        " ",
        f"{subject or ''} {readable}"
    )[:_MAX]


def inspect_contextual_risks(
    subject: str,
    body: str,
    html: str = ""
) -> list[dict[str, object]]:
    """Find explicit threats, credential requests and social-engineering risks."""

    text = _normalize(subject, body, html)
    findings: list[dict[str, object]] = []

    def flag(
        code: str,
        severity: str,
        reason: str,
        *,
        confirmed: bool = False,
        confidence: float = 1.0,
    ) -> None:
        finding: dict[str, object] = {
            "code": code,
            "category": "SOCIAL_ENGINEERING",
            "severity": severity,
            "confidence": confidence,
            "message": reason,
        }

        if confirmed:
            finding["confirmed"] = True

        findings.append(finding)

    # ---------------------------------------------------------
    # CRITICAL: DIRECT PHYSICAL THREATS AND EXTORTION
    # ---------------------------------------------------------

    threat_patterns = (
        # "I will kill you"
        # "I will physically attack you"
        # "I will come to your workplace and hurt you"
        r"\bi\s+(?:will|am\s+going\s+to|'ll)\s+"
        r"(?!not\b|never\b)"
        r".{0,120}?\b(?:kill|murder|shoot|stab|attack|hurt|harm)\s+you\b",

        # "You will die"
        r"\byou\s+will\s+(?:die|be\s+killed)\b",

        # "You are going to die"
        r"\byou\s+are\s+going\s+to\s+(?:die|be\s+killed)\b",

        # "I will make you pay with your life"
        r"\bi\s+will\s+make\s+you\s+pay\s+with\s+your\s+life\b",

        # Conditional threats:
        # "If you refuse, I will physically attack you."
        r"\bif\s+you\s+(?:do\s+not|don't|dont|refuse|fail\s+to)\b"
        r".{0,160}?\bi\s+(?:will|am\s+going\s+to|'ll)\s+"
        r".{0,120}?\b(?:kill|murder|shoot|stab|attack|hurt|harm)\s+you\b",
    )

    death_threat = any(
        _has(pattern, text)
        for pattern in threat_patterns
    )

    # Avoid blocking clearly educational or preventive content.
    threat_awareness = _has(
        r"\b(?:security awareness|threat awareness|anti-violence training)\b"
        r"|\bexample of a (?:death threat|violent threat)\b"
        r"|\b(?:do not|don't|never)\s+(?:threaten|kill|murder|hurt)\s+anyone\b",
        text,
    )

    if death_threat and not threat_awareness:

        flag(
            "DEATH_THREAT",
            "CRITICAL",
            "Explicit threat of death or serious physical violence detected.",
            confirmed=True,
            confidence=1.0,
        )

        money_demand = _has(
            r"\b(?:give|pay|send|transfer|hand\s+over)\b"
            r".{0,80}\b(?:me|money|cash|funds|payment|ransom)\b"
            r"|\b(?:money|cash|funds|payment)\b"
            r".{0,60}\b(?:or|otherwise)\b",
            text,
        )

        conditional_demand = _has(
            r"\bif\s+you\s+(?:do\s+not|don't|dont|refuse|fail\s+to)\b"
            r".{0,120}\b(?:give|pay|send|transfer)\b",
            text,
        )

        if money_demand or conditional_demand:
            flag(
                "THREATENING_EXTORTION",
                "CRITICAL",
                "A demand for money or payment is combined with a violent threat.",
                confirmed=True,
                confidence=1.0,
            )

    # ---------------------------------------------------------
    # INVESTMENT SCAM
    # ---------------------------------------------------------

    investment_context = _has(
        r"\b(?:invest(?:ment)?|investor|returns?|profit|earnings?)\b",
        text,
    )

    guaranteed_return_claim = _has(
        r"\bguaranteed\b.{0,80}\b(?:returns?|profit|earnings?|income)\b"
        r"|\b(?:returns?|profit|earnings?)\b.{0,50}\bguaranteed\b",
        text,
    )

    extreme_return_claim = _has(
        r"\b(?:[2-9]\d{2,}|[2-9]\d)\s*%\b"
        r"|\b(?:double|triple|quadruple|fivefold|tenfold|ten\s+times)\b.{0,40}"
        r"\b(?:money|investment|returns?|profit)\b"
        r"|\b\d+(?:\.\d+)?\s*x\s+(?:returns?|profit)\b",
        text,
    )

    fast_return_claim = _has(
        r"\btoday\b"
        r"|\b(?:within|in)\s+(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten|"
        r"eleven|twelve|fifteen|twenty|thirty|forty|fifty|sixty|ninety|hundred)"
        r"\s+(?:hours?|days?|weeks?|months?)\b",
        text,
    )

    safeguard_bypass_claim = _has(
        r"\bno\s+(?:risk|documentation|verification|due\s+diligence|paperwork)\b"
        r"|\bwithout\s+(?:risk|documentation|verification|due\s+diligence|paperwork)\b"
        r"|\b(?:no[- ]risk|risk[- ]free)\b",
        text,
    )

    investment_awareness = _has(
        r"\b(?:beware|warning|alert|avoid|never trust|do not trust)\b"
        r".{0,100}\b(?:investment scam|guaranteed returns?|no risk|high returns?)\b",
        text,
    )

    advance_fee_payment = _has(
        r"\b(?:registration|processing|clearance|release|activation|transfer|handling)\s+fee\b"
        r"|\b(?:pay|transfer|send|submit|wire)\b.{0,60}\bfee\b",
        text,
    )

    if (
        investment_context
        and guaranteed_return_claim
        and fast_return_claim
        and (
            extreme_return_claim
            or safeguard_bypass_claim
            or advance_fee_payment
        )
        and not investment_awareness
    ):
        flag(
            "GUARANTEED_INVESTMENT_SCAM",
            "CRITICAL",
            "The investment message promises guaranteed rapid returns while using extreme claims or dismissing basic safeguards.",
            confirmed=True,
        )

    # ---------------------------------------------------------
    # UNAUTHORIZED SECRET EXFILTRATION
    # ---------------------------------------------------------

    production_secrets_requested = _has(
        r"\b(?:production|prod)\s+(?:api\s+keys?|credentials?|tokens?|secrets?)\b"
        r"|\b(?:api\s+keys?|database\s+credentials?|private\s+access\s+tokens?|"
        r"access\s+tokens?|private\s+keys?|client\s+secrets?)\b",
        text,
    )

    secret_disclosure_actions = re.finditer(
        r"\b(?:share|send|provide|forward|email|paste|post|upload|include|disclose)\b",
        text,
        re.IGNORECASE,
    )

    secret_disclosure_requested = False

    for action in secret_disclosure_actions:
        before = text[max(0, action.start() - 100):action.start()]
        after = text[action.end():action.end() + 100]

        if re.search(
            r"\b(?:never|do\s+not|don't|must\s+not|should\s+not|avoid)\s*$",
            before,
            re.IGNORECASE,
        ):
            continue

        if _has(
            r"\b(?:api\s+keys?|database\s+credentials?|private\s+access\s+tokens?|"
            r"access\s+tokens?|credentials?|tokens?|secrets?|private\s+keys?|client\s+secrets?)\b",
            before + after,
        ):
            secret_disclosure_requested = True
            break

    unauthorized_external_use = _has(
        r"\b(?:unauthori[sz]ed|unapproved|untrusted|third.party)\b.{0,60}"
        r"\b(?:external|outside|remote)\b.{0,40}\b(?:server|system|service|account|environment)\b"
        r"|\b(?:external|outside|remote)\b.{0,40}"
        r"\b(?:server|system|service|account|environment)\b.{0,60}"
        r"\b(?:unauthori[sz]ed|unapproved|untrusted)\b",
        text,
    )

    if (
        production_secrets_requested
        and secret_disclosure_requested
        and unauthorized_external_use
    ):
        flag(
            "UNAUTHORIZED_SECRET_EXFILTRATION",
            "CRITICAL",
            "The message requests production credentials or secrets for unauthorized external use.",
            confirmed=True,
        )

    # ---------------------------------------------------------
    # SENSITIVE CUSTOMER DATA EXFILTRATION
    # ---------------------------------------------------------

    sensitive_customer_data = _has(
        r"\b(?:customer|client|consumer|patient|employee)\s+"
        r"(?:database|records?|data|information|details|files?|list|spreadsheet)\b"
        r"|\b(?:personal|financial|banking)\s+(?:information|data|details|records?)\b"
        r"|\b(?:contact|phone|account|credit\s+card)\s+(?:numbers?|details|records?)\b",
        text,
    )

    transfers_data = _has(
        r"\b(?:forward|send|email|share|transfer|upload|copy|export|attach)\b",
        text,
    )

    personal_destination = _has(
        r"\b(?:my|our|a|the)\s+personal\s+(?:email|e-mail|account|address)\b"
        r"|\b(?:gmail|yahoo|hotmail|outlook)\.com\b",
        text,
    )

    concealment = _has(
        r"\bwithout\s+(?:informing|notifying|telling|alerting|including)\b"
        r".{0,60}\b(?:security|compliance|privacy|legal|management|manager|team)\b"
        r"|\b(?:do\s+not|don't|never)\s+(?:inform|notify|tell|alert)\b"
        r".{0,60}\b(?:security|compliance|privacy|legal|management|manager|team)\b"
        r"|\bhide\b.{0,40}\b(?:from|it\s+from)\b.{0,30}"
        r"\b(?:security|compliance|privacy|legal|management|manager|team)\b"
        r"|\bkeep\b.{0,30}\b(?:secret|confidential)\b.{0,40}"
        r"\b(?:security|compliance|privacy|legal|management|manager|team)\b",
        text,
    )

    if (
        sensitive_customer_data
        and transfers_data
        and personal_destination
        and concealment
    ):
        flag(
            "SENSITIVE_DATA_EXFILTRATION",
            "CRITICAL",
            "Sensitive customer data is being sent to a personal destination while bypassing security oversight.",
            confirmed=True,
        )

    # ---------------------------------------------------------
    # CREDENTIAL AND OTP COLLECTION
    # ---------------------------------------------------------

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

        if re.search(
            r"\b(?:do\s+not|don't|never|avoid|must\s+not|should\s+not|"
            r"not\s+allowed\s+to|not\s+permitted\s+to|do\s+not\s+ever)\s*$",
            before,
        ):
            continue

        if re.search(
            r"\b(?:not|never)\s+(?:to\s+)?(?:send|share|provide|enter|submit|"
            r"forward|reply|upload|disclose)\b",
            clause,
        ):
            continue

        context_after = text[match.end():match.end() + 75]

        if _has(
            r"\b(?:training|awareness|policy|guide|documentation|manual|"
            r"slides|brochure|article|example|tutorial|notes)\b",
            clause + " " + context_after,
        ) and not _has(
            r"\b(?:your|their|my|corporate|company|login|account)\b.{0,30}"
            r"\b(?:password|passcode|otp|verification\s+code)\b",
            clause,
        ):
            continue

        if re.match(r"^(?:enter|type)\b", clause) and not (
            _has(
                r"\b(?:otp|one[ -]?time\s+(?:code|passcode|password)|"
                r"verification\s+code)\b",
                clause,
            )
            or _has(
                r"\b(?:within\s+\d+\s+minutes?|disabled|suspended|"
                r"deactivated|do\s+not\s+contact|bypass|permanently)\b",
                text,
            )
            or _has(
                r"\b(?:suspicious|unverified|unofficial|fraudulent|fake|"
                r"phishing)\b",
                text[max(0, match.start() - 60):match.end() + 60],
            )
        ):
            continue

        credential_collection = True
        break

    if credential_collection:
        flag(
            "CREDENTIAL_COLLECTION_REQUEST",
            "CRITICAL",
            "Message asks a recipient to disclose passwords or authentication codes; independently verify the request.",
            confirmed=True,
        )

    # ---------------------------------------------------------
    # PAYMENT APPROVAL BYPASS
    # ---------------------------------------------------------

    money_context = _has(
        r"\b(?:payment|invoice|vendor|finance|bank|funds|money|wire|transfer|remittance)\b|₹\s*\d",
        text,
    )

    payment_action = _has(
        r"\b(?:transfer|wire|send|process|make|complete|arrange|initiate|release|"
        r"pay|change|update|redirect)\b"
        r".{0,100}(?:₹\s*[\d,]+|(?:rs\.?|inr)\s*[\d,]+|payment|funds|money|invoice|"
        r"amounts?|balance|account|payroll)\b",
        text,
    )

    bypass_patterns = (
        r"\b(?:bypass|skip|ignore|circumvent|override|avoid)\b.{0,60}"
        r"\b(?:approval|authorization|verification|review|checks?|process|procedure|policy)\b",

        r"\b(?:do\s+not|don't)\s+(?:verify|confirm|check|contact|call|consult|"
        r"discuss|notify|ask)\b.{0,100}"
        r"\b(?:vendor|bank|finance|manager|transfer|transaction|payment|accounts?|anyone)\b",

        r"\bwithout\b.{0,70}\b(?:approval|authorization|verification|"
        r"consulting|informing)\b",
    )

    approval_bypass = False

    for expression in bypass_patterns:
        for match in re.finditer(expression, text, re.IGNORECASE):
            before = text[max(0, match.start() - 35):match.start()].lower()

            if re.search(
                r"\b(?:never|do\s+not|don't|must\s+not|should\s+not)\s*$",
                before,
            ):
                continue

            approval_bypass = True
            break

        if approval_bypass:
            break

    if money_context and payment_action and approval_bypass:
        flag(
            "PAYMENT_APPROVAL_BYPASS",
            "CRITICAL",
            "Payment or transfer instructions explicitly bypass approval or independent verification.",
            confirmed=True,
        )

    # ---------------------------------------------------------
    # FINANCIAL ACCOUNT CHANGES
    # ---------------------------------------------------------

    financial_context = _has(
        r"\b(?:salary|payroll|direct\s+deposit|vendor|payment|invoice|remittance|finance|bank)\b",
        text,
    )

    bank_change = (
        _has(
            r"\b(?:new|updated|changed|revised|recently\s+changed)\b.{0,80}"
            r"\b(?:bank\s+account|bank\s+details|account\s+details|payment\s+details|"
            r"payment\s+instructions|account\s+information)\b",
            text,
        )
        or _has(
            r"\b(?:bank\s+account|bank\s+details|account\s+details|payment\s+details|"
            r"payment\s+instructions|salary\s+account|direct\s+deposit|vendor.s\s+bank\s+account)\b"
            r".{0,60}\b(?:changed|updated|revised|replaced|new)\b",
            text,
        )
    )

    if financial_context and bank_change and not approval_bypass:
        flag(
            "SENSITIVE_FINANCIAL_CHANGE",
            "MINOR",
            "A change to financial or payroll account information needs out-of-band verification.",
            confidence=0.7,
        )

    # ---------------------------------------------------------
    # PRIZE AND LOTTERY FRAUD
    # ---------------------------------------------------------

    prize_context = _has(
        r"\b(?:lottery|lucky\s+draw|sweepstakes|jackpot|raffle|prize|winnings|reward)\b",
        text,
    )

    winner_claim = _has(
        r"\b(?:congratulations|winner|winning|selected|chosen|you\s+(?:have\s+)?won|"
        r"claim\s+(?:your|the)\s+(?:prize|reward|winnings))\b",
        text,
    )

    fee_request = _has(
        r"\b(?:processing|release|administrative|handling|verification|transfer)\s+fee\b"
        r"|(?:₹|\brs\.?|\binr\b)\s*[\d,]+(?:\.\d+)?\s+(?:processing\s+)?fee\b"
        r"|\b(?:pay|submit|deposit|transfer)\b.{0,90}\b(?:fee|charge)\b",
        text,
    )

    fee_to_claim = _has(
        r"\b(?:fee|charge)\b.{0,90}\b(?:release|unlock|receive|claim|collect)\b"
        r".{0,70}\b(?:prize|winnings|reward|money|funds)\b",
        text,
    )

    requests_personal_data = _has(
        r"\b(?:provide|send|share|submit|enter|reply\s+with|upload)\b.{0,240}"
        r"\b(?:bank\s+account\s+details|bank\s+details|aadhaar|aadhar|pan\s+(?:card|details)|"
        r"passport\s+(?:details|number)|identity\s+documents?|credit\s+card\s+(?:details|number))\b",
        text,
    )

    identity_document_request = _has(
        r"\b(?:send|provide|share|submit|email|upload|reply\s+with|forward)\b.{0,180}"
        r"\b(?:passport(?:\s+(?:number|details|scan|copy))?|"
        r"national\s+(?:id|identity)(?:\s+(?:number|card|document))?|"
        r"identity\s+(?:documents?|cards?|proof)|date\s+of\s+birth|"
        r"social\s+security\s+number|bank\s+(?:account\s+)?details)\b",
        text,
    )

    identity_request_negated = _has(
        r"\b(?:never|do\s+not|don.t|must\s+not|should\s+not)\b.{0,60}"
        r"\b(?:send|provide|share|submit|email|upload)\b.{0,80}"
        r"\b(?:passport|national\s+(?:id|identity)|identity\s+documents?|"
        r"bank\s+(?:account\s+)?details)\b",
        text,
    )

    unofficial_destination = _has(
        r"\b(?:this|my|our|a)\s+personal\s+(?:email|e-mail|address|account|inbox)\b"
        r"|\b(?:gmail|yahoo|hotmail|outlook|proton(?:mail)?)\.(?:com|me|net)\b"
        r"|\b(?:cannot|can.t|unable\s+to|do\s+not|don.t)\s+use\b.{0,50}"
        r"\b(?:official|company|corporate|secure|internal)\s+"
        r"(?:portal|channel|system|website|email)\b"
        r"|\binstead\s+of\b.{0,40}\b(?:official|company|corporate|secure|internal)\s+"
        r"(?:portal|channel|system|website|email)\b",
        text,
    )

    if (
        identity_document_request
        and unofficial_destination
        and not identity_request_negated
    ):
        flag(
            "IDENTITY_DOCUMENT_PHISHING",
            "CRITICAL",
            "Identity documents and banking data are requested through a personal address that bypasses the official portal.",
            confirmed=True,
        )

    awareness = _has(
        r"\b(?:scam\s+alert|security\s+awareness|warning\s+about\s+lottery\s+scams|"
        r"beware\s+of\s+lottery\s+scams|example\s+of\s+a\s+lottery\s+scam|"
        r"never\s+pay\s+(?:a\s+)?(?:processing\s+)?fee|"
        r"do\s+not\s+pay\s+(?:a\s+)?(?:processing\s+)?fee|"
        r"no\s+(?:processing\s+)?fee\s+is\s+required)\b",
        text,
    )

    if prize_context and winner_claim and not awareness:
        if fee_request and (fee_to_claim or requests_personal_data):
            flag(
                "LOTTERY_SCAM",
                "CRITICAL",
                "Lottery/prize claim combined with an advance-fee demand; possible prize fraud.",
                confirmed=True,
            )
            flag(
                "ADVANCE_FEE_FRAUD",
                "CRITICAL",
                "Payment is requested to release an alleged prize or winnings.",
                confirmed=True,
            )
        elif requests_personal_data:
            flag(
                "PRIZE_SENSITIVE_DATA_REQUEST",
                "HIGH",
                "Prize notification requests banking or identity information; verify independently.",
                confidence=0.8,
            )

    # ---------------------------------------------------------
    # GIFT CARD FRAUD
    # ---------------------------------------------------------

    gift_card_context = _has(
        r"\b(?:gift\s*cards?|redemption\s+codes?|itunes\s+cards?|"
        r"google\s+play\s+cards?|steam\s+cards?)\b",
        text,
    )

    code_handover = _has(
        r"\b(?:send|share|provide|forward|reply\s+with|read)\b.{0,60}"
        r"\b(?:codes?|numbers?|digits?)\b",
        text,
    )

    scam_secrecy = _has(
        r"\b(?:secretly|confidential(?:ly)?|quietly)\b"
        r"|\b(?:do\s+not|don't|never)\s+(?:tell|inform|notify|mention)\b"
        r"|\bkeep\s+(?:this|it)\s+(?:secret|confidential)\b",
        text,
    )

    urgency = _has(
        r"\b(?:immediately|right\s+away|urgent(?:ly)?|asap|today)\b",
        text,
    )

    if gift_card_context and code_handover and (scam_secrecy or urgency):
        flag(
            "GIFT_CARD_SCAM",
            "CRITICAL",
            "Gift-card codes are being collected from the recipient; this is an untraceable payment scam.",
            confirmed=True,
        )

    # ---------------------------------------------------------
    # INHERITANCE ADVANCE-FEE FRAUD
    # ---------------------------------------------------------

    inheritance_context = _has(
        r"\b(?:inheritance|inheritor|beneficiary|unclaimed\s+(?:funds|inheritance|estate)|"
        r"next\s+of\s+kin|deceased|estate\s+funds?)\b",
        text,
    )

    advance_fee_transfer = _has(
        r"\btransfer\b.{0,40}\b(?:clearance|processing|release|registration|transfer|activation)\s+fee\b"
        r"|\b(?:clearance|processing|release|registration|transfer|activation)\s+fee\b",
        text,
    )

    identity_or_bank_request = _has(
        r"\b(?:provide|send|share|submit|reply\s+with|upload)\b.{0,120}"
        r"\b(?:passport|bank\s+details|bank\s+account|account\s+number|"
        r"identity\s+documents?|national\s+id)\b",
        text,
    )

    release_after_payment = _has(
        r"\b(?:released\s+only\s+after|funds\s+will\s+be\s+released|after\s+payment\s+is\s+received)\b",
        text,
    )

    if inheritance_context and advance_fee_transfer and (
        identity_or_bank_request or release_after_payment
    ):
        flag(
            "INHERITANCE_ADVANCE_FEE_SCAM",
            "CRITICAL",
            "An alleged inheritance requires an upfront fee and/or identity and bank details before release.",
            confirmed=True,
        )

    # ---------------------------------------------------------
    # EXECUTIVE IMPERSONATION PAYMENT FRAUD
    # ---------------------------------------------------------

    executive_claim = _has(
        r"\b(?:i\s+am|this\s+is)\s+(?:the\s+)?(?:ceo|chief\s+executive|managing\s+director|"
        r"chairman|president|owner|director)\b|\b(?:ceo|chief\s+executive)\b",
        text,
    )

    transfer_of_funds = _has(
        r"\b(?:transfer|wire|send|pay)\b.{0,60}\b(?:funds|money|payment|amount)\b",
        text,
    )

    new_or_personal_account = _has(
        r"\b(?:new|different|personal|this)\s+(?:bank\s+)?account\b",
        text,
    )

    if executive_claim and transfer_of_funds and (
        scam_secrecy or approval_bypass or new_or_personal_account
    ):
        flag(
            "EXECUTIVE_IMPERSONATION_PAYMENT",
            "CRITICAL",
            "A message claiming executive authority directs funds to a new or unverified account.",
            confirmed=True,
        )

    # ---------------------------------------------------------
    # PAYROLL REDIRECTION
    # ---------------------------------------------------------

    payroll_context = _has(
        r"\b(?:payroll|salar(?:y|ies)|direct\s+deposit|employee\s+(?:bank\s+)?account)\b",
        text,
    )

    if payroll_context and new_or_personal_account and (
        approval_bypass or scam_secrecy
    ):
        flag(
            "PAYROLL_REDIRECTION",
            "CRITICAL",
            "Payroll or employee bank-account details are being redirected without independent approval.",
            confirmed=True,
        )

    # ---------------------------------------------------------
    # MALWARE DELIVERY
    # ---------------------------------------------------------

    dangerous_file = _has(
        r"\b(?:executable|\.exe\b|\.scr\b|\.bat\b|\.cmd\b|macro|enable\s+(?:content|macros)|"
        r"disable\s+(?:your\s+)?(?:antivirus|anti-virus|security|defender|firewall))\b",
        text,
    )

    open_action = _has(
        r"\b(?:open|run|execute|download|click|enable)\b",
        text,
    )

    negated_action = _has(
        r"\b(?:never|do\s+not|don't|must\s+not|should\s+not)\b.{0,40}"
        r"\b(?:open|run|execute|download|disable|enable)\b",
        text,
    )

    if dangerous_file and open_action and not negated_action:
        flag(
            "MALWARE_DELIVERY_ATTEMPT",
            "CRITICAL",
            "The message directs the recipient to run a risky file or disable security controls.",
            confirmed=True,
        )

    # ---------------------------------------------------------
    # EXTORTION / BLACKMAIL
    # ---------------------------------------------------------

    extortion_threat = _has(
        r"\b(?:expose|publish|release|leak|reveal|share)\b.{0,60}"
        r"\b(?:private|personal|sensitive|intimate|embarrassing|compromising)\b.{0,30}"
        r"\b(?:information|data|photos?|photographs?|videos?|files?|messages?)\b"
        r"|\b(?:compromising|intimate|private)\s+"
        r"(?:information|data|photos?|photographs?|videos?)\b"
        r"|\b(?:blackmail|extort(?:ion)?)\b",
        text,
    )

    payment_demand = _has(
        r"\b(?:pay|send|transfer|wire)\b.{0,60}"
        r"\b(?:amount|money|funds|bitcoin|crypto|cryptocurrenc(?:y|ies)|ransom|"
        r"wallet|payment|btc|usdt)\b",
        text,
    )

    if extortion_threat and payment_demand:
        flag(
            "EXTORTION_THREAT",
            "CRITICAL",
            "A payment demand is combined with a threat to expose private information.",
            confirmed=True,
        )

    # ---------------------------------------------------------
    # VERIFICATION AND REVIEW REQUESTS
    # ---------------------------------------------------------

    review_guidance = _has(
        r"\b(?:verif(?:y|ied|ication)|confirm(?:ed|ing|ation|s)?|check(?:ed|ing)?|"
        r"review(?:ed|ing)?|validate|navigate|visit|contact(?:ed|ing)?)\b"
        r"|\b(?:official|trusted|known)\b.{0,30}"
        r"\b(?:website|portal|application|channel|address|service)\b"
        r"|\bnormal\s+(?:company\s+)?(?:support\s+|communication\s+)?(?:channel|contact)\b",
        text,
    )

    risk_event = _has(
        r"\bunexpected\b|\bunfamiliar\b|\bunknown\s+sender\b"
        r"|\bnot\s+(?:expect|expecting|recognize|recognized)\b"
        r"|\bnew\s+device\b|\bnot\s+commonly\s+associated\b|\bsign-?in\s+attempt\b"
        r"|\blogin\s+(?:from|attempt|alert)\b|\bunusual\s+(?:login|sign-in)\b"
        r"|\b(?:has\s+shared|shared)\b.{0,30}\b(?:file|document)\b"
        r"|\b(?:file|document)\b.{0,20}\bshared\b"
        r"|\brequires?\s+(?:account\s+)?verification\b|\bverification\s+required\b"
        r"|\baccount\s+(?:information\s+)?(?:may\s+need|requires)\s+review\b"
        r"|\bsecurity\s+settings\s+may\s+need\s+attention\b"
        r"|\bflagged\s+for\b.{0,30}\b(?:security\s+)?review\b"
        r"|\bsecurity\s+(?:alert|review|notification)\b"
        r"|\b(?:payment|invoice|bank|account)\s+(?:details|information)\s+(?:has|have)\s+changed\b"
        r"|\binvoice\s+details\s+have\s+changed\b|\bcorrected\s+invoice\b"
        r"|\brevised\s+(?:amount|invoice)\b"
        r"|\bis\s+pending\b|\baccess\b.{0,30}\bpending\b"
        r"|\bpending\s+(?:payment|business\s+transaction|transaction\s+approval)\b"
        r"|\btransaction\s+(?:is\s+)?pending\b"
        r"|\boverdue\b|\bapproaching\s+its\s+due\b"
        r"|\b(?:may\s+expire|may\s+be\s+nearing)\b|\bnearing\s+its\s+expiration\b"
        r"|\bpassword\s+expiry\b"
        r"|\bdelayed\b|\bcould\s+not\s+be\s+delivered\b|\bdelivery\s+problem\b"
        r"|\bpromotional\s+(?:reward|prize)\b"
        r"|\bselected\s+for\s+(?:a\s+)?(?:promotional|prize)\b|\bprize\s+notification\b"
        r"|\bexternal\s+(?:vendor|collaborator|contact|project\s+contact|partner|service|sender)\b"
        r"|\bunexpected\s+(?:file|attachment)\b|\bsent\s+an\s+unexpected\b"
        r"|\bdon.t\s+believe\s+we\s+discussed\b"
        r"|\bpayment\s+(?:request|reminder)\b|\brequest\s+for\s+payment\b"
        r"|\bdeadline\s+(?:is|was)\s+approaching\b|\bbefore\s+the\s+end\s+of\s+the\s+day\b"
        r"|\brequested\s+(?:company|confidential|sensitive)\s+information\b"
        r"|\bcontact\s+list\b|\bstaff\b.{0,20}\blist\b|\bbusiness\s+opportunity\b"
        r"|\bwas\s+not\s+you\b|\bdo(?:es)?\s+not\s+recognize\b",
        text,
    )

    strong_finding = any(
        str(item.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
        for item in findings
    )

    if risk_event and review_guidance and not strong_finding:

        sensitive_event = _has(
            r"\b(?:password|otp|login|sign-?in|credentials?|payment|invoice|bank|"
            r"account|verification|prize|reward|security|transaction|approval)\b",
            text,
        )

        external_event = _has(
            r"\b(?:external|unfamiliar|unknown|unexpected|new\s+device|third.party)\b",
            text,
        )

        pressure_event = _has(
            r"\b(?:urgent(?:ly)?|immediately|asap|as\s+soon\s+as\s+possible|"
            r"deadline|overdue|expir(?:e|es|ed|ing|y)|pending|approaching|"
            r"before\s+the\s+end|today)\b",
            text,
        )

        signal_count = sum(
            (sensitive_event, external_event, pressure_event)
        )

        flag(
            "VERIFICATION_REQUEST_REVIEW",
            "MEDIUM" if signal_count >= 2 else "LOW",
            "This message reports a security-relevant event and asks the recipient to verify it independently. Review the context before sending.",
            confidence=round(min(0.9, 0.6 + 0.1 * signal_count), 2),
        )

    return findings
