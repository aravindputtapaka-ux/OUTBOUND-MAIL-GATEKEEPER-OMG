import ipaddress
import html as html_utils
from difflib import SequenceMatcher
from urllib.parse import unquote, urlsplit
import os
import re
from urllib.parse import urlparse

import idna
from bs4 import BeautifulSoup


# Extract explicit HTTP(S) and bare www. links from email text.
# This does not verify external domain reputation.
URL_PATTERN = re.compile(
    r"""(?<![A-Za-z0-9@])(?:https?://|www\.)[^\s<>"']+""",
    re.IGNORECASE,
)


def _normalize_visible_link(value: str) -> str:
    """Allow structural hostname inspection for bare www. mentions.

    The HTTPS prefix is a parser convention, NOT proof the original link
    uses HTTPS or that its destination is trustworthy.
    """
    return "https://" + value if value.lower().startswith("www.") else value

# Remove common punctuation that may follow a URL in a sentence.
TRAILING_PUNCTUATION = ".,;:!?)]}"


def _validate_hostname(hostname: str) -> tuple[bool, bool]:
    """Validate a hostname and identify internationalized domain names."""
    if not hostname:
        return False, False

    try:
        ipaddress.ip_address(hostname)
        return True, False
    except ValueError:
        pass

    hostname = hostname.rstrip(".")

    if not hostname or len(hostname) > 253:
        return False, False

    labels = hostname.split(".")
    is_internationalized = False

    for label in labels:
        if not label or len(label) > 63:
            return False, is_internationalized

        if label.startswith("-") or label.endswith("-"):
            return False, is_internationalized

        if not re.fullmatch(r"[A-Za-z0-9-]+", label):
            is_internationalized = True

        if label.lower().startswith("xn--"):
            is_internationalized = True

        try:
            idna.encode(label, uts46=True, std3_rules=True)
        except idna.IDNAError:
            return False, is_internationalized

    return True, is_internationalized


def _inspect_single_url(
    href: str,
    display_text: str = "",
) -> list[dict]:
    """Inspect one URL and return any security findings."""
    findings = []

    href = href.strip()

    if not href:
        return findings

    parsed = urlparse(href)
    scheme = parsed.scheme.lower()

    # Preserve the existing rule for non-HTTP(S) hyperlinks.
    if scheme not in {"http", "https"}:
        findings.append(
            {
                "code": "NON_HTTP_LINK",
                "category": "SUSPICIOUS_LINK",
                "message": "A hyperlink uses a non-HTTP(S) scheme.",
            }
        )
        return findings

    try:
        hostname = parsed.hostname
        parsed.port  # Accessing this validates the port.
    except ValueError:
        findings.append(
            {
                "code": "MALFORMED_URL",
                "category": "SUSPICIOUS_LINK",
                "message": "A URL contains an invalid host or port.",
            }
        )
        return findings

    if not hostname or not parsed.netloc:
        findings.append(
            {
                "code": "MALFORMED_URL",
                "category": "SUSPICIOUS_LINK",
                "message": (
                    "An HTTP(S) hyperlink has a missing or invalid hostname."
                ),
            }
        )
        return findings

    # Warn if an account-login/credential page is linked using plain HTTP.
    # This signal alone does not prove phishing or malware.
    if scheme == "http" and re.search(
        r"(?:login|sign[-_]?in|passw(?:or)?d|credential|reset|verify)",
        parsed.path + "?" + parsed.query,
        flags=re.IGNORECASE,
    ):
        findings.append({
            "code": "INSECURE_LOGIN_URL",
            "category": "SUSPICIOUS_LINK",
            "message": "A login or verification link uses unencrypted HTTP; review before sending.",
        })

    if parsed.username is not None or parsed.password is not None:
        findings.append(
            {
                "code": "URL_CREDENTIALS_PRESENT",
                "category": "SUSPICIOUS_LINK",
                "message": (
                    "A URL contains embedded user information before its host."
                ),
            }
        )

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False

    if is_ip_address:
        findings.append(
            {
                "code": "IP_ADDRESS_LINK",
                "category": "SUSPICIOUS_LINK",
                "message": "A hyperlink uses an IP address as its host.",
            }
        )
    else:
        valid_hostname, is_internationalized = _validate_hostname(hostname)

        if not valid_hostname:
            findings.append(
                {
                    "code": "INVALID_HOSTNAME",
                    "category": "SUSPICIOUS_LINK",
                    "message": "A hyperlink contains a malformed hostname.",
                }
            )

        if is_internationalized:
            findings.append(
                {
                    "code": "IDN_HOSTNAME",
                    "category": "SUSPICIOUS_LINK",
                    "message": (
                        "A hyperlink uses Unicode or Punycode hostname "
                        "characters. Review the domain carefully."
                    ),
                }
            )

    # Compare the displayed URL with the actual destination.
    if display_text:
        displayed = display_text.lower().strip().rstrip("/")
        actual = href.lower().rstrip("/")

        if (
            displayed.startswith(("http://", "https://"))
            and displayed != actual
        ):
            findings.append(
                {
                    "code": "LINK_TEXT_MISMATCH",
                    "category": "SUSPICIOUS_LINK",
                    "message": (
                        "The displayed URL differs from the hyperlink target."
                    ),
                }
            )

    return findings


def inspect_urls(html: str) -> list[dict]:
    """
    Inspect hyperlinks and plain-text HTTP/HTTPS URLs in an email body.

    This function performs structural URL checks only. It does not establish
    whether a website is malicious or safe using live reputation data.
    """
    soup = BeautifulSoup(html or "", "html.parser")
    findings = []

    # Track inspected URLs to avoid duplicate findings when a URL appears
    # both as an href and as visible text.
    inspected_urls = set()

    # 1. Inspect HTML hyperlinks, including non-HTTP(S) schemes.
    for link in soup.find_all("a", href=True):
        href = link.get("href", "").strip()
        display_text = link.get_text(" ", strip=True)

        if not href:
            continue

        key = href

        if key in inspected_urls:
            continue

        inspected_urls.add(key)
        findings.extend(_inspect_single_url(href, display_text))

    # 2. Inspect URLs written directly in the email's visible text.
    visible_text = soup.get_text(" ", strip=True)

    for match in URL_PATTERN.finditer(visible_text):
        href = _normalize_visible_link(match.group(0).rstrip(TRAILING_PUNCTUATION))

        if not href:
            continue

        key = href

        if key in inspected_urls:
            continue

        inspected_urls.add(key)
        findings.extend(_inspect_single_url(href))

    return findings

SHORTENER_HOSTS = frozenset({"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "ow.ly"})

def _normalized_email_url_text(body: str, html: str) -> str:
    """Decode common email encodings without fetching or following links.

    Bounded decoding also exposes HTML-escaped and percent-escaped URLs. Do
    not trust the result as a safe destination; validation is static only.
    """
    raw = "\n".join((body or "", html or ""))[:200_000]
    for _ in range(2):
        changed = html_utils.unescape(raw)
        changed = re.sub(r"\\u003[aA]", ":", changed)
        changed = changed.replace("\\/", "/")
        # Unquote only if the content contains an encoded URL *prefix*, not
        # arbitrary URL query parameters that might change their semantics.
        if re.search(r"https?%3a%2f%2f|www%2e", changed, re.I):
            changed = unquote(changed)
        if changed == raw:
            break
        raw = changed[:200_000]
    return raw


def _candidate_urls(text: str) -> list[tuple[str, str]]:
    """Return (destination, displayed text) preserving anchor link labels."""
    document = BeautifulSoup(text, "html.parser")
    results: list[tuple[str, str]] = []
    for a in document.find_all("a", href=True):
        url = _normalize_visible_link(html_utils.unescape(a.get("href", "")).strip())
        if url:
            results.append((url, a.get_text(" ", strip=True)))
    for match in URL_PATTERN.finditer(document.get_text(" ", strip=True)):
        link = _normalize_visible_link(match.group(0).rstrip(TRAILING_PUNCTUATION))
        if link:
            results.append((link, ""))
    return list(dict.fromkeys(results))


def validate_urls(body: str = "", html: str = "", extra_urls: list[str] | None = None) -> dict:
    """Statically inspect URL structure and *email-context* security signals.

    No DNS queries, redirect following, downloaded pages or domain-reputation
    assertions occur. A valid HTTPS scheme is NOT proof of a legitimate link.
    """
    normalized = _normalized_email_url_text(body, html)
    doc = BeautifulSoup(normalized, "html.parser")
    visible = re.sub(r"\s+", " ", doc.get_text(" ", strip=True))[:100_000]
    entries = _candidate_urls(normalized)
    entries.extend((v.strip(), "") for v in (extra_urls or []) if isinstance(v, str) and v.strip())
    candidates = list(dict.fromkeys((url for url, _ in entries)))
    findings: list[dict] = []
    seen = set()
    for value, display in entries:
        for issue in _inspect_single_url(value, display):
            k = (value, issue["code"])
            if k not in seen:
                findings.append(issue)
                seen.add(k)

    trusted = {
        x.strip().lower().rstrip(".")
        for x in os.getenv("OMG_TRUSTED_LINK_DOMAINS", "").split(",") if x.strip()
    }

    def allowlisted(host: str) -> bool:
        return any(host == domain or host.endswith("." + domain) for domain in trusted)

    untrusted = []
    hosts = set()
    for value in candidates:
        try:
            hostname = (urlsplit(value).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if not hostname:
            continue
        hosts.add(hostname)
        if hostname in SHORTENER_HOSTS:
            findings.append({"code": "SHORTENED_URL", "category": "SUSPICIOUS_LINK", "severity": "MEDIUM",
                             "message": "A URL shortener conceals its destination; review the target."})
        if hostname.endswith((".example", ".test", ".invalid")) or hostname == "example":
            findings.append({"code": "RESERVED_TEST_DOMAIN", "category": "URL_INFORMATION", "severity": "INFO",
                             "message": "Link uses a reserved test domain; it is not a verified payment or login destination."})
        if not allowlisted(hostname):
            untrusted.append(value)
            # Compare only against explicitly configured trusted registrable
            # domains; resemblance alone is a warning, never a malware claim.
            for known in trusted:
                if hostname != known and not hostname.endswith("." + known):
                    candidate_root = hostname.split(".")[-2:] if "." in hostname else [hostname]
                    trusted_root = known.split(".")[-2:] if "." in known else [known]
                    if (candidate_root[-1:] == trusted_root[-1:] and
                            SequenceMatcher(None, ".".join(candidate_root), ".".join(trusted_root)).ratio() >= 0.84):
                        findings.append({"code": "LOOKALIKE_TRUSTED_DOMAIN", "category": "DOMAIN_IMPERSONATION",
                                         "severity": "MEDIUM",
                                         "message": "A URL domain resembles an explicitly trusted domain but is not allowlisted."})
                        break

    # The host alone never proves fraud: account-change and financial-change
    # warnings require an actual URL *and* corroborating email instructions.
    if untrusted:
        account_topic = bool(re.search(r"\b(?:account|identity|login|profile)\b", visible, re.I))
        account_update = bool(re.search(
            r"\b(?:review|verify|validate|confirm|update|revalidate)\b.{0,75}"
            r"\b(?:account|identity|details|information|profile|login)\b"
            r"|\b(?:account|profile)\b.{0,70}\b(?:outdated|verification|update|verify|review)\b",
            visible, re.I,
        ))
        payment_topic = bool(re.search(r"\b(?:payment|invoice|bank|vendor|billing|remittance|transfer)\b", visible, re.I))
        payment_change = bool(re.search(
            r"\b(?:revised|updated|changed|new|different)\b.{0,90}"
            r"\b(?:payment|bank|account|instructions|details)\b"
            r"|\b(?:payment|bank|account|instructions|details)\b.{0,90}"
            r"\b(?:changed|updated|revised|replaced)\b", visible, re.I,
        ))
        bypass = bool(re.search(
            r"\b(?:bypass|skip|ignore|circumvent)\b.{0,65}\b(?:approval|process|review|checks?|verification)\b"
            r"|\b(?:do\s+not|don't)\s+(?:verify|contact|confirm|consult)\b.{0,80}"
            r"\b(?:vendor|finance|manager|bank|payment|account)\b", visible, re.I,
        ))
        if account_topic and account_update:
            findings.append({"code": "ACCOUNT_UPDATE_LINK_REVIEW", "category": "LINK_CONTEXT", "severity": "MEDIUM",
                             "message": "Account-update instructions contain a non-allowlisted URL; verify ownership and authorization."})
        if payment_topic and payment_change:
            findings.append({"code": "PAYMENT_CHANGE_LINK_REVIEW", "category": "LINK_CONTEXT", "severity": "MEDIUM",
                             "message": "Changed payment details are accompanied by a non-allowlisted URL; confirm the bank details independently."})
        if payment_topic and payment_change and bypass:
            findings.append({"code": "PAYMENT_APPROVAL_BYPASS_LINK", "category": "LINK_CONTEXT", "severity": "HIGH",
                             "message": "Payment-update link appears together with instructions to evade independent approval or verification."})
        secret_request = bool(re.search(
            r"\b(?:submit|send|share|provide|enter|type|upload)\b.{0,90}"
            r"\b(?:your\s+)?(?:password|otp|one.time\s+(?:code|password)|verification\s+code)\b",
            visible, re.I,
        ))
        # Do not flag education such as 'never share your password'.
        security_advice = bool(re.search(
            r"\b(?:never|do\s+not|don't)\s+(?:send|share|provide|enter|submit|upload)\b",
            visible, re.I,
        ))
        link_instruction = bool(re.search(r"\b(?:click|open|visit|follow|use|at|via)\b.{0,100}"
                                          r"\b(?:link|url|website|page|portal|https?)\b", visible, re.I))
        if secret_request and link_instruction and not security_advice:
            findings.append({"code": "CREDENTIAL_PHISHING", "category": "LINK_CONTEXT", "severity": "CRITICAL",
                             "message": "A link is paired with an instruction to submit a password or authentication code."})

    # Maintain consistent order, de-duplicate repeated body/HTML URL mentions.
    unique: list[dict] = []
    seen_finding = set()
    for f in findings:
        key = (f.get("code"), f.get("message"))
        if key not in seen_finding:
            seen_finding.add(key)
            unique.append(f)
    return {
        "findings": unique,
        "url_count": len(candidates),
        "coverage": {"url_syntax_inspection": "complete", "url_reputation": "not_implemented",
                     "redirect_verification": "not_performed_no_network_fetch"},
    }
