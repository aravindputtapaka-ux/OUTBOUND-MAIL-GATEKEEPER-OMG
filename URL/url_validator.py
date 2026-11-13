"""Structural URL inspection for outbound email.

This module performs structural checks only. It never browses a destination,
resolves external reputation, or claims that a URL is malicious/safe.

Link classification matters for the verdict: in-page anchors (``#section``),
relative links (``/unsubscribe``) and application schemes such as ``mailto:``
or ``tel:`` are normal in legitimate mail and must NOT be flagged. Executable
schemes (``javascript:``, ``data:``, ``vbscript:``, ...) are active-content
threats and are reported as confirmed critical findings.
"""
from __future__ import annotations

import ipaddress
import os
import re
import warnings
from urllib.parse import urlparse, urlsplit

import idna
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning


# A body that is only a URL is still valid email text. BeautifulSoup warns when
# input resembles a URL/filename; that warning is irrelevant to link inspection.
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


# Extract explicit HTTP(S) and bare www. links from email text.
URL_PATTERN = re.compile(
    r"""(?<![A-Za-z0-9@])(?:https?://|www\.)[^\s<>"']+""",
    re.IGNORECASE,
)

# Punctuation that commonly follows a URL inside a sentence.
TRAILING_PUNCTUATION = ".,;:!?)]}"

# Schemes that are legitimate links in email and have no network destination.
BENIGN_SCHEMES = frozenset({
    "mailto", "tel", "sms", "cid", "mid", "callto", "calendar",
})

# Schemes that can execute or inline active content. A link using one of
# these in outbound mail is unambiguously hostile.
DANGEROUS_SCHEMES = frozenset({
    "javascript", "data", "vbscript", "file", "blob", "filesystem", "about",
})

# Severity metadata for every finding this module can emit. The scoring
# engine consumes these fields directly; omitting them silently downgrades a
# finding to LOW.
FINDING_SEVERITIES = {
    "DANGEROUS_URL_SCHEME": "CRITICAL",
    "NON_HTTP_LINK": "MEDIUM",
    "MALFORMED_URL": "MEDIUM",
    "INVALID_HOSTNAME": "MEDIUM",
    "INSECURE_LOGIN_URL": "MEDIUM",
    "IP_ADDRESS_LINK": "MEDIUM",
    "URL_CREDENTIALS_PRESENT": "HIGH",
    "LINK_TEXT_MISMATCH": "HIGH",
    "IDN_HOSTNAME": "LOW",
    "SHORTENED_URL": "LOW",
    "ACCOUNT_UPDATE_LINK_REVIEW": "MINOR",
    "PAYMENT_UPDATE_LINK_REVIEW": "MINOR",
}


def _finding(code, message, *, confirmed=False):
    finding = {
        "code": code,
        "category": "SUSPICIOUS_LINK",
        "severity": FINDING_SEVERITIES.get(code, "MEDIUM"),
        "message": message,
    }
    if confirmed:
        finding["confirmed"] = True
    return finding


def _normalize_visible_link(value: str) -> str:
    """Allow structural hostname inspection for bare www. mentions.

    The HTTPS prefix is a parser convention, NOT proof the original link
    uses HTTPS or that its destination is trustworthy.
    """
    return "https://" + value if value.lower().startswith("www.") else value


def _network_href(href: str) -> str | None:
    """Return the inspectable HTTP(S) form of a link, or None.

    ``None`` means the value is not a network destination (fragment, relative
    path, mailto:, tel:, ...), so it must not be treated as a suspicious link.
    """
    value = (href or "").strip()
    if not value:
        return None
    if value.startswith("#"):
        return None
    # Protocol-relative links (//host/path) do have a network destination.
    if value.startswith("//"):
        return "https:" + value
    try:
        scheme = urlparse(value).scheme.lower()
    except ValueError:
        return None
    return value if scheme in {"http", "https"} else None


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


def _scheme_of(href: str) -> str | None:
    try:
        return (urlparse(href).scheme or "").lower() or None
    except ValueError:
        return None


def _inspect_single_url(
    href: str,
    display_text: str = "",
) -> list[dict]:
    """Inspect one URL and return any security findings.

    Non-network links that are legitimate in email (mailto:, tel:, cid:,
    fragments and relative paths) yield no findings.
    """
    findings: list[dict] = []

    href = (href or "").strip()
    if not href:
        return findings

    # In-page anchors and relative links have no network destination.
    if href.startswith("#"):
        return findings

    scheme = _scheme_of(href)

    if scheme in BENIGN_SCHEMES:
        return findings

    if scheme in DANGEROUS_SCHEMES:
        findings.append(_finding(
            "DANGEROUS_URL_SCHEME",
            "A hyperlink uses a scheme that can execute or inline active content.",
            confirmed=True,
        ))
        return findings

    if scheme is None:
        # Relative link: "/unsubscribe", "images/logo.png", "?page=2".
        # Protocol-relative "//host/path" is a real network destination.
        if href.startswith("//"):
            href = "https:" + href
        else:
            return findings

    elif scheme not in {"http", "https"}:
        # FTP, news, custom application schemes, etc.
        return [_finding(
            "NON_HTTP_LINK",
            "A hyperlink uses a non-HTTP(S) scheme.",
        )]

    parsed = urlparse(href)

    try:
        hostname = parsed.hostname
        parsed.port  # Accessing this validates the port.
    except ValueError:
        return [_finding("MALFORMED_URL", "A URL contains an invalid host or port.")]

    if not hostname or not parsed.netloc:
        return [_finding(
            "MALFORMED_URL",
            "An HTTP(S) hyperlink has a missing or invalid hostname.",
        )]

    # Warn if an account-login/credential page is linked using plain HTTP.
    # This signal alone does not prove phishing or malware.
    if scheme == "http" and re.search(
        r"(?:login|sign[-_]?in|passw(?:or)?d|credential|reset|verify)",
        parsed.path + "?" + parsed.query,
        flags=re.IGNORECASE,
    ):
        findings.append(_finding(
            "INSECURE_LOGIN_URL",
            "A login or verification link uses unencrypted HTTP; review before sending.",
        ))

    if parsed.username is not None or parsed.password is not None:
        findings.append(_finding(
            "URL_CREDENTIALS_PRESENT",
            "A URL contains embedded user information before its host.",
        ))

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False

    if is_ip_address:
        findings.append(_finding(
            "IP_ADDRESS_LINK",
            "A hyperlink uses an IP address as its host.",
        ))
    else:
        valid_hostname, is_internationalized = _validate_hostname(hostname)

        if not valid_hostname:
            findings.append(_finding(
                "INVALID_HOSTNAME",
                "A hyperlink contains a malformed hostname.",
            ))

        if is_internationalized:
            findings.append(_finding(
                "IDN_HOSTNAME",
                "A hyperlink uses Unicode or Punycode hostname characters. "
                "Review the domain carefully.",
            ))

    # Compare the displayed URL with the actual destination.
    if display_text:
        displayed = display_text.lower().strip().rstrip("/")
        actual = href.lower().rstrip("/")

        if (
            displayed.startswith(("http://", "https://"))
            and displayed != actual
        ):
            findings.append(_finding(
                "LINK_TEXT_MISMATCH",
                "The displayed URL differs from the hyperlink target.",
            ))

    return findings


def _document_candidates(soup: BeautifulSoup) -> list[str]:
    """Return unique, structurally inspectable network URLs in the document."""
    candidates: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            candidates.append(value)

    for link in soup.find_all("a", href=True):
        network = _network_href((link.get("href") or "").strip())
        if network:
            add(network)

    for match in URL_PATTERN.finditer(soup.get_text(" ", strip=True)):
        network = _network_href(
            _normalize_visible_link(match.group(0).rstrip(TRAILING_PUNCTUATION))
        )
        if network:
            add(network)

    return candidates


def _dedupe(findings: list[dict]) -> list[dict]:
    unique: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in findings:
        key = (str(item.get("code", "")), str(item.get("message", "")))
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _inspect_document(soup: BeautifulSoup) -> list[dict]:
    findings: list[dict] = []
    inspected: set[str] = set()

    # 1. Inspect HTML hyperlinks, including non-HTTP(S) schemes.
    for link in soup.find_all("a", href=True):
        href = (link.get("href") or "").strip()
        if not href or href in inspected:
            continue
        inspected.add(href)
        findings.extend(_inspect_single_url(href, link.get_text(" ", strip=True)))

    # 2. Inspect URLs written directly in the email's visible text.
    visible_text = soup.get_text(" ", strip=True)

    for match in URL_PATTERN.finditer(visible_text):
        href = _normalize_visible_link(match.group(0).rstrip(TRAILING_PUNCTUATION))

        if not href or href in inspected:
            continue

        inspected.add(href)
        findings.extend(_inspect_single_url(href))

    return _dedupe(findings)


def inspect_urls(html: str) -> list[dict]:
    """
    Inspect hyperlinks and plain-text HTTP/HTTPS URLs in an email body.

    This function performs structural URL checks only. It does not establish
    whether a website is malicious or safe using live reputation data.
    """
    soup = BeautifulSoup(html or "", "html.parser")
    return _inspect_document(soup)


SHORTENER_HOSTS = frozenset({"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "ow.ly"})


def _trusted_domains() -> set[str]:
    return {
        x.strip().lower().rstrip(".")
        for x in os.getenv("OMG_TRUSTED_LINK_DOMAINS", "").split(",")
        if x.strip()
    }


def validate_urls(body: str = "", html: str = "", extra_urls: list[str] | None = None) -> dict:
    """Original HTML/plain URL inspection + a shortener indicator (no reputation lookup)."""
    combined = "\n\n".join(x for x in (body, html) if x)
    soup = BeautifulSoup(combined, "html.parser")

    findings = _inspect_document(soup)
    candidates = _document_candidates(soup)

    # Explicit URL field(s) are inspected even when not written in the body.
    # Include non-http schemes in the detector rather than silently ignoring them.
    listed_urls = [x.strip() for x in (extra_urls or []) if x and x.strip()]
    seen_candidates = set(candidates)
    for value in listed_urls:
        findings.extend(_inspect_single_url(value))
        if value not in seen_candidates:
            seen_candidates.add(value)
            network = _network_href(value)
            if network:
                candidates.append(network)

    # Distinct static warning heuristic; does NOT assert the target is malicious.
    seen_hosts = set()
    for value in candidates:
        try:
            host = (urlsplit(value).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if host in SHORTENER_HOSTS and host not in seen_hosts:
            seen_hosts.add(host)
            findings.append(_finding(
                "SHORTENED_URL",
                "A URL shortener obscures its destination; review the redirect before sending.",
            ))

    # Context matters: a structurally normal HTTPS URL may still ask users to
    # change financial details or verify an account. This is review-only; no
    # live reputation or sender-identity verification is performed here.
    # Configure OMG_TRUSTED_LINK_DOMAINS with explicit, verified domains.
    trusted = _trusted_domains()

    def allowlisted(host: str) -> bool:
        return any(host == domain or host.endswith("." + domain) for domain in trusted)

    untrusted_urls = []
    for value in sorted(set(candidates)):
        try:
            parsed = urlsplit(value)
            hostname = (parsed.hostname or "").lower().rstrip(".")
            if hostname and not allowlisted(hostname):
                untrusted_urls.append(value)
        except ValueError:
            continue
    if untrusted_urls:
        visible = soup.get_text(" ", strip=True)
        visible = re.sub(r"\s+", " ", visible)[:100_000]
        account_topic = re.search(r"\b(?:account|identity|login|profile)\b", visible, re.I)
        account_update = re.search(
            r"\b(?:review|verify|validate|confirm|update|revalidate)\b.{0,75}"
            r"\b(?:account|identity|details|information|profile|login)\b"
            r"|\b(?:account|profile)\b.{0,70}\b(?:outdated|verification|update|verify|review)\b",
            visible, re.I,
        )
        payment_topic = re.search(r"\b(?:payment|invoice|bank|vendor|billing|remittance)\b", visible, re.I)
        payment_change = re.search(
            r"\b(?:revised|updated|changed|new)\b.{0,75}\b(?:payment|bank|account|instructions|details)\b"
            r"|\b(?:payment|bank|account|instructions|details)\b.{0,75}\b(?:changed|updated|revised)\b",
            visible, re.I,
        )
        if account_topic and account_update:
            findings.append(_finding(
                "ACCOUNT_UPDATE_LINK_REVIEW",
                "Account-update request includes a URL whose destination and authorization have not been independently verified.",
            ))
        if payment_topic and payment_change:
            findings.append(_finding(
                "PAYMENT_UPDATE_LINK_REVIEW",
                "Changed payment instructions include a non-allowlisted URL; independently confirm bank details.",
            ))

    return {
        "findings": _dedupe(findings),
        "url_count": len(candidates),
        "context_penalty": round(min(4.0, float(len(candidates))), 2),
        "coverage": {
            "url_syntax_inspection": "complete",
            "url_reputation": "not_implemented",
        },
    }
