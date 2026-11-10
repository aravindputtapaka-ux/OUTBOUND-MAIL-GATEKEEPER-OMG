import base64
import binascii
import html
import re
from bs4 import BeautifulSoup
from urllib.parse import unquote


SUSPICIOUS_TEXT_PATTERN = re.compile(
    r"\b(?:verify your password|claim your lottery prize|"
    r"earn money fast)\b",
    flags=re.IGNORECASE,
)


def inspect_html_content(subject: str, html_content: str) -> list[dict]:
    """
    Inspect email HTML for suspicious hidden content and encoded text.

    These checks identify indicators for further inspection; they do not
    independently prove that an email is malicious.
    """

    findings = []
    raw_html = html_content or ""

    # 1. Inspect raw HTML before parsing, because BeautifulSoup automatically
    # decodes HTML entities during parsing.
    decoded_raw_html = html.unescape(raw_html)

    if (
        decoded_raw_html != raw_html
        and SUSPICIOUS_TEXT_PATTERN.search(decoded_raw_html)
    ):
        findings.append({
            "code": "ENCODED_SUSPICIOUS_TEXT",
            "category": "SUSPICIOUS_CONTENT",
            "message": (
                "Suspicious text was identified after HTML-entity decoding."
            ),
        })

    # 2. Parse the HTML and inspect elements marked as hidden.
    soup = BeautifulSoup(raw_html, "html.parser")

    for element in soup.find_all(True):
        style = (element.get("style") or "").lower()
        aria_hidden = (element.get("aria-hidden") or "").lower()

        is_hidden = (
            element.has_attr("hidden")
            or aria_hidden == "true"
            or bool(re.search(r"display\s*:\s*none", style))
            or bool(re.search(r"visibility\s*:\s*hidden", style))
            or bool(re.search(r"opacity\s*:\s*0(?:\s*;|\s*$)", style))
        )

        if is_hidden and element.get_text(" ", strip=True):
            findings.append({
                "code": "HIDDEN_HTML_TEXT",
                "category": "SUSPICIOUS_CONTENT",
                "message": (
                    "An HTML element contains text but is marked as hidden. "
                    "Review it in context."
                ),
            })

    # 3. Inspect parsed text for percent-encoded suspicious content.
    visible_text = soup.get_text(" ", strip=True)
    percent_decoded = unquote(visible_text)

    if (
        percent_decoded != visible_text
        and SUSPICIOUS_TEXT_PATTERN.search(percent_decoded)
    ):
        findings.append({
            "code": "ENCODED_SUSPICIOUS_TEXT",
            "category": "SUSPICIOUS_CONTENT",
            "message": (
                "Suspicious text was identified after percent decoding."
            ),
        })

    # 4. Inspect Base64-like tokens only when they decode to suspicious text.
    for token in re.findall(
        r"(?<!\w)[A-Za-z0-9+/]{16,}={0,2}(?!\w)",
        visible_text,
    ):
        try:
            padded = token + "=" * (-len(token) % 4)
            raw = base64.b64decode(padded, validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue

        if SUSPICIOUS_TEXT_PATTERN.search(decoded):
            findings.append({
                "code": "ENCODED_SUSPICIOUS_TEXT",
                "category": "SUSPICIOUS_CONTENT",
                "message": (
                    "A Base64-like token decodes to suspicious text."
                ),
            })
            break

    return findings