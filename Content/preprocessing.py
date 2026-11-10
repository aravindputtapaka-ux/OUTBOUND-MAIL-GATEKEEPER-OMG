from bs4 import BeautifulSoup


def email_to_text(subject: str, body: str) -> str:
    """Normalize subject and HTML/plain-text body for the local text model."""
    visible = BeautifulSoup(body or "", "html.parser").get_text(" ", strip=True)
    return " ".join(f"{subject or ''} {visible}".split())
