import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_EMAIL_LIKE = re.compile(r"^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$")


class EmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel: Literal["email"] = "email"
    subject: str = Field(..., min_length=1, max_length=998)
    # `body` is the plain-text email body. `html` remains supported for
    # existing Notify clients that submit HTML content. At least one is required.
    body: str | None = Field(default=None, max_length=1_000_000)
    html: str | None = Field(default=None, max_length=1_000_000)
    recipients: list[str] = Field(..., min_length=1, max_length=100)
    attachments: list[dict] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def require_email_content(self):
        body_present = self.body is not None and bool(self.body.strip())
        html_present = self.html is not None and bool(self.html.strip())
        if not body_present and not html_present:
            raise ValueError("provide a non-empty email body using 'body' or 'html'")
        return self

    @property
    def inspection_content(self) -> str:
        """Combined content used by text, URL and ML inspections."""
        parts = [part.strip() for part in (self.body, self.html) if part and part.strip()]
        return "\n\n".join(parts)

    @property
    def html_content(self) -> str:
        """HTML payload for HTML-specific inspection, falling back to body."""
        return self.html if self.html and self.html.strip() else (self.body or "")

    @field_validator("subject")
    @classmethod
    def subject_not_whitespace(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("subject must not be whitespace only")
        return value.strip()

    @field_validator("recipients")
    @classmethod
    def validate_recipients(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            if not isinstance(value, str) or not _EMAIL_LIKE.fullmatch(value.strip()):
                raise ValueError("each recipient must be a valid email address")
            cleaned.append(value.strip())
        return cleaned
