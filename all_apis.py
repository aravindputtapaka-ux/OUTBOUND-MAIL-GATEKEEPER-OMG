"""Merged OMG application (app.py + all_apis.py).

One business endpoint: POST /api/v1/analyze, accepting JSON or multipart
with binary attachments. GET /, /health, /ready, and /status are operational
endpoints from the second developer's app.py (excluded from Swagger).

This backend validates but never sends emails. A delivery gateway must
re-run authorization and verify warning acknowledgment server-side.
"""
from __future__ import annotations
import hmac
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")
if (os.getenv("OMG_ENV", "").lower() in {"production", "prod"}
        or os.getenv("OMG_ENVIRONMENT", "").lower() in {"production", "prod"}):
    os.environ["OMG_ENV"] = "production"
    os.environ["OMG_ENVIRONMENT"] = "production"

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile as StarletteUploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException

from Attachments.api import format_public_response
from Attachments.attachment_gate import POLICY, read_uploads
from Attachments.attachment_validator import scan_bytes
from Attachments.warning_ack import issue_warning_challenge
from Content.config import settings
from Content.content_validator import validate_content
from Content.email_schema import EmailRequest
from Content.request_middleware import RequestLoggingMiddleware
from URL.url_validator import validate_urls
from decision_making import decide_email

logger = logging.getLogger("omg.email")
logging.basicConfig(level=settings.LOG_LEVEL)


def omit_empty_arrays(value: Any) -> Any:
    """Keep the requested Error: [] but omit unhelpful empty scanner lists."""
    if isinstance(value, dict):
        return {
            key: omit_empty_arrays(item)
            for key, item in value.items()
            if key == "Error" or not (isinstance(item, list) and not item)
        }
    if isinstance(value, list):
        return [omit_empty_arrays(item) for item in value]
    return value


class CompactJSONResponse(JSONResponse):
    def render(self, content: Any) -> bytes:
        return super().render(omit_empty_arrays(content))


async def require_api_key(
    request: Request,
    x_omg_api_key: str | None = Header(None),
    x_api_key: str | None = Header(None),
) -> None:
    """Retain both existing authentication header names for compatibility."""
    expected = settings.API_KEY
    if expected:
        if not hmac.compare_digest(x_omg_api_key or x_api_key or "", expected):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")
    elif settings.is_production:
        raise HTTPException(status_code=503, detail="API key not configured")
    elif (request.client.host if request.client else "") not in {"127.0.0.1", "::1", "testclient"}:
        raise HTTPException(status_code=403, detail="Unauthenticated access permitted only for local development")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate_production_configuration()
    if settings.is_production:
        if not POLICY.require_clamav:
            raise RuntimeError("Production requires ClamAV attachment scanning")
        from Content.rule_checks import _load_runtime_rules
        from Content.model_loader import load_model
        _load_runtime_rules()
        load_model(str(settings.resolve_path(settings.MODEL_PATH)))
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    default_response_class=CompactJSONResponse,
    description=(
        "Single security endpoint for email subject, body, HTML, embedded URLs, "
        "and optional binary attachments. This service does not send emails."
    ),
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
)
app.add_middleware(RequestLoggingMiddleware)

# Operational endpoints migrated from the separate app.py. They are not
# business-validation endpoints and are intentionally hidden in Swagger.
_PREFIX = settings.API_PREFIX


@app.get("/", include_in_schema=False)
def service_root() -> dict:
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "message": "OMG email validation backend is running; mail delivery is not implemented.",
        "docs": None if settings.is_production else "/docs",
    }


@app.get("/demo", include_in_schema=False)
def local_demo():
    """Same-origin, validation-only demo. Never publish a browser service key."""
    if settings.is_production:
        raise HTTPException(404, detail="Demo is disabled in production")
    response = FileResponse(Path(__file__).resolve().parent / "OMG_Mail_Portal_Demo.html", media_type="text/html")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; connect-src 'self'; style-src 'unsafe-inline'; "
        "script-src 'unsafe-inline'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    return response


@app.get(f"{_PREFIX}/health", include_in_schema=False)
def health_check() -> dict:
    """Process liveness only; does not certify that all scanners are available."""
    return {"service": "OMG", "status": "running"}


def _readiness_checks() -> dict[str, str]:
    rules = settings.resolve_path(settings.RULES_PATH)
    model = settings.resolve_path(settings.MODEL_PATH)
    checks = {
        "content_rules": "present" if rules.is_file() else "missing",
        "content_engine": "loaded",
        "url_engine": "loaded",
        "attachment_engine": "loaded",
        "required_ml_artifact": (
            "present" if model.is_file() else "missing"
        ) if settings.REQUIRE_ML else "not_required",
        "antivirus": (
            "required_runtime_check" if POLICY.require_clamav else "not_required_by_policy"
        ),
    }
    return checks


@app.get(f"{_PREFIX}/ready", include_in_schema=False)
def readiness_check():
    """Static dependency checks, not a substitute for a live AV/OCR self-test."""
    checks = _readiness_checks()
    ready = checks["content_rules"] == "present" and checks["required_ml_artifact"] != "missing"
    data = {"service": "OMG", "ready": ready, "checks": checks,
            "notice": "Antivirus/OCR readiness requires separate runtime checks."}
    if not ready:
        return JSONResponse(status_code=503, content=data)
    return data


@app.get(f"{_PREFIX}/status", include_in_schema=False,
         dependencies=[Depends(require_api_key)])
def service_status() -> dict:
    checks = _readiness_checks()
    return {
        "service": "OMG", "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "verdicts": ["SAFE", "WARNING", "RESTRICTED"],
        "email_validation_endpoint": f"{_PREFIX}/analyze",
        "content_rules": checks["content_rules"],
        "ml_classification": "enabled" if settings.ENABLE_ML or settings.REQUIRE_ML else "disabled",
        "experimental_tfidf": "enabled_review_only" if settings.ENABLE_EXPERIMENTAL_TFIDF else "disabled",
        "url_reputation": "not_implemented",
        "mail_delivery": "not_implemented",
        "attachment_antivirus": checks["antivirus"],
    }


def _valid_email(data: dict[str, Any]) -> EmailRequest:
    try:
        return EmailRequest.model_validate(data)
    except ValidationError as exc:
        raise HTTPException(422, detail=[{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()])


def _recipients_from_form(value: str | None) -> list[str]:
    if value is None:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        parsed = [part.strip() for part in value.split(",") if part.strip()]
    if not isinstance(parsed, list):
        raise HTTPException(422, detail="recipients must be a JSON array or comma-separated addresses")
    return parsed


async def _multipart_payload(request: Request) -> tuple[dict[str, Any], list[StarletteUploadFile]]:
    """Parse optional files without depending on newer Starlette form options.

    Starlette versions installed with older FastAPI releases may reject the
    `max_part_size` argument with TypeError. Only use the widely supported
    `max_files` and `max_fields` options; enforce field limits explicitly.
    """
    # The attachment policy already enforces 3 MB/file and 10 MB overall.
    # Allow another 3 MB for subject/body/HTML, recipients and multipart headers.
    max_body_bytes = min(settings.MAX_REQUEST_BYTES, POLICY.max_total_bytes + 3 * 1024 * 1024)
    length = request.headers.get("content-length")
    if length is not None:
        try:
            if int(length) > max_body_bytes:
                raise HTTPException(413, detail="Multipart request exceeds the configured size limit")
        except ValueError:
            raise HTTPException(400, detail="Invalid Content-Length header")

    try:
        form = await request.form(max_files=POLICY.max_files + 1, max_fields=30)
    except StarletteHTTPException as exc:
        # Real multipart parser limits are different from syntax errors.
        detail = str(exc.detail).lower()
        if any(term in detail for term in ("too many", "maximum", "exceeded", "part exceeded")):
            raise HTTPException(413, detail="Multipart attachment or field limit exceeded") from exc
        raise HTTPException(400, detail="Malformed multipart body") from exc
    except TypeError as exc:
        logger.exception("Multipart parser compatibility error")
        raise HTTPException(500, detail="Multipart parser is incompatible; update FastAPI/Starlette/python-multipart") from exc
    except Exception as exc:
        logger.warning("Malformed multipart data: %s", type(exc).__name__)
        raise HTTPException(400, detail="Malformed multipart body") from exc

    uploaded: list[StarletteUploadFile] = []
    allowed_fields = {"channel", "subject", "body", "html", "recipients", "files", "attachments"}
    for field, value in form.multi_items():
        if field not in allowed_fields:
            raise HTTPException(422, detail=f"Unexpected form field: {field}; URLs must be included in body or HTML")
        if isinstance(value, StarletteUploadFile):
            if field not in {"files", "attachments"}:
                raise HTTPException(422, detail=f"Unexpected file field: {field}")
            if not value.filename:
                # Swagger can submit an empty, filename-less file control.
                if value.size != 0 or await value.read(1):
                    raise HTTPException(422, detail="Uploaded file requires a filename")
                continue
            uploaded.append(value)
        elif field in {"files", "attachments"}:
            # Swagger's optional file chooser sends files="" when left untouched.
            if value not in ("", "[]"):
                raise HTTPException(422, detail="files must be binary uploads, not text")
        else:
            if len(str(value).encode("utf-8")) > 1024 * 1024:
                raise HTTPException(413, detail=f"Multipart field '{field}' exceeds 1 MB")

    data: dict[str, Any] = {
        "channel": form.get("channel", "email"),
        "subject": form.get("subject"),
        "body": form.get("body"),
        "html": form.get("html"),
        "recipients": _recipients_from_form(form.get("recipients")),
        "attachments": [],
    }
    return data, uploaded



def _public_issues(findings: list[dict]) -> list[dict]:
    """Expose ALL actionable findings; do not hide evidence behind one example."""
    issues = []
    seen = set()
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "MINOR": 3, "LOW": 3, "INFO": 4}
    for f in sorted(findings, key=lambda x: rank.get(str(x.get("severity", "HIGH")).upper(), 2)):
        code = str(f.get("code") or "UNKNOWN_FINDING")
        reason = str(f.get("message") or f.get("reason") or "Security review required")
        key = (code, reason)
        if key in seen:
            continue
        seen.add(key)
        issues.append({"code": code, "severity": str(f.get("severity") or "HIGH").upper(), "reason": reason})
    return issues


def _overall_reason(result: dict, report: dict | None) -> str:
    findings = result.get("findings", [])
    codes = {f["code"] for f in findings}
    if "VENDOR_PAYMENT_DIVERSION" in codes:
        reason = "Suspicious vendor bank-account redirection and instructions to bypass payment approvals were detected."
    elif {"LOTTERY_SCAM", "ADVANCE_FEE_FRAUD", "LOTTERY_IDENTITY_HARVEST"} & codes:
        reason = "Possible lottery-prize fraud or a request for sensitive information was detected."
    elif findings:
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "MINOR": 3, "LOW": 3, "INFO": 4}
        top = min(findings, key=lambda f: rank.get(f.get("severity", "HIGH"), 1))
        reason = str(top["message"]).rstrip(". ") + "."
    elif report and report.get("status") in {"WARNING", "RESTRICTED"}:
        reason = "Attachment inspection requires attention."
    else:
        reason = "Email security review is required."
    if result["status"] == "RESTRICTED":
        return reason + " Sending is blocked until the issues are corrected and revalidated."
    return reason + " Review the issue and explicitly acknowledge before sending."


def _format_public(result: dict, content: dict, urls: dict, report: dict | None) -> dict:
    """Use the exact current unified-email contract with stable JSON key order."""
    vr = result["validation_results"]
    c = vr["content"]
    text_section: dict | str = {"status": c["status"]}
    text_issues = _public_issues(c["findings"])
    if text_issues:
        text_section["issues"] = text_issues

    url_section: dict | str = "empty"
    if vr["urls"] != "empty":
        url_section = {"status": vr["urls"]["status"]}
        url_issues = _public_issues(vr["urls"]["findings"])
        if url_issues:
            url_section["issues"] = url_issues

    attachments_section: list[dict] | str = "empty"
    if report is not None:
        attachments_section = []
        formatted = format_public_response(report)
        for item in formatted.get("attachments", []):
            file_record = {k: item.get(k) for k in
                           ("filename", "status", "detected_type", "antivirus")}
            items = _public_issues(item.get("issues", []))
            if items:
                file_record["issues"] = items
            attachments_section.append(file_record)
        # Some blocks occur before a file is individually inspected. Preserve
        # these global reasons instead of emitting a restricted empty array.
        if not attachments_section or report.get("findings"):
            group_issues = [*report.get("findings", [])]
            for reason in (report.get("popup") or {}).get("reasons", []):
                if isinstance(reason, dict):
                    group_issues.append(reason)
            if not group_issues and not attachments_section and report.get("status") != "SAFE":
                group_issues = [{"code": "ATTACHMENT_INSPECTION_INCOMPLETE",
                                 "severity": "CRITICAL", "reason": "Attachment could not be inspected."}]
            group_public = _public_issues(group_issues)
            if group_public:
                reasons = (report.get("popup") or {}).get("reasons", [])
                names = {r.get("filename") for r in reasons if isinstance(r, dict) and r.get("filename")}
                name = next(iter(names)) if len(names) == 1 and not attachments_section else "(attachments)"
                attachments_section.append({"filename": name, "status": report.get("status"),
                                            "detected_type": None, "antivirus": "NOT_RUN", "issues": group_public})
        if not attachments_section:
            attachments_section = "empty"

    errors = []
    if any(f["severity"] != "INFO" for f in c["findings"]):
        errors.append("text")
    if isinstance(vr["urls"], dict) and any(f["severity"] != "INFO" for f in vr["urls"].get("findings", [])):
        errors.append("URL")
    if isinstance(vr["attachments"], dict) and (
        vr["attachments"]["status"] != "SAFE" or
        any(f["source"] == "attachments" and f["severity"] != "INFO" for f in result["findings"])
    ):
        errors.append("attachments")

    popup = None
    status = result["status"]
    if status in {"WARNING", "RESTRICTED"}:
        popup = {
            "show": True, "type": status,
            "title": "Email Security Warning" if status == "WARNING" else "Email Restricted",
            "message": _overall_reason(result, report),
            "actions": ["EDIT_MAIL", "CLOSE"] if status == "WARNING" else ["CLOSE"],
        }

    public = {
        "status": status,
        "can_send": result["can_send"],
        "confidence_score": result["confidence_score"],
        "score_contributions": result["score_contributions"],
        "text": text_section,
        "URL": url_section,
        "attachments": attachments_section,
        "Error": errors,
        "requires_acknowledgement": result["requires_acknowledgement"],
        "confidence_source": result["confidence_source"],
        "popup": popup,
    }
    # A signed attachment-warning challenge is necessary only for legacy
    # server-side attachment acknowledgement; never treat popup CLOSE as proof.
    if status == "WARNING" and result.get("warning_challenge"):
        public["warning_challenge"] = result["warning_challenge"]
    return public


def _attachment_failure(code: str, message: str) -> dict[str, Any]:
    """Fail closed if upload reading or mandatory attachment validation fails."""
    return {
        "status": "RESTRICTED", "can_send": False, "confidence_score": None,
        "findings": [{"code": code, "category": "INSPECTION_FAILURE", "reason": message}],
        "attachments": [], "popup": {"reasons": [
            {"code": code, "reason": message, "severity": "CRITICAL"}
        ]},
    }


def _validate_module_report(data: Any, name: str) -> dict:
    """A malformed/missing detector result cannot silently become SAFE."""
    valid = (isinstance(data, dict)
             and isinstance(data.get("findings"), list)
             and isinstance(data.get("coverage"), dict))
    if valid:
        mandatory_checks = (
            ("url_syntax_inspection",) if name == "URL"
            else ("runtime_text_rules", "html_inspection", "contextual_text_rules")
        )
        findings = data["findings"]
        valid = all(isinstance(finding, dict) for finding in findings)
        if valid:
            incomplete_checks = [
                check for check in mandatory_checks
                if data["coverage"].get(check) != "complete"
            ]
            if incomplete_checks and not any(
                finding.get("category") == "INSPECTION_FAILURE" for finding in findings
            ):
                # A detector marking a mandatory check failed without emitting
                # a finding must not produce a misleading SAFE decision.
                data = {
                    **data,
                    "findings": [*findings, {
                        "code": f"{name}_SCAN_INCOMPLETE",
                        "category": "INSPECTION_FAILURE",
                        "message": "Mandatory checks incomplete: " + ", ".join(incomplete_checks),
                    }],
                }
    if valid:
        return data
    return {
        "findings": [{
            "code": f"{name}_SCAN_INCOMPLETE", "category": "INSPECTION_FAILURE",
            "message": f"{name} scanner did not return a complete, valid inspection report.",
        }],
        "coverage": {
            "url_syntax_inspection" if name == "URL" else "runtime_text_rules": "failed"
        },
    }


async def _analyze(data: dict[str, Any], uploaded: list[StarletteUploadFile] | None = None) -> dict:
    # All URLs must be present in subject/body/HTML. The URL validator extracts
    # them automatically; do not accept separate url/urls request fields.
    email = _valid_email(data)

    if email.attachments and not uploaded:
        # A JSON attachment object is not equivalent to binary file inspection.
        report = {
            "status": "RESTRICTED", "can_send": False, "confidence_score": None,
            "findings": [{
                "code": "ATTACHMENT_BINARY_REQUIRED", "category": "INSPECTION_FAILURE",
                "reason": "Attachments require actual binary multipart uploads.",
            }],
            "attachments": [],
        }
    elif uploaded:
        try:
            items, error = await read_uploads(uploaded)
            if error:
                report = error
            else:
                report = await run_in_threadpool(scan_bytes, items)
                if not isinstance(report, dict) or report.get("status") not in {"SAFE", "WARNING", "RESTRICTED"}:
                    report = _attachment_failure("ATTACHMENT_SCAN_INCOMPLETE", "Attachment scanner returned an invalid result.")
                elif report["status"] == "WARNING":
                    report["warning_challenge"] = issue_warning_challenge(items)
        except Exception:
            logger.exception("Attachment engine failed")
            report = _attachment_failure("ATTACHMENT_SCAN_FAILED", "Attachment security inspection could not be completed.")
    else:
        report = None

    try:
        content = await run_in_threadpool(validate_content, email.subject, email.body or "", email.html or "")
    except Exception as exc:
        logger.exception("Content engine failed")
        content = {
            "findings": [{"code": "CONTENT_SCAN_FAILED", "category": "INSPECTION_FAILURE",
                          "message": f"Content engine failed ({type(exc).__name__})"}],
            "coverage": {"runtime_text_rules": "failed"},
        }
    try:
        urls = await run_in_threadpool(
            validate_urls,
            "\n\n".join((email.subject, email.body or "")),
            email.html or "",
        )
    except Exception as exc:
        logger.exception("URL engine failed")
        urls = {
            "findings": [{"code": "URL_SCAN_FAILED", "category": "INSPECTION_FAILURE",
                          "message": f"URL engine failed ({type(exc).__name__})"}],
            "coverage": {"url_syntax_inspection": "failed"},
        }
    content = _validate_module_report(content, "CONTENT")
    urls = _validate_module_report(urls, "URL")
    decided = decide_email(content, urls, report)
    return _format_public(decided, content, urls, report)


# Both content-types are documented on this ONE endpoint. Swagger provides the
# multipart file picker without creating a duplicate '/analyze-with-attachments'.
_ANALYZE_REQUEST_BODY = {
    "required": True,
    "content": {
        "application/json": {
            "schema": {
                "type": "object",
                "required": ["subject", "recipients"],
                "properties": {
                    "subject": {"type": "string", "example": "October invoice"},
                    "body": {"type": "string", "example": "Please review the invoice."},
                    "html": {"type": "string", "example": ""},
                    "recipients": {"type": "array", "items": {"type": "string"}, "example": ["user@example.com"]},
                    "attachments": {"type": "array", "items": {"type": "object"}, "description": "Do not use JSON placeholders for real attachments; upload binary files using multipart."},
                },
            },
        },
        "multipart/form-data": {
            "schema": {
                "type": "object",
                "required": ["subject", "recipients"],
                "properties": {
                    "subject": {"type": "string"},
                    "body": {"type": "string", "description": "Plain-text email body (or provide HTML)"},
                    "html": {"type": "string", "description": "Optional HTML body"},
                    "recipients": {"type": "string", "description": 'JSON list or comma-separated addresses, e.g. ["user@example.com"]'},
                    "files": {"type": "array", "items": {"type": "string", "format": "binary"}, "description": "Optional attachments (0–5 files)"},
                },
            },
            "encoding": {"files": {"style": "form", "explode": True}},
        },
    },
}


@app.post(
    f"{_PREFIX}/analyze",
    tags=["Email Validation"],
    summary="Email Validation — subject, body, URLs and optional attachments",
    dependencies=[Depends(require_api_key)],
    openapi_extra={"requestBody": _ANALYZE_REQUEST_BODY},
)
async def analyze(request: Request):
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type == "application/json":
        try:
            payload = await request.json()
        except (ValueError, UnicodeError):
            raise HTTPException(400, detail="Invalid JSON payload")
        if not isinstance(payload, dict):
            raise HTTPException(422, detail="JSON root must be an object")
        return await _analyze(payload)
    if content_type in {"multipart/form-data", "application/x-www-form-urlencoded"}:
        payload, files = await _multipart_payload(request)
        return await _analyze(payload, files)
    raise HTTPException(415, detail="Use application/json or multipart/form-data")
