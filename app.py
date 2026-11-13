# """Merged OMG application (app.py + all_apis.py).

# One business endpoint: POST /api/v1/analyze, accepting JSON or multipart
# with binary attachments. GET /, /health, /ready, and /status are operational
# endpoints from the second developer's app.py (excluded from Swagger).

# This backend validates but never sends emails. A delivery gateway must
# re-run authorization and verify warning acknowledgment server-side.
# """
# from __future__ import annotations
# from fastapi.responses import JSONResponse, FileResponse
# import hmac
# import json
# import logging
# import os
# from decision_making import decide_email
# from fastapi import FastAPI, Request, HTTPException
# from contextlib import asynccontextmanager
# from pathlib import Path
# from typing import Any
# from database import connect_to_mongodb, close_mongodb_connection
# from db_repository import save_analysis
# from dotenv import load_dotenv

# load_dotenv(Path(__file__).resolve().parent / ".env")
# if (os.getenv("OMG_ENV", "").lower() in {"production", "prod"}
#         or os.getenv("OMG_ENVIRONMENT", "").lower() in {"production", "prod"}):
#     os.environ["OMG_ENV"] = "production"
#     os.environ["OMG_ENVIRONMENT"] = "production"

# from fastapi import Depends, FastAPI, Header, HTTPException, Request
# from fastapi.responses import JSONResponse
# from pydantic import ValidationError
# from starlette.concurrency import run_in_threadpool
# from starlette.datastructures import UploadFile as StarletteUploadFile
# from starlette.exceptions import HTTPException as StarletteHTTPException

# from Attachments.api import format_public_response
# from Attachments.attachment_gate import POLICY, read_uploads
# from Attachments.attachment_validator import scan_bytes
# from Attachments.warning_ack import issue_warning_challenge
# from Content.config import settings
# from Content.content_validator import validate_content
# from Content.email_schema import EmailRequest
# from Content.request_middleware import RequestLoggingMiddleware
# from URL.url_validator import validate_urls
# from decision_making import decide_email

# logger = logging.getLogger("omg.email")
# logging.basicConfig(level=settings.LOG_LEVEL)


# def omit_empty_arrays(value: Any) -> Any:
#     """Keep the requested Error: [] but omit unhelpful empty scanner lists."""
#     if isinstance(value, dict):
#         return {
#             key: omit_empty_arrays(item)
#             for key, item in value.items()
#             if key == "Error" or not (isinstance(item, list) and not item)
#         }
#     if isinstance(value, list):
#         return [omit_empty_arrays(item) for item in value]
#     return value


# class CompactJSONResponse(JSONResponse):
#     def render(self, content: Any) -> bytes:
#         return super().render(omit_empty_arrays(content))


# async def require_api_key(
#     request: Request,
#     x_omg_api_key: str | None = Header(None),
#     x_api_key: str | None = Header(None),
# ) -> None:
#     """Retain both existing authentication header names for compatibility."""
#     expected = settings.API_KEY
#     if expected:
#         if not hmac.compare_digest(x_omg_api_key or x_api_key or "", expected):
#             raise HTTPException(status_code=401, detail="Invalid or missing API key")
#     elif settings.is_production:
#         raise HTTPException(status_code=503, detail="API key not configured")
#     elif (request.client.host if request.client else "") not in {"127.0.0.1", "::1", "testclient"}:
#         raise HTTPException(status_code=403, detail="Unauthenticated access permitted only for local development")


# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     settings.validate_production_configuration()
#     if settings.is_production:
#         if not POLICY.require_clamav:
#             raise RuntimeError("Production requires ClamAV attachment scanning")
#         from Content.rule_checks import _load_runtime_rules
#         from Content.model_loader import load_model
#         _load_runtime_rules()
#         load_model(str(settings.resolve_path(settings.MODEL_PATH)))
#     yield


# app = FastAPI(
#     title=settings.APP_NAME,
#     version=settings.APP_VERSION,
#     lifespan=lifespan,
#     default_response_class=CompactJSONResponse,
#     description=(
#         "Single security endpoint for email subject, body, HTML, embedded URLs, "
#         "and optional binary attachments. This service does not send emails."
#     ),
#     docs_url=None if settings.is_production else "/docs",
#     redoc_url=None if settings.is_production else "/redoc",
#     openapi_url=None if settings.is_production else "/openapi.json",
# )
# app.add_middleware(RequestLoggingMiddleware)

# # Operational endpoints migrated from the separate app.py. They are not
# # business-validation endpoints and are intentionally hidden in Swagger.
# _PREFIX = settings.API_PREFIX

# @app.get("/portal", include_in_schema=False)
# def mail_portal():
#     return FileResponse(
#         Path(__file__).resolve().parent
#         / "OMG_Mail_Portal_Demo.html"
#     )

# @app.get("/", include_in_schema=False)
# def service_root() -> dict:
#     return {
#         "service": settings.APP_NAME,
#         "version": settings.APP_VERSION,
#         "message": "OMG email validation backend is running; mail delivery is not implemented.",
#         "docs": None if settings.is_production else "/docs",
#     }


# @app.get(f"{_PREFIX}/health", include_in_schema=False)
# def health_check() -> dict:
#     """Process liveness only; does not certify that all scanners are available."""
#     return {"service": "OMG", "status": "running"}


# def _readiness_checks() -> dict[str, str]:
#     rules = settings.resolve_path(settings.RULES_PATH)
#     model = settings.resolve_path(settings.MODEL_PATH)
#     checks = {
#         "content_rules": "present" if rules.is_file() else "missing",
#         "content_engine": "loaded",
#         "url_engine": "loaded",
#         "attachment_engine": "loaded",
#         "required_ml_artifact": (
#             "present" if model.is_file() else "missing"
#         ) if settings.REQUIRE_ML else "not_required",
#         "antivirus": (
#             "required_runtime_check" if POLICY.require_clamav else "not_required_by_policy"
#         ),
#     }
#     return checks


# @app.get(f"{_PREFIX}/ready", include_in_schema=False)
# def readiness_check():
#     """Static dependency checks, not a substitute for a live AV/OCR self-test."""
#     checks = _readiness_checks()
#     ready = checks["content_rules"] == "present" and checks["required_ml_artifact"] != "missing"
#     data = {"service": "OMG", "ready": ready, "checks": checks,
#             "notice": "Antivirus/OCR readiness requires separate runtime checks."}
#     if not ready:
#         return JSONResponse(status_code=503, content=data)
#     return data


# @app.get(f"{_PREFIX}/status", include_in_schema=False,
#          dependencies=[Depends(require_api_key)])
# def service_status() -> dict:
#     checks = _readiness_checks()
#     return {
#         "service": "OMG", "version": settings.APP_VERSION,
#         "environment": settings.ENVIRONMENT,
#         "verdicts": ["SAFE", "WARNING", "RESTRICTED"],
#         "email_validation_endpoint": f"{_PREFIX}/analyze",
#         "content_rules": checks["content_rules"],
#         "ml_classification": "enabled" if settings.ENABLE_ML or settings.REQUIRE_ML else "disabled",
#         "experimental_tfidf": "enabled_review_only" if settings.ENABLE_EXPERIMENTAL_TFIDF else "disabled",
#         "url_reputation": "not_implemented",
#         "mail_delivery": "not_implemented",
#         "attachment_antivirus": checks["antivirus"],
#     }


# def _valid_email(data: dict[str, Any]) -> EmailRequest:
#     try:
#         return EmailRequest.model_validate(data)
#     except ValidationError as exc:
#         raise HTTPException(422, detail=[{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()])


# def _recipients_from_form(value: str | None) -> list[str]:
#     if value is None:
#         return []
#     try:
#         parsed = json.loads(value)
#     except json.JSONDecodeError:
#         parsed = [part.strip() for part in value.split(",") if part.strip()]
#     if not isinstance(parsed, list):
#         raise HTTPException(422, detail="recipients must be a JSON array or comma-separated addresses")
#     return parsed


# async def _multipart_payload(request: Request) -> tuple[dict[str, Any], list[StarletteUploadFile]]:
#     """Parse optional files without depending on newer Starlette form options.

#     Starlette versions installed with older FastAPI releases may reject the
#     `max_part_size` argument with TypeError. Only use the widely supported
#     `max_files` and `max_fields` options; enforce field limits explicitly.
#     """
#     # The attachment policy already enforces 3 MB/file and 10 MB overall.
#     # Allow another 3 MB for subject/body/HTML, recipients and multipart headers.
#     max_body_bytes = min(settings.MAX_REQUEST_BYTES, POLICY.max_total_bytes + 3 * 1024 * 1024)
#     length = request.headers.get("content-length")
#     if length is not None:
#         try:
#             if int(length) > max_body_bytes:
#                 raise HTTPException(413, detail="Multipart request exceeds the configured size limit")
#         except ValueError:
#             raise HTTPException(400, detail="Invalid Content-Length header")

#     try:
#         form = await request.form(max_files=POLICY.max_files + 1, max_fields=30)
#     except StarletteHTTPException as exc:
#         # Real multipart parser limits are different from syntax errors.
#         detail = str(exc.detail).lower()
#         if any(term in detail for term in ("too many", "maximum", "exceeded", "part exceeded")):
#             raise HTTPException(413, detail="Multipart attachment or field limit exceeded") from exc
#         raise HTTPException(400, detail="Malformed multipart body") from exc
#     except TypeError as exc:
#         logger.exception("Multipart parser compatibility error")
#         raise HTTPException(500, detail="Multipart parser is incompatible; update FastAPI/Starlette/python-multipart") from exc
#     except Exception as exc:
#         logger.warning("Malformed multipart data: %s", type(exc).__name__)
#         raise HTTPException(400, detail="Malformed multipart body") from exc

#     uploaded: list[StarletteUploadFile] = []
#     allowed_fields = {"channel", "subject", "body", "html", "recipients", "files", "attachments"}
#     for field, value in form.multi_items():
#         if field not in allowed_fields:
#             raise HTTPException(422, detail=f"Unexpected form field: {field}; URLs must be included in body or HTML")
#         if isinstance(value, StarletteUploadFile):
#             if field not in {"files", "attachments"}:
#                 raise HTTPException(422, detail=f"Unexpected file field: {field}")
#             if not value.filename:
#                 # Swagger can submit an empty, filename-less file control.
#                 if value.size != 0 or await value.read(1):
#                     raise HTTPException(422, detail="Uploaded file requires a filename")
#                 continue
#             uploaded.append(value)
#         elif field in {"files", "attachments"}:
#             # Swagger's optional file chooser sends files="" when left untouched.
#             if value not in ("", "[]"):
#                 raise HTTPException(422, detail="files must be binary uploads, not text")
#         else:
#             if len(str(value).encode("utf-8")) > 1024 * 1024:
#                 raise HTTPException(413, detail=f"Multipart field '{field}' exceeds 1 MB")

#     data: dict[str, Any] = {
#         "channel": form.get("channel", "email"),
#         "subject": form.get("subject"),
#         "body": form.get("body"),
#         "html": form.get("html"),
#         "recipients": _recipients_from_form(form.get("recipients")),
#         "attachments": [],
#     }
#     return data, uploaded



# def _one_issue(findings: list[dict], *, module: str) -> list[dict]:
#     """Select one representative, actionable public finding per module.

#     IMPORTANT: This is presentation only.  All the original findings remain
#     in decision_making.py and participate in scoring and blocking.
#     """
#     if not findings:
#         return []
#     # Missing/incomplete security scans must always be conspicuous.
#     failures = [f for f in findings if
#                 f.get("category") == "INSPECTION_FAILURE" or
#                 str(f.get("code", "")).endswith(
#                     ("_FAILED", "_UNAVAILABLE", "_ERROR", "_INCOMPLETE", "_FAILURE"))]
#     if failures:
#         winner = failures[0]
#     else:
#         # Requested lottery display: identity harvesting is the most
#         # actionable representative item for this scam family, despite
#         # other CRITICAL matches which STILL enforce RESTRICTED.
#         preferred = (
#             ("LOTTERY_IDENTITY_HARVEST", "ADVANCE_FEE_SCAM", "LOTTERY_SCAM")
#             if module == "text" else
#             ("ACCOUNT_UPDATE_LINK_REVIEW", "URL_CREDENTIALS_PRESENT")
#             if module == "URL" else ()
#         )
#         winner = next((f for code in preferred for f in findings
#                        if f.get("code") == code), None)
#         if winner is None:
#             weight = {
#                 "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
#                 "LOW": 3, "MINOR": 3, "INFO": 4,
#             }
#             winner = min(findings, key=lambda f: weight.get(
#                 str(f.get("severity") or "HIGH").upper(), 1))
#     return [{
#         "code": winner.get("code") or "SECURITY_FINDING",
#         "severity": str(winner.get("severity") or "HIGH").upper(),
#         "reason": winner.get("message") or winner.get("reason") or "Security finding requires review.",
#     }]


# def _overall_reason(result: dict, report: dict | None) -> str:
#     """One grounded, concise explanation, never exposing message contents."""
#     findings = result.get("findings", [])
#     by = lambda src: [f for f in findings if f.get("source") == src]
#     content = by("content")
#     urls = by("urls")
#     files = by("attachments")
#     codes = {str(f.get("code", "")) for f in content}
#     parts: list[str] = []
#     if any(f.get("category") == "INSPECTION_FAILURE" for f in findings):
#         parts.append("One or more required security inspections could not be completed")
#     if "LOTTERY_SCAM" in codes or "LOTTERY_IDENTITY_HARVEST" in codes:
#         if "ADVANCE_FEE_SCAM" in codes and "LOTTERY_IDENTITY_HARVEST" in codes:
#             parts.append("The email resembles a lottery-prize scam requesting sensitive bank or identity details and an upfront fee")
#         elif "ADVANCE_FEE_SCAM" in codes:
#             parts.append("The email resembles a lottery-prize claim requesting an upfront fee")
#         elif "LOTTERY_IDENTITY_HARVEST" in codes:
#             parts.append("The email contains a lottery-prize claim requesting sensitive identity or bank details")
#         else:
#             parts.append("The email contains suspicious lottery-prize claims")
#         if {"LOTTERY_DEADLINE_PRESSURE", "LOTTERY_SECRECY_REQUEST"} & codes:
#             parts.append("It also uses urgency or secrecy tactics")
#     elif content:
#         # Explain the most significant actual rule finding without listing
#         # all of the matched phrases in the popup.
#         selected = _one_issue(content, module="text")[0]
#         parts.append("Email content requires action: " + selected["reason"].rstrip(". "))
#     if urls:
#         top = _one_issue(urls, module="URL")[0]
#         parts.append("A URL in the message requires review: " + top["reason"].rstrip(". "))
#     if files:
#         filenames = sorted({f.get("filename") for f in files if f.get("filename")})
#         if filenames and len(filenames) == 1:
#             parts.append("Attachment '" + str(filenames[0]) + "' has a security finding")
#         else:
#             parts.append("One or more attachments have security findings")
#     elif report and report.get("status") in {"WARNING", "RESTRICTED"}:
#         parts.append("Attachment validation requires review or was blocked")
#     if not parts:
#         parts.append("Security validation requires review" if result["status"] == "WARNING"
#                      else "A security policy restriction was triggered")
#     summary = ". ".join(p.rstrip(". ") for p in parts) + "."
#     if result["status"] == "RESTRICTED":
#         summary += " Sending is blocked until the issues are corrected and revalidated."
#     else:
#         summary += " Review the issue and acknowledge the warning before sending."
#     return summary


# def _format_public(result: dict, content: dict, urls: dict, report: dict | None) -> dict:
#     """Compact client schema. Decisions always retain ALL original findings."""
#     vr = result["validation_results"]
#     text_section = {
#         "status": vr["content"]["status"],
#         "confidence_score": vr["content"]["confidence_score"],
#         "issues": _one_issue(vr["content"].get("findings", []), module="text"),
#     }
#     urls_section: dict | str = "empty"
#     if vr["urls"] != "empty":
#         urls_section = {
#             "status": vr["urls"]["status"],
#             "confidence_score": vr["urls"]["confidence_score"],
#             "issues": _one_issue(vr["urls"].get("findings", []), module="URL"),
#         }

#     attachments_section: list[dict] | str = "empty"
#     warnings: list[str] = []
#     if report is not None:
#         public_report = format_public_response(report)
#         attachments_section = []
#         warnings = list(public_report.get("warnings", []))
#         # Exactly one issue per file in the PUBLIC response. Retain all
#         # per-file findings in the original report/decision engine.
#         for file in public_report.get("attachments", []):
#             issues = [{"code": x["code"], "severity": x["severity"],
#                        "message": x["reason"], "category": "ATTACHMENT"}
#                       for x in file.get("issues", [])]
#             attachments_section.append({
#                 **{k: v for k, v in file.items() if k != "issues"},
#                 "issues": _one_issue(issues, module="attachments"),
#             })
#         if not attachments_section and report.get("status") in {"WARNING", "RESTRICTED"}:
#             reasons = (report.get("popup") or {}).get("reasons", []) or report.get("findings", [])
#             grouped: dict[str, list[dict]] = {}
#             for r in reasons:
#                 if not isinstance(r, dict):
#                     continue
#                 name = str(r.get("filename") or "(attachments)")
#                 grouped.setdefault(name, []).append({
#                     "code": str(r.get("code") or "ATTACHMENT_INSPECTION_INCOMPLETE"),
#                     "severity": str(r.get("severity") or "CRITICAL").upper(),
#                     "category": r.get("category", "INSPECTION_FAILURE"),
#                     "message": str(r.get("reason") or r.get("message") or "Attachment blocked by policy"),
#                 })
#             if not grouped:
#                 grouped["(attachments)"] = [{"code": "ATTACHMENT_INSPECTION_INCOMPLETE",
#                     "severity": "CRITICAL", "category": "INSPECTION_FAILURE",
#                     "message": "Attachment scanning was blocked or incomplete."}]
#             attachments_section = [{"filename": name, "status": report["status"],
#                 "detected_type": None, "antivirus": "NOT_RUN",
#                 "confidence_score": report.get("confidence_score"),
#                 "issues": _one_issue(items, module="attachments")}
#                 for name, items in grouped.items()]

#     # Error is module attribution, not an HTTP error.
#     errors: list[str] = []
#     if vr["content"].get("findings"):
#         errors.append("text")
#     if isinstance(vr["urls"], dict) and vr["urls"].get("findings"):
#         errors.append("URL")
#     if report and (result["validation_results"]["attachments"].get("status") in {"WARNING", "RESTRICTED"}
#                    or result["validation_results"]["attachments"].get("files")
#                    and any(f.get("findings") or f.get("advisories") for f in report.get("attachments", []))):
#         errors.append("attachments")

#     status = result["status"]
#     popup = None
#     if status in {"WARNING", "RESTRICTED"}:
#         attachment_only = errors == ["attachments"]
#         popup = {
#             "show": True,
#             "type": status,
#             "title": ("Attachment" if attachment_only else "Email") + (
#                 " Warning" if status == "WARNING" else " Restricted"),
#             "message": ("Review the detected security issues before sending."
#                         if status == "WARNING" else
#                         "Sending is blocked. Correct the detected issues before trying again."),
#             "actions": ["EDIT_MAIL", "CLOSE"] if status == "WARNING" else ["DISCARD_MAIL"],
#             "reasons": [_overall_reason(result, report)],
#         }

#     public = {
#         "status": status,
#         "can_send": result["can_send"],
#         "confidence_score": result["confidence_score"],
#         "requires_acknowledgement": result["requires_acknowledgement"],
#         "confidence_source": result["confidence_source"],
#         "text": text_section,
#         "URL": urls_section,
#         "attachments": attachments_section,
#         "Error": errors,
#         "warnings": warnings,
#         "popup": popup,
#     }
#     if result.get("warning_challenge") and status == "WARNING":
#         public["warning_challenge"] = result["warning_challenge"]
#     return public


# def _attachment_failure(code: str, message: str) -> dict[str, Any]:
#     """Fail closed if upload reading or mandatory attachment validation fails."""
#     return {
#         "status": "RESTRICTED", "can_send": False, "confidence_score": None,
#         "findings": [{"code": code, "category": "INSPECTION_FAILURE", "reason": message}],
#         "attachments": [], "popup": {"reasons": [
#             {"code": code, "reason": message, "severity": "CRITICAL"}
#         ]},
#     }


# def _validate_module_report(data: Any, name: str) -> dict:
#     """A malformed/missing detector result cannot silently become SAFE."""
#     valid = (isinstance(data, dict)
#              and isinstance(data.get("findings"), list)
#              and isinstance(data.get("coverage"), dict))
#     if valid:
#         mandatory_checks = (
#             ("url_syntax_inspection",) if name == "URL"
#             else ("runtime_text_rules", "html_inspection", "contextual_text_rules")
#         )
#         findings = data["findings"]
#         valid = all(isinstance(finding, dict) for finding in findings)
#         if valid:
#             incomplete_checks = [
#                 check for check in mandatory_checks
#                 if data["coverage"].get(check) != "complete"
#             ]
#             if incomplete_checks and not any(
#                 finding.get("category") == "INSPECTION_FAILURE" for finding in findings
#             ):
#                 # A detector marking a mandatory check failed without emitting
#                 # a finding must not produce a misleading SAFE decision.
#                 data = {
#                     **data,
#                     "findings": [*findings, {
#                         "code": f"{name}_SCAN_INCOMPLETE",
#                         "category": "INSPECTION_FAILURE",
#                         "message": "Mandatory checks incomplete: " + ", ".join(incomplete_checks),
#                     }],
#                 }
#     if valid:
#         return data
#     return {
#         "findings": [{
#             "code": f"{name}_SCAN_INCOMPLETE", "category": "INSPECTION_FAILURE",
#             "message": f"{name} scanner did not return a complete, valid inspection report.",
#         }],
#         "coverage": {
#             "url_syntax_inspection" if name == "URL" else "runtime_text_rules": "failed"
#         },
#     }


# async def _analyze(data: dict[str, Any], uploaded: list[StarletteUploadFile] | None = None) -> dict:
#     # All URLs must be present in subject/body/HTML. The URL validator extracts
#     # them automatically; do not accept separate url/urls request fields.
#     email = _valid_email(data)

#     if email.attachments and not uploaded:
#         # A JSON attachment object is not equivalent to binary file inspection.
#         report = {
#             "status": "RESTRICTED", "can_send": False, "confidence_score": None,
#             "findings": [{
#                 "code": "ATTACHMENT_BINARY_REQUIRED", "category": "INSPECTION_FAILURE",
#                 "reason": "Attachments require actual binary multipart uploads.",
#             }],
#             "attachments": [],
#         }
#     elif uploaded:
#         try:
#             items, error = await read_uploads(uploaded)
#             if error:
#                 report = error
#             else:
#                 report = await run_in_threadpool(scan_bytes, items)
#                 if not isinstance(report, dict) or report.get("status") not in {"SAFE", "WARNING", "RESTRICTED"}:
#                     report = _attachment_failure("ATTACHMENT_SCAN_INCOMPLETE", "Attachment scanner returned an invalid result.")
#                 elif report["status"] == "WARNING":
#                     report["warning_challenge"] = issue_warning_challenge(items)
#         except Exception:
#             logger.exception("Attachment engine failed")
#             report = _attachment_failure("ATTACHMENT_SCAN_FAILED", "Attachment security inspection could not be completed.")
#     else:
#         report = None

#     try:
#         content = await run_in_threadpool(validate_content, email.subject, email.body or "", email.html or "")
#     except Exception as exc:
#         logger.exception("Content engine failed")
#         content = {
#             "findings": [{"code": "CONTENT_SCAN_FAILED", "category": "INSPECTION_FAILURE",
#                           "message": f"Content engine failed ({type(exc).__name__})"}],
#             "coverage": {"runtime_text_rules": "failed"},
#         }
#     try:
#         urls = await run_in_threadpool(
#             validate_urls,
#             "\n\n".join((email.subject, email.body or "")),
#             email.html or "",
#         )
#     except Exception as exc:
#         logger.exception("URL engine failed")
#         urls = {
#             "findings": [{"code": "URL_SCAN_FAILED", "category": "INSPECTION_FAILURE",
#                           "message": f"URL engine failed ({type(exc).__name__})"}],
#             "coverage": {"url_syntax_inspection": "failed"},
#         }
#     content = _validate_module_report(content, "CONTENT")
#     urls = _validate_module_report(urls, "URL")
#     decided = decide_email(content, urls, report)
#     return _format_public(decided, content, urls, report)


# # Both content-types are documented on this ONE endpoint. Swagger provides the
# # multipart file picker without creating a duplicate '/analyze-with-attachments'.
# _ANALYZE_REQUEST_BODY = {
#     "required": True,
#     "content": {
#         "application/json": {
#             "schema": {
#                 "type": "object",
#                 "required": ["subject", "recipients"],
#                 "properties": {
#                     "subject": {"type": "string", "example": "October invoice"},
#                     "body": {"type": "string", "example": "Please review the invoice."},
#                     "html": {"type": "string", "example": ""},
#                     "recipients": {"type": "array", "items": {"type": "string"}, "example": ["user@example.com"]},
#                     "attachments": {"type": "array", "items": {"type": "object"}, "description": "Do not use JSON placeholders for real attachments; upload binary files using multipart."},
#                 },
#             },
#         },
#         "multipart/form-data": {
#             "schema": {
#                 "type": "object",
#                 "required": ["subject", "recipients"],
#                 "properties": {
#                     "subject": {"type": "string"},
#                     "body": {"type": "string", "description": "Plain-text email body (or provide HTML)"},
#                     "html": {"type": "string", "description": "Optional HTML body"},
#                     "recipients": {"type": "string", "description": 'JSON list or comma-separated addresses, e.g. ["user@example.com"]'},
#                     "files": {"type": "array", "items": {"type": "string", "format": "binary"}, "description": "Optional attachments (0–5 files)"},
#                 },
#             },
#             "encoding": {"files": {"style": "form", "explode": True}},
#         },
#     },
# }


# @app.post(
#     f"{_PREFIX}/analyze",
#     tags=["Email Validation"],
#     summary="Email Validation — subject, body, URLs and optional attachments",
#     dependencies=[Depends(require_api_key)],
#     openapi_extra={"requestBody": _ANALYZE_REQUEST_BODY},
# )
# async def analyze(request: Request):
#     content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
#     if content_type == "application/json":
#         try:
#             payload = await request.json()
#         except (ValueError, UnicodeError):
#             raise HTTPException(400, detail="Invalid JSON payload")
#         if not isinstance(payload, dict):
#             raise HTTPException(422, detail="JSON root must be an object")
#         return await _analyze(payload)
#     if content_type in {"multipart/form-data", "application/x-www-form-urlencoded"}:
#         payload, files = await _multipart_payload(request)
#         return await _analyze(payload, files)
#     raise HTTPException(415, detail="Use application/json or multipart/form-data")






"""
Merged OMG application with MongoDB persistence.

Business endpoint:
    POST /api/v1/analyze

Accepts:
    application/json
    multipart/form-data

Validates:
    Email content
    URLs
    Binary attachments

MongoDB:
    Saves completed analysis results.

This backend validates emails but NEVER sends emails.
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

from fastapi import (
    FastAPI,
    Request,
    HTTPException,
    Depends,
    Header,
)

from fastapi.responses import JSONResponse, FileResponse

from pydantic import ValidationError

from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile as StarletteUploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException

# ---------------------------------------------------------
# ENVIRONMENT CONFIGURATION
# ---------------------------------------------------------

load_dotenv(Path(__file__).resolve().parent / ".env")

if (
    os.getenv("OMG_ENV", "").lower() in {"production", "prod"}
    or os.getenv("OMG_ENVIRONMENT", "").lower()
    in {"production", "prod"}
):
    os.environ["OMG_ENV"] = "production"
    os.environ["OMG_ENVIRONMENT"] = "production"


# ---------------------------------------------------------
# EXISTING OMG MODULES
# ---------------------------------------------------------

from decision_making import decide_email

from Attachments.api import format_public_response
from Attachments.attachment_gate import POLICY, read_uploads
from Attachments.attachment_validator import scan_bytes
from Attachments.warning_ack import issue_warning_challenge

from Content.config import settings
from Content.content_validator import validate_content
from Content.email_schema import EmailRequest
from Content.request_middleware import RequestLoggingMiddleware

from URL.url_validator import validate_urls


# ---------------------------------------------------------
# NEW MONGODB MODULES
# ---------------------------------------------------------

from database import (
    connect_to_mongodb,
    close_mongodb_connection,
)

from db_repository import save_analysis


# ---------------------------------------------------------
# LOGGING
# ---------------------------------------------------------

logger = logging.getLogger("omg.email")
logging.basicConfig(level=settings.LOG_LEVEL)


# ---------------------------------------------------------
# RESPONSE HANDLING
# ---------------------------------------------------------

def omit_empty_arrays(value: Any) -> Any:
    """Keep Error arrays while omitting unnecessary empty lists."""

    if isinstance(value, dict):
        return {
            key: omit_empty_arrays(item)
            for key, item in value.items()
            if key == "Error"
            or not (isinstance(item, list) and not item)
        }

    if isinstance(value, list):
        return [omit_empty_arrays(item) for item in value]

    return value


class CompactJSONResponse(JSONResponse):

    def render(self, content: Any) -> bytes:
        return super().render(omit_empty_arrays(content))


# ---------------------------------------------------------
# API KEY AUTHENTICATION
# ---------------------------------------------------------

async def require_api_key(
    request: Request,
    x_omg_api_key: str | None = Header(None),
    x_api_key: str | None = Header(None),
) -> None:

    """Retain both existing authentication header names."""

    expected = settings.API_KEY

    if expected:

        supplied = x_omg_api_key or x_api_key or ""

        if not hmac.compare_digest(supplied, expected):
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing API key",
            )

    elif settings.is_production:

        raise HTTPException(
            status_code=503,
            detail="API key not configured",
        )

    elif (
        request.client.host if request.client else ""
    ) not in {"127.0.0.1", "::1", "testclient"}:

        raise HTTPException(
            status_code=403,
            detail="Unauthenticated access permitted only for local development",
        )


# ---------------------------------------------------------
# APPLICATION LIFESPAN AND MONGODB
# ---------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):

    settings.validate_production_configuration()

    # Connect to MongoDB when the application starts.
    await run_in_threadpool(connect_to_mongodb)

    logger.info("OMG MongoDB connection initialized")

    try:

        if settings.is_production:

            if not POLICY.require_clamav:
                raise RuntimeError(
                    "Production requires ClamAV attachment scanning"
                )

            from Content.rule_checks import _load_runtime_rules
            from Content.model_loader import load_model

            _load_runtime_rules()

            load_model(
                str(settings.resolve_path(settings.MODEL_PATH))
            )

        yield

    finally:

        # Close MongoDB when the application stops.
        await run_in_threadpool(close_mongodb_connection)

        logger.info("OMG MongoDB connection closed")


# ---------------------------------------------------------
# FASTAPI APPLICATION
# ---------------------------------------------------------

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    default_response_class=CompactJSONResponse,
    description=(
        "Single security endpoint for email subject, body, HTML, "
        "embedded URLs, and optional binary attachments. "
        "This service does not send emails."
    ),
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
)

app.add_middleware(RequestLoggingMiddleware)

_PREFIX = settings.API_PREFIX


# ---------------------------------------------------------
# OPERATIONAL ENDPOINTS
# ---------------------------------------------------------

@app.get("/portal", include_in_schema=False)
def mail_portal():

    return FileResponse(
        Path(__file__).resolve().parent
        / "OMG_Mail_Portal_Demo.html"
    )


@app.get("/", include_in_schema=False)
def service_root() -> dict:

    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "message": (
            "OMG email validation backend is running; "
            "mail delivery is not implemented."
        ),
        "docs": None if settings.is_production else "/docs",
    }


@app.get("/health", include_in_schema=False)
@app.get(f"{_PREFIX}/health", include_in_schema=False)
def health_check() -> dict:

    return {
        "service": "OMG",
        "status": "running",
    }


def _readiness_checks() -> dict[str, str]:

    rules = settings.resolve_path(settings.RULES_PATH)
    model = settings.resolve_path(settings.MODEL_PATH)

    checks = {

        "content_rules": (
            "present" if rules.is_file() else "missing"
        ),

        "content_engine": "loaded",

        "url_engine": "loaded",

        "attachment_engine": "loaded",

        "required_ml_artifact": (
            "present" if model.is_file() else "missing"
        ) if settings.REQUIRE_ML else "not_required",

        "antivirus": (
            "required_runtime_check"
            if POLICY.require_clamav
            else "not_required_by_policy"
        ),
    }

    return checks


@app.get(
    "/ready",
    include_in_schema=False,
)
@app.get(
    f"{_PREFIX}/ready",
    include_in_schema=False,
)
def readiness_check():

    checks = _readiness_checks()

    ready = (
        checks["content_rules"] == "present"
        and checks["required_ml_artifact"] != "missing"
    )

    data = {
        "service": "OMG",
        "ready": ready,
        "checks": checks,
        "notice": (
            "Antivirus/OCR readiness requires separate runtime checks."
        ),
    }

    if not ready:
        return JSONResponse(
            status_code=503,
            content=data,
        )

    return data


@app.get(
    "/status",
    include_in_schema=False,
    dependencies=[Depends(require_api_key)],
)
@app.get(
    f"{_PREFIX}/status",
    include_in_schema=False,
    dependencies=[Depends(require_api_key)],
)
def service_status() -> dict:

    checks = _readiness_checks()

    return {
        "service": "OMG",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "verdicts": [
            "SAFE",
            "WARNING",
            "RESTRICTED",
        ],
        "email_validation_endpoint": f"{_PREFIX}/analyze",
        "content_rules": checks["content_rules"],
        "ml_classification": (
            "enabled"
            if settings.ENABLE_ML or settings.REQUIRE_ML
            else "disabled"
        ),
        "experimental_tfidf": (
            "enabled_review_only"
            if settings.ENABLE_EXPERIMENTAL_TFIDF
            else "disabled"
        ),
        "url_reputation": "not_implemented",
        "mail_delivery": "not_implemented",
        "attachment_antivirus": checks["antivirus"],
    }


# ---------------------------------------------------------
# EMAIL REQUEST VALIDATION
# ---------------------------------------------------------

def _valid_email(data: dict[str, Any]) -> EmailRequest:

    try:

        return EmailRequest.model_validate(data)

    except ValidationError as exc:

        raise HTTPException(
            status_code=422,
            detail=[
                {
                    "loc": list(error["loc"]),
                    "msg": error["msg"],
                }
                for error in exc.errors()
            ],
        )


def _recipients_from_form(
    value: str | None,
) -> list[str]:

    if value is None:
        return []

    try:

        parsed = json.loads(value)

    except json.JSONDecodeError:

        parsed = [
            part.strip()
            for part in value.split(",")
            if part.strip()
        ]

    if not isinstance(parsed, list):

        raise HTTPException(
            status_code=422,
            detail=(
                "recipients must be a JSON array "
                "or comma-separated addresses"
            ),
        )

    return parsed


# ---------------------------------------------------------
# MULTIPART REQUEST PARSING
# ---------------------------------------------------------

async def _multipart_payload(
    request: Request,
) -> tuple[dict[str, Any], list[StarletteUploadFile]]:

    max_body_bytes = min(
        settings.MAX_REQUEST_BYTES,
        POLICY.max_total_bytes + 3 * 1024 * 1024,
    )

    length = request.headers.get("content-length")

    if length is not None:

        try:

            if int(length) > max_body_bytes:

                raise HTTPException(
                    413,
                    detail=(
                        "Multipart request exceeds "
                        "the configured size limit"
                    ),
                )

        except ValueError:

            raise HTTPException(
                400,
                detail="Invalid Content-Length header",
            )

    try:

        form = await request.form(
            max_files=POLICY.max_files + 1,
            max_fields=30,
        )

    except StarletteHTTPException as exc:

        detail = str(exc.detail).lower()

        if any(
            term in detail
            for term in (
                "too many",
                "maximum",
                "exceeded",
                "part exceeded",
            )
        ):

            raise HTTPException(
                413,
                detail="Multipart attachment or field limit exceeded",
            ) from exc

        raise HTTPException(
            400,
            detail="Malformed multipart body",
        ) from exc

    except TypeError as exc:

        logger.exception(
            "Multipart parser compatibility error"
        )

        raise HTTPException(
            500,
            detail=(
                "Multipart parser is incompatible; "
                "update FastAPI/Starlette/python-multipart"
            ),
        ) from exc

    except Exception as exc:

        logger.warning(
            "Malformed multipart data: %s",
            type(exc).__name__,
        )

        raise HTTPException(
            400,
            detail="Malformed multipart body",
        ) from exc

    uploaded = []

    allowed_fields = {
        "channel",
        "subject",
        "body",
        "html",
        "recipients",
        "files",
        "attachments",
    }

    for field, value in form.multi_items():

        if field not in allowed_fields:

            raise HTTPException(
                422,
                detail=(
                    f"Unexpected form field: {field}; "
                    "URLs must be included in body or HTML"
                ),
            )

        if isinstance(value, StarletteUploadFile):

            if field not in {"files", "attachments"}:

                raise HTTPException(
                    422,
                    detail=f"Unexpected file field: {field}",
                )

            if not value.filename:

                if value.size != 0 or await value.read(1):

                    raise HTTPException(
                        422,
                        detail="Uploaded file requires a filename",
                    )

                continue

            uploaded.append(value)

        elif field in {"files", "attachments"}:

            if value not in ("", "[]"):

                raise HTTPException(
                    422,
                    detail="files must be binary uploads, not text",
                )

        else:

            if len(str(value).encode("utf-8")) > 1024 * 1024:

                raise HTTPException(
                    413,
                    detail=f"Multipart field '{field}' exceeds 1 MB",
                )

    data = {
        "channel": form.get("channel", "email"),
        "subject": form.get("subject"),
        "body": form.get("body"),
        "html": form.get("html"),
        "recipients": _recipients_from_form(
            form.get("recipients")
        ),
        "attachments": [],
    }

    return data, uploaded


# ---------------------------------------------------------
# PUBLIC FINDING FORMATTING
# ---------------------------------------------------------

def _one_issue(
    findings: list[dict],
    *,
    module: str,
) -> list[dict]:

    if not findings:
        return []

    failures = [
        finding
        for finding in findings
        if (
            finding.get("category") == "INSPECTION_FAILURE"
            or str(finding.get("code", "")).endswith(
                (
                    "_FAILED",
                    "_UNAVAILABLE",
                    "_ERROR",
                    "_INCOMPLETE",
                    "_FAILURE",
                )
            )
        )
    ]

    if failures:

        winner = failures[0]

    else:

        preferred = (

            (
                "LOTTERY_IDENTITY_HARVEST",
                "ADVANCE_FEE_SCAM",
                "LOTTERY_SCAM",
            )
            if module == "text"

            else (
                "ACCOUNT_UPDATE_LINK_REVIEW",
                "URL_CREDENTIALS_PRESENT",
            )
            if module == "URL"

            else ()
        )

        winner = next(
            (
                finding
                for code in preferred
                for finding in findings
                if finding.get("code") == code
            ),
            None,
        )

        if winner is None:

            weight = {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 3,
                "MINOR": 3,
                "INFO": 4,
            }

            winner = min(
                findings,
                key=lambda finding: weight.get(
                    str(
                        finding.get("severity") or "HIGH"
                    ).upper(),
                    1,
                ),
            )

    return [
        {
            "code": winner.get("code") or "SECURITY_FINDING",
            "severity": str(
                winner.get("severity") or "HIGH"
            ).upper(),
            "reason": (
                winner.get("message")
                or winner.get("reason")
                or "Security finding requires review."
            ),
        }
    ]


def _overall_reason(
    result: dict,
    report: dict | None,
) -> str:

    findings = result.get("findings", [])

    def by(source):
        return [
            finding
            for finding in findings
            if finding.get("source") == source
        ]

    content = by("content")
    urls = by("urls")
    files = by("attachments")

    codes = {
        str(finding.get("code", ""))
        for finding in content
    }

    parts = []

    if any(
        finding.get("category") == "INSPECTION_FAILURE"
        for finding in findings
    ):

        parts.append(
            "One or more required security inspections could not be completed"
        )

    if (
        "LOTTERY_SCAM" in codes
        or "LOTTERY_IDENTITY_HARVEST" in codes
    ):

        if (
            "ADVANCE_FEE_SCAM" in codes
            and "LOTTERY_IDENTITY_HARVEST" in codes
        ):

            parts.append(
                "The email resembles a lottery-prize scam requesting sensitive bank or identity details and an upfront fee"
            )

        elif "ADVANCE_FEE_SCAM" in codes:

            parts.append(
                "The email resembles a lottery-prize claim requesting an upfront fee"
            )

        elif "LOTTERY_IDENTITY_HARVEST" in codes:

            parts.append(
                "The email contains a lottery-prize claim requesting sensitive identity or bank details"
            )

        else:

            parts.append(
                "The email contains suspicious lottery-prize claims"
            )

        if {
            "LOTTERY_DEADLINE_PRESSURE",
            "LOTTERY_SECRECY_REQUEST",
        } & codes:

            parts.append(
                "It also uses urgency or secrecy tactics"
            )

    elif content:

        selected = _one_issue(
            content,
            module="text",
        )[0]

        parts.append(
            "Email content requires action: "
            + selected["reason"].rstrip(". ")
        )

    if urls:

        top = _one_issue(
            urls,
            module="URL",
        )[0]

        parts.append(
            "A URL in the message requires review: "
            + top["reason"].rstrip(". ")
        )

    if files:

        filenames = sorted({
            finding.get("filename")
            for finding in files
            if finding.get("filename")
        })

        if filenames and len(filenames) == 1:

            parts.append(
                "Attachment '"
                + str(filenames[0])
                + "' has a security finding"
            )

        else:

            parts.append(
                "One or more attachments have security findings"
            )

    elif report and report.get("status") in {
        "WARNING",
        "RESTRICTED",
    }:

        parts.append(
            "Attachment validation requires review or was blocked"
        )

    if not parts:

        parts.append(
            "Security validation requires review"
            if result["status"] == "WARNING"
            else "A security policy restriction was triggered"
        )

    summary = ". ".join(
        part.rstrip(". ")
        for part in parts
    ) + "."

    if result["status"] == "RESTRICTED":

        summary += (
            " Sending is blocked until the issues are corrected and revalidated."
        )

    else:

        summary += (
            " Review the issue and acknowledge the warning before sending."
        )

    return summary


# ---------------------------------------------------------
# PUBLIC RESPONSE FORMAT
# ---------------------------------------------------------

def _format_public(
    result: dict,
    content: dict,
    urls: dict,
    report: dict | None,
) -> dict:

    vr = result["validation_results"]

    text_section = {
        "status": vr["content"]["status"],
        "confidence_score": vr["content"]["confidence_score"],
        "issues": _one_issue(
            vr["content"].get("findings", []),
            module="text",
        ),
    }

    urls_section: dict | str = "empty"

    if vr["urls"] != "empty":

        urls_section = {
            "status": vr["urls"]["status"],
            "confidence_score": vr["urls"]["confidence_score"],
            "issues": _one_issue(
                vr["urls"].get("findings", []),
                module="URL",
            ),
        }

    attachments_section: list[dict] | str = "empty"

    warnings = []

    if report is not None:

        public_report = format_public_response(report)

        attachments_section = []

        warnings = list(
            public_report.get("warnings", [])
        )

        for file in public_report.get("attachments", []):

            issues = [
                {
                    "code": issue["code"],
                    "severity": issue["severity"],
                    "message": issue["reason"],
                    "category": "ATTACHMENT",
                }
                for issue in file.get("issues", [])
            ]

            attachments_section.append(
                {
                    **{
                        key: value
                        for key, value in file.items()
                        if key != "issues"
                    },
                    "issues": _one_issue(
                        issues,
                        module="attachments",
                    ),
                }
            )

        if (
            not attachments_section
            and report.get("status") in {
                "WARNING",
                "RESTRICTED",
            }
        ):

            reasons = (
                report.get("popup") or {}
            ).get("reasons", []) or report.get("findings", [])

            grouped = {}

            for reason in reasons:

                if not isinstance(reason, dict):
                    continue

                name = str(
                    reason.get("filename") or "(attachments)"
                )

                grouped.setdefault(name, []).append(
                    {
                        "code": str(
                            reason.get("code")
                            or "ATTACHMENT_INSPECTION_INCOMPLETE"
                        ),
                        "severity": str(
                            reason.get("severity") or "CRITICAL"
                        ).upper(),
                        "category": reason.get(
                            "category",
                            "INSPECTION_FAILURE",
                        ),
                        "message": str(
                            reason.get("reason")
                            or reason.get("message")
                            or "Attachment blocked by policy"
                        ),
                    }
                )

            if not grouped:

                grouped["(attachments)"] = [
                    {
                        "code": "ATTACHMENT_INSPECTION_INCOMPLETE",
                        "severity": "CRITICAL",
                        "category": "INSPECTION_FAILURE",
                        "message": (
                            "Attachment scanning was blocked or incomplete."
                        ),
                    }
                ]

            attachments_section = [
                {
                    "filename": name,
                    "status": report["status"],
                    "detected_type": None,
                    "antivirus": "NOT_RUN",
                    "confidence_score": report.get(
                        "confidence_score"
                    ),
                    "issues": _one_issue(
                        items,
                        module="attachments",
                    ),
                }
                for name, items in grouped.items()
            ]

    errors = []

    if vr["content"].get("findings"):
        errors.append("text")

    if (
        isinstance(vr["urls"], dict)
        and vr["urls"].get("findings")
    ):
        errors.append("URL")

    if report and (
        result["validation_results"]["attachments"].get(
            "status"
        ) in {"WARNING", "RESTRICTED"}
        or (
            result["validation_results"]["attachments"].get(
                "files"
            )
            and any(
                file.get("findings") or file.get("advisories")
                for file in report.get("attachments", [])
            )
        )
    ):

        errors.append("attachments")

    status = result["status"]

    popup = None

    if status in {"WARNING", "RESTRICTED"}:

        attachment_only = errors == ["attachments"]

        popup = {
            "show": True,
            "type": status,
            "title": (
                "Attachment" if attachment_only else "Email"
            ) + (
                " Warning"
                if status == "WARNING"
                else " Restricted"
            ),
            "message": (
                "Review the detected security issues before sending."
                if status == "WARNING"
                else (
                    "Sending is blocked. Correct the detected "
                    "issues before trying again."
                )
            ),
            "actions": (
                ["EDIT_MAIL", "CLOSE"]
                if status == "WARNING"
                else ["DISCARD_MAIL"]
            ),
            "reasons": [
                _overall_reason(result, report)
            ],
        }

    public = {
        "status": status,
        "can_send": result["can_send"],
        "confidence_score": result["confidence_score"],
        "requires_acknowledgement": result[
            "requires_acknowledgement"
        ],
        "confidence_source": result["confidence_source"],
        "text": text_section,
        "URL": urls_section,
        "attachments": attachments_section,
        "Error": errors,
        "warnings": warnings,
        "popup": popup,
    }

    if (
        result.get("warning_challenge")
        and status == "WARNING"
    ):

        public["warning_challenge"] = (
            result["warning_challenge"]
        )

    return public


# ---------------------------------------------------------
# ATTACHMENT FAILURE HANDLING
# ---------------------------------------------------------

def _attachment_failure(
    code: str,
    message: str,
) -> dict[str, Any]:

    return {
        "status": "RESTRICTED",
        "can_send": False,
        "confidence_score": None,
        "findings": [
            {
                "code": code,
                "category": "INSPECTION_FAILURE",
                "reason": message,
            }
        ],
        "attachments": [],
        "popup": {
            "reasons": [
                {
                    "code": code,
                    "reason": message,
                    "severity": "CRITICAL",
                }
            ]
        },
    }


# ---------------------------------------------------------
# VALIDATE MODULE REPORT
# ---------------------------------------------------------

def _validate_module_report(
    data: Any,
    name: str,
) -> dict:

    valid = (
        isinstance(data, dict)
        and isinstance(data.get("findings"), list)
        and isinstance(data.get("coverage"), dict)
    )

    if valid:

        mandatory_checks = (
            ("url_syntax_inspection",)
            if name == "URL"
            else (
                "runtime_text_rules",
                "html_inspection",
                "contextual_text_rules",
            )
        )

        findings = data["findings"]

        valid = all(
            isinstance(finding, dict)
            for finding in findings
        )

        if valid:

            incomplete_checks = [
                check
                for check in mandatory_checks
                if data["coverage"].get(check) != "complete"
            ]

            if (
                incomplete_checks
                and not any(
                    finding.get("category") == "INSPECTION_FAILURE"
                    for finding in findings
                )
            ):

                data = {
                    **data,
                    "findings": [
                        *findings,
                        {
                            "code": f"{name}_SCAN_INCOMPLETE",
                            "category": "INSPECTION_FAILURE",
                            "message": (
                                "Mandatory checks incomplete: "
                                + ", ".join(incomplete_checks)
                            ),
                        },
                    ],
                }

    if valid:
        return data

    return {
        "findings": [
            {
                "code": f"{name}_SCAN_INCOMPLETE",
                "category": "INSPECTION_FAILURE",
                "message": (
                    f"{name} scanner did not return a complete, "
                    "valid inspection report."
                ),
            }
        ],
        "coverage": {
            (
                "url_syntax_inspection"
                if name == "URL"
                else "runtime_text_rules"
            ): "failed"
        },
    }


# ---------------------------------------------------------
# MAIN VALIDATION ENGINE
# ---------------------------------------------------------

async def _analyze(
    data: dict[str, Any],
    uploaded: list[StarletteUploadFile] | None = None,
) -> dict:

    email = _valid_email(data)

    # ---------------- ATTACHMENTS ----------------

    if email.attachments and not uploaded:

        report = {
            "status": "RESTRICTED",
            "can_send": False,
            "confidence_score": None,
            "findings": [
                {
                    "code": "ATTACHMENT_BINARY_REQUIRED",
                    "category": "INSPECTION_FAILURE",
                    "reason": (
                        "Attachments require actual binary multipart uploads."
                    ),
                }
            ],
            "attachments": [],
        }

    elif uploaded:

        try:

            items, error = await read_uploads(uploaded)

            if error:

                report = error

            else:

                report = await run_in_threadpool(
                    scan_bytes,
                    items,
                )

                if (
                    not isinstance(report, dict)
                    or report.get("status")
                    not in {"SAFE", "WARNING", "RESTRICTED"}
                ):

                    report = _attachment_failure(
                        "ATTACHMENT_SCAN_INCOMPLETE",
                        "Attachment scanner returned an invalid result.",
                    )

                elif report["status"] == "WARNING":

                    report["warning_challenge"] = (
                        issue_warning_challenge(items)
                    )

        except Exception:

            logger.exception(
                "Attachment engine failed"
            )

            report = _attachment_failure(
                "ATTACHMENT_SCAN_FAILED",
                "Attachment security inspection could not be completed.",
            )

    else:

        report = None

    # ---------------- CONTENT ----------------

    try:

        content = await run_in_threadpool(
            validate_content,
            email.subject,
            email.body or "",
            email.html or "",
        )

    except Exception as exc:

        logger.exception(
            "Content engine failed"
        )

        content = {
            "findings": [
                {
                    "code": "CONTENT_SCAN_FAILED",
                    "category": "INSPECTION_FAILURE",
                    "message": (
                        f"Content engine failed ({type(exc).__name__})"
                    ),
                }
            ],
            "coverage": {
                "runtime_text_rules": "failed"
            },
        }

    # ---------------- URL ----------------

    try:

        urls = await run_in_threadpool(
            validate_urls,
            "\n\n".join(
                (
                    email.subject,
                    email.body or "",
                )
            ),
            email.html or "",
        )

    except Exception as exc:

        logger.exception(
            "URL engine failed"
        )

        urls = {
            "findings": [
                {
                    "code": "URL_SCAN_FAILED",
                    "category": "INSPECTION_FAILURE",
                    "message": (
                        f"URL engine failed ({type(exc).__name__})"
                    ),
                }
            ],
            "coverage": {
                "url_syntax_inspection": "failed"
            },
        }

    # ---------------- DECISION ----------------

    content = _validate_module_report(
        content,
        "CONTENT",
    )

    urls = _validate_module_report(
        urls,
        "URL",
    )

    decided = decide_email(
        content,
        urls,
        report,
    )

    return _format_public(
        decided,
        content,
        urls,
        report,
    )


# ---------------------------------------------------------
# SWAGGER REQUEST BODY SCHEMA
# ---------------------------------------------------------

_ANALYZE_REQUEST_BODY = {

    "required": True,

    "content": {

        "application/json": {

            "schema": {

                "type": "object",

                "required": [
                    "subject",
                    "recipients",
                ],

                "properties": {

                    "subject": {
                        "type": "string",
                        "example": "October invoice",
                    },

                    "body": {
                        "type": "string",
                        "example": "Please review the invoice.",
                    },

                    "html": {
                        "type": "string",
                        "example": "",
                    },

                    "recipients": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "example": [
                            "user@example.com"
                        ],
                    },

                    "attachments": {
                        "type": "array",
                        "items": {
                            "type": "object"
                        },
                        "description": (
                            "Use multipart binary uploads for real attachments."
                        ),
                    },
                },
            },
        },

        "multipart/form-data": {

            "schema": {

                "type": "object",

                "required": [
                    "subject",
                    "recipients",
                ],

                "properties": {

                    "subject": {
                        "type": "string"
                    },

                    "body": {
                        "type": "string"
                    },

                    "html": {
                        "type": "string"
                    },

                    "recipients": {
                        "type": "string",
                        "description": (
                            'JSON list or comma-separated addresses, '
                            'e.g. ["user@example.com"]'
                        ),
                    },

                    "files": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "format": "binary",
                        },
                        "description": (
                            "Optional attachments (0–5 files)"
                        ),
                    },
                },
            },

            "encoding": {
                "files": {
                    "style": "form",
                    "explode": True,
                }
            },
        },
    },
}


# ---------------------------------------------------------
# SINGLE BUSINESS ENDPOINT: ANALYZE EMAIL
# ---------------------------------------------------------

@app.post(
    f"{_PREFIX}/analyze",
    tags=["Email Validation"],
    summary=(
        "Email Validation — subject, body, URLs "
        "and optional attachments"
    ),
    dependencies=[
        Depends(require_api_key)
    ],
    openapi_extra={
        "requestBody": _ANALYZE_REQUEST_BODY
    },
)
async def analyze(request: Request):

    content_type = (
        request.headers.get("content-type", "")
        .split(";", 1)[0]
        .strip()
        .lower()
    )

    uploaded_files = []

    email_data = {}

    # ---------------- JSON REQUEST ----------------

    if content_type == "application/json":

        try:

            payload = await request.json()

        except (ValueError, UnicodeError):

            raise HTTPException(
                400,
                detail="Invalid JSON payload",
            )

        if not isinstance(payload, dict):

            raise HTTPException(
                422,
                detail="JSON root must be an object",
            )

        email_data = {
            "from": payload.get("from"),
            "to": payload.get("recipients", []),
            "subject": payload.get("subject"),
            "body": payload.get("body"),
        }

        final_result = await _analyze(payload)

    # ---------------- MULTIPART REQUEST ----------------

    elif content_type in {
        "multipart/form-data",
        "application/x-www-form-urlencoded",
    }:

        payload, uploaded_files = await _multipart_payload(
            request
        )

        email_data = {
            "from": payload.get("from"),
            "to": payload.get("recipients", []),
            "subject": payload.get("subject"),
            "body": payload.get("body"),
        }

        final_result = await _analyze(
            payload,
            uploaded_files,
        )

    else:

        raise HTTPException(
            415,
            detail=(
                "Use application/json or multipart/form-data"
            ),
        )

    # ---------------- SAVE RESULT IN MONGODB ----------------

    try:

        request_id = request.headers.get(
            "x-request-id"
        )

        # Current API-key authentication does not identify
        # individual application users. Use a fixed account
        # label until the existing user authentication
        # dependency is connected to this endpoint.
        save_result = await run_in_threadpool(
            save_analysis,
            account_id="api-key-client",
            analysis_result=final_result,
            email_data=email_data,
            request_id=request_id,
        )

        logger.info(
            "MongoDB save successful. Record ID: %s",
            save_result.get("record_id"),
        )

    except Exception:

        logger.exception(
            "Failed to save email analysis in MongoDB"
        )

        raise HTTPException(
            status_code=503,
            detail=(
                "Email validation completed, but "
                "saving the result failed."
            ),
        )

    # ---------------- RETURN ORIGINAL RESPONSE ----------------

    return final_result



