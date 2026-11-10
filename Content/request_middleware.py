import logging
import re
import time
import uuid

from starlette.responses import JSONResponse

from Content.config import settings

logger = logging.getLogger(__name__)
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")


class _RequestTooLarge(Exception):
    pass


class RequestLoggingMiddleware:
    """ASGI middleware for request IDs, body-size enforcement, headers, and logs."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_headers = {key.lower(): value for key, value in scope.get("headers", [])}
        supplied_id = request_headers.get(b"x-request-id", b"").decode("ascii", errors="ignore")
        request_id = supplied_id if _REQUEST_ID_RE.fullmatch(supplied_id) else str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = request_id
        started = time.perf_counter()
        response_status = 500
        response_started = False
        bytes_received = 0

        async def send_with_headers(message):
            nonlocal response_status, response_started
            if message["type"] == "http.response.start":
                response_started = True
                response_status = message["status"]
                headers = list(message.get("headers", []))
                existing = {key.lower() for key, _ in headers}
                additions = {
                    b"x-request-id": request_id.encode("ascii"),
                    b"x-content-type-options": b"nosniff",
                    b"cache-control": b"no-store",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                }
                for key, value in additions.items():
                    if key not in existing:
                        headers.append((key, value))
                message["headers"] = headers
            await send(message)

        content_length = request_headers.get(b"content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
                if declared_size < 0:
                    raise ValueError
                if declared_size > settings.MAX_REQUEST_BYTES:
                    response = JSONResponse(
                        status_code=413,
                        content={"detail": "Request body exceeds the configured size limit."},
                    )
                    await response(scope, receive, send_with_headers)
                    self._log(request_id, scope, response_status, started)
                    return
            except ValueError:
                response = JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header."})
                await response(scope, receive, send_with_headers)
                self._log(request_id, scope, response_status, started)
                return

        async def limited_receive():
            nonlocal bytes_received
            message = await receive()
            if message["type"] == "http.request":
                bytes_received += len(message.get("body", b""))
                if bytes_received > settings.MAX_REQUEST_BYTES:
                    raise _RequestTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send_with_headers)
        except _RequestTooLarge:
            if not response_started:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": "Request body exceeds the configured size limit."},
                )
                await response(scope, receive, send_with_headers)
            else:
                logger.error("request_body_limit_exceeded_after_response_started request_id=%s", request_id)
        except Exception:
            logger.exception("request_failed request_id=%s path=%s", request_id, scope.get("path", ""))
            raise
        finally:
            self._log(request_id, scope, response_status, started)

    @staticmethod
    def _log(request_id, scope, response_status, started):
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        logger.info(
            "request_complete request_id=%s method=%s path=%s status=%s elapsed_ms=%s",
            request_id,
            scope.get("method", ""),
            scope.get("path", ""),
            response_status,
            elapsed_ms,
        )
