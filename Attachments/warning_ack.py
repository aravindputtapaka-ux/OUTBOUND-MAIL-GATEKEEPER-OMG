"""Local demo warning acknowledgment tokens, bound to the EXACT attachment bytes.

Not user authentication: replace with authenticated, audited consent in production.
Each process uses an ephemeral random HMAC key unless OMG_WARNING_SIGNING_KEY
is configured. Never put a signing key in browser JavaScript.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import secrets
import time

_configured_key = os.getenv('OMG_WARNING_SIGNING_KEY', '')
if os.getenv('OMG_ENV', 'development').lower() == 'production' and len(_configured_key.encode()) < 32:
    raise RuntimeError('Production requires OMG_WARNING_SIGNING_KEY with at least 32 random bytes')
SECRET = _configured_key.encode() or secrets.token_bytes(32)
TTL_SECONDS = 10 * 60


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode('ascii').rstrip('=')


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def fingerprint(items: list[tuple[str, bytes]]) -> str:
    """Name, size, order and content digest all matter."""
    h = hashlib.sha256()
    for name, content in items:
        chunk = json.dumps([name, len(content), hashlib.sha256(content).hexdigest()], separators=(',', ':'), ensure_ascii=True).encode()
        h.update(len(chunk).to_bytes(4, 'big'))
        h.update(chunk)
    return h.hexdigest()


def _sign(payload: dict) -> str:
    encoded = _b64(json.dumps(payload, separators=(',', ':')).encode())
    sig = _b64(hmac.new(SECRET, encoded.encode('ascii'), hashlib.sha256).digest())
    return encoded + '.' + sig


def _read_verified(token: str, now: int | None = None) -> dict | None:
    if not token or len(token) > 600 or token.count('.') != 1:
        return None
    try:
        encoded, signature = token.split('.', 1)
        expected = hmac.new(SECRET, encoded.encode('ascii'), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(signature)):
            return None
        obj = json.loads(_unb64(encoded))
        moment = int(time.time()) if now is None else int(now)
        if (obj.get('v') == 1 and obj.get('p') in {'challenge', 'ack'}
                and isinstance(obj.get('iat'), int)
                and 0 <= moment - obj['iat'] <= TTL_SECONDS):
            return obj
    except (ValueError, TypeError, UnicodeError, KeyError, OverflowError):
        pass
    return None


def issue_warning_challenge(items: list[tuple[str, bytes]], now: int | None = None) -> str:
    return _sign({'v': 1, 'p': 'challenge', 'fp': fingerprint(items),
                  'iat': int(time.time()) if now is None else int(now)})


def acknowledge_warning_challenge(challenge: str, now: int | None = None) -> str | None:
    """Called only by the explicit UI Close action; issue a distinct ACK token.

    The server cannot cryptographically prove a human actually read a popup;
    a production integration must use authenticated sessions and audit logs.
    """
    obj = _read_verified(challenge, now)
    if not obj or obj['p'] != 'challenge':
        return None
    return _sign({'v': 1, 'p': 'ack', 'fp': obj['fp'],
                  'iat': int(time.time()) if now is None else int(now)})


def verify_warning_ack_token(token: str, items: list[tuple[str, bytes]], now: int | None = None) -> bool:
    obj = _read_verified(token, now)
    return bool(obj and obj['p'] == 'ack' and hmac.compare_digest(obj.get('fp', ''), fingerprint(items)))


def verify_warning_challenge(challenge: str, items: list[tuple[str, bytes]], now: int | None = None) -> bool:
    """Verify a preflight WARNING challenge for the exact file set.

    The parent portal must additionally record an explicit user Close/acknowledgment
    in its authenticated session before calling its send endpoint.
    """
    obj = _read_verified(challenge, now)
    return bool(obj and obj.get('p') == 'challenge' and
                hmac.compare_digest(obj.get('fp', ''), fingerprint(items)))
