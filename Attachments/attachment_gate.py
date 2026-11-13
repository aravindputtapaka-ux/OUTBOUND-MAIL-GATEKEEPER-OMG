"""Reusable pre-send attachment checks for existing Resident Connect / OMG portal.

Call `scan_uploads(files)` when the user selects an attachment AND again
inside the existing server-side send/queue route before any email is queued.
A green/SAFE response is only an *attachment* verdict.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from starlette.datastructures import UploadFile
from .attachments import load_policy, validate_attachments
from .attachment_ml import MLDetector
from .content_validator import inspect_content, load_content_policy
from .text_content_ml import TextContentML
from .decision_metadata import with_decision_metadata

ROOT = Path(__file__).resolve().parent
# Match existing portal's displayed limits even if .env was not copied yet.
os.environ.setdefault('OMG_MAX_FILES', '5')
os.environ.setdefault('OMG_MAX_FILE_MB', '3')
os.environ.setdefault('OMG_MAX_TOTAL_MB', '10')
# Relative hash file paths should work regardless of startup current directory.
if os.getenv('OMG_DENIED_HASHES_FILE', '').replace('\\', '/').startswith('security/'):
    os.environ['OMG_DENIED_HASHES_FILE'] = str(ROOT / os.environ['OMG_DENIED_HASHES_FILE'])
POLICY = load_policy()
ML = MLDetector(
    mode=os.getenv('OMG_ML_MODE', 'off').lower(),
    artifact=os.getenv('OMG_ML_MODEL_PATH', str(ROOT / 'models/file_risk.joblib')),
    threshold=float(os.getenv('OMG_ML_THRESHOLD', '0.90')),
)

# Matches the portal UI screenshot. Change *both* this list and the UI hint
# if a business policy requires additional types.
PORTAL_EXTENSIONS = {'.pdf', '.txt', '.csv', '.json', '.jpg', '.jpeg', '.png', '.gif', '.docx', '.xlsx', '.pptx', '.zip'}
CONTENT_POLICY = load_content_policy()
CONTENT_ML = TextContentML.from_env()
if os.getenv('OMG_ENV', 'development').lower() == 'production':
    if not POLICY.require_clamav:
        raise RuntimeError('OMG production requires ClamAV (OMG_REQUIRE_CLAMAV=true)')
    if not CONTENT_POLICY.enabled:
        raise RuntimeError('OMG production requires content inspection enabled')
    if CONTENT_POLICY.ocr_mode == 'off' or not CONTENT_POLICY.ocr_required:
        raise RuntimeError('OMG production requires mandatory OCR on inspectable scanned text')
    if CONTENT_POLICY.image_policy != 'restrict':
        raise RuntimeError('OMG production must RESTRICT unclassified visual media until a vetted vision model is integrated')


def restricted(reason: str, code: str, filename: str = '(attachments)') -> dict[str, Any]:
    return with_decision_metadata({
        'status': 'RESTRICTED', 'can_send': False,
        'popup': {'show': True, 'type': 'RESTRICTED', 'title': 'Email Restricted', 'message': 'Email sending is blocked. Remove or replace the restricted attachment.',
                  'reasons': [{'filename': filename, 'code': code, 'reason': reason}], 'actions': ['CLOSE']},
        'attachments': [], 'scope': 'ATTACHMENTS_ONLY',
    })


def normalize_result(report: dict[str, Any]) -> dict[str, Any]:
    """Priority: RESTRICTED > WARNING > SAFE; minor advisories never override major findings."""
    attachments = report['attachments']
    block_reasons = [
        {'filename': item['filename'], 'code': issue['code'], 'reason': issue['reason']}
        for item in attachments for issue in item.get('findings', [])
    ] + [
        {'filename': '(attachments)', 'code': issue['code'], 'reason': issue['reason']}
        for issue in report.get('findings', [])
    ]
    advisory_reasons = [
        {'filename': item['filename'], 'code': issue['code'], 'reason': issue['reason']}
        for item in attachments for issue in item.get('advisories', [])
    ]
    common = {'attachments': attachments, 'scope': 'ATTACHMENTS_ONLY',
              'warnings': report.get('warnings', []), 'advisories': advisory_reasons}
    if block_reasons or report['status'] == 'RESTRICTED':
        return with_decision_metadata({**common, 'status': 'RESTRICTED', 'can_send': False,
            'requires_acknowledgement': False,
            'popup': {'show': True, 'type': 'RESTRICTED', 'title': 'Email Restricted',
                'actions': ['DISCARD_MAIL'], 'message': 'Email sending is blocked. Correct or remove the restricted attachment and validate again.',
                'reasons': block_reasons}})
    if advisory_reasons:
        return with_decision_metadata({**common, 'status': 'WARNING', 'can_send': False,
            'requires_acknowledgement': True,
            'popup': {'show': True, 'type': 'WARNING', 'title': 'Email Warning',
                'message': 'Minor attachment concern. You may edit the email or close this warning and proceed.',
                'reasons': advisory_reasons,
                'actions': ['EDIT_MAIL', 'CLOSE']}})
    return with_decision_metadata({**common, 'status': 'SAFE', 'can_send': True,
            'requires_acknowledgement': False, 'popup': None})


def scan_bytes(items: list[tuple[str, bytes]]) -> dict[str, Any]:
    """Same function is called by preview/preflight and the actual send handler."""
    if len(items) > POLICY.max_files:
        return restricted(f'Maximum {POLICY.max_files} attachments allowed', 'TOO_MANY_ATTACHMENTS')
    total = 0
    for name, data in items:
        if not isinstance(name, str) or not isinstance(data, bytes):
            return restricted('Invalid uploaded attachment', 'INVALID_UPLOAD')
        total += len(data)
        if len(data) > POLICY.max_file_bytes:
            return restricted('File exceeds the 3 MB portal limit', 'FILE_TOO_LARGE', name)
        if total > POLICY.max_total_bytes:
            return restricted('Total attachments exceed the 10 MB portal limit', 'TOTAL_SIZE_EXCEEDED')
        suffix = Path(name).suffix.lower()
        if suffix not in PORTAL_EXTENSIONS:
            return restricted(f'{suffix or "Unknown"} is not an allowed attachment type', 'UNSUPPORTED_EXTENSION', name)
    # For each supported file: hash, signature, deep parser, AV, and optional ML.
    try:
        report = validate_attachments(items, POLICY)
        attachments = report.get('attachments')
        if not isinstance(attachments, list) or len(attachments) != len(items):
            return restricted('Attachment security engine returned an incomplete report', 'SCANNER_FAILURE')
        # Apply content policy to every *structurally SAFE* file, not only to
        # an all-SAFE batch. This preserves per-file reasons in mixed batches.
        for i, (name, data) in enumerate(items):
            attachment = attachments[i]
            if not isinstance(attachment, dict) or not isinstance(attachment.get('findings'), list):
                return restricted('Attachment security engine returned a malformed file report', 'SCANNER_FAILURE', name)
            if attachment['status'] == 'RESTRICTED':
                continue
            content = inspect_content(name, data, CONTENT_POLICY)
            attachment['content_characters_inspected'] = content['characters_inspected']
            attachment['content_warnings'] = content['warnings']
            attachment['visual_content_present'] = content['visual_present']
            # Never return extracted content to the browser or write it to logs.
            attachment['findings'].extend(content['findings'])
            attachment['advisories'] = content.get('advisories', [])
            if not content['findings']:
                text_ml = CONTENT_ML.inspect(content['text_for_ml'])
                attachment['findings'].extend(text_ml['findings'])
                attachment['content_warnings'].extend(text_ml['warnings'])
                if text_ml['scores']:
                    attachment['content_ml_scores'] = text_ml['scores']
            if not attachment['findings']:
                ml = ML.inspect(name, data)
                if ml.get('score') is not None:
                    attachment['file_ml_score'] = ml['score']
                if ml.get('enforced') and (ml.get('flagged') or ml.get('error')):
                    attachment['findings'].append({
                        'code': 'ML_RISK' if ml.get('flagged') else 'ML_UNAVAILABLE',
                        'reason': 'Approved file-risk ML marked the attachment high-risk' if ml.get('flagged')
                                  else 'Mandatory file-risk ML inference unavailable',
                    })
            if attachment['findings']:
                attachment['status'] = 'RESTRICTED'
                report['status'] = 'RESTRICTED'
            elif attachment.get('advisories'):
                attachment['status'] = 'WARNING'
        return normalize_result(report)
    except Exception:
        # Do not expose parser stack traces or allow the mail through on failures.
        return restricted('Attachment security engine could not finish validation', 'SCANNER_FAILURE')


async def read_uploads(uploads: list[UploadFile]) -> tuple[list[tuple[str, bytes]], dict[str, Any] | None]:
    """Read bounded bytes. Reset UploadFile cursors for an existing portal send handler.
    `uploads` are real binary files, not Swagger empty placeholders.
    """
    if len(uploads) > POLICY.max_files:
        return [], restricted(f'Maximum {POLICY.max_files} attachments allowed', 'TOO_MANY_ATTACHMENTS')
    items: list[tuple[str, bytes]] = []
    total = 0
    for up in uploads:
        await up.seek(0)
        data = await up.read(POLICY.max_file_bytes + 1)
        await up.seek(0)
        total += len(data)
        if len(data) > POLICY.max_file_bytes:
            return [], restricted('File exceeds the 3 MB portal limit', 'FILE_TOO_LARGE', up.filename or '(unnamed)')
        if total > POLICY.max_total_bytes:
            return [], restricted('Total attachments exceed the 10 MB portal limit', 'TOTAL_SIZE_EXCEEDED')
        items.append((up.filename or '', data))
    return items, None


async def scan_uploads(uploads: list[UploadFile]) -> dict[str, Any]:
    items, error = await read_uploads(uploads)
    if error:
        return error
    # Scanner is CPU/IO-bound (parsers + AV); keep the ASGI loop responsive.
    from starlette.concurrency import run_in_threadpool
    return await run_in_threadpool(scan_bytes, items)


async def authorize_uploads_before_send(uploads: list[UploadFile], *,
                                        warning_acknowledged: bool = False,
                                        warning_challenge: str = '') -> tuple[bool, dict[str, Any]]:
    """Integration helper for the MAIN project's existing send/queue API.

    Re-inspects the current attachment bytes. Must be called AFTER user/session
    authentication, immediately BEFORE enqueue or SMTP. No email sending here.

    The calling portal must set warning_acknowledged from an explicit, audited
    user action (WARNING popup 'Close'), not silently from a browser default.
    The signed challenge must match exactly the files being sent.
    """
    report = await scan_uploads(uploads)
    if report['status'] == 'RESTRICTED':
        return False, report
    if report['status'] == 'SAFE':
        return True, report
    items, error = await read_uploads(uploads)
    if error:
        return False, error
    from .warning_ack import verify_warning_challenge
    if not warning_acknowledged or not verify_warning_challenge(warning_challenge, items):
        return False, report
    report['can_send'] = True
    report['requires_acknowledgement'] = False
    report['warning_acknowledged'] = True
    report['popup'] = None
    return True, report
