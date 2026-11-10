"""Attachment *content* security for the existing OMG attachment gate.

Explicit format support, byte/text budgets, OCR for text embedded in images and
scanned PDFs, and contextual policy detection. This is NOT a substitute for a
reviewed visual moderation model or a validated multilingual toxic-text model.

Call inspect_content(filename, data) ONLY after Attachments.py validates
format, archive safety and (when required) the mandatory antivirus scanner.
Never execute uploaded data or follow external links.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO
import os
from pathlib import PurePosixPath
import re
import zipfile

import pymupdf
from PIL import Image, ImageSequence
from defusedxml import ElementTree as SafeET
from .content_risk_rules import detect_lure_patterns
from Content.contextual_risk import inspect_contextual_risks
from URL.url_validator import validate_urls

try:
    import pytesseract
except ImportError:
    pytesseract = None
else:
    # Optional explicit Windows path when tesseract.exe is not on PATH.
    # The scanned-PDF OCR path uses PyMuPDF and also needs TESSDATA_PREFIX.
    tesseract_command = os.getenv('OMG_TESSERACT_CMD', '').strip().strip('"')
    if tesseract_command:
        pytesseract.pytesseract.tesseract_cmd = tesseract_command

EXT_TEXT = {'.txt', '.csv', '.json'}
EXT_PDF = {'.pdf'}
EXT_IMAGE = {'.png', '.jpg', '.jpeg', '.gif'}
EXT_OFFICE = {'.docx', '.xlsx', '.pptx'}
EXT_ZIP = {'.zip'}

# Strict, deliberately narrow rules. These are EXAMPLES, not a comprehensive
# harassment/hate/violence detector. Expand against reviewed organizational
# policy, labeled negative examples and a measured text classifier.
BLOCK_PATTERNS = (
    ('DIRECT_THREAT', 'Direct threat of physical harm', re.compile(
        r"\b(?:i\s+(?:will|am\s+going\s+to|shall)|we\s+will)\s+(?:kill|hurt|attack|beat)\s+(?:you|your\s+family)\b", re.I)),
    ('TARGETED_ABUSE', 'Targeted abusive language', re.compile(
        r"\b(?:you\s+are|you\s*['’]re)\s+(?:an?\s+)?(?:worthless|idiot|moron)\b", re.I)),
    ('CREDENTIAL_REQUEST', 'Request to disclose credentials or verification codes', re.compile(
        r"\b(?:send|share|provide|reply\s+with)\s+(?:me\s+)?(?:your|the)\s+(?:account\s+)?(?:password|otp|one[ -]time\s+(?:password|code)|verification\s+code)\b", re.I)),
    ('SEXUAL_SOLICITATION', 'Solicitation for sexual services', re.compile(
        r"\b(?:buy|book|hire|need)\s+(?:any\s+|a\s+)?(?:sex\s+worker|sexual\s+services)\b", re.I)),
)


class ContentError(Exception):
    def __init__(self, code: str, reason: str):
        self.code, self.reason = code, reason
        super().__init__(reason)


@dataclass(frozen=True)
class ContentPolicy:
    enabled: bool = True
    lure_rules_enabled: bool = True
    ocr_mode: str = 'when_needed'  # off, when_needed, all
    ocr_required: bool = False
    image_policy: str = 'ocr_only'  # ocr_only, restrict
    max_text_chars: int = 500_000
    max_xml_bytes: int = 3_000_000
    max_image_frames: int = 5
    max_ocr_pages: int = 15
    max_pdf_pages: int = 200
    max_archive_depth: int = 3
    max_archive_members: int = 200
    max_archive_uncompressed: int = 40 * 1024 * 1024
    max_ocr_image_pixels: int = 20_000_000
    ocr_language: str = 'eng'
    ocr_timeout: int = 12


def load_content_policy() -> ContentPolicy:
    def num(key, default, low, high):
        n = int(os.getenv(key, str(default)))
        if not low <= n <= high:
            raise ValueError(f'{key} must be between {low} and {high}')
        return n
    mode = os.getenv('OMG_CONTENT_OCR_MODE', 'when_needed').lower()
    vision = os.getenv('OMG_CONTENT_IMAGE_POLICY', 'ocr_only').lower()
    if mode not in {'off', 'when_needed', 'all'}:
        raise ValueError('OMG_CONTENT_OCR_MODE must be off, when_needed or all')
    if vision not in {'ocr_only', 'restrict'}:
        raise ValueError('OMG_CONTENT_IMAGE_POLICY must be ocr_only or restrict')
    return ContentPolicy(
        enabled=os.getenv('OMG_CONTENT_ENABLED', 'true').lower() in {'true', 'yes', '1'},
        lure_rules_enabled=os.getenv('OMG_CONTENT_LURE_RULES', 'true').lower() in {'true', 'yes', '1'},
        ocr_mode=mode,
        ocr_required=os.getenv('OMG_CONTENT_OCR_REQUIRED', 'false').lower() in {'true', 'yes', '1'},
        image_policy=vision,
        max_text_chars=num('OMG_CONTENT_MAX_CHARS', 500_000, 1000, 2_000_000),
        max_xml_bytes=num('OMG_CONTENT_MAX_XML_MB', 3, 1, 10) * 1024 * 1024,
        max_ocr_pages=num('OMG_CONTENT_MAX_OCR_PAGES', 15, 1, 200),
        ocr_language=os.getenv('OMG_CONTENT_OCR_LANGUAGE', 'eng'),
        ocr_timeout=num('OMG_CONTENT_OCR_TIMEOUT', 12, 2, 120),
    )


@dataclass
class ExtractState:
    policy: ContentPolicy
    fragments: list[str] = field(default_factory=list)
    sourced_fragments: list[tuple[str, str]] = field(default_factory=list)
    current_source: str = '(attachment)'
    length: int = 0
    entries_left: int = 200
    expanded_left: int = 40 * 1024 * 1024
    ocr_left: int = 15
    saw_visual: bool = False
    warnings: list[str] = field(default_factory=list)

    def append(self, text: str) -> None:
        if not text:
            return
        length = len(text)
        if self.length + length > self.policy.max_text_chars:
            raise ContentError('CONTENT_LIMIT', 'Document text exceeds the inspection budget; cannot validate completely')
        self.length += length
        self.fragments.append(text)
        self.sourced_fragments.append((self.current_source, text))


def _ocr_image(image: Image.Image, state: ExtractState) -> None:
    state.saw_visual = True
    p = state.policy
    if p.image_policy == 'restrict':
        raise ContentError('VISUAL_CONTENT_NOT_CLASSIFIED',
                           'Images cannot be fully screened for harmful visual content without an approved vision model')
    if p.ocr_mode == 'off':
        if p.ocr_required:
            raise ContentError('OCR_DISABLED', 'OCR is mandatory but disabled')
        state.warnings.append('Image text was not scanned: OCR disabled')
        return
    if pytesseract is None:
        raise ContentError('OCR_UNAVAILABLE', 'Image OCR library is not available')
    if state.ocr_left <= 0:
        raise ContentError('OCR_PAGE_LIMIT', 'OCR inspection limit exceeded')
    if image.width * image.height > p.max_ocr_image_pixels:
        raise ContentError('IMAGE_PIXEL_LIMIT', 'Image exceeds OCR pixel budget')
    state.ocr_left -= 1
    try:
        # Decoded image only; never execute or follow content links.
        text = pytesseract.image_to_string(image.convert('RGB'), lang=p.ocr_language,
                                           config='--psm 3', timeout=p.ocr_timeout)
        state.append(text)
    except (RuntimeError, OSError, ValueError, pytesseract.TesseractNotFoundError,
            pytesseract.TesseractError) as exc:
        raise ContentError('OCR_UNAVAILABLE', 'Tesseract OCR is unavailable or could not inspect this image') from exc


def _image(data: bytes, state: ExtractState) -> None:
    try:
        with Image.open(BytesIO(data)) as image:
            frames = getattr(image, 'n_frames', 1)
            if frames > state.policy.max_image_frames:
                raise ContentError('IMAGE_FRAME_LIMIT', 'Animated image contains too many frames to inspect')
            for frame in ImageSequence.Iterator(image):
                _ocr_image(frame.copy(), state)
    except ContentError:
        raise
    except Exception as exc:
        raise ContentError('IMAGE_CONTENT_PARSE_FAILED', 'Cannot inspect image contents') from exc


def _pdf(data: bytes, state: ExtractState) -> None:
    try:
        with pymupdf.open(stream=data, filetype='pdf') as doc:
            if doc.needs_pass:
                raise ContentError('ENCRYPTED_PDF', 'Encrypted PDF text cannot be inspected')
            if doc.page_count > state.policy.max_pdf_pages:
                raise ContentError('PDF_PAGE_LIMIT', 'PDF has too many pages to inspect')
            for page in doc:
                text = page.get_text('text')
                # OCR when no selectable text or when images are embedded (mode=all).
                has_images = bool(page.get_images(full=True))
                if has_images:
                    state.saw_visual = True
                if state.policy.image_policy == 'restrict' and has_images:
                    raise ContentError('VISUAL_CONTENT_NOT_CLASSIFIED',
                                       'PDF contains images that require an approved visual moderation model')
                needs_ocr = (len(text.strip()) < 25 or has_images)
                if state.policy.ocr_mode == 'all' or (state.policy.ocr_mode == 'when_needed' and needs_ocr):
                    if state.ocr_left <= 0:
                        raise ContentError('OCR_PAGE_LIMIT', 'PDF contains more image pages than the OCR limit')
                    if state.policy.ocr_mode != 'off':
                        if pytesseract is None:
                            raise ContentError('OCR_UNAVAILABLE', 'Tesseract OCR library is unavailable')
                        state.ocr_left -= 1
                        try:
                            # OCR the page once, including any embedded text in pictures.
                            tp = page.get_textpage_ocr(language=state.policy.ocr_language, dpi=125, full=True)
                            text = page.get_text('text', textpage=tp)
                        except Exception as exc:
                            raise ContentError('OCR_UNAVAILABLE', 'Could not OCR a scanned PDF page') from exc
                elif state.policy.ocr_mode == 'off' and needs_ocr:
                    state.saw_visual = True
                    if state.policy.ocr_required:
                        raise ContentError('OCR_DISABLED', 'Scanned PDF requires OCR but OCR is disabled')
                    state.warnings.append('Scanned PDF or embedded page imagery was not OCR scanned')
                state.append(text)
    except ContentError:
        raise
    except Exception as exc:
        raise ContentError('PDF_CONTENT_PARSE_FAILED', 'Could not inspect PDF text') from exc


def _xml_text(payload: bytes, state: ExtractState) -> None:
    if len(payload) > state.policy.max_xml_bytes:
        raise ContentError('XML_TOO_LARGE', 'Office XML member exceeds the inspection budget')
    try:
        root = SafeET.fromstring(payload)
        for element in root.iter():
            if element.tag.rsplit('}', 1)[-1] in {'t', 'v', 'f'} and element.text:
                state.append(element.text + ' ')
    except ContentError:
        raise
    except Exception as exc:
        raise ContentError('OFFICE_CONTENT_PARSE_FAILED', 'Office XML content could not be inspected') from exc


def _office(zf: zipfile.ZipFile, ext: str, state: ExtractState) -> None:
    prefixes = {
        '.docx': ('word/',),
        '.xlsx': ('xl/',),
        '.pptx': ('ppt/',),
    }[ext]
    # Include comments, notes, shared strings, headers and footers.
    for member in zf.infolist():
        name = member.filename.lower()
        if member.is_dir():
            continue
        visible_xml = (
            (ext == '.docx' and name.startswith('word/') and not any(
                name.startswith('word/' + v) for v in ('styles', 'settings', 'theme', 'fonttable', 'numbering', 'websettings')))
            or (ext == '.xlsx' and name.startswith(('xl/worksheets/', 'xl/sharedstrings.xml', 'xl/comments/', 'xl/drawings/')))
            or (ext == '.pptx' and name.startswith(('ppt/slides/', 'ppt/notesslides/', 'ppt/comments/')))
        )
        if visible_xml and name.endswith('.xml'):
            if member.file_size > state.policy.max_xml_bytes:
                raise ContentError('XML_TOO_LARGE', 'Office text part too large to inspect')
            with zf.open(member) as stream:
                _xml_text(stream.read(state.policy.max_xml_bytes + 1), state)
        elif any(name.startswith(prefix + 'media/') for prefix in prefixes):
            # Enforce strict visual policy even when document text itself is SAFE.
            state.saw_visual = True
            if state.policy.image_policy == 'restrict':
                raise ContentError('VISUAL_CONTENT_NOT_CLASSIFIED',
                                   'Office attachment has embedded images requiring a visual content model')
            if name.endswith(tuple(EXT_IMAGE)):
                if member.file_size > 8 * 1024 * 1024:
                    raise ContentError('IMAGE_TOO_LARGE', 'Embedded image exceeds content inspection limit')
                with zf.open(member) as stream:
                    _image(stream.read(8 * 1024 * 1024 + 1), state)
            else:
                raise ContentError('UNSUPPORTED_EMBEDDED_MEDIA', 'Office attachment has media that cannot be inspected')


def _walk(filename: str, data: bytes, state: ExtractState, depth: int = 0) -> None:
    # Keep text and findings associated with each file *inside* a ZIP.
    previous = state.current_source
    state.current_source = filename
    try:
        _walk_payload(filename, data, state, depth)
    finally:
        state.current_source = previous


def _walk_payload(filename: str, data: bytes, state: ExtractState, depth: int = 0) -> None:
    ext = PurePosixPath(filename.lower()).suffix
    if ext in EXT_TEXT:
        try:
            state.append(data.decode('utf-8-sig'))
        except UnicodeError as exc:
            raise ContentError('CONTENT_DECODE_FAILED', 'Text file must be valid UTF-8') from exc
    elif ext in EXT_PDF:
        _pdf(data, state)
    elif ext in EXT_IMAGE:
        _image(data, state)
    elif ext in EXT_OFFICE or ext in EXT_ZIP:
        if depth > state.policy.max_archive_depth:
            raise ContentError('ARCHIVE_DEPTH', 'Nested archive content cannot be inspected completely')
        try:
            with zipfile.ZipFile(BytesIO(data)) as zf:
                if ext in EXT_OFFICE:
                    _office(zf, ext, state)
                else:
                    for member in zf.infolist():
                        if member.is_dir():
                            continue
                        state.entries_left -= 1
                        state.expanded_left -= member.file_size
                        if state.entries_left < 0 or state.expanded_left < 0:
                            raise ContentError('CONTENT_ARCHIVE_LIMIT', 'Archive extraction budget exceeded')
                        if member.file_size > 8 * 1024 * 1024:
                            raise ContentError('CONTENT_ARCHIVE_LIMIT', 'Archive member exceeds content inspection budget')
                        with zf.open(member) as stream:
                            payload = stream.read(member.file_size + 1)
                        if len(payload) != member.file_size:
                            raise ContentError('ARCHIVE_READ_FAILED', 'Could not read complete archive member')
                        _walk(member.filename, payload, state, depth + 1)
        except ContentError:
            raise
        except Exception as exc:
            raise ContentError('CONTENT_ARCHIVE_FAILED', 'Could not inspect archive contents') from exc
    else:
        raise ContentError('UNSUPPORTED_CONTENT_TYPE', f'{ext or "Unknown"} content cannot be inspected')


def inspect_content(filename: str, data: bytes, policy: ContentPolicy | None = None) -> dict:
    """Return findings and safe-to-display metadata (not the extracted sensitive text)."""
    policy = policy or load_content_policy()
    if not policy.enabled:
        return {'findings': [], 'warnings': ['Content inspection is disabled'], 'characters_inspected': 0,
                'visual_present': False, 'text_for_ml': ''}
    state = ExtractState(policy, entries_left=policy.max_archive_members,
                         expanded_left=policy.max_archive_uncompressed, ocr_left=policy.max_ocr_pages)
    try:
        _walk(filename, data, state)
        text = '\n'.join(state.fragments)
        findings = []
        advisories = []
        from .warning_rules import detect_minor_advisories
        # Scan the text of every ZIP member separately to avoid combining a
        # mailbox warning in one document with an unrelated action in another.
        by_source: dict[str, list[str]] = {}
        for source, fragment in state.sourced_fragments:
            by_source.setdefault(source, []).append(fragment)
        for source, parts in by_source.items():
            source_text = '\n'.join(parts)
            suffix = f' (inside ZIP: {source})' if source != filename else ''
            for code, reason, pattern in BLOCK_PATTERNS:
                matches = list(pattern.finditer(source_text))
                if code == 'CREDENTIAL_REQUEST':
                    # Awareness materials saying 'never share your OTP' are not
                    # direct requests for secrets.
                    matches = [m for m in matches if not re.search(
                        r"\b(?:do\s+not|don.t|never|must\s+not|should\s+not|avoid)\s*$",
                        source_text[max(0, m.start() - 28):m.start()], re.I)]
                if matches:
                    findings.append({'code': code, 'reason': reason + ' found in attachment content' + suffix,
                                     'occurrences': min(len(matches), 5), 'source': source})
            for issue in inspect_contextual_risks('', source_text):
                entry = {'code': issue['code'], 'reason': issue['message'] + suffix, 'source': source,
                         'severity': issue['severity']}
                if issue['severity'] == 'MINOR':
                    advisories.append(entry)
                elif not any(x['code'] == issue['code'] for x in findings):
                    findings.append(entry)
            # Attachment-embedded URLs are inspected with the same structural
            # and context checks as links in the email body. No live browsing.
            attachment_url_warnings = {
                'SHORTENED_URL', 'POTENTIAL_PAYMENT_REDIRECTION',
                'POTENTIAL_ACCOUNT_VERIFICATION_LURE', 'INSECURE_LOGIN_URL',
                'ACCOUNT_UPDATE_LINK_REVIEW', 'PAYMENT_UPDATE_LINK_REVIEW',
            }
            for issue in validate_urls(source_text).get('findings', []):
                minor = issue.get('severity') == 'MINOR' or issue['code'] in attachment_url_warnings
                entry = {
                    'code': 'ATTACHMENT_' + issue['code'],
                    'reason': issue['message'] + suffix,
                    'source': source,
                    'severity': 'MINOR' if minor else 'HIGH',
                }
                (advisories if minor else findings).append(entry)
            if policy.lure_rules_enabled:
                for issue in detect_lure_patterns(source_text):
                    findings.append({'code': issue['code'], 'reason': issue['reason'] + suffix, 'source': source})
            for issue in detect_minor_advisories(source_text):
                advisories.append({**issue, 'reason': issue['reason'] + suffix, 'source': source})
        if state.saw_visual and policy.image_policy == 'ocr_only':
            state.warnings.append('OCR inspects readable image text; harmful visual imagery is NOT classified')
        return {'findings': findings, 'advisories': advisories, 'warnings': state.warnings,
                'characters_inspected': state.length, 'visual_present': state.saw_visual,
                'text_for_ml': text}
    except ContentError as exc:
        return {'findings': [{'code': exc.code, 'reason': exc.reason}], 'warnings': [],
                'characters_inspected': state.length, 'visual_present': state.saw_visual,
                'text_for_ml': ''}
    except Exception:
        return {'findings': [{'code': 'CONTENT_SCANNER_FAILURE', 'reason': 'Attachment content inspection failed'}],
                'warnings': [], 'characters_inspected': state.length,
                'visual_present': state.saw_visual, 'text_for_ml': ''}
