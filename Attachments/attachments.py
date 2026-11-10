"""OMG attachment-only security gate. No file execution or extraction to disk.

Python 3.10+. All untrusted content is size bounded before inspection. This module
is a *policy plus signature plus optional malware* gate, not a proof of safety.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import PurePosixPath
import re
import socket
import struct
from typing import Any, Iterable
import zipfile

from pypdf import PdfReader
import pymupdf as fitz  # supported PyMuPDF import
from PIL import Image, UnidentifiedImageError

# Upper bound for decoded pixel dimensions before Pillow processes an image.
Image.MAX_IMAGE_PIXELS = 20_000_000


EXTENSIONS = frozenset({
    ".pdf", ".txt", ".csv", ".json", ".png", ".jpg", ".jpeg",
    ".gif", ".docx", ".xlsx", ".pptx", ".zip",
})
OFFICE_ROOTS = {
    ".docx": "word/document.xml",
    ".xlsx": "xl/workbook.xml",
    ".pptx": "ppt/presentation.xml",
}
SIGNATURES = {
    ".pdf": b"%PDF-",
    ".png": b"\x89PNG\r\n\x1a\n",
    ".jpg": b"\xff\xd8\xff",
    ".jpeg": b"\xff\xd8\xff",
    ".gif": b"GIF8",
}
DANGEROUS_SUFFIXES = frozenset({
    ".exe", ".dll", ".com", ".scr", ".msi", ".bat", ".cmd",
    ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
    ".jar", ".class", ".sh", ".py", ".php", ".phtml", ".jsp",
    ".asp", ".aspx", ".html", ".htm", ".svg", ".lnk", ".url",
    ".iso", ".img", ".reg", ".cpl", ".chm", ".app", ".dmg",
    ".docm", ".xlsm", ".pptm", ".xlam", ".xlsb",
})


@dataclass(frozen=True)
class Policy:
    max_file_bytes: int = 10 * 1024 * 1024
    max_total_bytes: int = 20 * 1024 * 1024
    max_files: int = 10
    max_zip_entries: int = 200
    max_uncompressed_bytes: int = 40 * 1024 * 1024
    max_zip_ratio: int = 100
    max_zip_depth: int = 3
    max_pdf_pages: int = 200
    require_clamav: bool = False
    clamav_host: str = "127.0.0.1"
    clamav_port: int = 3310
    clamav_timeout: float = 6.0
    # Optional SHA256 denylist: each line one SHA256, # comments permitted
    denied_hashes: frozenset[str] = frozenset()


def load_policy() -> Policy:
    def read_int(name: str, default: int, lo: int = 1, hi: int = 1_000_000_000) -> int:
        value = int(os.getenv(name, str(default)))
        if not lo <= value <= hi:
            raise ValueError(f"{name} must be in [{lo}, {hi}]")
        return value

    file_mb = read_int("OMG_MAX_FILE_MB", 10, 1, 100)
    total_mb = read_int("OMG_MAX_TOTAL_MB", 20, 1, 200)
    hashes: set[str] = set()
    hash_path = os.getenv("OMG_DENIED_HASHES_FILE", "").strip()
    if hash_path:
        with open(hash_path, encoding="utf-8") as fh:
            for line in fh:
                candidate = line.split("#", 1)[0].strip().lower()
                if candidate:
                    if not re.fullmatch(r"[a-f0-9]{64}", candidate):
                        raise ValueError("Denied hashes file must contain only SHA256 strings")
                    hashes.add(candidate)
    return Policy(
        max_file_bytes=file_mb * 1024 * 1024,
        max_total_bytes=total_mb * 1024 * 1024,
        max_files=read_int("OMG_MAX_FILES", 10, 1, 100),
        require_clamav=os.getenv("OMG_REQUIRE_CLAMAV", "false").lower() in {"true", "1", "yes"},
        clamav_host=os.getenv("OMG_CLAMAV_HOST", "127.0.0.1"),
        clamav_port=read_int("OMG_CLAMAV_PORT", 3310, 1, 65535),
        clamav_timeout=float(os.getenv("OMG_CLAMAV_TIMEOUT", "6.0")),
        max_zip_entries=read_int("OMG_MAX_ZIP_ENTRIES", 200, 1, 5000),
        max_zip_depth=read_int("OMG_MAX_ZIP_DEPTH", 3, 0, 8),
        max_uncompressed_bytes=read_int("OMG_MAX_ARCHIVE_EXPANDED_MB", 40, 1, 500) * 1024 * 1024,
        max_zip_ratio=read_int("OMG_MAX_ZIP_RATIO", 100, 1, 10000),
        max_pdf_pages=read_int("OMG_MAX_PDF_PAGES", 200, 1, 10000),
        denied_hashes=frozenset(hashes),
    )


def finding(code: str, reason: str) -> dict[str, str]:
    return {"code": code, "reason": reason}


class UnsafeAttachment(Exception):
    def __init__(self, code: str, reason: str):
        self.code, self.reason = code, reason
        super().__init__(reason)


def _filename(name: str) -> tuple[str, str]:
    """Reject path elements, dangerous double suffixes, and path tricks."""
    if not isinstance(name, str) or not name or len(name) > 180:
        raise UnsafeAttachment("INVALID_FILENAME", "Missing or overly long filename")
    if any(c in name for c in ("/", "\\", "\x00", "\r", "\n", ":")) or name in {".", ".."}:
        raise UnsafeAttachment("INVALID_FILENAME", "Filename contains an unsafe path or control character")
    if name.startswith(".") or name.endswith((".", " ")) or any(ord(c) < 32 for c in name):
        raise UnsafeAttachment("INVALID_FILENAME", "Filename has an unsafe prefix, suffix or control character")
    parts = name.lower().split(".")
    if len(parts) < 2 or not parts[-1]:
        raise UnsafeAttachment("NO_EXTENSION", "An explicitly allowed file extension is required")
    ext = "." + parts[-1]
    if any("." + p in DANGEROUS_SUFFIXES for p in parts[1:]):
        raise UnsafeAttachment("DANGEROUS_EXTENSION", "Executable, script or macro-enabled attachment extension")
    if ext not in EXTENSIONS:
        raise UnsafeAttachment("UNSUPPORTED_EXTENSION", f"Extension {ext} is not on the allowed list")
    return name, ext


def _text_check(data: bytes, ext: str) -> None:
    try:
        value = data.decode("utf-8-sig", errors="strict")
    except UnicodeError as exc:
        raise UnsafeAttachment("INVALID_TEXT", "Text must be valid UTF-8") from exc
    if "\x00" in value or any(ord(c) < 32 and c not in "\t\n\r\f" for c in value):
        raise UnsafeAttachment("BINARY_DISGUISED_AS_TEXT", "Text file contains binary control characters")
    if ext == ".json":
        try:
            json.loads(value)
        except (ValueError, RecursionError) as exc:
            raise UnsafeAttachment("INVALID_JSON", "Invalid JSON document") from exc


def _pdf_check(data: bytes, policy: Policy) -> None:
    if not data.startswith(b"%PDF-"):
        raise UnsafeAttachment("TYPE_MISMATCH", "PDF extension does not match file signature")
    try:
        # Independent PyMuPDF parser cross-check; no page rendering and no embedded scripts run.
        with fitz.open(stream=data, filetype="pdf") as doc:
            if doc.needs_pass:
                raise UnsafeAttachment("ENCRYPTED_PDF", "Encrypted PDFs cannot be fully inspected")
            if doc.page_count > policy.max_pdf_pages:
                raise UnsafeAttachment("PDF_PAGE_LIMIT", "PDF exceeds configured page limit")
        reader = PdfReader(BytesIO(data), strict=True)
        if reader.is_encrypted:
            raise UnsafeAttachment("ENCRYPTED_PDF", "Encrypted PDFs cannot be fully inspected")
        page_count = len(reader.pages)
        if page_count > policy.max_pdf_pages:
            raise UnsafeAttachment("PDF_PAGE_LIMIT", "PDF exceeds the configured page inspection limit")
        root = reader.trailer["/Root"]
        for key in ("/OpenAction", "/AA"):
            if key in root:
                raise UnsafeAttachment("PDF_ACTIVE_CONTENT", f"PDF has an active action: {key}")
        names = root.get("/Names")
        if names:
            names = names.get_object()
            if any(key in names for key in ("/JavaScript", "/EmbeddedFiles")):
                raise UnsafeAttachment("PDF_ACTIVE_CONTENT", "PDF contains JavaScript or embedded files")
        for page in reader.pages:
            annots = page.get("/Annots")
            if not annots:
                continue
            if len(annots) > 1000:
                raise UnsafeAttachment("PDF_ANNOTATION_LIMIT", "Too many PDF annotations")
            for annot in annots:
                obj = annot.get_object()
                if any(k in obj for k in ("/AA", "/RichMediaContent")):
                    raise UnsafeAttachment("PDF_ACTIVE_CONTENT", "PDF annotation has active content")
                action = obj.get("/A")
                if action:
                    action = action.get_object()
                    if action.get("/S") in ("/JavaScript", "/Launch", "/SubmitForm", "/GoToR"):
                        raise UnsafeAttachment("PDF_ACTIVE_CONTENT", "PDF annotation contains a risky action")
    except UnsafeAttachment:
        raise
    except Exception as exc:
        raise UnsafeAttachment("INVALID_PDF", "PDF could not be completely parsed") from exc


def _clamav_scan(data: bytes, policy: Policy) -> tuple[str, str | None]:
    """clamd INSTREAM protocol; no shell and no local filesystem paths."""
    if not policy.require_clamav:
        return "NOT_CONFIGURED", None
    try:
        with socket.create_connection((policy.clamav_host, policy.clamav_port), timeout=policy.clamav_timeout) as sock:
            sock.settimeout(policy.clamav_timeout)
            sock.sendall(b"zINSTREAM\x00")
            for start in range(0, len(data), 65536):
                chunk = data[start:start + 65536]
                sock.sendall(struct.pack("!I", len(chunk)) + chunk)
            sock.sendall(struct.pack("!I", 0))
            response = bytearray()
            while len(response) < 4096:
                part = sock.recv(4096)
                if not part:
                    break
                response.extend(part)
                if b"\x00" in part or b"\n" in part:
                    break
            result = response.decode("utf-8", errors="replace").strip("\x00\r\n")
            if result.endswith(" OK"):
                return "CLEAN", None
            if result.endswith(" FOUND"):
                return "DETECTED", result[:250]
            return "ERROR", result[:250] or "Invalid clamd response"
    except (OSError, TimeoutError) as exc:
        return "ERROR", f"ClamAV unavailable ({type(exc).__name__})"


def _zip_check(data: bytes, ext: str, policy: Policy, depth: int, remaining: list[int]) -> None:
    if depth > policy.max_zip_depth:
        raise UnsafeAttachment("ARCHIVE_DEPTH", "Archive nesting depth exceeded")
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > policy.max_zip_entries or len(members) > remaining[1]:
                raise UnsafeAttachment("ARCHIVE_ENTRY_LIMIT", "Too many archive members")
            remaining[1] -= len(members)
            names = {m.filename for m in members}
            if ext in OFFICE_ROOTS:
                if "[Content_Types].xml" not in names or OFFICE_ROOTS[ext] not in names:
                    raise UnsafeAttachment("TYPE_MISMATCH", "Office file is not a valid OOXML package for its extension")
            for member in members:
                name = member.filename
                path = PurePosixPath(name)
                if name.startswith(("/", "\\")) or "\\" in name or "\x00" in name or ":" in name or ".." in path.parts:
                    raise UnsafeAttachment("ARCHIVE_PATH_TRAVERSAL", "Archive contains unsafe member paths")
                # UNIX symlinks as recorded in ZIP external attributes
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise UnsafeAttachment("ARCHIVE_SYMLINK", "Archive contains a symlink")
                if member.flag_bits & 0x1:
                    raise UnsafeAttachment("ENCRYPTED_ARCHIVE", "Encrypted archive members cannot be inspected")
                if member.is_dir():
                    continue
                if member.file_size > policy.max_file_bytes:
                    raise UnsafeAttachment("ARCHIVE_MEMBER_SIZE", "Archive member exceeds the per-file limit")
                if member.file_size >= 1024 * 1024 and member.file_size / max(member.compress_size, 1) > policy.max_zip_ratio:
                    raise UnsafeAttachment("ZIP_BOMB", "Archive compression ratio exceeds safety limit")
                remaining[0] -= member.file_size
                if remaining[0] < 0:
                    raise UnsafeAttachment("ARCHIVE_EXPANSION_LIMIT", "Archive decompressed size exceeds the budget")
                # Check misleading OOXML package contents: macros, embedded packages, remote links
                low = name.lower()
                if ext in OFFICE_ROOTS:
                    if low.endswith("vbaproject.bin") or "/embeddings/" in low or low.endswith("activex.xml"):
                        raise UnsafeAttachment("OFFICE_ACTIVE_CONTENT", "Office document contains macros or embedded objects")
                    if low.endswith(".rels"):
                        if member.file_size > 1024 * 1024:
                            raise UnsafeAttachment("OFFICE_RELATIONSHIP_LIMIT", "Office relationship metadata is too large")
                        with archive.open(member) as fh:
                            rels = fh.read(1024 * 1024 + 1)
                        if re.search(br'TargetMode\s*=\s*["\']External["\']', rels, re.I):
                            raise UnsafeAttachment("OFFICE_EXTERNAL_LINK", "Office document contains external linked content")
                    # OOXML internals aren't independent attachments, but could carry a disguised executable
                    if PurePosixPath(low).suffix in DANGEROUS_SUFFIXES:
                        raise UnsafeAttachment("OFFICE_ACTIVE_CONTENT", "Office document contains an executable member")
                else:
                    # For standalone ZIP, check all members, nested archives, and signatures.
                    if not path.name:
                        raise UnsafeAttachment("INVALID_FILENAME", "Archive has an unnamed entry")
                    if member.file_size == 0:
                        raise UnsafeAttachment("EMPTY_ARCHIVE_MEMBER", "Archive contains an empty file")
                    with archive.open(member) as fh:
                        contents = fh.read(policy.max_file_bytes + 1)
                    if len(contents) > policy.max_file_bytes:
                        raise UnsafeAttachment("ARCHIVE_MEMBER_SIZE", "Archive member exceeds size limit")
                    _inspect_content(path.name, contents, policy, depth=depth + 1, remaining=remaining)
    except UnsafeAttachment:
        raise
    except (zipfile.BadZipFile, RuntimeError, EOFError, OSError, ValueError) as exc:
        raise UnsafeAttachment("INVALID_ARCHIVE", "Archive is malformed, unsupported or cannot be fully read") from exc


def _inspect_content(name: str, data: bytes, policy: Policy, *, depth: int, remaining: list[int]) -> str:
    _, ext = _filename(name)
    if len(data) == 0:
        raise UnsafeAttachment("EMPTY_FILE", "Zero-byte attachments are not allowed")
    if len(data) > policy.max_file_bytes:
        raise UnsafeAttachment("FILE_TOO_LARGE", "Attachment exceeds maximum allowed file size")
    digest = sha256(data).hexdigest()
    if digest in policy.denied_hashes:
        raise UnsafeAttachment("HASH_DENYLIST", "Attachment hash is on the denylist")
    if ext in SIGNATURES:
        sig = SIGNATURES[ext]
        if not data.startswith(sig):
            raise UnsafeAttachment("TYPE_MISMATCH", f"{ext} extension does not match content signature")
        if ext == ".pdf":
            _pdf_check(data, policy)
        else:
            try:
                with Image.open(BytesIO(data)) as pic:
                    expected_format = {".png": "PNG", ".jpg": "JPEG", ".jpeg": "JPEG", ".gif": "GIF"}[ext]
                    if pic.format != expected_format:
                        raise UnsafeAttachment("TYPE_MISMATCH", "Image decoder format does not match the filename")
                    pic.verify()
            except UnsafeAttachment:
                raise
            except (OSError, ValueError, SyntaxError, UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
                raise UnsafeAttachment("INVALID_IMAGE", "Image could not be safely decoded or exceeds pixel limits") from exc
    elif ext in {".txt", ".csv", ".json"}:
        _text_check(data, ext)
    elif ext in OFFICE_ROOTS or ext == ".zip":
        if not zipfile.is_zipfile(BytesIO(data)):
            raise UnsafeAttachment("TYPE_MISMATCH", "ZIP/Office extension does not match file format")
        _zip_check(data, ext, policy, depth, remaining)
    return ext.removeprefix(".").upper()


def validate_attachment(filename: str, data: bytes, policy: Policy | None = None) -> dict[str, Any]:
    policy = policy or load_policy()
    issues: list[dict[str, str]] = []
    size = len(data)
    digest = sha256(data).hexdigest()
    detected = None
    antivirus = "NOT_RUN"
    try:
        detected = _inspect_content(filename, data, policy, depth=0, remaining=[policy.max_uncompressed_bytes, policy.max_zip_entries])
    except UnsafeAttachment as exc:
        issues.append(finding(exc.code, exc.reason))
    # Scan only supported and format-validated attachments. Policy reject is already final.
    if not issues:
        antivirus, detail = _clamav_scan(data, policy)
        if antivirus == "DETECTED":
            issues.append(finding("MALWARE_DETECTED", f"ClamAV detected a threat: {detail}"))
        if antivirus == "ERROR":
            issues.append(finding("ANTIVIRUS_UNAVAILABLE", "Mandatory malware scan failed or is unavailable"))
    return {
        "filename": filename,
        "status": "RESTRICTED" if issues else "SAFE",
        "detected_type": detected,
        "size_bytes": size,
        "sha256": digest,
        "antivirus": antivirus,
        "findings": issues,
    }


def validate_attachments(attachments: Iterable[tuple[str, bytes]], policy: Policy | None = None) -> dict[str, Any]:
    """Attachment verdict only: full OMG mail decision also needs text/URL policies."""
    policy = policy or load_policy()
    items = list(attachments)
    size = sum(len(data) for _, data in items)
    results: list[dict[str, Any]] = []
    envelope_issues: list[dict[str, str]] = []
    if len(items) > policy.max_files:
        envelope_issues.append(finding("TOO_MANY_ATTACHMENTS", "Attachment count exceeds policy limit"))
    if size > policy.max_total_bytes:
        envelope_issues.append(finding("TOTAL_SIZE_EXCEEDED", "Combined attachment size exceeds policy limit"))
    if not envelope_issues:
        results = [validate_attachment(name, contents, policy) for name, contents in items]
    restricted = bool(envelope_issues) or any(r["status"] == "RESTRICTED" for r in results)
    reasons = [*envelope_issues, *(f for result in results for f in result["findings"])]
    return {
        "scope": "ATTACHMENTS_ONLY",
        "status": "RESTRICTED" if restricted else "SAFE",
        "can_send": not restricted,  # attachment gate only; not a whole-email authorization
        "message": "Attachment validation passed (other email checks still required)." if not restricted
            else "Email sending blocked by attachment security policy.",
        "popup": {"title": "Email Restricted", "reasons": reasons} if restricted else None,
        "attachment_count": len(items),
        "total_bytes": size,
        "antivirus_required": policy.require_clamav,
        "warnings": [] if policy.require_clamav else ["Malware scanning is disabled; SAFE does not certify absence of malware."],
        "findings": envelope_issues,
        "attachments": results,
    }
