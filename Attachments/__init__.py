"""Independent attachment security and OCR engine."""
from .attachment_validator import scan_bytes, scan_uploads
__all__ = ["scan_bytes", "scan_uploads"]
