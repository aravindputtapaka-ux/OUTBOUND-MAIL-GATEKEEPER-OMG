"""Optional SUPERVISED file-risk model; trained on labeled real examples.

Not a malware signature detector. The rules + ClamAV remain primary controls.
Never deserialize artifacts from an untrusted source (joblib uses pickle).
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
from io import BytesIO
import json
import math
import os
from pathlib import Path
import zipfile

import joblib
import numpy as np

FEATURE_VERSION = 1
MAX_ML_BYTES = 20 * 1024 * 1024


def features(filename: str, data: bytes) -> dict[str, float]:
    """Fixed numeric features; do not execute or fully decompress content."""
    sample = data[:32768]
    size = max(len(sample), 1)
    counts = Counter(sample)
    entropy = -sum((c / size) * math.log2(c / size) for c in counts.values())
    lower = sample.lower()
    suffix = Path(filename).suffix.lower()
    result: dict[str, float] = {
        'log_size': math.log1p(len(data)),
        'entropy': entropy,
        'nul_ratio': sample.count(0) / size,
        'printable_ratio': sum(32 <= b <= 126 for b in sample) / size,
        'high_byte_ratio': sum(b >= 128 for b in sample) / size,
        'digit_ratio': sum(48 <= b <= 57 for b in sample) / size,
        'name_length': min(len(filename), 180),
        'filename_dots': min(filename.count('.'), 8),
        'pdf_magic': float(data.startswith(b'%PDF-')),
        'zip_magic': float(data.startswith(b'PK\x03\x04')),
        'mz_magic': float(data.startswith(b'MZ')),
        'ext_pdf': float(suffix == '.pdf'),
        'ext_office': float(suffix in ('.docx', '.xlsx', '.pptx')),
        'ext_image': float(suffix in ('.png', '.jpg', '.jpeg', '.gif')),
        'ext_archive': float(suffix == '.zip'),
        'ext_text': float(suffix in ('.txt', '.csv', '.json')),
        'pdf_javascript_marker': float(b'/javascript' in lower or b'/js' in lower),
        'pdf_openaction_marker': float(b'/openaction' in lower),
        'pdf_embedded_marker': float(b'/embeddedfile' in lower),
        'url_marker_count': min(lower.count(b'http://') + lower.count(b'https://'), 100),
        'zip_entry_count': 0.0,
        'zip_encrypted_entry_count': 0.0,
        'zip_max_ratio': 0.0,
    }
    if suffix in {'.zip', '.docx', '.xlsx', '.pptx'} and len(data) <= MAX_ML_BYTES:
        try:
            with zipfile.ZipFile(BytesIO(data)) as zf:
                entries = zf.infolist()[:500]
                result['zip_entry_count'] = float(len(entries))
                result['zip_encrypted_entry_count'] = float(sum(bool(i.flag_bits & 1) for i in entries))
                result['zip_max_ratio'] = float(min(max((i.file_size / max(i.compress_size, 1) for i in entries), default=0), 100000))
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
            pass
    return result


class MLDetector:
    def __init__(self, mode: str = 'off', artifact: str = 'models/file_risk.joblib', threshold: float = 0.90):
        if mode not in {'off', 'observe', 'enforce'}:
            raise ValueError('OMG_ML_MODE must be off, observe, or enforce')
        self.mode = mode
        self.threshold = threshold
        self.model = None
        self.metadata: dict = {}
        if mode == 'off':
            return
        metadata_path = Path(artifact).with_suffix('.json')
        try:
            # Administrative filesystem only. NEVER accept a model path from an API request.
            self.metadata = json.loads(metadata_path.read_text(encoding='utf-8'))
            if self.metadata.get('feature_version') != FEATURE_VERSION:
                raise ValueError('ML feature version mismatch')
            if mode == 'enforce' and not self.metadata.get('approved_for_enforcement'):
                raise ValueError('ML model has not received documented enforcement approval')
            if mode == 'enforce' and not 0 < threshold < 1:
                raise ValueError('ML threshold must be between zero and one')
            self.model = joblib.load(artifact)
        except (FileNotFoundError, OSError, ValueError, KeyError) as exc:
            if mode == 'enforce':
                raise RuntimeError('Mandatory ML model unavailable or unapproved') from exc
            self.metadata = {'notice': 'Model not configured: observe mode gives no scores'}

    def inspect(self, filename: str, data: bytes) -> dict:
        if self.mode == 'off':
            return {'mode': 'off', 'score': None, 'enforced': False}
        if self.model is None:
            return {'mode': self.mode, 'score': None, 'enforced': False,
                    'notice': 'Model missing; no ML classification performed'}
        try:
            # sklearn Pipeline must come from trained trusted local artifact.
            score = float(self.model.predict_proba([features(filename, data)])[0][1])
            return {'mode': self.mode, 'score': round(score, 4),
                    'enforced': self.mode == 'enforce', 'flagged': score >= self.threshold,
                    'model_version': self.metadata.get('model_version', 'unknown')}
        except Exception:
            # Fail closed if ML is part of mandatory policy.
            return {'mode': self.mode, 'score': None, 'enforced': self.mode == 'enforce',
                    'error': 'ML inference failed'}
