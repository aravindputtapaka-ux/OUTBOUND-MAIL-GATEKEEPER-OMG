"""Optional supervised NLP classifier for extracted attachment text.

Uses a locally trained / internally approved scikit-learn multi-label model.
No paid API or remote inference. Never load untrusted joblib artifacts.
Nothing in this module is automatically approved for production blocking.
"""
from __future__ import annotations

from pathlib import Path
import json
import os

import joblib

LABELS = ('abuse', 'threat', 'hate', 'sexual_content', 'fraud', 'phishing', 'spam')


class TextContentML:
    def __init__(self, mode: str = 'off', artifact: str = 'models/content_policy.joblib',
                 threshold: float = 0.95):
        if mode not in {'off', 'observe', 'enforce'}:
            raise ValueError('OMG_CONTENT_ML_MODE must be off, observe or enforce')
        if not 0 < threshold < 1:
            raise ValueError('OMG_CONTENT_ML_THRESHOLD must be between 0 and 1')
        self.mode = mode
        self.threshold = threshold
        self.model = None
        self.meta: dict = {}
        if mode == 'off':
            return
        try:
            path = Path(artifact)
            self.meta = json.loads(path.with_suffix('.json').read_text(encoding='utf-8'))
            if tuple(self.meta.get('labels', ())) != LABELS:
                raise ValueError('Model labels do not match expected policy labels')
            if mode == 'enforce' and not self.meta.get('approved_for_enforcement', False):
                raise ValueError('Model has not passed independent production approval')
            self.model = joblib.load(path)
        except Exception as exc:
            if mode == 'enforce':
                raise RuntimeError('Mandatory text-content ML model unavailable or not approved') from exc
            self.meta = {'notice': 'Text ML unavailable; observe mode runs rules only'}

    @classmethod
    def from_env(cls) -> 'TextContentML':
        return cls(mode=os.getenv('OMG_CONTENT_ML_MODE', 'off').lower(),
                   artifact=os.getenv('OMG_CONTENT_ML_MODEL_PATH', 'models/content_policy.joblib'),
                   threshold=float(os.getenv('OMG_CONTENT_ML_THRESHOLD', '0.95')))

    def inspect(self, text: str) -> dict:
        if self.mode == 'off':
            return {'findings': [], 'warnings': [], 'scores': {}}
        if not text.strip():
            return {'findings': [], 'warnings': ['No readable text extracted for NLP classification'], 'scores': {}}
        if self.model is None:
            return {'findings': [], 'warnings': ['Text NLP classifier not configured'], 'scores': {}}
        try:
            # Multi-label OneVsRest classifier, internally evaluated and approved separately.
            probabilities = self.model.predict_proba([text[:250_000]])[0]
            scores = {label: round(float(probabilities[i]), 4) for i, label in enumerate(LABELS)}
            findings = [
                {'code': f'ML_{label.upper()}', 'reason': f'Approved text classifier flagged {label} content'}
                for label, score in scores.items() if score >= self.threshold
            ] if self.mode == 'enforce' else []
            return {'findings': findings, 'warnings': [], 'scores': scores}
        except Exception:
            if self.mode == 'enforce':
                return {'findings': [{'code': 'CONTENT_ML_UNAVAILABLE',
                                      'reason': 'Mandatory content classification could not complete'}],
                        'warnings': [], 'scores': {}}
            return {'findings': [], 'warnings': ['Text ML inference failed in observe mode'], 'scores': {}}
