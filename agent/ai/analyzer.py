"""Simple analyzer using sentence-transformers (all-MiniLM-L6-v2) embeddings
plus a lightweight heuristic fallback.

Behavior:
- If sentence-transformers is available, embed event summary and compute cosine
  similarity to a benign centroid. Lower similarity => more suspicious.
- Combine embedding-based score with a small keyword heuristic to produce a
  final 0-100 suspiciousness score and a 1-2 line advice message.

Utilities:
- train_baseline(input_csv, out_npy): compute centroid from many benign events
  (CSV should contain a column named 'text' with event summaries) and save a
  numpy .npy file which the analyzer will load.

This is intentionally simple so it can run on CPU and be used for prototyping.
"""
from __future__ import annotations

import json
import os
import joblib
import numpy as np
from typing import Dict, Any, List

BASE_DIR = os.path.dirname(__file__)
CENTROID_PATH = os.path.join(BASE_DIR, 'benign_centroid.npy')
data = joblib.load('agent/ai/lof_model.joblib')
pipeline = data['pipeline']
features = data['features']

# Lazy imports
_model = None
_np = None


def _load_numpy():
    global _np
    if _np is None:
        import numpy as np

        _np = np
    return _np


def _load_model():
    global _model
    if _model is not None:
        return _model
    try:
        from sentence_transformers import SentenceTransformer

        _model = SentenceTransformer('all-MiniLM-L6-v2')
        return _model
    except Exception:
        _model = None
        return None


def _event_to_text(event: Dict[str, Any]) -> str:
    parts: List[str] = []
    parts.append(f"event_id:{event.get('event_id')}")
    parts.append(f"time:{event.get('time')}")
    parts.append(f"source:{event.get('source')}")
    data = event.get('data') or {}
    if 'Image' in data:
        parts.append(f"image:{data.get('Image')}")
    if 'CommandLine' in data:
        parts.append(f"cmd:{data.get('CommandLine')}")
    # add a few other helpful fields if present
    for k in ('ParentImage', 'User', 'Hashes', 'DestinationIp', 'SourceIp'):
        if k in data:
            parts.append(f"{k}:{data.get(k)}")
    return '\n'.join(parts)

def event_to_feature_vector(event_dict):
    # Same feature extraction logic as extract_features.py but applied to single event
    v = []
    v.append(len(event_dict.get('CommandLine') or ''))
    v.append(1 if 'powershell' in (event_dict.get('CommandLine') or '').lower() else 0)
    v.append(1 if '\\temp\\' in (event_dict.get('Image') or '').lower() else 0)
    v.append(1 if event_dict.get('DestinationIp') else 0)
    # parent_bucket example (must match same bucketing code)
    import hashlib
    p = event_dict.get('ParentImage') or ''
    h = int(hashlib.md5(p.encode('utf-8')).hexdigest()[:8], 16) % 64
    v.append(float(h))
    # hour (if time available)
    # ... append hour ...
    X = np.array(v, dtype=float).reshape(1,-1)
    Xs = pipeline.named_steps['scaler'].transform(X)
    score = pipeline.named_steps['lof'].decision_function(Xs)[0]
    # convert to 0..100 as earlier
    suspicious = int(max(0, min(100, int(( -score) * 20 + 50))))
    return suspicious

def compute_embedding(text: str):
    """Return a normalized embedding vector (numpy) or None if model missing."""
    model = _load_model()
    if model is None:
        return None
    np = _load_numpy()
    emb = model.encode(text, normalize_embeddings=True)
    return np.array(emb, dtype=float)


def load_centroid(path: str = CENTROID_PATH):
    np = _load_numpy()
    try:
        if os.path.exists(path):
            return np.load(path)
    except Exception:
        return None
    return None


def save_centroid(centroid, path: str = CENTROID_PATH):
    np = _load_numpy()
    np.save(path, centroid)


def default_benign_texts() -> List[str]:
    # small set of benign process summaries to form a weak centroid if none provided
    return [
        'image:c:\\windows\\system32\\svchost.exe\ncmd:',
        'image:c:\\windows\\system32\\explorer.exe\ncmd:',
        'image:c:\\windows\\system32\\services.exe\ncmd:',
        'image:c:\\program files\\google\\chrome\\application\\chrome.exe\ncmd:',
    ]


def embedding_score_for_event(event: Dict[str, Any]) -> float:
    """Return a 0-1 embedding-based suspiciousness score (1 = most suspicious).

    Uses cosine similarity to benign centroid: sim in [-1,1]. We map sim->score as
    score = clamp((0.9 - sim) / 1.8, 0, 1) so that sim ~0.9 -> low score, sim low->higher.
    """
    np = _load_numpy()
    emb = compute_embedding(_event_to_text(event))
    if emb is None:
        return 0.0
    centroid = load_centroid()
    if centroid is None:
        # build weak centroid from defaults
        model = _load_model()
        texts = default_benign_texts()
        vecs = model.encode(texts, normalize_embeddings=True)
        centroid = np.mean(vecs, axis=0)
    # cosine similarity (emb normalized)
    # if centroid not normalized, normalize it
    from numpy.linalg import norm

    if norm(centroid) > 0:
        centroid = centroid / norm(centroid)
    sim = float(np.dot(emb, centroid))  # in [-1,1]
    # map similarity to suspiciousness (heuristic mapping)
    # high sim -> low suspicion, low sim -> high suspicion
    score = (0.9 - sim) / 1.8
    if score < 0:
        score = 0.0
    if score > 1:
        score = 1.0
    return score


def heuristic_score(event: Dict[str, Any]) -> float:
    """Lightweight keyword heuristic returning 0-1 score."""
    data = event.get('data') or {}
    image = (data.get('Image') or '').lower()
    cmd = (data.get('CommandLine') or '').lower()
    score = 0.0
    suspicious_terms = ['powershell', '-enc', 'invoke-', 'base64', 'iex', 'download', 'request.get']
    for t in suspicious_terms:
        if t in image or t in cmd:
            score += 0.3
    # network endpoints
    if data.get('DestinationIp') and data.get('DestinationIp') not in ('127.0.0.1', '::1'):
        score += 0.2
    # execution from temp
    if '\\temp\\' in image or '\\appdata\\local\\temp\\' in image:
        score += 0.2
    return min(1.0, score)


def analyze_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Return {'score':int, 'advice':str, 'meta':{...}}.

    Combines embedding-based score and heuristic.
    """
    emb_score = embedding_score_for_event(event)
    heur = heuristic_score(event)
    lof_score = event_to_feature_vector(event)
    # combine: weight embedding more
    combined = 0.6 * emb_score + 0.2 * heur + 0.2 * (lof_score / 100)
    # map to 0-100
    final = int(max(0, min(100, round(combined * 100))))

    advice = ''
    if final >= 75:
        advice = 'High suspicion — investigate and consider quarantining the file.'
    elif final >= 40:
        advice = 'Moderate suspicion — review process and command-line carefully.'
    else:
        advice = 'Low suspicion — monitor for further activity.'

    return {'score': final, 'advice': advice, 'meta': {'emb_score': emb_score, 'heuristic': heur}}


def train_baseline(input_csv: str, out_npy: str = CENTROID_PATH):
    """Train a benign centroid from CSV with a 'text' column. Saves numpy .npy centroid."""
    import pandas as pd

    model = _load_model()
    if model is None:
        raise RuntimeError('sentence-transformers not installed')
    df = pd.read_csv(input_csv)
    if 'text' not in df.columns:
        raise RuntimeError("input CSV must have a 'text' column containing event summaries")
    texts = df['text'].fillna('').astype(str).tolist()
    vecs = model.encode(texts, normalize_embeddings=True)
    np = _load_numpy()
    centroid = np.mean(vecs, axis=0)
    save_centroid(centroid, out_npy)
    print('Saved centroid to', out_npy)


if __name__ == '__main__':
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument('--input', help='CSV with text column', required=True)
    p.add_argument('--out', help='path to save centroid .npy', default=CENTROID_PATH)
    args = p.parse_args()
    train_baseline(args.input, args.out)
