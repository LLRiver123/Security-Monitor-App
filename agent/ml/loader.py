"""Flexible ML loader for embeddings + detector.

Search order:
- top-level `ml/iso_forest.joblib` and optional `ml/embed_model/`
- fallback to `sentence-transformers/all-MiniLM-L6-v2` if installed

Provides: load_detector(), train_detector(events), score_event(event)
"""
import os
import logging

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TOP_ML_DIR = os.path.join(ROOT, "ml")
LOCAL_DETECTOR = os.path.join(TOP_ML_DIR, "iso_forest.joblib")
LOCAL_EMBED = os.path.join(TOP_ML_DIR, "embed_model")

logger = logging.getLogger(__name__)

try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
    from sklearn.ensemble import IsolationForest
    import joblib
except Exception:
    SentenceTransformer = None
    np = None
    IsolationForest = None
    joblib = None


def _load_local_detector():
    if joblib is None:
        return None
    if os.path.exists(LOCAL_DETECTOR):
        try:
            return joblib.load(LOCAL_DETECTOR)
        except Exception:
            logger.exception("Failed to load local detector")
    return None


def _load_local_embed():
    if SentenceTransformer is None:
        return None
    if os.path.exists(LOCAL_EMBED):
        try:
            return SentenceTransformer(LOCAL_EMBED, device="cpu")
        except Exception:
            logger.exception("Failed to load local embed model")
    return None


_DET = None
_EMBED = None


def load_detector():
    global _DET, _EMBED
    if _DET is not None:
        return _DET

    # 1) try local detector
    _DET = _load_local_detector()
    if _DET is not None:
        _EMBED = _load_local_embed()
        return _DET

    # 2) fallback to sentence-transformers hosted model
    if SentenceTransformer is None or IsolationForest is None:
        logger.info("ML dependencies not available; ML disabled")
        return None

    try:
        _EMBED = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")
    except Exception:
        logger.exception("Failed to load fallback embed model")
        _EMBED = None

    # Try to load detector from local path anyway
    if os.path.exists(LOCAL_DETECTOR) and joblib is not None:
        try:
            _DET = joblib.load(LOCAL_DETECTOR)
            return _DET
        except Exception:
            logger.exception("Failed to load local detector after embed fallback")

    # No detector available yet
    return None


def train_detector(events, n_estimators=100, contamination=0.01):
    """Train and save an IsolationForest under top-level ml/ directory."""
    if SentenceTransformer is None or IsolationForest is None or joblib is None or np is None:
        raise RuntimeError("ML dependencies missing; install sentence-transformers, scikit-learn, joblib, numpy")

    # prepare embeddings
    embed = _load_local_embed() or SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")
    X = []
    for e in events:
        data = e.get("data", {})
        parts = [data.get("Image", ""), data.get("ParentImage", ""), data.get("CommandLine", ""), str(e.get("event_id", ""))]
        text = " ||| ".join([p for p in parts if p])
        v = embed.encode(text, convert_to_numpy=True, normalize_embeddings=True)
        X.append(v)
    X = np.vstack(X)
    clf = IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=42)
    clf.fit(X)
    os.makedirs(TOP_ML_DIR, exist_ok=True)
    joblib.dump(clf, LOCAL_DETECTOR)
    # reload into memory
    global _DET, _EMBED
    _DET = clf
    _EMBED = embed
    return clf


def score_event(ev, clf=None):
    """Return (is_anomaly, score) or (None, None) if ML not available."""
    det = clf or load_detector()
    if det is None or _EMBED is None:
        return None, None
    try:
        data = ev.get("data", {})
        parts = [data.get("Image", ""), data.get("ParentImage", ""), data.get("CommandLine", ""), str(ev.get("event_id", ""))]
        text = " ||| ".join([p for p in parts if p])
        emb = _EMBED.encode(text, convert_to_numpy=True, normalize_embeddings=True)
        x = emb.reshape(1, -1)
        score = float(det.decision_function(x)[0])
        pred = int(det.predict(x)[0])
        return (pred == -1), score
    except Exception:
        logger.exception("Failed to score event")
        return None, None
