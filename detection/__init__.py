"""Nexora detection engine.

Two cooperating parts (plan §3 Detection Engine):
  - anomaly detection: IsolationForest over engineered features -> anomaly_score
  - attack classification: a trained classifier over the same features, plus a
    transparent rule layer that reliably flags the four scoped attacks for the
    live pipeline.

Public API:
    from detection import Detector
    det = Detector.load()            # loads trained models (falls back to rules)
    det.annotate(window_events)      # sets anomaly_score / flagged / attack_label in place
"""

from .detector import Detector  # noqa: F401
