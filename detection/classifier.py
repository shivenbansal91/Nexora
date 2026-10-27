"""
Attack classifier — supervised model over the shared feature space.

Trained by train_baseline.py on labeled *simulated* data (benign + the four
injected attack types) to produce the per-class precision/recall/F1 the viva
needs. benchmark_cicids.py produces the equivalent numbers on real labeled
data (CICIDS2017 / UNSW-NB15) when the dataset is present in data/raw/.

In the live pipeline the rule layer in detector.py does the flagging (it is
more reliable for bursts); this classifier is loaded for the reported metric
and is available as a secondary label if needed.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import numpy as np

from .features import events_to_matrix

MODELS_DIR = Path(__file__).resolve().parent / "models"
CLF_PATH = MODELS_DIR / "classifier.joblib"

LABELS = ["benign", "brute_force", "port_scan", "data_exfiltration", "api_abuse"]


class AttackClassifier:
    def __init__(self, model=None):
        self._model = model

    @classmethod
    def load(cls) -> "AttackClassifier":
        model = None
        try:
            import joblib
            if CLF_PATH.exists():
                model = joblib.load(CLF_PATH)
        except Exception as exc:  # pragma: no cover
            print(f"[classifier] could not load model ({exc}).")
        return cls(model)

    @property
    def loaded(self) -> bool:
        return self._model is not None

    def predict(self, events: List[dict]) -> List[str]:
        if self._model is None or not events:
            return ["benign"] * len(events)
        X, order = events_to_matrix(events)
        preds = self._model.predict(X)
        out: List[Optional[str]] = [None] * len(events)
        for pos, orig_idx in enumerate(order):
            out[orig_idx] = str(preds[pos])
        return [p or "benign" for p in out]
