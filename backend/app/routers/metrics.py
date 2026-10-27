"""Evaluation metrics endpoint — the numbers shown to the panel (plan §10)."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter

from ..config import settings
from ..pipeline import pipeline

from simulator.generator import NormalTrafficGenerator, iso
from simulator.injectors import AttackInjector, ATTACK_TYPES
from detection import Detector
from correlation import reconstruct_incidents

router = APIRouter(tags=["metrics"])

_corr_cache: dict | None = None


def _correlation_selfcheck() -> dict:
    """Reproducible correlation accuracy: inject each scoped attack into benign
    traffic and check it is reconstructed into one correctly-typed incident."""
    global _corr_cache
    if _corr_cache is not None:
        return _corr_cache

    gen = NormalTrafficGenerator(seed=99)
    inj = AttackInjector(seed=99)
    det = Detector.load()
    base = datetime(2026, 5, 1, tzinfo=timezone.utc)
    correct = 0
    per_type = {}
    for k, atk in enumerate(ATTACK_TYPES):
        win_base = base + timedelta(minutes=10 * k)
        normal = list(gen.stream(25))
        for i, e in enumerate(normal):
            e.timestamp = iso(win_base + timedelta(seconds=i * 0.4))
        attack = inj.inject(atk, start_time=win_base + timedelta(seconds=15))
        window = [e.to_dict() for e in normal] + [e.to_dict() for e in attack]
        det.annotate(window)
        incs = reconstruct_incidents(window)
        hit = len(incs) == 1 and incs[0]["attack_type"] == atk
        per_type[atk] = hit
        correct += int(hit)

    _corr_cache = {
        "attacks_tested": len(ATTACK_TYPES),
        "correctly_reconstructed": correct,
        "accuracy": round(correct / len(ATTACK_TYPES), 4),
        "per_type": per_type,
    }
    return _corr_cache


@router.get("/metrics")
def metrics():
    model_metrics = {}
    p = Path(settings.metrics_path)
    if p.exists():
        try:
            model_metrics = json.loads(p.read_text())
        except Exception:
            model_metrics = {}

    real_path = p.with_name("metrics_real.json")
    if real_path.exists():
        try:
            real = json.loads(real_path.read_text())
            model_metrics = {**real, **real["classifier"]}
        except (OSError, ValueError, KeyError):
            model_metrics = {"source": "unavailable", "note": "Real benchmark file is unreadable. Re-run detection.benchmark_cicids."}

    return {
        "detection": model_metrics,
        "correlation": _correlation_selfcheck(),
        "runtime": {
            "ml_models_loaded": pipeline.ml_loaded,
            "max_detection_latency_seconds": pipeline.max_latency_seconds,
            **pipeline.stats(),
        },
    }


@router.get("/health")
def health():
    from fastapi.responses import JSONResponse
    healthy = pipeline._running and pipeline.last_error is None
    return JSONResponse({"status": "ok" if healthy else "degraded", "ml_models_loaded": pipeline.ml_loaded,
                         "event_source": "simulator"}, status_code=200 if healthy else 503)
