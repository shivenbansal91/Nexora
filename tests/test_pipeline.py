"""End-to-end pipeline tests: detection + correlation over simulator output,
plus the cross-module schema/label consistency that the whole project hinges on.
Run from repo root:  python -m pytest tests/ -v
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from simulator.generator import NormalTrafficGenerator, iso
from simulator.injectors import AttackInjector, ATTACK_TYPES
from detection import Detector
from correlation import reconstruct_incidents

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "p2-pipeline" / "schema" / "event_schema.json").read_text())


def _spread(events, base, step=1.5):
    t = base
    for e in events:
        e.timestamp = iso(t)
        t += timedelta(seconds=step)
    return events


def _window_for(attack_type):
    gen = NormalTrafficGenerator(seed=7)
    inj = AttackInjector(seed=7)
    base = datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
    normal = _spread(list(gen.stream(25)), base)
    attack = inj.inject(attack_type, start_time=base + timedelta(seconds=20))
    window = [e.to_dict() for e in normal] + [e.to_dict() for e in attack]
    Detector.load().annotate(window)
    return window


def test_normal_traffic_zero_incidents():
    gen = NormalTrafficGenerator(seed=11)
    base = datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
    normal = [e.to_dict() for e in _spread(list(gen.stream_sessions(40)), base)]
    Detector.load().annotate(normal)
    assert reconstruct_incidents(normal) == []


@pytest.mark.parametrize("attack_type", ATTACK_TYPES)
def test_each_attack_reconstructs_to_one_incident(attack_type):
    window = _window_for(attack_type)
    incidents = reconstruct_incidents(window)
    matching = [i for i in incidents if i["attack_type"] == attack_type]
    assert len(matching) == 1, f"{attack_type}: got {[i['attack_type'] for i in incidents]}"
    inc = matching[0]
    assert inc["events"], "incident must carry its evidence chain"
    assert inc["severity"] in ("low", "medium", "high", "critical")
    assert 0.0 <= inc["confidence"] <= 1.0
    assert inc["recommended_action"]


def test_schema_and_labels_stay_in_sync():
    """The canonical schema, the injector labels, and the correlation templates
    must agree on the attack-type vocabulary — the #1 integration-bug source."""
    schema_labels = set(SCHEMA["properties"]["attack_label"]["enum"]) - {None, "benign"}
    assert set(ATTACK_TYPES) == schema_labels

    from correlation import ALL_TEMPLATES
    template_types = {t.attack_type for t in ALL_TEMPLATES}
    assert template_types == set(ATTACK_TYPES)


def test_backend_schema_mirrors_canonical():
    """Backend Pydantic EventOut must expose the canonical required fields."""
    import sys
    sys.path.insert(0, str(ROOT / "backend"))
    from app.schemas import EventOut
    required = {"id", "event_type", "timestamp", "user", "ip", "session", "severity"}
    assert required <= set(EventOut.model_fields.keys())
