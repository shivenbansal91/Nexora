"""Negative cases found during the November ML and UI audit."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import joblib
import numpy as np
import pytest

from correlation import reconstruct_incidents
from detection import Detector
from detection import detector as module
from detection.features import FEATURE_NAMES
from simulator.injectors import AttackInjector


def test_simulated_anomaly_fpr_is_measured_separately_from_classifier():
    from detection.train_baseline import _anomaly_detection_metrics
    model = SimpleNamespace(score_samples=lambda X: np.array([-.9, -.1, -.8]))
    result = _anomaly_detection_metrics(model, {'p1': 0, 'p99': 1}, np.zeros((3,1)), np.array(['benign','benign','api_abuse']))
    assert result['false_positive_rate_benign'] == .5


def test_infrastructure_does_not_invent_services():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from backend.app.db import Base
    from backend.app.models import EventRow
    from backend.app.routers.events import list_entities
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            assert list_entities(db)['services'] == []
            db.add(EventRow(id='api', event_type='api_call', timestamp='2026-11-02T10:00:00Z', user='alice', ip='192.0.2.1', session='session'))
            db.commit()
            assert list_entities(db)['services'] == ['API']
    finally:
        engine.dispose()


def attack(kind):
    return [e.to_dict() for e in AttackInjector(seed=80).inject(kind, datetime(2026, 11, 2, 10, tzinfo=timezone.utc))]


def test_rules_preserve_model_score_and_ignore_generator_answer():
    events = attack('api_abuse')
    detector = Detector()
    detector._anomaly_scores = lambda events: np.full(len(events), .12)
    detector.annotate(events)
    assert all(e['flagged'] and e['anomaly_score'] == .12 for e in events)
    first = attack('data_exfiltration')[0]
    detector.annotate([first])
    assert not first['flagged'] and first['attack_label'] == 'benign'


@pytest.mark.parametrize('session', ['', None, 'unknown'])
def test_missing_session_never_links_other_accounts(session):
    events = attack('data_exfiltration')
    for e in events:
        e['session'] = session
    unrelated = {**events[0], 'id': 'unrelated', 'user': 'other-user'}
    Detector().annotate(events + [unrelated])
    assert not unrelated['flagged']
    assert events[-1]['flagged']


def test_repeated_single_destination_is_not_a_scan_even_if_preflagged():
    events = attack('port_scan')
    for e in events:
        e['metadata']['dest_port'] = 443
    Detector().annotate(events)
    assert not any(e['flagged'] for e in events)
    for e in events:
        e['flagged'] = True
    assert reconstruct_incidents(events) == []


def test_bulk_download_does_not_link_future_or_other_account_actions():
    events = attack('data_exfiltration')
    other = {**events[0], 'id': 'other-account', 'user': 'other-user'}
    future = {**events[0], 'id': 'future', 'timestamp': (datetime(2026,11,2,10,tzinfo=timezone.utc) + timedelta(hours=1)).isoformat()}
    Detector().annotate(events + [other, future])
    assert not other['flagged'] and not future['flagged']
    assert len(reconstruct_incidents(events)) == 1


def test_small_database_read_is_not_a_bulk_exfiltration_chain():
    events = attack('data_exfiltration')
    events[1]['metadata']['rows'] = 3
    Detector().annotate(events)
    for e in events:
        e['flagged'] = True
    assert reconstruct_incidents(events) == []


def test_old_session_activity_does_not_become_brute_force_evidence():
    events = attack('brute_force')
    old = {**events[0], 'id': 'old-login', 'timestamp': '2026-11-02T09:00:00Z'}
    Detector().annotate([old] + events)
    assert not old['flagged']
    assert len(reconstruct_incidents(events)) == 1


def test_model_load_rejects_missing_normalization(tmp_path, monkeypatch):
    model = tmp_path / 'model.joblib'
    joblib.dump(SimpleNamespace(n_features_in_=len(FEATURE_NAMES)), model)
    monkeypatch.setattr(module, 'ISO_PATH', model)
    monkeypatch.setattr(module, 'NORM_PATH', tmp_path / 'missing.json')
    assert not Detector.load().ml_loaded
