from copy import deepcopy

import numpy as np

from detection import Detector
from detection.features import events_to_matrix, FEATURE_NAMES
from detection.train_baseline import build_dataset
from correlation import reconstruct_incidents
from simulator.injectors import AttackInjector


def test_rotating_ips_and_sessions_targeting_one_account():
    events = [e.to_dict() for e in AttackInjector(seed=7).inject('brute_force')]
    for index, event in enumerate(events):
        if event['event_type'] == 'auth_login_failure':
            event.update(ip=f'192.0.2.{index+1}',session=f'login-{index}')
    Detector().annotate(events)
    assert all(e['flagged'] for e in events)
    incidents = reconstruct_incidents(events)
    assert len(incidents) == 1
    assert len(incidents[0]['entities']['ips']) > 1
    assert incidents[0]['attack_pattern'] == 'Credential Brute Force'
    failures = [e for e in events if e['event_type'] == 'auth_login_failure']
    attempts = reconstruct_incidents(failures)
    assert len(attempts) == 1 and attempts[0]['attack_pattern'] == 'Account login attack'
    assert 'Compromise is not established' in attempts[0]['description']


def test_different_accounts_do_not_get_merged_into_one_attack():
    events = [e.to_dict() for e in AttackInjector(seed=7).inject('brute_force')][:5]
    for i,e in enumerate(events):
        e['user'] = f'user-{i}'
    Detector().annotate(events)
    assert not any(e['flagged'] for e in events)
    assert not reconstruct_incidents(events)


def test_severity_time_and_ground_truth_do_not_change_features():
    events = [e.to_dict() for e in AttackInjector(seed=7).inject('port_scan')]
    changed = deepcopy(events)
    for e in changed:
        e.update(severity=0,attack_label='benign')
    assert 'severity' not in FEATURE_NAMES and 'hour_norm' not in FEATURE_NAMES
    np.testing.assert_equal(events_to_matrix(events)[0],events_to_matrix(changed)[0])
    assert len(FEATURE_NAMES) == events_to_matrix(events)[0].shape[1]
    assert events_to_matrix(events)[0][-1,FEATURE_NAMES.index('distinct_destinations_ip_60s')] > 0


def test_generated_partition_is_reproducible():
    a,ay = build_dataset(8,3,seed=42)
    b,by = build_dataset(8,3,seed=42)
    np.testing.assert_equal(a,b)
    np.testing.assert_equal(ay,by)
