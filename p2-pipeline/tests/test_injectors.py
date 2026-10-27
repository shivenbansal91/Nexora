"""Attack injectors must emit schema-valid, correctly-labelled sequences."""

import json
from pathlib import Path

import jsonschema
import pytest

from simulator.injectors import AttackInjector, ATTACK_TYPES

SCHEMA_PATH = Path(__file__).parent.parent / "schema" / "event_schema.json"


@pytest.fixture(scope="module")
def schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


@pytest.mark.parametrize("attack_type", ATTACK_TYPES)
def test_injector_output_matches_schema(schema, attack_type):
    inj = AttackInjector(seed=1)
    events = inj.inject(attack_type)
    assert len(events) >= 3
    for ev in events:
        payload = json.loads(ev.to_json())
        jsonschema.validate(instance=payload, schema=schema)
        assert payload["attack_label"] == attack_type


def test_brute_force_has_compromise_chain():
    evs = AttackInjector(seed=2).brute_force(__import__("datetime").datetime(2026, 1, 1))
    types = [e.event_type for e in evs]
    assert types.count("auth_login_failure") >= 5
    assert "auth_login_success" in types
    assert "db_query" in types
    assert any(e.event_type == "file_access" and e.metadata["action"] == "download" for e in evs)
    # one shared user + ip across the chain
    assert len({e.user for e in evs}) == 1
    assert len({e.ip for e in evs}) == 1


def test_port_scan_is_connection_burst():
    evs = AttackInjector(seed=3).port_scan(__import__("datetime").datetime(2026, 1, 1))
    assert all(e.event_type == "connection_attempt" for e in evs)
    assert len(evs) >= 15
    assert len({e.ip for e in evs}) == 1


def test_unknown_attack_raises():
    with pytest.raises(ValueError):
        AttackInjector().inject("sql_injection")
