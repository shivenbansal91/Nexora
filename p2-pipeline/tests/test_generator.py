"""
Sanity tests: generator output must always match the team's schema contract.
Run with: pytest p2-pipeline/tests/test_generator.py -v
"""

import json
from pathlib import Path

import jsonschema
import pytest

from simulator.generator import NormalTrafficGenerator

SCHEMA_PATH = Path(__file__).parent.parent / "schema" / "event_schema.json"

ALL_NORMAL_EVENT_TYPES = [
    "auth_login_success",
    "auth_login_failure",
    "auth_logout",
    "api_call",
    "db_query",
    "file_access",
]


@pytest.fixture(scope="module")
def schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


# --- Week 1 tests (unchanged, still must pass) -----------------------------

def test_generated_events_match_schema(schema):
    gen = NormalTrafficGenerator(seed=1)
    events = list(gen.stream(50))
    assert len(events) == 50

    for event in events:
        payload = json.loads(event.to_json())
        jsonschema.validate(instance=payload, schema=schema)


def test_severity_in_range():
    gen = NormalTrafficGenerator(seed=2)
    for event in gen.stream(20):
        assert 0.0 <= event.severity <= 1.0


def test_timestamp_is_iso_utc():
    gen = NormalTrafficGenerator(seed=3)
    for event in gen.stream(5):
        assert event.timestamp.endswith("Z")


# --- Week 2 tests: new event types ------------------------------------------

def test_all_normal_event_types_match_schema(schema):
    """
    Deterministically build one event of each new type and validate it,
    rather than relying on random sampling to happen to hit every type
    (auth_login_failure is only ~3% of flat stream() output, so a small
    random sample could miss it and give a false pass).
    """
    gen = NormalTrafficGenerator(seed=7)
    for event_type in ALL_NORMAL_EVENT_TYPES:
        event = gen._make_event(event_type, "alice", "10.0.1.5", "sess123")
        payload = json.loads(event.to_json())
        jsonschema.validate(instance=payload, schema=schema)


def test_db_query_metadata_shape():
    gen = NormalTrafficGenerator(seed=8)
    event = gen._make_event("db_query", "alice", "10.0.1.5", "sess123")
    assert "table" in event.metadata
    assert "query" in event.metadata


def test_file_access_metadata_shape():
    gen = NormalTrafficGenerator(seed=8)
    event = gen._make_event("file_access", "alice", "10.0.1.5", "sess123")
    assert "path" in event.metadata
    assert "action" in event.metadata


# --- Week 2 tests: session continuity ---------------------------------------

def test_stream_sessions_share_one_session_id():
    gen = NormalTrafficGenerator(seed=5)
    events = list(gen.stream_sessions(1))
    assert len(events) >= 2  # at least a login + one action

    session_ids = {e.session for e in events}
    assert len(session_ids) == 1, "all events in one session must share a session id"


def test_stream_sessions_starts_with_auth_event():
    gen = NormalTrafficGenerator(seed=5)
    events = list(gen.stream_sessions(1))
    assert events[0].event_type in ("auth_login_success", "auth_login_failure")


def test_stream_sessions_match_schema(schema):
    gen = NormalTrafficGenerator(seed=9)
    events = list(gen.stream_sessions(10))
    assert len(events) > 10  # 10 sessions, each with >= 1 event beyond login

    for event in events:
        payload = json.loads(event.to_json())
        jsonschema.validate(instance=payload, schema=schema)