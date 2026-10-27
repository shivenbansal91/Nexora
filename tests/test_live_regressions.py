"""Regression checks for incremental detection, persistence, and correlation."""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.app import pipeline as module
from backend.app.db import Base
from backend.app.models import EventRow, IncidentRow
from correlation import reconstruct_incidents
from detection import Detector
from simulator.injectors import AttackInjector, ATTACK_TYPES


def test_normal_cadence_does_not_delay_attacks(monkeypatch):
    monkeypatch.setattr(module.settings, "normal_rate_per_tick", 1)
    monkeypatch.setattr(module.settings, "normal_event_interval_seconds", 3.0)
    clock = [100.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    live = module.LivePipeline()
    live._det = Detector()
    monkeypatch.setattr(live, "_persist", lambda *args: None)

    async def check():
        await live._tick()
        assert live.stats()["events"] == 1
        clock[0] += .6
        await live._tick()
        assert live.stats()["events"] == 1
        live._pending = [(clock[0], AttackInjector(seed=1).inject("data_exfiltration")[0].to_dict())]
        await live._tick()
        assert live.stats()["events"] == 2
        clock[0] = 103.0
        await live._tick()
        assert live.stats()["events"] == 3
    asyncio.run(check())


@pytest.mark.parametrize("attack_type", ATTACK_TYPES)
def test_incremental_attack_persists_earlier_flags_and_complete_evidence(tmp_path, monkeypatch, attack_type):
    engine = create_engine(f"sqlite:///{(tmp_path / 'test.db').as_posix()}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(module, "SessionLocal", sessions)
    monkeypatch.setattr(module.settings, "normal_rate_per_tick", 0)
    live = module.LivePipeline()
    live._det = Detector()
    raw = AttackInjector(seed=7).inject(attack_type, datetime.now(timezone.utc))

    async def check():
        for event in raw:
            live._pending = [(0, event.to_dict())]
            await live._tick()
        with sessions() as db:
            events = db.scalars(select(EventRow)).all()
            incidents = db.scalars(select(IncidentRow)).all()
            assert len(events) == len(raw)
            assert all(e.flagged for e in events)
            assert len(incidents) == 1
            assert incidents[0].attack_type == attack_type
            assert incidents[0].event_count >= 3
            if attack_type in ("port_scan", "api_abuse"):
                assert incidents[0].event_count == len(raw)
        assert live.stats()["events"] == len(raw)
        restored = module.LivePipeline()
        await restored.start()
        await restored.stop()
        assert restored.stats()["events"] == len(raw)
        assert restored.stats()["active_threats"] == 1

    try:
        asyncio.run(check())
    finally:
        engine.dispose()


def test_repeated_chains_for_same_account_are_not_lost():
    base = datetime.now(timezone.utc)
    injector = AttackInjector(seed=7)
    first = [e.to_dict() for e in injector.inject("data_exfiltration", base)]
    second = [e.to_dict() for e in injector.inject("data_exfiltration", base + timedelta(minutes=5))]
    # Same account/session, but two complete separate chains.
    for event in second:
        event["user"], event["session"] = first[0]["user"], first[0]["session"]
    Detector().annotate(first + second)
    assert len(reconstruct_incidents(first + second)) == 2


def test_expired_partial_chain_does_not_hide_later_complete_chain():
    base = datetime.now(timezone.utc)
    injector = AttackInjector(seed=9)
    stale = [e.to_dict() for e in injector.inject("data_exfiltration", base)][:1]
    fresh = [e.to_dict() for e in injector.inject("data_exfiltration", base + timedelta(minutes=6))]
    stale[0].update(user=fresh[0]["user"], session=fresh[0]["session"], flagged=True)
    Detector().annotate(fresh)
    incidents = reconstruct_incidents(stale + fresh)
    assert len(incidents) == 1
    assert stale[0]["id"] not in {e["id"] for e in incidents[0]["events"]}


def test_burst_does_not_flag_unrelated_older_calls_from_same_ip():
    base = datetime.now(timezone.utc)
    attack = [e.to_dict() for e in AttackInjector(seed=3).inject("api_abuse", base)]
    older = {**attack[0], "id": "older-normal-call", "timestamp": (base - timedelta(minutes=5)).isoformat(),
             "attack_label": "benign", "flagged": False}
    Detector().annotate([older] + attack)
    assert not older["flagged"]
    assert all(e["flagged"] for e in attack)


def test_failed_write_is_retried_without_losing_event_counts(monkeypatch):
    live = module.LivePipeline()
    live._det = Detector()
    monkeypatch.setattr(module.settings, "normal_rate_per_tick", 0)
    event = AttackInjector(seed=2).inject("data_exfiltration")[0].to_dict()
    live._pending = [(0, event)]
    writes = []

    def persist(events, incidents):
        writes.append([e["id"] for e in events])
        if len(writes) == 1:
            raise RuntimeError("temporary database failure")

    monkeypatch.setattr(live, "_persist", persist)

    async def check():
        with pytest.raises(RuntimeError):
            await live._tick()
        await live._tick()
        assert writes == [[event["id"]], [event["id"]]]
        assert live.stats()["events"] == 1
        assert not live._dirty_events

    asyncio.run(check())
