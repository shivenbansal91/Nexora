"""
Live pipeline: the running heart of the backend.

Every tick it (1) emits a little benign traffic plus any due events from an
injected attack, (2) runs the detection engine over a rolling window to score
and flag them, (3) runs the correlation engine to reconstruct incidents, then
(4) persists new events/incidents and broadcasts them over WebSocket.

    simulator ──▶ rolling window ──▶ detector.annotate ──▶ correlation ──▶ store + broadcast
                        ▲
            POST /simulate/attack/{type}
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Deque, List, Optional, Tuple

from . import bootstrap  # noqa: F401  (sets sys.path for the imports below)
from .config import settings
from .db import SessionLocal
from .models import EventRow, IncidentRow
from sqlalchemy import select, func
from .ws import manager

from simulator.generator import NormalTrafficGenerator, iso
from simulator.injectors import AttackInjector, ATTACK_TYPES
from detection import Detector
from correlation import reconstruct_incidents

class LivePipeline:
    def __init__(self) -> None:
        self._gen = NormalTrafficGenerator(seed=None)
        self._inj = AttackInjector(seed=None)
        self._det = Detector.load()
        self._window: Deque[dict] = deque()
        self._pending: List[Tuple[float, dict]] = []  # (emit_at_monotonic, event)
        self._seen_incidents: set[str] = set()
        self._flagged_ids: set[str] = set()
        self._total_events = 0
        self.max_latency_seconds = 0.0
        self.last_error: str | None = None
        self._dirty_events: dict[str, dict] = {}
        self._new_event_ids: set[str] = set()
        self._incident_sizes: dict[str, int] = {}
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._next_normal_at = 0.0

    # ── lifecycle ──────────────────────────────────────────────────────────
    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._window.clear()
        with SessionLocal() as session:
            self._total_events = session.scalar(select(func.count()).select_from(EventRow)) or 0
            self._flagged_ids = set(session.scalars(select(EventRow.id).where(EventRow.flagged.is_(True))))
            stored = session.execute(select(IncidentRow.id, IncidentRow.event_count)).all()
            self._incident_sizes = dict(stored)
            self._seen_incidents = set(self._incident_sizes)
            rows = session.scalars(select(EventRow).order_by(EventRow.timestamp.desc()).limit(settings.max_window_events)).all()
            self._window.extend(r.to_event_dict() for r in reversed(rows))
        self._warmup()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def _warmup(self) -> None:
        """Pre-fill the window with a little recent benign history so the live
        stream and graph aren't empty on first load."""
        if self._window:
            return
        now = datetime.now(timezone.utc)
        hist = list(self._gen.stream(60))
        for i, ev in enumerate(hist):
            d = ev.to_dict()
            d["timestamp"] = iso(now - timedelta(seconds=(len(hist) - i) * 0.5))
            self._window.append(d)
        self._det.annotate(list(self._window))
        self._persist(list(self._window), [])
        self._total_events += len(self._window)

    # ── stats ────────────────────────────────────────────────────────────────
    @property
    def ml_loaded(self) -> bool:
        return self._det.ml_loaded

    def stats(self) -> dict:
        return {
            "events": self._total_events,
            "anomalies": len(self._flagged_ids),
            "active_threats": len(self._seen_incidents),
            "ws_clients": manager.count,
            "window_size": len(self._window),
        }

    # ── attack injection ──────────────────────────────────────────────────────
    def inject_attack(self, attack_type: str) -> int:
        if attack_type not in ATTACK_TYPES:
            raise ValueError(f"Unknown attack type {attack_type!r}; valid: {ATTACK_TYPES}")
        now = datetime.now(timezone.utc)
        raw = self._inj.inject(attack_type, start_time=now)
        n = len(raw)
        spread = settings.attack_spread_seconds
        base_mono = time.monotonic()
        for i, ev in enumerate(raw):
            frac = i / max(1, n - 1)
            # compress logical timestamps + real emit times into ~spread seconds
            ev.timestamp = iso(now + timedelta(seconds=frac * spread))
            self._pending.append((base_mono + frac * spread, ev.to_dict()))
        self._pending.sort(key=lambda p: p[0])
        return n

    # ── main loop ──────────────────────────────────────────────────────────────
    async def _run(self) -> None:
        while self._running:
            try:
                await self._tick()
            except Exception as exc:  # keep the loop alive
                self.last_error = str(exc)
                print(f"[pipeline] tick error: {exc}")
            await asyncio.sleep(settings.tick_seconds)

    async def _tick(self) -> None:
        started = time.monotonic()
        now = datetime.now(timezone.utc)
        new_events: List[dict] = []

        # 1. due attack events
        mono = time.monotonic()
        still_pending = []
        for emit_at, ev in self._pending:
            if emit_at <= mono:
                new_events.append(ev)
            else:
                still_pending.append((emit_at, ev))
        self._pending = still_pending

        # 2. a little benign traffic
        normal_count = settings.normal_rate_per_tick if mono >= self._next_normal_at else 0
        if normal_count:
            self._next_normal_at = mono + settings.normal_event_interval_seconds
        for _ in range(normal_count):
            ev = next(iter(self._gen.stream(1)))
            d = ev.to_dict()
            d["timestamp"] = iso(now)
            new_events.append(d)

        if not new_events and not self._dirty_events:
            return

        for d in new_events:
            self._window.append(d)
        self._dirty_events.update({d["id"]: d for d in new_events})
        self._new_event_ids.update(d["id"] for d in new_events)
        self._trim_window(now)

        window_list = list(self._window)
        old_flags = {d["id"]: (d.get("flagged"), d.get("attack_label")) for d in window_list}
        await asyncio.to_thread(self._det.annotate, window_list)
        for d in window_list:
            if d.get("flagged"):
                self._flagged_ids.add(d["id"])

        incidents = await asyncio.to_thread(reconstruct_incidents, window_list)
        new_incidents = [i for i in incidents if self._incident_sizes.get(i["id"]) != len(i["events"])]

        changed = [d for d in window_list if old_flags[d["id"]] != (d.get("flagged"), d.get("attack_label"))]
        self._dirty_events.update({d["id"]: d for d in changed})
        updates = dict(self._dirty_events)
        await asyncio.to_thread(self._persist, list(updates.values()), new_incidents)
        self._total_events += len(self._new_event_ids)
        self._new_event_ids.clear()
        # Retry failed writes on the next tick before discarding their evidence.
        self._dirty_events.clear()
        for inc in new_incidents:
            self._seen_incidents.add(inc["id"])
            self._incident_sizes[inc["id"]] = len(inc["events"])
        self.last_error = None
        self.max_latency_seconds = max(self.max_latency_seconds, time.monotonic() - started)
        await self._broadcast(list(updates.values()), new_incidents)

    def _trim_window(self, now: datetime) -> None:
        cutoff = now - timedelta(minutes=settings.window_minutes)
        while self._window and _ts(self._window[0]) < cutoff:
            self._window.popleft()
        while len(self._window) > settings.max_window_events:
            self._window.popleft()

    # ── persistence ─────────────────────────────────────────────────────────
    def _persist(self, events: List[dict], incidents: List[dict]) -> None:
        session = SessionLocal()
        try:
            for d in events:
                session.merge(EventRow(
                    id=d["id"], event_type=d["event_type"], timestamp=d["timestamp"],
                    user=d.get("user", ""), ip=d.get("ip", ""), session=d.get("session", ""),
                    severity=float(d.get("severity") or 0.0),
                    anomaly_score=d.get("anomaly_score"),
                    attack_label=d.get("attack_label"),
                    flagged=bool(d.get("flagged")),
                    event_metadata=d.get("metadata") or {},
                ))
            for inc in incidents:
                session.merge(IncidentRow(
                    id=inc["id"], attack_type=inc["attack_type"],
                    attack_pattern=inc["attack_pattern"], severity=inc["severity"],
                    severity_score=inc["severity_score"], confidence=inc["confidence"],
                    event_count=len(inc["events"]),
                    started_at=inc["timeline"]["started_at"],
                    ended_at=inc["timeline"]["ended_at"],
                    payload=inc,
                ))
            session.commit()
        except Exception:  # pragma: no cover
            session.rollback()
            raise
        finally:
            session.close()

    # ── broadcast ─────────────────────────────────────────────────────────────
    async def _broadcast(self, events: List[dict], incidents: List[dict]) -> None:
        for d in events:
            await manager.broadcast({"type": "event", "data": d})
        for inc in incidents:
            await manager.broadcast({"type": "incident", "data": inc})
        await manager.broadcast({"type": "stats", "data": self.stats()})


def _ts(ev: dict) -> datetime:
    dt = datetime.fromisoformat(str(ev["timestamp"]).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


pipeline = LivePipeline()
