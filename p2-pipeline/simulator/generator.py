"""
Normal traffic generator — Week 2.

Week 1 proved the schema round-trips. Week 2 goal (per project plan):
"Finish the baseline normal-traffic generator (auth/API/DB/file events),
outputting schema-compliant JSON."

New this week:
- auth_login_failure, auth_logout, db_query, file_access event types
- session continuity: stream_sessions() emits realistic session-shaped
  sequences (login -> a few actions -> logout) sharing one session ID,
  instead of every event getting a random unrelated session ID.

stream() is kept as-is (flat, independent events) so Week 1's tests and
anything already depending on it keep working. stream_sessions() is the
new, more realistic entry point — P3 (correlation) and P4 (frontend
timeline) will want session-shaped data to build against.

Run directly to print a mix of sample events:
    python -m simulator.generator
"""

from __future__ import annotations

import json
import random
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Iterator, Optional


# --- Config -----------------------------------------------------------

USERS = ["alice", "bob", "carol", "dave", "svc_billing", "svc_reports"]

# Proportion of each event type in flat/independent "normal" traffic
# (used by stream()). Session-shaped traffic (stream_sessions()) picks
# actions from ACTION_EVENT_TYPES instead — see below.
EVENT_WEIGHTS = {
    "auth_login_success": 0.12,
    "auth_login_failure": 0.03,
    "auth_logout": 0.10,
    "api_call": 0.45,
    "db_query": 0.20,
    "file_access": 0.10,
}

# Event types that can appear as "actions" inside an already-open
# session (everything except login/logout, which bookend a session).
ACTION_EVENT_TYPES = ["api_call", "db_query", "file_access"]

API_ENDPOINTS = ["/api/orders", "/api/users", "/api/reports", "/api/invoices"]
DB_QUERIES = [
    "SELECT * FROM orders WHERE user_id = ?",
    "SELECT * FROM invoices WHERE status = 'pending'",
    "UPDATE users SET last_login = ? WHERE id = ?",
    "SELECT COUNT(*) FROM sessions WHERE active = true",
]
DB_TABLES = ["orders", "invoices", "users", "sessions", "reports"]
FILE_PATHS = [
    "/data/reports/q3_summary.pdf",
    "/data/invoices/inv_2291.pdf",
    "/data/exports/users_export.csv",
    "/data/uploads/contract_draft.docx",
]


# --- Data model ---------------------------------------------------------

@dataclass
class Event:
    event_type: str
    timestamp: str
    user: str
    ip: str
    session: str
    severity: float
    metadata: dict
    # Assigned at creation so every event is addressable end-to-end. The
    # correlation graph keys nodes on this, and the frontend uses it as a
    # React key. Detection fills in anomaly_score / attack_label / flagged.
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    anomaly_score: Optional[float] = None
    attack_label: Optional[str] = None
    flagged: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))


# --- Helpers --------------------------------------------------------------

def _random_ip() -> str:
    return f"10.0.{random.randint(0, 5)}.{random.randint(2, 254)}"


def _random_session() -> str:
    return uuid.uuid4().hex[:12]


def iso(dt: datetime) -> str:
    """Format a datetime as the canonical ISO-8601 UTC '...Z' string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _now_iso() -> str:
    return iso(datetime.now(timezone.utc))


def _pick_event_type() -> str:
    types, weights = zip(*EVENT_WEIGHTS.items())
    return random.choices(types, weights=weights, k=1)[0]


# --- Per-event-type payload builders --------------------------------------
# Each returns (metadata, severity) for a given event_type. Pulled out
# so both stream() and stream_sessions() share the same logic.

def _build_payload(event_type: str) -> tuple[dict, float]:
    if event_type == "auth_login_success":
        return {"method": random.choice(["password", "sso"])}, 0.0

    if event_type == "auth_login_failure":
        # Low but nonzero: a handful of failed logins is normal human
        # error (typos, expired passwords), not an attack. Repeated
        # failures from the same user/IP is what brute_force_attempt
        # (a separate, Week 3 attack event type) represents.
        return {
            "method": random.choice(["password", "sso"]),
            "reason": random.choice(["bad_password", "expired_credentials"]),
        }, 0.1

    if event_type == "auth_logout":
        return {"reason": "user_initiated"}, 0.0

    if event_type == "api_call":
        return {
            "endpoint": random.choice(API_ENDPOINTS),
            "method": random.choice(["GET", "POST"]),
            "status_code": random.choice([200, 200, 200, 201, 204]),
        }, 0.0

    if event_type == "db_query":
        return {
            "query_type": random.choice(["SELECT", "SELECT", "UPDATE"]),
            "table": random.choice(DB_TABLES),
            "query": random.choice(DB_QUERIES),
        }, 0.0

    if event_type == "file_access":
        return {
            "path": random.choice(FILE_PATHS),
            "action": random.choice(["read", "read", "download"]),
        }, 0.0

    raise ValueError(f"Unhandled event_type: {event_type}")


# --- Generator ------------------------------------------------------------

class NormalTrafficGenerator:
    """
    Emits schema-compliant 'normal' (non-attack) events.

    Two ways to generate traffic:
      - stream(n): n independent events, each with its own random
        session ID. Fast, simple, good for schema/volume testing.
        (This is the Week 1 behavior, unchanged.)
      - stream_sessions(n_sessions): realistic session-shaped traffic —
        each session is login -> a few actions -> optional logout, all
        sharing one session ID. This is what P3 (correlation) and P4
        (timeline UI) should build against, since it looks like real
        user activity instead of disconnected random events.
    """

    def __init__(self, seed: int | None = None):
        if seed is not None:
            random.seed(seed)

    def _make_event(self, event_type: str, user: str, ip: str, session: str) -> Event:
        metadata, severity = _build_payload(event_type)
        return Event(
            event_type=event_type,
            timestamp=_now_iso(),
            user=user,
            ip=ip,
            session=session,
            severity=severity,
            metadata=metadata,
        )

    def stream(self, n: int) -> Iterator[Event]:
        """Yield n independent schema-compliant normal events."""
        for _ in range(n):
            event_type = _pick_event_type()
            user = random.choice(USERS)
            ip = _random_ip()
            session = _random_session()
            yield self._make_event(event_type, user, ip, session)

    def stream_sessions(
        self,
        n_sessions: int,
        min_actions: int = 1,
        max_actions: int = 5,
        logout_probability: float = 0.7,
    ) -> Iterator[Event]:
        """
        Yield realistic session-shaped traffic.

        For each session: one user+ip+session_id is picked and reused
        across a login event, a handful of action events (api/db/file),
        and (probabilistically) a logout event — the way a real user
        session actually looks.
        """
        for _ in range(n_sessions):
            user = random.choice(USERS)
            ip = _random_ip()
            session = _random_session()

            # Most sessions start with a successful login; a few start
            # with a failed attempt followed by a success, which is
            # realistic (mistyped password, correct on retry).
            if random.random() < 0.85:
                yield self._make_event("auth_login_success", user, ip, session)
            else:
                yield self._make_event("auth_login_failure", user, ip, session)
                yield self._make_event("auth_login_success", user, ip, session)

            n_actions = random.randint(min_actions, max_actions)
            for _ in range(n_actions):
                action_type = random.choice(ACTION_EVENT_TYPES)
                yield self._make_event(action_type, user, ip, session)

            if random.random() < logout_probability:
                yield self._make_event("auth_logout", user, ip, session)


# --- Manual sanity check ---------------------------------------------------

if __name__ == "__main__":
    gen = NormalTrafficGenerator(seed=42)

    print("Sample of 6 independent events (stream):\n")
    for event in gen.stream(6):
        print(event.to_json())

    print("\nSample of 1 full session (stream_sessions):\n")
    for event in gen.stream_sessions(1):
        print(event.to_json())