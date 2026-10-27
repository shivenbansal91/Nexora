"""
Attack injectors — Week 3+.

Produces schema-compliant *attack* event sequences to interleave with the
NormalTrafficGenerator's benign traffic. Each injector emits a coherent,
entity-linked sequence (shared user / ip / session) so the correlation
engine can reconstruct it into a single incident, and carries metadata the
detection engine's rules + classifier key on.

Scope (project plan §5, §7) — exactly four attack types, one per signal class:
  - brute_force        auth: failed-login burst -> success -> db/file access
  - port_scan          network: many connection_attempt from one ip
  - data_exfiltration  volume: login -> db query -> large file download
  - api_abuse          rate: api_call burst from one user/ip

Each injector returns list[Event] in chronological order. Timestamps are
spaced with realistic gaps that fit inside the correlation templates' windows.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import List

from .generator import Event, iso

# Attack types exposed to the API / frontend. Keep this list in lockstep with
# the correlation templates and the classifier labels.
ATTACK_TYPES = ["brute_force", "port_scan", "data_exfiltration", "api_abuse"]

# IPs that look external/suspicious — used for geo flavour in the UI. These are
# documentation/reserved-style values, not real hosts.
MALICIOUS_IPS = ["185.42.91.8", "45.138.27.41", "103.56.148.22", "91.239.244.11"]
TARGET_USERS = ["admin", "svc_billing", "svc_reports", "dbadmin"]
SENSITIVE_FILES = [
    "/data/exports/customers_full.csv",
    "/data/exports/payroll_2026.csv",
    "/data/reports/financials_q3.pdf",
    "/data/backups/users_dump.sql",
]
SENSITIVE_TABLES = ["customers", "payments", "users", "salaries"]


def _session() -> str:
    return uuid.uuid4().hex[:12]


def _ev(event_type, ts, user, ip, session, severity, metadata, attack_label):
    """Build an attack Event. attack_label is the ground-truth type (used for
    the simulated-data classifier metric); the live detector re-derives it."""
    return Event(
        event_type=event_type,
        timestamp=iso(ts),
        user=user,
        ip=ip,
        session=session,
        severity=severity,
        metadata=metadata,
        attack_label=attack_label,
    )


class AttackInjector:
    """Generates attack event sequences. Pass a seed for reproducible demos."""

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)

    # ── dispatch ────────────────────────────────────────────────────────────
    def inject(self, attack_type: str, start_time: datetime | None = None) -> List[Event]:
        start_time = start_time or datetime.now(timezone.utc)
        if attack_type == "brute_force":
            return self.brute_force(start_time)
        if attack_type == "port_scan":
            return self.port_scan(start_time)
        if attack_type == "data_exfiltration":
            return self.data_exfiltration(start_time)
        if attack_type == "api_abuse":
            return self.api_abuse(start_time)
        raise ValueError(f"Unknown attack_type: {attack_type!r}. Valid: {ATTACK_TYPES}")

    # ── 1. Brute force -> credential compromise -> exfiltration ──────────────
    def brute_force(self, t0: datetime, n_failures: int = 8) -> List[Event]:
        ip = self._rng.choice(MALICIOUS_IPS)
        user = self._rng.choice(TARGET_USERS)
        session = _session()
        events: List[Event] = []
        t = t0

        for _ in range(n_failures):
            events.append(_ev(
                "auth_login_failure", t, user, ip, session, 0.35,
                {"method": "password", "reason": "bad_password", "source": "external"},
                "brute_force",
            ))
            t += timedelta(seconds=self._rng.uniform(3, 9))

        # Eventually the attacker guesses right.
        events.append(_ev(
            "auth_login_success", t, user, ip, session, 0.55,
            {"method": "password", "new_source": True, "source": "external"},
            "brute_force",
        ))
        t += timedelta(seconds=self._rng.uniform(5, 15))

        # Then reaches for sensitive data.
        events.append(_ev(
            "db_query", t, user, ip, session, 0.5,
            {"query_type": "SELECT", "table": self._rng.choice(SENSITIVE_TABLES),
             "rows": self._rng.randint(5000, 50000)},
            "brute_force",
        ))
        t += timedelta(seconds=self._rng.uniform(5, 20))
        events.append(_ev(
            "file_access", t, user, ip, session, 0.65,
            {"path": self._rng.choice(SENSITIVE_FILES), "action": "download",
             "bytes": self._rng.randint(5_000_000, 80_000_000)},
            "brute_force",
        ))
        return events

    # ── 2. Port / network scan ───────────────────────────────────────────────
    def port_scan(self, t0: datetime, n_probes: int = 25) -> List[Event]:
        ip = self._rng.choice(MALICIOUS_IPS)
        session = _session()
        target_host = f"10.0.{self._rng.randint(0, 3)}.{self._rng.randint(2, 254)}"
        events: List[Event] = []
        t = t0
        ports = self._rng.sample(range(1, 10000), n_probes)
        for port in ports:
            events.append(_ev(
                "connection_attempt", t, "unknown", ip, session, 0.25,
                {"dest_host": target_host, "dest_port": port,
                 "state": self._rng.choice(["closed", "closed", "open", "filtered"])},
                "port_scan",
            ))
            t += timedelta(seconds=self._rng.uniform(0.3, 1.5))
        return events

    # ── 3. Data exfiltration (volume) ────────────────────────────────────────
    def data_exfiltration(self, t0: datetime) -> List[Event]:
        ip = self._rng.choice(MALICIOUS_IPS)
        user = self._rng.choice(TARGET_USERS)
        session = _session()
        events: List[Event] = []
        t = t0

        events.append(_ev(
            "auth_login_success", t, user, ip, session, 0.3,
            {"method": "sso", "new_source": True, "source": "external"},
            "data_exfiltration",
        ))
        t += timedelta(seconds=self._rng.uniform(10, 40))
        events.append(_ev(
            "db_query", t, user, ip, session, 0.5,
            {"query_type": "SELECT", "table": self._rng.choice(SENSITIVE_TABLES),
             "rows": self._rng.randint(50000, 500000)},
            "data_exfiltration",
        ))
        t += timedelta(seconds=self._rng.uniform(10, 60))
        events.append(_ev(
            "file_access", t, user, ip, session, 0.7,
            {"path": self._rng.choice(SENSITIVE_FILES), "action": "download",
             "bytes": self._rng.randint(50_000_000, 500_000_000)},
            "data_exfiltration",
        ))
        return events

    # ── 4. API abuse / rate burst ─────────────────────────────────────────────
    def api_abuse(self, t0: datetime, n_calls: int = 40) -> List[Event]:
        ip = self._rng.choice(MALICIOUS_IPS)
        user = self._rng.choice(["svc_reports", "svc_billing", "unknown"])
        session = _session()
        endpoint = self._rng.choice(["/api/users", "/api/orders", "/api/invoices"])
        events: List[Event] = []
        t = t0
        for i in range(n_calls):
            events.append(_ev(
                "api_call", t, user, ip, session, 0.2,
                {"endpoint": endpoint, "method": "GET",
                 "status_code": 200 if i % 7 else 429, "seq": i},
                "api_abuse",
            ))
            t += timedelta(seconds=self._rng.uniform(0.1, 0.6))
        return events


if __name__ == "__main__":
    inj = AttackInjector(seed=1)
    for atk in ATTACK_TYPES:
        evs = inj.inject(atk)
        print(f"{atk}: {len(evs)} events; first={evs[0].event_type}, last={evs[-1].event_type}")
