"""
Detector — anomaly scoring (IsolationForest) + rule-based attack flagging.

Design (plan §6 + risk mitigation "start with rule/template matching"):
  - The IsolationForest gives every event a continuous anomaly_score in [0,1].
    This is the unsupervised ML signal and the headline "anomaly detection".
  - A transparent rule layer flags the four scoped attacks reliably, marking
    whole bursts so the correlation engine has complete chains to reconstruct.
    Rules are explainable in a viva and don't depend on the IF being perfectly
    tuned.

annotate(events) mutates each event in place, setting:
    anomaly_score : float 0..1
    flagged       : bool
    attack_label  : one of benign|brute_force|port_scan|data_exfiltration|api_abuse

Operates over a *window* of events (the backend passes its rolling buffer), so
burst detection sees the whole burst at once.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import numpy as np

from .features import events_to_matrix

MODELS_DIR = Path(__file__).resolve().parent / "models"
ISO_PATH = MODELS_DIR / "isoforest.joblib"
NORM_PATH = MODELS_DIR / "isoforest_norm.json"

# Rule thresholds — kept here, not buried, so they're easy to defend/tune.
BRUTE_FORCE_FAILURES = 5
BRUTE_FORCE_WINDOW_S = 120
PORT_SCAN_PROBES = 15
PORT_SCAN_WINDOW_S = 60
API_BURST_CALLS = 25
API_BURST_WINDOW_S = 30
EXFIL_BYTES = 10_000_000  # 10 MB


def _as_dt(ts) -> datetime:
    if isinstance(ts, datetime):
        dt = ts
    else:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _has_burst(times: List[datetime], n: int, window_s: float) -> bool:
    """True if any sliding window of length window_s holds >= n timestamps."""
    if len(times) < n:
        return False
    ts = sorted(t.timestamp() for t in times)
    j = 0
    for i in range(len(ts)):
        while ts[i] - ts[j] > window_s:
            j += 1
        if i - j + 1 >= n:
            return True
    return False


def _burst_ids(events: List[dict], n: int, window_s: float) -> set[str]:
    ordered = sorted(events, key=lambda e: _as_dt(e["timestamp"]))
    times = [_as_dt(e["timestamp"]).timestamp() for e in ordered]
    ids: set[str] = set()
    left = 0
    for right, timestamp in enumerate(times):
        while timestamp - times[left] > window_s:
            left += 1
        if right - left + 1 >= n:
            ids.update(e["id"] for e in ordered[left:right + 1])
    return ids


class Detector:
    def __init__(self, iso_model=None, norm: Optional[dict] = None):
        self._iso = iso_model
        self._norm = norm or {}

    # ── loading ──────────────────────────────────────────────────────────────
    @classmethod
    def load(cls) -> "Detector":
        """Load trained models if present; otherwise return a rules-only detector
        (anomaly_score falls back to event severity). Never raises."""
        iso, norm = None, None
        try:
            import joblib
            if ISO_PATH.exists():
                iso = joblib.load(ISO_PATH)
            if NORM_PATH.exists():
                norm = json.loads(NORM_PATH.read_text())
        except Exception as exc:  # pragma: no cover
            print(f"[detector] could not load models ({exc}); running rules-only.")
        return cls(iso, norm)

    @property
    def ml_loaded(self) -> bool:
        return self._iso is not None

    # ── scoring ───────────────────────────────────────────────────────────────
    def _anomaly_scores(self, events: List[dict]) -> np.ndarray:
        n = len(events)
        if n == 0:
            return np.zeros(0)
        if self._iso is None:
            return np.array([float(e.get("severity", 0.0) or 0.0) for e in events])
        X, order = events_to_matrix(events)
        raw = -self._iso.score_samples(X)  # higher = more anomalous
        lo = self._norm.get("p1", float(raw.min()))
        hi = self._norm.get("p99", float(raw.max()))
        span = (hi - lo) or 1.0
        norm = np.clip((raw - lo) / span, 0.0, 1.0)
        # map back to original event order
        out = np.zeros(n)
        for pos, orig_idx in enumerate(order):
            out[orig_idx] = norm[pos]
        return out

    # ── main entry point ──────────────────────────────────────────────────────
    def annotate(self, events: List[dict]) -> List[dict]:
        if not events:
            return events

        scores = self._anomaly_scores(events)
        for ev, s in zip(events, scores):
            ev["anomaly_score"] = round(float(s), 3)
            ev.setdefault("flagged", False)
            ev.setdefault("attack_label", "benign")

        self._apply_rules(events)
        return events

    def _apply_rules(self, events: List[dict]) -> None:
        by_ip: dict[str, list] = {}
        by_session: dict[str, list] = {}
        for ev in events:
            by_ip.setdefault(ev.get("ip", ""), []).append(ev)
            by_session.setdefault(ev.get("session", ""), []).append(ev)

        def flag(ev, label):
            ev["flagged"] = True
            ev["attack_label"] = label
            ev["anomaly_score"] = max(ev.get("anomaly_score", 0.0), 0.8)

        # 1. Brute force -> compromise chain. Detect the failed-login burst within
        #    a SESSION (not across all of a username's unrelated normal sessions,
        #    which would over-flag), then flag that session's compromise chain.
        for session, evs in by_session.items():
            if not session:
                continue
            fails = [_as_dt(e["timestamp"]) for e in evs if e["event_type"] == "auth_login_failure"]
            if _has_burst(fails, BRUTE_FORCE_FAILURES, BRUTE_FORCE_WINDOW_S):
                for e in evs:
                    if e["event_type"] in ("auth_login_failure", "auth_login_success", "db_query") \
                            or (e["event_type"] == "file_access" and (e.get("metadata") or {}).get("action") == "download"):
                        flag(e, "brute_force")

        # 2. Port scan, per ip
        for ip, evs in by_ip.items():
            conns = [e for e in evs if e["event_type"] == "connection_attempt"]
            ids = _burst_ids(conns, PORT_SCAN_PROBES, PORT_SCAN_WINDOW_S)
            for e in conns:
                if e["id"] in ids:
                    flag(e, "port_scan")

        # 3. API abuse / rate burst, per ip
        for ip, evs in by_ip.items():
            calls = [e for e in evs if e["event_type"] == "api_call"]
            ids = _burst_ids(calls, API_BURST_CALLS, API_BURST_WINDOW_S)
            for e in calls:
                if e["id"] in ids:
                    flag(e, "api_abuse")

        # 4. Data exfiltration — large download; pull in its session's login+query.
        for ev in events:
            meta = ev.get("metadata") or {}
            if ev["event_type"] == "file_access" and meta.get("action") == "download" \
                    and (meta.get("bytes") or 0) >= EXFIL_BYTES:
                if not ev.get("flagged"):
                    flag(ev, "data_exfiltration")
                sess = ev.get("session")
                for e in events:
                    if e.get("session") == sess and e["event_type"] in ("auth_login_success", "db_query") \
                            and not e.get("flagged"):
                        flag(e, "data_exfiltration")
