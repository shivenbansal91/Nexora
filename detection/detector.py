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

from .features import FEATURE_NAMES, events_to_matrix

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


def _burst_ids(events: List[dict], n: int, window_s: float, distinct_destinations: bool = False) -> set[str]:
    ordered = sorted(events, key=lambda e: _as_dt(e["timestamp"]))
    times = [_as_dt(e["timestamp"]).timestamp() for e in ordered]
    ids: set[str] = set()
    left = 0
    for right, timestamp in enumerate(times):
        while timestamp - times[left] > window_s:
            left += 1
        if right - left + 1 >= n:
            if distinct_destinations:
                targets = {((e.get('metadata') or {}).get('dest_host'), (e.get('metadata') or {}).get('dest_port'))
                           for e in ordered[left:right + 1]}
                if len({(host, port) for host, port in targets if host and port is not None}) < n:
                    continue
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
            if ISO_PATH.exists() and NORM_PATH.exists():
                iso = joblib.load(ISO_PATH)
                norm = json.loads(NORM_PATH.read_text())
                if iso.n_features_in_ != len(FEATURE_NAMES) or not (
                    np.isfinite(norm['p1']) and np.isfinite(norm['p99']) and norm['p99'] > norm['p1']
                ):
                    raise ValueError('Model feature count or score normalization is incompatible')
                if norm.get('feature_names') != FEATURE_NAMES:
                    raise ValueError('Model feature order is incompatible')
        except Exception as exc:  # pragma: no cover
            print(f"[detector] could not load models ({exc}); running rules-only.")
            iso, norm = None, None
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
        if 'raw_threshold' in self._norm:
            norm = np.clip(.6 + (raw - self._norm['raw_threshold']) / span, 0, 1)
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
            # Simulator answers are evaluation labels, not detector predictions.
            if not ev['flagged']:
                ev['attack_label'] = 'benign'

        self._apply_rules(events)
        return events

    def _apply_rules(self, events: List[dict]) -> None:
        by_ip: dict[str, list] = {}
        by_session: dict[tuple[str, str], list] = {}
        by_user: dict[str, list] = {}
        for ev in events:
            if ev.get('user') not in (None, '', 'unknown'):
                by_user.setdefault(ev['user'], []).append(ev)
            if ev.get('ip') not in (None, '', 'unknown'):
                by_ip.setdefault(ev['ip'], []).append(ev)
            if all(ev.get(key) not in (None, '', 'unknown') for key in ('user', 'session')):
                by_session.setdefault((ev['user'], ev['session']), []).append(ev)

        def flag(ev, label):
            ev["flagged"] = True
            ev["attack_label"] = label

        # Account failures can rotate IPs/sessions; correlation validates the
        # successful session before assembling a full compromise chain.
        for evs in by_user.values():
            fails = [e for e in evs if e['event_type'] == 'auth_login_failure']
            fail_ids = _burst_ids(fails, BRUTE_FORCE_FAILURES, BRUTE_FORCE_WINDOW_S)
            if fail_ids:
                failure_times = [_as_dt(e['timestamp']) for e in fails if e['id'] in fail_ids]
                for e in evs:
                    follows_burst = any(0 <= (_as_dt(e['timestamp']) - t).total_seconds() <= 600 for t in failure_times)
                    if e['id'] in fail_ids or (follows_burst and (
                        e['event_type'] in ('auth_login_success', 'db_query')
                        or (e['event_type'] == 'file_access' and (e.get('metadata') or {}).get('action') == 'download')
                    )):
                        flag(e, "brute_force")

        # 2. Port scan, per ip
        for ip, evs in by_ip.items():
            conns = [e for e in evs if e["event_type"] == "connection_attempt"]
            ids = _burst_ids(conns, PORT_SCAN_PROBES, PORT_SCAN_WINDOW_S, distinct_destinations=True)
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
                for e in by_session.get((ev.get('user'), ev.get('session')), []):
                    if 0 <= (_as_dt(ev['timestamp']) - _as_dt(e['timestamp'])).total_seconds() <= 600 \
                            and e["event_type"] in ("auth_login_success", "db_query") \
                            and not e.get("flagged"):
                        flag(e, "data_exfiltration")
