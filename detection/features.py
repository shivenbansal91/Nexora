"""
Feature extraction — canonical events -> numeric matrix.

Shared by the IsolationForest anomaly detector, the attack classifier, and the
real-dataset benchmark, so every model sees the same feature definition.

Two feature families:
  - per-event:  event type (one-hot), hour-of-day, severity, log(bytes),
                log(rows), error-status flag
  - rolling context (what makes burst attacks visible): counts of recent
                events by the same ip / user within short windows

Context features require chronological order, so events_to_matrix() sorts a
copy by timestamp before computing them.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import List, Tuple

import numpy as np

EVENT_TYPES = [
    "auth_login_success",
    "auth_login_failure",
    "auth_logout",
    "api_call",
    "db_query",
    "file_access",
    "connection_attempt",
]

_ONEHOT = {t: i for i, t in enumerate(EVENT_TYPES)}

FEATURE_NAMES = (
    [f"is_{t}" for t in EVENT_TYPES]
    + [
        "hour_norm",
        "severity",
        "log_bytes",
        "log_rows",
        "is_error_status",
        "is_download",
        "cnt_same_ip_60s",
        "cnt_fail_user_120s",
        "cnt_conn_ip_60s",
        "cnt_api_ip_30s",
    ]
)


def _as_dt(ts) -> datetime:
    if isinstance(ts, datetime):
        dt = ts
    else:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _count_recent(times: List[datetime], now: datetime, window_s: float) -> int:
    # times is ascending; count those within [now-window, now)
    lo = now.timestamp() - window_s
    c = 0
    for t in reversed(times):
        if t.timestamp() < lo:
            break
        c += 1
    return c


def events_to_matrix(events: List[dict]) -> Tuple[np.ndarray, List[int]]:
    """Return (X, order) where X[i] is the feature row for events sorted by time,
    and order[i] is the index of that event in the original list."""
    indexed = list(enumerate(events))
    indexed.sort(key=lambda p: _as_dt(p[1]["timestamp"]))

    # rolling per-entity timelines
    ip_times: dict[str, list] = {}
    user_fail_times: dict[str, list] = {}
    ip_conn_times: dict[str, list] = {}
    ip_api_times: dict[str, list] = {}

    rows = []
    order = []
    for orig_idx, ev in indexed:
        dt = _as_dt(ev["timestamp"])
        et = ev.get("event_type", "")
        meta = ev.get("metadata", {}) or {}
        ip = ev.get("ip", "")
        user = ev.get("user", "")

        onehot = [0.0] * len(EVENT_TYPES)
        if et in _ONEHOT:
            onehot[_ONEHOT[et]] = 1.0

        hour_norm = dt.hour / 23.0
        severity = float(ev.get("severity", 0.0) or 0.0)
        log_bytes = math.log1p(float(meta.get("bytes", 0) or 0)) / 20.0
        log_rows = math.log1p(float(meta.get("rows", 0) or 0)) / 15.0
        status = meta.get("status_code", 200)
        is_error = 1.0 if isinstance(status, (int, float)) and status >= 400 else 0.0
        is_download = 1.0 if meta.get("action") == "download" else 0.0

        cnt_ip = _count_recent(ip_times.get(ip, []), dt, 60)
        cnt_fail = _count_recent(user_fail_times.get(user, []), dt, 120)
        cnt_conn = _count_recent(ip_conn_times.get(ip, []), dt, 60)
        cnt_api = _count_recent(ip_api_times.get(ip, []), dt, 30)

        rows.append(onehot + [
            hour_norm, severity, log_bytes, log_rows, is_error, is_download,
            cnt_ip / 20.0, cnt_fail / 10.0, cnt_conn / 20.0, cnt_api / 40.0,
        ])
        order.append(orig_idx)

        # update timelines AFTER computing (counts are of prior events)
        ip_times.setdefault(ip, []).append(dt)
        if et == "auth_login_failure":
            user_fail_times.setdefault(user, []).append(dt)
        if et == "connection_attempt":
            ip_conn_times.setdefault(ip, []).append(dt)
        if et == "api_call":
            ip_api_times.setdefault(ip, []).append(dt)

    return np.asarray(rows, dtype=float), order
