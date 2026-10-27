"""
High-level correlation engine: canonical events in, reconstructed incidents out.

    from correlation import reconstruct_incidents
    incidents = reconstruct_incidents(events)

Pipeline:
  1. Only events the detector flagged are candidates (flagged=True, or
     anomaly_score >= FLAG_THRESHOLD as a fallback).
  2. Build the entity-linked event graph over those events.
  3. Run every attack-chain template over the flagged events.
  4. Deduplicate overlapping matches (a brute-force chain also looks like a
     data-exfil chain; keep the richer one).
  5. Score each surviving match and build an incident with its evidence chain.
"""

from datetime import timedelta
from hashlib import sha256
from typing import Dict, List, Optional

try:
    from .graph_builder import EventGraph, _as_datetime
    from .matcher import run_all_templates
    from .scoring import score_incident, recommended_action
except ImportError:  # pragma: no cover - script-mode fallback
    from graph_builder import EventGraph, _as_datetime
    from matcher import run_all_templates
    from scoring import score_incident, recommended_action

FLAG_THRESHOLD = 0.6


def _is_flagged(ev: dict) -> bool:
    # The detector's explicit flag is authoritative. Only fall back to the
    # anomaly-score threshold for raw events that never went through a detector
    # (no "flagged" key at all).
    if "flagged" in ev:
        return bool(ev["flagged"])
    score = ev.get("anomaly_score")
    return score is not None and score >= FLAG_THRESHOLD


def _incident_id(match: dict) -> str:
    first = match["matched_events"][0]
    return f"INC-{match['template_name'][:4].upper()}-{sha256(str(first).encode()).hexdigest()[:16]}"


class CorrelationEngine:
    def __init__(self, window_minutes: int = 15):
        self.window = timedelta(minutes=window_minutes)

    def reconstruct(self, events: List[dict]) -> List[dict]:
        by_id: Dict[str, dict] = {}
        flagged_ids: List[str] = []

        graph = EventGraph(window=self.window)
        for ev in events:
            ev = dict(ev)
            if "id" not in ev or ev["id"] is None:
                # correlation needs a key; synthesise a stable one if missing
                ev["id"] = f"ev-{len(by_id)}"
            by_id[ev["id"]] = ev
            # Templates group nodes by entity; constructing pairwise edges is unnecessary.
            graph.add_event(ev, link=False)
            if _is_flagged(ev):
                flagged_ids.append(ev["id"])

        matches = run_all_templates(graph, flagged_ids)
        matches = self._dedupe(matches)

        incidents = [self._build_incident(m, by_id) for m in matches]
        # Highest severity first — that is the order a SOC analyst wants.
        incidents.sort(key=lambda i: i["severity_score"], reverse=True)
        return incidents

    @staticmethod
    def _dedupe(matches: List[dict]) -> List[dict]:
        """Drop a match whose events are a subset-overlap of an already-kept,
        richer match. ALL_TEMPLATES is ordered richest-first, so a simple
        greedy keep works."""
        kept: List[dict] = []
        claimed: set = set()
        for m in sorted(matches, key=lambda x: len(x["matched_events"]), reverse=True):
            ids = set(m["matched_events"])
            if ids & claimed:
                continue
            kept.append(m)
            claimed |= ids
        return kept

    @staticmethod
    def _build_incident(match: dict, by_id: Dict[str, dict]) -> dict:
        member_events = [by_id[i] for i in match["matched_events"] if i in by_id]
        member_events.sort(key=lambda e: _as_datetime(e["timestamp"]))

        scoring = score_incident(
            base_severity=_base_severity(match["template_name"]),
            member_events=member_events,
        )

        users = sorted({e["user"] for e in member_events if e.get("user") and e["user"] != "unknown"})
        ips = sorted({e["ip"] for e in member_events if e.get("ip")})
        sessions = sorted({e["session"] for e in member_events if e.get("session")})

        evidence = [_evidence_row(e) for e in member_events]

        return {
            "id": _incident_id(match),
            "attack_type": match["attack_type"],
            "attack_pattern": match["display_name"],
            "description": match["description"],
            "severity": scoring["severity"],
            "severity_score": scoring["severity_score"],
            "confidence": scoring["confidence"],
            "timeline": {
                "started_at": _iso(match["start_time"]),
                "ended_at": _iso(match["end_time"]),
            },
            "entities": {"users": users, "ips": ips, "sessions": sessions},
            "events": member_events,
            "evidence": evidence,
            "recommended_action": recommended_action(match["attack_type"], scoring["severity"]),
        }


def _base_severity(template_name: str) -> float:
    try:
        from .attack_templates import TEMPLATES_BY_NAME
    except ImportError:  # pragma: no cover
        from attack_templates import TEMPLATES_BY_NAME
    t = TEMPLATES_BY_NAME.get(template_name)
    return t.base_severity if t else 0.6


def _evidence_row(ev: dict) -> dict:
    """One human-readable line of the evidence chain, with the signal score and
    a short 'why this was flagged' reason."""
    meta = ev.get("metadata", {}) or {}
    reason = {
        "auth_login_failure": f"Failed login ({meta.get('reason', 'auth failure')})",
        "auth_login_success": "Successful login" + (" from new source" if meta.get("new_source") else ""),
        "db_query": f"DB read on {meta.get('table', 'table')}" + (f" ({meta.get('rows')} rows)" if meta.get("rows") else ""),
        "file_access": f"{meta.get('action', 'access')} {meta.get('path', 'file')}" + (f" ({_fmt_bytes(meta.get('bytes'))})" if meta.get("bytes") else ""),
        "connection_attempt": f"Probe {meta.get('dest_host', '')}:{meta.get('dest_port', '')} ({meta.get('state', '')})",
        "api_call": f"{meta.get('method', 'GET')} {meta.get('endpoint', '/')} -> {meta.get('status_code', '')}",
    }.get(ev["event_type"], ev["event_type"])
    return {
        "id": ev["id"],
        "timestamp": ev["timestamp"],
        "event_type": ev["event_type"],
        "user": ev.get("user"),
        "ip": ev.get("ip"),
        "reason": reason,
        "score": ev.get("anomaly_score") if ev.get("anomaly_score") is not None else ev.get("severity"),
    }


def _fmt_bytes(n: Optional[int]) -> str:
    if not n:
        return ""
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.0f}TB"


def _iso(dt) -> str:
    if hasattr(dt, "isoformat"):
        return dt.isoformat().replace("+00:00", "Z")
    return str(dt)


_DEFAULT_ENGINE = CorrelationEngine()


def reconstruct_incidents(events: List[dict]) -> List[dict]:
    """Module-level convenience wrapper used by the backend pipeline."""
    return _DEFAULT_ENGINE.reconstruct(events)
