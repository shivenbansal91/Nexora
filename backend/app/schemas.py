"""Pydantic response models (mirror the canonical event schema). Kept light;
the pipeline passes dicts, these are mainly for OpenAPI documentation."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class EventOut(BaseModel):
    id: str
    event_type: str
    timestamp: str
    user: str
    ip: str
    session: str
    severity: float
    anomaly_score: Optional[float] = None
    attack_label: Optional[str] = None
    flagged: bool = False
    metadata: Dict[str, Any] = {}


class Timeline(BaseModel):
    started_at: str
    ended_at: str


class IncidentOut(BaseModel):
    id: str
    attack_type: str
    attack_pattern: str
    description: str
    severity: str
    severity_score: float
    confidence: float
    timeline: Timeline
    entities: Dict[str, List[str]]
    events: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    recommended_action: str


class StatsOut(BaseModel):
    events: int
    anomalies: int
    active_threats: int
    ws_clients: int
    window_size: int


class AttackResponse(BaseModel):
    status: str
    attack_type: str
    injected: int
