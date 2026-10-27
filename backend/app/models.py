"""ORM models: persisted events and reconstructed incidents."""

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, String, Integer
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EventRow(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(48), index=True)
    timestamp: Mapped[str] = mapped_column(String(40), index=True)
    user: Mapped[str] = mapped_column(String(64), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    session: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[float] = mapped_column(Float, default=0.0)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    attack_label: Mapped[str | None] = mapped_column(String(48), nullable=True)
    flagged: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    event_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    def to_event_dict(self) -> dict:
        return {
            "id": self.id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "user": self.user,
            "ip": self.ip,
            "session": self.session,
            "severity": self.severity,
            "anomaly_score": self.anomaly_score,
            "attack_label": self.attack_label,
            "flagged": self.flagged,
            "metadata": self.event_metadata or {},
        }


class IncidentRow(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    attack_type: Mapped[str] = mapped_column(String(48), index=True)
    attack_pattern: Mapped[str] = mapped_column(String(96))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    severity_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[str] = mapped_column(String(40))
    ended_at: Mapped[str] = mapped_column(String(40))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
