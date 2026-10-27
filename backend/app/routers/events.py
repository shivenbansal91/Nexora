"""Event + entity endpoints."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import EventRow

router = APIRouter(tags=["events"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/events")
def list_events(
    limit: int = Query(50, ge=1, le=500),
    flagged_only: bool = False,
    db: Session = Depends(get_db),
):
    stmt = select(EventRow).order_by(EventRow.created_at.desc()).limit(limit)
    if flagged_only:
        stmt = select(EventRow).where(EventRow.flagged.is_(True)).order_by(
            EventRow.created_at.desc()
        ).limit(limit)
    rows = db.execute(stmt).scalars().all()
    return [r.to_event_dict() for r in rows]


@router.get("/entities")
def list_entities(db: Session = Depends(get_db)):
    """Distinct recent entities, for the search box / graph filters."""
    rows = db.execute(
        select(EventRow).order_by(EventRow.created_at.desc()).limit(500)
    ).scalars().all()
    users, ips, sessions = set(), set(), set()
    for r in rows:
        if r.user and r.user != "unknown":
            users.add(r.user)
        if r.ip:
            ips.add(r.ip)
        if r.session:
            sessions.add(r.session)
    return {
        "users": sorted(users),
        "ips": sorted(ips),
        "sessions": sorted(sessions),
        "services": ["auth-server", "api-gateway", "db-prod-01", "file-store", "edge-fw"],
    }
