"""Incident endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import IncidentRow

router = APIRouter(tags=["incidents"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/incidents")
def list_incidents(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    rows = db.execute(
        select(IncidentRow).order_by(IncidentRow.created_at.desc()).limit(limit)
    ).scalars().all()
    return [r.payload for r in rows]


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    row = db.get(IncidentRow, incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row.payload
