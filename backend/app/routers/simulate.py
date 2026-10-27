"""Attack injection endpoints — drive the live demo."""

from fastapi import APIRouter, HTTPException

from ..pipeline import pipeline
from simulator.injectors import ATTACK_TYPES

router = APIRouter(tags=["simulate"])


@router.get("/simulate/attack-types")
def attack_types():
    return {"attack_types": ATTACK_TYPES}


@router.post("/simulate/attack/{attack_type}")
async def inject_attack(attack_type: str):
    if len(pipeline._pending) >= 1000:
        raise HTTPException(status_code=429, detail="Attack queue is full; wait for pending events to finish.")
    try:
        n = pipeline.inject_attack(attack_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"status": "injected", "attack_type": attack_type, "injected": n}
